#define _GNU_SOURCE
#include "afalg_gcm.h"

#include <errno.h>
#include <linux/if_alg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif
#ifndef ALG_SET_AEAD_ASSOCLEN
#define ALG_SET_AEAD_ASSOCLEN 4
#endif
#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE 5
#endif

#define GCM_IV_LEN       12U
#define GCM_MAX_TAG_LEN  16U
#define GCM_DEFAULT_BUF  (1024U * 1024U)

typedef struct {
    int tfmfd;
    int opfd;
    int enc;
    int key_set;
    int iv_set;
    int tag_set;
    int processed;

    size_t keylen;
    size_t ivlen;
    size_t taglen;
    size_t sock_buf_cap;

    uint8_t key[32];
    uint8_t iv[GCM_IV_LEN];
    uint8_t tag[GCM_MAX_TAG_LEN];

    uint8_t *aad;
    size_t aad_len;
    size_t aad_cap;

    uint8_t *aad_discard;
    size_t aad_discard_cap;

    uint8_t *saved_ct;
    size_t saved_ct_len;
    size_t saved_ct_cap;
    uint8_t *saved_out;
} AFALG_GCM_CTX;

static void afalg_gcm_close_fds(AFALG_GCM_CTX *ctx)
{
    if (ctx->opfd >= 0) {
        close(ctx->opfd);
        ctx->opfd = -1;
    }
    if (ctx->tfmfd >= 0) {
        close(ctx->tfmfd);
        ctx->tfmfd = -1;
    }
    ctx->sock_buf_cap = 0;
}

static void afalg_gcm_set_sock_buf(AFALG_GCM_CTX *ctx, size_t min_bytes)
{
    size_t target = min_bytes < GCM_DEFAULT_BUF ? GCM_DEFAULT_BUF : min_bytes;
    if (ctx->opfd < 0 || target <= ctx->sock_buf_cap)
        return;

    int bufsize = (target > (size_t)INT32_MAX / 2) ? (INT32_MAX / 2) : (int)target;
    if (setsockopt(ctx->opfd, SOL_SOCKET, SO_SNDBUFFORCE, &bufsize, sizeof(bufsize)) < 0)
        (void)setsockopt(ctx->opfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    if (setsockopt(ctx->opfd, SOL_SOCKET, SO_RCVBUFFORCE, &bufsize, sizeof(bufsize)) < 0)
        (void)setsockopt(ctx->opfd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

    ctx->sock_buf_cap = target;
}

static int afalg_gcm_setup_socket(AFALG_GCM_CTX *ctx)
{
    struct sockaddr_alg sa;

    afalg_gcm_close_fds(ctx);

    ctx->tfmfd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (ctx->tfmfd < 0)
        return 0;

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    memcpy(sa.salg_type, "aead", 4);
    memcpy(sa.salg_name, "gcm(aes)", 8);

    if (bind(ctx->tfmfd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        goto err;

    if (setsockopt(ctx->tfmfd, SOL_ALG, ALG_SET_KEY,
                   ctx->key, (socklen_t)ctx->keylen) < 0)
        goto err;

    if (setsockopt(ctx->tfmfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
                   NULL, (socklen_t)ctx->taglen) < 0)
        goto err;

    ctx->opfd = accept4(ctx->tfmfd, NULL, 0, SOCK_CLOEXEC);
    if (ctx->opfd < 0)
        goto err;

    afalg_gcm_set_sock_buf(ctx, GCM_DEFAULT_BUF);
    return 1;

err:
    afalg_gcm_close_fds(ctx);
    return 0;
}

static int afalg_gcm_ensure_aad_discard(AFALG_GCM_CTX *ctx, size_t len)
{
    if (len <= ctx->aad_discard_cap)
        return 1;
    uint8_t *p = realloc(ctx->aad_discard, len);
    if (p == NULL)
        return 0;
    ctx->aad_discard = p;
    ctx->aad_discard_cap = len;
    return 1;
}

static int afalg_gcm_run(AFALG_GCM_CTX *ctx, uint8_t *out, const uint8_t *in, size_t inl)
{
    char cbuf[CMSG_SPACE(sizeof(uint32_t)) +
              CMSG_SPACE(sizeof(struct af_alg_iv) + GCM_IV_LEN) +
              CMSG_SPACE(sizeof(uint32_t))];
    struct iovec in_iov[3];
    struct iovec out_iov[3];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct af_alg_iv *alg_iv;
    int in_iovcnt = 0;
    int out_iovcnt = 0;
    size_t total_msg;
    ssize_t expected_in;
    ssize_t expected_out;
    ssize_t r;

    if (ctx->opfd < 0 && !afalg_gcm_setup_socket(ctx))
        return 0;

    total_msg = ctx->aad_len + inl + GCM_MAX_TAG_LEN + 64U;
    if (total_msg > ctx->sock_buf_cap)
        afalg_gcm_set_sock_buf(ctx, total_msg);

    if (ctx->aad_len > 0 && !afalg_gcm_ensure_aad_discard(ctx, ctx->aad_len))
        return 0;

    memset(cbuf, 0, sizeof(cbuf));

    if (ctx->aad_len > 0) {
        in_iov[in_iovcnt].iov_base = ctx->aad;
        in_iov[in_iovcnt].iov_len = ctx->aad_len;
        in_iovcnt++;
    }
    if (inl > 0) {
        in_iov[in_iovcnt].iov_base = (void *)in;
        in_iov[in_iovcnt].iov_len = inl;
        in_iovcnt++;
    }
    if (!ctx->enc) {
        in_iov[in_iovcnt].iov_base = ctx->tag;
        in_iov[in_iovcnt].iov_len = ctx->taglen;
        in_iovcnt++;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = in_iov;
    msg.msg_iovlen = (size_t)in_iovcnt;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t *)CMSG_DATA(cmsg) = ctx->enc ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + GCM_IV_LEN);
    alg_iv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    alg_iv->ivlen = GCM_IV_LEN;
    memcpy(alg_iv->iv, ctx->iv, GCM_IV_LEN);

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t *)CMSG_DATA(cmsg) = (uint32_t)ctx->aad_len;

    expected_in = (ssize_t)(ctx->aad_len + inl + (ctx->enc ? 0U : ctx->taglen));
    if (sendmsg(ctx->opfd, &msg, 0) != expected_in)
        return 0;

    if (ctx->aad_len > 0) {
        out_iov[out_iovcnt].iov_base = ctx->aad_discard;
        out_iov[out_iovcnt].iov_len = ctx->aad_len;
        out_iovcnt++;
    }
    if (inl > 0) {
        out_iov[out_iovcnt].iov_base = out;
        out_iov[out_iovcnt].iov_len = inl;
        out_iovcnt++;
    }
    if (ctx->enc) {
        out_iov[out_iovcnt].iov_base = ctx->tag;
        out_iov[out_iovcnt].iov_len = ctx->taglen;
        out_iovcnt++;
    }

    expected_out = (ssize_t)(ctx->aad_len + inl + (ctx->enc ? ctx->taglen : 0U));
    r = readv(ctx->opfd, out_iov, out_iovcnt);
    if (r != expected_out)
        return 0;

    ctx->processed = 1;
    return 1;
}

static AFALG_GCM_CTX *afalg_gcm_newctx_common(size_t keylen)
{
    AFALG_GCM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;
    ctx->tfmfd = -1;
    ctx->opfd = -1;
    ctx->keylen = keylen;
    ctx->ivlen = GCM_IV_LEN;
    ctx->taglen = GCM_MAX_TAG_LEN;
    return ctx;
}

static void *afalg_aes128gcm_newctx(void *provctx)
{
    (void)provctx;
    return afalg_gcm_newctx_common(16);
}

static void *afalg_aes192gcm_newctx(void *provctx)
{
    (void)provctx;
    return afalg_gcm_newctx_common(24);
}

static void *afalg_aes256gcm_newctx(void *provctx)
{
    (void)provctx;
    return afalg_gcm_newctx_common(32);
}

static void afalg_gcm_freectx(void *vctx)
{
    AFALG_GCM_CTX *ctx = (AFALG_GCM_CTX *)vctx;
    if (ctx == NULL)
        return;
    afalg_gcm_close_fds(ctx);
    free(ctx->aad);
    free(ctx->aad_discard);
    free(ctx->saved_ct);
    OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
    OPENSSL_cleanse(ctx->iv, sizeof(ctx->iv));
    OPENSSL_cleanse(ctx->tag, sizeof(ctx->tag));
    OPENSSL_free(ctx);
}

static void *afalg_gcm_dupctx(void *vctx)
{
    AFALG_GCM_CTX *src = (AFALG_GCM_CTX *)vctx;
    AFALG_GCM_CTX *dst;

    if (src == NULL)
        return NULL;

    dst = afalg_gcm_newctx_common(src->keylen);
    if (dst == NULL)
        return NULL;

    dst->enc = src->enc;
    dst->key_set = src->key_set;
    dst->iv_set = src->iv_set;
    dst->tag_set = src->tag_set;
    dst->processed = src->processed;
    dst->ivlen = src->ivlen;
    dst->taglen = src->taglen;
    memcpy(dst->key, src->key, src->keylen);
    memcpy(dst->iv, src->iv, GCM_IV_LEN);
    memcpy(dst->tag, src->tag, GCM_MAX_TAG_LEN);

    if (src->aad_len > 0) {
        dst->aad = malloc(src->aad_len);
        if (dst->aad == NULL) {
            afalg_gcm_freectx(dst);
            return NULL;
        }
        memcpy(dst->aad, src->aad, src->aad_len);
        dst->aad_len = src->aad_len;
        dst->aad_cap = src->aad_len;
    }

    if (src->key_set && !afalg_gcm_setup_socket(dst)) {
        afalg_gcm_freectx(dst);
        return NULL;
    }
    return dst;
}

static int afalg_gcm_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    AFALG_GCM_CTX *ctx = (AFALG_GCM_CTX *)vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING || p->data_size > GCM_MAX_TAG_LEN)
            return 0;
        if (p->data != NULL) {
            memcpy(ctx->tag, p->data, p->data_size);
            ctx->tag_set = 1;
        }
        if (p->data_size > 0 && ctx->taglen != p->data_size) {
            ctx->taglen = p->data_size;
            if (ctx->key_set && ctx->opfd >= 0 && !afalg_gcm_setup_socket(ctx))
                return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL) {
        size_t taglen = 0;
        if (!OSSL_PARAM_get_size_t(p, &taglen) || taglen == 0 || taglen > GCM_MAX_TAG_LEN)
            return 0;
        if (ctx->taglen != taglen) {
            ctx->taglen = taglen;
            if (ctx->key_set && ctx->opfd >= 0 && !afalg_gcm_setup_socket(ctx))
                return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p == NULL)
        p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if (p != NULL) {
        size_t ivlen = 0;
        if (!OSSL_PARAM_get_size_t(p, &ivlen) || ivlen != GCM_IV_LEN)
            return 0;
        ctx->ivlen = ivlen;
    }

    return 1;
}

static int afalg_gcm_init_common(void *vctx, int enc,
                                 const unsigned char *key, size_t keylen,
                                 const unsigned char *iv, size_t ivlen,
                                 const OSSL_PARAM params[])
{
    AFALG_GCM_CTX *ctx = (AFALG_GCM_CTX *)vctx;

    if (ctx == NULL)
        return 0;

    ctx->enc = enc;
    ctx->aad_len = 0;
    ctx->tag_set = 0;
    ctx->processed = 0;
    ctx->saved_ct_len = 0;
    ctx->saved_out = NULL;

    if (!afalg_gcm_set_ctx_params(ctx, params))
        return 0;

    if (iv != NULL) {
        if (ivlen != GCM_IV_LEN)
            return 0;
        memcpy(ctx->iv, iv, GCM_IV_LEN);
        ctx->iv_set = 1;
    }

    if (key != NULL) {
        if (keylen != ctx->keylen)
            return 0;
        memcpy(ctx->key, key, keylen);
        ctx->key_set = 1;
        if (!afalg_gcm_setup_socket(ctx))
            return 0;
    }

    return 1;
}

static int afalg_gcm_einit(void *vctx, const unsigned char *key, size_t keylen,
                           const unsigned char *iv, size_t ivlen,
                           const OSSL_PARAM params[])
{
    return afalg_gcm_init_common(vctx, 1, key, keylen, iv, ivlen, params);
}

static int afalg_gcm_dinit(void *vctx, const unsigned char *key, size_t keylen,
                           const unsigned char *iv, size_t ivlen,
                           const OSSL_PARAM params[])
{
    return afalg_gcm_init_common(vctx, 0, key, keylen, iv, ivlen, params);
}

static int afalg_gcm_update(void *vctx, unsigned char *out, size_t *outl,
                            size_t outsize, const unsigned char *in, size_t inl)
{
    AFALG_GCM_CTX *ctx = (AFALG_GCM_CTX *)vctx;

    if (ctx == NULL || outl == NULL || ctx->processed)
        return 0;

    if (out == NULL) {
        if (inl > 0) {
            if (ctx->aad_len + inl > ctx->aad_cap) {
                size_t new_cap = (ctx->aad_len + inl + 63U) & ~(size_t)63U;
                uint8_t *p = realloc(ctx->aad, new_cap);
                if (p == NULL)
                    return 0;
                ctx->aad = p;
                ctx->aad_cap = new_cap;
            }
            memcpy(ctx->aad + ctx->aad_len, in, inl);
            ctx->aad_len += inl;
        }
        *outl = inl;
        return 1;
    }

    if (outsize < inl || !ctx->key_set || !ctx->iv_set)
        return 0;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (ctx->enc || ctx->tag_set) {
        if (!afalg_gcm_run(ctx, out, in, inl))
            return 0;
        *outl = inl;
        return 1;
    }

    if (ctx->saved_ct_len > 0)
        return 0;
    if (inl > ctx->saved_ct_cap) {
        uint8_t *p = realloc(ctx->saved_ct, inl);
        if (p == NULL)
            return 0;
        ctx->saved_ct = p;
        ctx->saved_ct_cap = inl;
    }
    memcpy(ctx->saved_ct, in, inl);
    ctx->saved_ct_len = inl;
    ctx->saved_out = out;
    *outl = inl;
    return 1;
}

static int afalg_gcm_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    AFALG_GCM_CTX *ctx = (AFALG_GCM_CTX *)vctx;
    (void)out;
    (void)outsize;

    if (ctx == NULL || outl == NULL || !ctx->key_set || !ctx->iv_set)
        return 0;

    if (!ctx->processed) {
        if (!ctx->enc && ctx->saved_ct_len > 0) {
            int ok;
            if (!ctx->tag_set)
                return 0;
            ok = afalg_gcm_run(ctx, ctx->saved_out, ctx->saved_ct, ctx->saved_ct_len);
            ctx->saved_ct_len = 0;
            if (!ok)
                return 0;
        } else {
            if (!ctx->enc && !ctx->tag_set)
                return 0;
            if (!afalg_gcm_run(ctx, NULL, NULL, 0))
                return 0;
        }
    }

    *outl = 0;
    return 1;
}

static int afalg_gcm_cipher(void *vctx, unsigned char *out, size_t *outl,
                            size_t outsize, const unsigned char *in, size_t inl)
{
    size_t upd_outl = 0;
    size_t fin_outl = 0;

    if (!afalg_gcm_update(vctx, out, &upd_outl, outsize, in, inl))
        return 0;
    if (!afalg_gcm_final(vctx, out + upd_outl, &fin_outl, outsize - upd_outl))
        return 0;
    *outl = upd_outl + fin_outl;
    return 1;
}

static int afalg_gcm_get_params_common(OSSL_PARAM params[], size_t keylen)
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE)) != NULL &&
        !OSSL_PARAM_set_uint(p, EVP_CIPH_GCM_MODE))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, keylen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, GCM_IV_LEN))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_IVLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, GCM_IV_LEN))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, 1))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD)) != NULL &&
        !OSSL_PARAM_set_int(p, 1))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV)) != NULL &&
        !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

static int afalg_aes128gcm_get_params(OSSL_PARAM params[])
{
    return afalg_gcm_get_params_common(params, 16);
}

static int afalg_aes192gcm_get_params(OSSL_PARAM params[])
{
    return afalg_gcm_get_params_common(params, 24);
}

static int afalg_aes256gcm_get_params(OSSL_PARAM params[])
{
    return afalg_gcm_get_params_common(params, 32);
}

static int afalg_gcm_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    AFALG_GCM_CTX *ctx = (AFALG_GCM_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ctx->keylen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ctx->ivlen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_IVLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ctx->ivlen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ctx->taglen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG)) != NULL) {
        if (!ctx->enc || !ctx->processed || p->data_size > ctx->taglen)
            return 0;
        if (!OSSL_PARAM_set_octet_string(p, ctx->tag, p->data_size))
            return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen))
        return 0;

    return 1;
}

static const OSSL_PARAM *afalg_gcm_gettable_params(void *provctx)
{
    (void)provctx;
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
        OSSL_PARAM_END
    };
    return table;
}

static const OSSL_PARAM *afalg_gcm_gettable_ctx_params(void *vctx, void *provctx)
{
    (void)vctx;
    (void)provctx;
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
        OSSL_PARAM_END
    };
    return table;
}

static const OSSL_PARAM *afalg_gcm_settable_ctx_params(void *vctx, void *provctx)
{
    (void)vctx;
    (void)provctx;
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
        OSSL_PARAM_END
    };
    return table;
}

#define IMPLEMENT_AFALG_GCM_DISPATCH(prefix)                                      \
    const OSSL_DISPATCH afalg_##prefix##_functions[] = {                          \
        { OSSL_FUNC_CIPHER_NEWCTX,              (void (*)(void))afalg_##prefix##_newctx }, \
        { OSSL_FUNC_CIPHER_FREECTX,             (void (*)(void))afalg_gcm_freectx },       \
        { OSSL_FUNC_CIPHER_DUPCTX,              (void (*)(void))afalg_gcm_dupctx },        \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT,        (void (*)(void))afalg_gcm_einit },         \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT,        (void (*)(void))afalg_gcm_dinit },         \
        { OSSL_FUNC_CIPHER_UPDATE,              (void (*)(void))afalg_gcm_update },        \
        { OSSL_FUNC_CIPHER_FINAL,               (void (*)(void))afalg_gcm_final },         \
        { OSSL_FUNC_CIPHER_CIPHER,              (void (*)(void))afalg_gcm_cipher },        \
        { OSSL_FUNC_CIPHER_GET_PARAMS,          (void (*)(void))afalg_##prefix##_get_params }, \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,     (void (*)(void))afalg_gcm_gettable_params },   \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,      (void (*)(void))afalg_gcm_get_ctx_params },    \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))afalg_gcm_gettable_ctx_params }, \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,      (void (*)(void))afalg_gcm_set_ctx_params },    \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))afalg_gcm_settable_ctx_params }, \
        { 0, NULL }                                                               \
    };

IMPLEMENT_AFALG_GCM_DISPATCH(aes128gcm)
IMPLEMENT_AFALG_GCM_DISPATCH(aes192gcm)
IMPLEMENT_AFALG_GCM_DISPATCH(aes256gcm)
