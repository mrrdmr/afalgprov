/*
 * afalgprov.c - Unified OpenSSL 3.5 AF_ALG Provider for NXP LS1024A
 */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_alg.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/provider.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef ALG_SET_AEAD_ASSOCLEN
#define ALG_SET_AEAD_ASSOCLEN 4
#endif

#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE 5
#endif

#define SPACC_HW_THRESHOLD          8192U
#define AFALG_SEND_CHUNK            57344U
#define AFALG_CTR_SOCK_BUF_SZ       (4U * AFALG_SEND_CHUNK)

#define AFALG_GCM_MIN_HW_BYTES      4096U
#define AFALG_GCM_L2_OPTIMAL_MAX    (128U * 1024U)
#define AFALG_GCM_SKB_OVERHEAD      (24U * 1024U)
#define AFALG_GCM_FALLBACK_WMEM     212992U

#define AES_BLOCK_SZ                16U
#define AES_IV_SZ                   16U
#define AES_MAX_KEY_SZ              32U
#define GCM_IV_SZ                   12U
#define GCM_TAG_SZ                  16U

#define AFALG_PROV_PARAM_HW_THRESHOLD "hw-threshold"

typedef struct {
    OSSL_LIB_CTX *libctx;
    size_t hw_threshold;
    size_t gcm_max_hw_payload;
    int sock_buf_req;
} AFALG_PROV_CTX;

static size_t afalg_read_sysctl_size(const char *path, size_t fallback)
{
    FILE *f = fopen(path, "r");
    unsigned long val = 0;

    if (f == NULL)
        return fallback;
    if (fscanf(f, "%lu", &val) != 1 || val == 0) {
        fclose(f);
        return fallback;
    }
    fclose(f);
    return (size_t)val;
}

static void afalg_detect_kernel_limits(size_t *max_hw_payload, int *sock_buf_req)
{
    size_t wmem = afalg_read_sysctl_size("/proc/sys/net/core/wmem_max",
                                         AFALG_GCM_FALLBACK_WMEM);
    size_t rmem = afalg_read_sysctl_size("/proc/sys/net/core/rmem_max",
                                         AFALG_GCM_FALLBACK_WMEM);
    size_t limit = (wmem < rmem) ? wmem : rmem;
    size_t safe_payload;

    *sock_buf_req = (limit > (size_t)INT_MAX) ? INT_MAX : (int)limit;

    if (limit <= AFALG_GCM_SKB_OVERHEAD) {
        *max_hw_payload = 65536U;
        return;
    }

    safe_payload = limit - AFALG_GCM_SKB_OVERHEAD;
    if (safe_payload > AFALG_GCM_L2_OPTIMAL_MAX)
        safe_payload = AFALG_GCM_L2_OPTIMAL_MAX;

    *max_hw_payload = safe_payload;
}

/* =========================================================================
 * PART 1: AES-128 / 192 / 256 - CTR (skcipher)
 * ========================================================================= */

typedef struct {
    const char *evp_name;
    const char *alg_name;
    size_t key_len;
    size_t iv_len;
    size_t block_size;
    int is_ctr;
} AFALG_CIPHER_INFO;

typedef struct {
    const AFALG_CIPHER_INFO *info;
    OSSL_LIB_CTX *libctx;
    size_t hw_threshold;

    int tfmfd;
    int opfd;

    uint8_t *cbuf;
    size_t cbuf_len;

    EVP_CIPHER *sw_cipher;
    EVP_CIPHER_CTX *sw_ctx;

    int enc;
    int padding;
    int key_set;
    int iv_set;
    int iv_dirty;
    int sw_unaligned;
    size_t sw_cbc_rem;
    unsigned int num;

    uint8_t key[AES_MAX_KEY_SZ];
    uint8_t iv[EVP_MAX_IV_LENGTH];
    uint8_t orig_iv[EVP_MAX_IV_LENGTH];
} AFALG_CTX;

static const AFALG_CIPHER_INFO cipher_table[] = {
    { "AES-128-CTR", "ctr-aes-ls1024a-spacc", 16, AES_IV_SZ, 1, 1 },
    { "AES-192-CTR", "ctr-aes-ls1024a-spacc", 24, AES_IV_SZ, 1, 1 },
    { "AES-256-CTR", "ctr-aes-ls1024a-spacc", 32, AES_IV_SZ, 1, 1 },
};

static void afalg_ctr128_inc(uint8_t iv[AES_IV_SZ], uint64_t blocks)
{
    uint64_t carry = blocks;
    for (int i = AES_IV_SZ - 1; i >= 0 && carry > 0; i--) {
        carry += iv[i];
        iv[i] = (uint8_t)(carry & 0xffU);
        carry >>= 8;
    }
}

static void afalg_advance_iv(AFALG_CTX *ctx,
                             const uint8_t *last_ct,
                             size_t bytes)
{
    if (ctx->info->is_ctr) {
        afalg_ctr128_inc(ctx->iv, bytes / AES_BLOCK_SZ);
        ctx->iv_dirty = 1;
        return;
    }

    if (last_ct != NULL && bytes >= AES_BLOCK_SZ) {
        memcpy(ctx->iv, last_ct, AES_BLOCK_SZ);
        ctx->iv_dirty = 1;
    }
}

static int afalg_sync_iv_from_sw(AFALG_CTX *ctx)
{
    int ok;

    ERR_set_mark();
    ok = EVP_CIPHER_CTX_get_updated_iv(ctx->sw_ctx, ctx->iv, ctx->info->iv_len);
    if (ok)
        ERR_pop_to_mark();
    else
        ERR_clear_last_mark();
    return ok;
}

static void afalg_reset_hw_descriptors(AFALG_CTX *ctx)
{
    if (ctx->opfd >= 0) {
        close(ctx->opfd);
        ctx->opfd = -1;
    }
    if (ctx->tfmfd >= 0) {
        close(ctx->tfmfd);
        ctx->tfmfd = -1;
    }
}

static int afalg_ensure_hw(AFALG_CTX *ctx)
{
    struct sockaddr_alg sa;
    int sockbuf = (int)AFALG_CTR_SOCK_BUF_SZ;

    if (!ctx->key_set)
        return 0;

    if (ctx->opfd >= 0)
        return 1;

    afalg_reset_hw_descriptors(ctx);

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    snprintf((char *)sa.salg_type, sizeof(sa.salg_type), "skcipher");
    snprintf((char *)sa.salg_name, sizeof(sa.salg_name), "%s", ctx->info->alg_name);

    ctx->tfmfd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (ctx->tfmfd < 0)
        goto err;

    if (bind(ctx->tfmfd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        goto err;

    if (setsockopt(ctx->tfmfd, SOL_ALG, ALG_SET_KEY,
                   ctx->key, (socklen_t)ctx->info->key_len) < 0)
        goto err;

    ctx->opfd = accept4(ctx->tfmfd, NULL, 0, SOCK_CLOEXEC);
    if (ctx->opfd < 0)
        goto err;

    (void)setsockopt(ctx->opfd, SOL_SOCKET, SO_SNDBUF, &sockbuf, sizeof(sockbuf));
    (void)setsockopt(ctx->opfd, SOL_SOCKET, SO_RCVBUF, &sockbuf, sizeof(sockbuf));

    return 1;

err:
    afalg_reset_hw_descriptors(ctx);
    return 0;
}

static int afalg_ensure_sw(AFALG_CTX *ctx)
{
    if (!ctx->key_set)
        return 0;

    if (ctx->sw_cipher == NULL) {
        ERR_set_mark();
        ctx->sw_cipher = EVP_CIPHER_fetch(ctx->libctx,
                                          ctx->info->evp_name,
                                          "provider=default");
        if (ctx->sw_cipher != NULL)
            ERR_pop_to_mark();
        else
            ERR_clear_last_mark();
        if (ctx->sw_cipher == NULL)
            return 0;
    }

    if (ctx->sw_ctx == NULL) {
        ctx->sw_ctx = EVP_CIPHER_CTX_new();
        if (ctx->sw_ctx == NULL)
            return 0;
        if (!EVP_CipherInit_ex(ctx->sw_ctx, ctx->sw_cipher, NULL,
                               ctx->key, ctx->iv, ctx->enc)) {
            EVP_CIPHER_CTX_free(ctx->sw_ctx);
            ctx->sw_ctx = NULL;
            return 0;
        }
        EVP_CIPHER_CTX_set_padding(ctx->sw_ctx, ctx->padding);
        ctx->iv_dirty = 0;
    }

    return 1;
}

static int afalg_hw_direct_sendmsg(AFALG_CTX *ctx,
                                   unsigned char *out,
                                   const unsigned char *in,
                                   size_t len,
                                   size_t *done,
                                   int *inplace_corrupted)
{
    struct msghdr msg;
    struct iovec iov;
    struct cmsghdr *cmsg;
    struct af_alg_iv *alg_iv;
    size_t iv_len = ctx->info->iv_len;
    size_t iv_cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + iv_len);
    size_t op_cmsg_len = CMSG_LEN(sizeof(uint32_t));
    size_t total_cmsg_len = CMSG_SPACE(sizeof(uint32_t)) +
                            CMSG_SPACE(sizeof(struct af_alg_iv) + iv_len);
    size_t processed = 0;
    uint32_t op = ctx->enc ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

    *done = 0;
    *inplace_corrupted = 0;

    if (len == 0)
        return 1;

    memset(ctx->cbuf, 0, total_cmsg_len);
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctx->cbuf;
    msg.msg_controllen = total_cmsg_len;

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL)
        return 0;
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = op_cmsg_len;
    memcpy(CMSG_DATA(cmsg), &op, sizeof(op));

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    if (cmsg == NULL)
        return 0;
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = iv_cmsg_len;
    alg_iv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    alg_iv->ivlen = (uint32_t)iv_len;

    while (processed < len) {
        size_t chunk = len - processed;
        uint8_t saved_last_in[AES_BLOCK_SZ];
        const uint8_t *last_ct = NULL;
        size_t got = 0;
        ssize_t sent;

        if (chunk > AFALG_SEND_CHUNK)
            chunk = AFALG_SEND_CHUNK;

        if (!ctx->info->is_ctr && !ctx->enc) {
            memcpy(saved_last_in, in + processed + chunk - AES_BLOCK_SZ, AES_BLOCK_SZ);
            last_ct = saved_last_in;
        }

        iov.iov_base = (void *)(in + processed);
        iov.iov_len = chunk;
        memcpy(alg_iv->iv, ctx->iv, iv_len);

        for (;;) {
            sent = sendmsg(ctx->opfd, &msg, 0);
            if (sent >= 0)
                break;
            if (errno == EINTR)
                continue;
            goto err;
        }
        if ((size_t)sent != chunk)
            goto err;

        while (got < chunk) {
            ssize_t r = read(ctx->opfd, out + processed + got, chunk - got);
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                if (got > 0 && in == out)
                    *inplace_corrupted = 1;
                goto err;
            }
            if (r == 0) {
                if (got > 0 && in == out)
                    *inplace_corrupted = 1;
                goto err;
            }
            got += (size_t)r;
        }

        if (!ctx->info->is_ctr && ctx->enc)
            last_ct = out + processed + chunk - AES_BLOCK_SZ;

        afalg_advance_iv(ctx, last_ct, chunk);
        processed += chunk;
    }

    *done = processed;
    return 1;

err:
    *done = processed;
    return 0;
}

static AFALG_CTX *afalg_newctx_common(void *provctx, const AFALG_CIPHER_INFO *info)
{
    AFALG_PROV_CTX *pctx = (AFALG_PROV_CTX *)provctx;
    AFALG_CTX *ctx;

    if (pctx == NULL)
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->info = info;
    ctx->libctx = pctx->libctx;
    ctx->hw_threshold = pctx->hw_threshold;
    ctx->tfmfd = -1;
    ctx->opfd = -1;
    ctx->padding = 1;

    ctx->cbuf_len = CMSG_SPACE(sizeof(uint32_t)) +
                    CMSG_SPACE(sizeof(struct af_alg_iv) + EVP_MAX_IV_LENGTH);
    ctx->cbuf = OPENSSL_zalloc(ctx->cbuf_len);
    if (ctx->cbuf == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }

    return ctx;
}

static void afalg_freectx(void *vctx)
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    if (ctx == NULL)
        return;

    afalg_reset_hw_descriptors(ctx);

    if (ctx->sw_ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx->sw_ctx);
        ctx->sw_ctx = NULL;
    }
    if (ctx->sw_cipher != NULL) {
        EVP_CIPHER_free(ctx->sw_cipher);
        ctx->sw_cipher = NULL;
    }
    if (ctx->cbuf != NULL) {
        OPENSSL_clear_free(ctx->cbuf, ctx->cbuf_len);
        ctx->cbuf = NULL;
    }

    OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
    OPENSSL_cleanse(ctx->iv, sizeof(ctx->iv));
    OPENSSL_cleanse(ctx->orig_iv, sizeof(ctx->orig_iv));
    OPENSSL_free(ctx);
}

static void *afalg_dupctx(void *vctx)
{
    AFALG_CTX *src = (AFALG_CTX *)vctx;
    AFALG_CTX *dst;

    if (src == NULL)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    dst->info = src->info;
    dst->libctx = src->libctx;
    dst->hw_threshold = src->hw_threshold;
    dst->tfmfd = -1;
    dst->opfd = -1;
    dst->cbuf_len = src->cbuf_len;

    dst->enc = src->enc;
    dst->padding = src->padding;
    dst->key_set = src->key_set;
    dst->iv_set = src->iv_set;
    dst->iv_dirty = src->iv_dirty;
    dst->sw_unaligned = src->sw_unaligned;
    dst->sw_cbc_rem = src->sw_cbc_rem;
    dst->num = src->num;

    memcpy(dst->key, src->key, sizeof(dst->key));
    memcpy(dst->iv, src->iv, sizeof(dst->iv));
    memcpy(dst->orig_iv, src->orig_iv, sizeof(dst->orig_iv));

    dst->cbuf = OPENSSL_zalloc(dst->cbuf_len);
    if (dst->cbuf == NULL) {
        afalg_freectx(dst);
        return NULL;
    }

    if (src->sw_cipher != NULL) {
        if (!EVP_CIPHER_up_ref(src->sw_cipher)) {
            afalg_freectx(dst);
            return NULL;
        }
        dst->sw_cipher = src->sw_cipher;
    }

    if (src->sw_ctx != NULL) {
        dst->sw_ctx = EVP_CIPHER_CTX_dup(src->sw_ctx);
        if (dst->sw_ctx == NULL) {
            afalg_freectx(dst);
            return NULL;
        }
    }

    return dst;
}

static int afalg_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int afalg_init_common(void *vctx,
                             const unsigned char *key, size_t keylen,
                             const unsigned char *iv, size_t ivlen,
                             const OSSL_PARAM params[],
                             int enc)
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    int key_changed = 0;

    if (ctx == NULL)
        return 0;

    ctx->enc = enc;
    ctx->num = 0;
    ctx->sw_unaligned = 0;
    ctx->sw_cbc_rem = 0;

    if (iv != NULL) {
        if (ivlen != ctx->info->iv_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        memcpy(ctx->iv, iv, ivlen);
        memcpy(ctx->orig_iv, iv, ivlen);
        ctx->iv_set = 1;
        ctx->iv_dirty = 1;
    } else if (ctx->iv_set) {
        memcpy(ctx->iv, ctx->orig_iv, ctx->info->iv_len);
        ctx->iv_dirty = 1;
    }

    if (key != NULL) {
        if (keylen != ctx->info->key_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        if (!ctx->key_set || CRYPTO_memcmp(ctx->key, key, keylen) != 0) {
            memcpy(ctx->key, key, keylen);
            ctx->key_set = 1;
            key_changed = 1;
        }
    }

    if (key_changed)
        afalg_reset_hw_descriptors(ctx);

    if (ctx->sw_ctx != NULL) {
        if (!EVP_CipherInit_ex(ctx->sw_ctx, NULL, NULL,
                               key != NULL ? ctx->key : NULL,
                               iv != NULL ? ctx->iv : NULL,
                               enc))
            return 0;
        EVP_CIPHER_CTX_set_padding(ctx->sw_ctx, ctx->padding);
        ctx->iv_dirty = 0;
    }

    if (params != NULL && !afalg_set_ctx_params(ctx, params))
        return 0;

    return 1;
}

static int afalg_einit(void *vctx,
                       const unsigned char *key, size_t keylen,
                       const unsigned char *iv, size_t ivlen,
                       const OSSL_PARAM params[])
{
    return afalg_init_common(vctx, key, keylen, iv, ivlen, params, 1);
}

static int afalg_dinit(void *vctx,
                       const unsigned char *key, size_t keylen,
                       const unsigned char *iv, size_t ivlen,
                       const OSSL_PARAM params[])
{
    return afalg_init_common(vctx, key, keylen, iv, ivlen, params, 0);
}

static int afalg_process_sw(AFALG_CTX *ctx,
                            unsigned char *out, size_t *outl, size_t outsize,
                            const unsigned char *in, size_t inl)
{
    size_t total_out = 0;
    size_t offset = 0;

    if (!afalg_ensure_sw(ctx))
        return 0;

    if (ctx->iv_dirty) {
        if (!EVP_CipherInit_ex(ctx->sw_ctx, NULL, NULL, NULL, ctx->iv, -1))
            return 0;
        ctx->iv_dirty = 0;
    }

    while (offset < inl) {
        size_t step = inl - offset;
        int step_outl = 0;

        if (step > (size_t)INT_MAX - AES_BLOCK_SZ)
            step = (size_t)INT_MAX - AES_BLOCK_SZ;

        if (!EVP_CipherUpdate(ctx->sw_ctx, out + total_out, &step_outl,
                              in + offset, (int)step))
            return 0;

        if (step_outl < 0 || total_out + (size_t)step_outl > outsize)
            return 0;

        total_out += (size_t)step_outl;
        offset += step;
    }

    if (ctx->info->is_ctr) {
        if (inl % AES_BLOCK_SZ != 0)
            ctx->sw_unaligned = 1;
    } else {
        ctx->sw_cbc_rem = (ctx->sw_cbc_rem + inl) % AES_BLOCK_SZ;
    }

    if (!ctx->sw_unaligned && ctx->sw_cbc_rem == 0) {
        if (!afalg_sync_iv_from_sw(ctx))
            return 0;
    }

    *outl = total_out;
    return 1;
}

static int afalg_process_hw(AFALG_CTX *ctx,
                            unsigned char *out, size_t *outl, size_t outsize,
                            const unsigned char *in, size_t len)
{
    size_t hw_done = 0;
    int inplace_corrupted = 0;
    size_t sw_outl = 0;

    if (outsize < len)
        return 0;

    if (!afalg_ensure_hw(ctx))
        return afalg_process_sw(ctx, out, outl, outsize, in, len);

    if (afalg_hw_direct_sendmsg(ctx, out, in, len, &hw_done, &inplace_corrupted)) {
        *outl = hw_done;
        return 1;
    }

    afalg_reset_hw_descriptors(ctx);

    if (inplace_corrupted)
        return 0;

    if (!afalg_process_sw(ctx, out + hw_done, &sw_outl, outsize - hw_done,
                          in + hw_done, len - hw_done))
        return 0;

    *outl = hw_done + sw_outl;
    return 1;
}

static int afalg_process_mixed(AFALG_CTX *ctx,
                               unsigned char *out, size_t *outl, size_t outsize,
                               const unsigned char *in,
                               size_t hw_len, size_t tail_len)
{
    size_t hw_outl = 0;
    size_t tail_outl = 0;

    if (!afalg_process_hw(ctx, out, &hw_outl, outsize, in, hw_len))
        return 0;

    if (!afalg_process_sw(ctx, out + hw_outl, &tail_outl, outsize - hw_outl,
                          in + hw_len, tail_len))
        return 0;

    *outl = hw_outl + tail_outl;
    return 1;
}

static int afalg_update(void *vctx,
                        unsigned char *out, size_t *outl, size_t outsize,
                        const unsigned char *in, size_t inl)
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    size_t min_out;
    size_t hw_len;
    size_t tail_len;

    if (ctx == NULL || out == NULL || outl == NULL || !ctx->key_set || !ctx->iv_set)
        return 0;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    min_out = inl + ((!ctx->info->is_ctr && ctx->padding) ? AES_BLOCK_SZ : 0);
    if (outsize < min_out) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (ctx->sw_unaligned ||
        ctx->sw_cbc_rem != 0 ||
        (!ctx->info->is_ctr && !ctx->enc && ctx->padding) ||
        inl < ctx->hw_threshold) {
        return afalg_process_sw(ctx, out, outl, outsize, in, inl);
    }

    hw_len = (inl / AES_BLOCK_SZ) * AES_BLOCK_SZ;
    tail_len = inl - hw_len;

    if (tail_len == 0)
        return afalg_process_hw(ctx, out, outl, outsize, in, hw_len);

    return afalg_process_mixed(ctx, out, outl, outsize, in, hw_len, tail_len);
}

static int afalg_final(void *vctx,
                       unsigned char *out, size_t *outl, size_t outsize)
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    int fin_outl = 0;

    if (ctx == NULL || out == NULL || outl == NULL || !ctx->key_set || !ctx->iv_set)
        return 0;

    if (ctx->sw_ctx == NULL && (ctx->info->is_ctr || !ctx->padding)) {
        *outl = 0;
        return 1;
    }

    if (!afalg_ensure_sw(ctx))
        return 0;

    if (ctx->iv_dirty) {
        if (!EVP_CipherInit_ex(ctx->sw_ctx, NULL, NULL, NULL, ctx->iv, -1))
            return 0;
        ctx->iv_dirty = 0;
    }

    if (outsize < AES_BLOCK_SZ && !ctx->info->is_ctr && ctx->padding) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!EVP_CipherFinal_ex(ctx->sw_ctx, out, &fin_outl) || fin_outl < 0)
        return 0;

    if (!afalg_sync_iv_from_sw(ctx))
        return 0;

    *outl = (size_t)fin_outl;
    return 1;
}

static int afalg_cipher(void *vctx,
                        unsigned char *out, size_t *outl, size_t outsize,
                        const unsigned char *in, size_t inl)
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    size_t upd_outl = 0;
    size_t fin_outl = 0;

    if (ctx == NULL || out == NULL || outl == NULL)
        return 0;

    if (!afalg_update(ctx, out, &upd_outl, outsize, in, inl))
        return 0;

    if (!ctx->info->is_ctr && ctx->padding) {
        if (!afalg_final(ctx, out + upd_outl, &fin_outl, outsize - upd_outl))
            return 0;
    }

    *outl = upd_outl + fin_outl;
    return 1;
}

static int afalg_get_params_common(OSSL_PARAM params[],
                                   const AFALG_CIPHER_INFO *info)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, info->block_size))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, info->key_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, info->iv_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL) {
        unsigned int mode = info->is_ctr ? EVP_CIPH_CTR_MODE : EVP_CIPH_CBC_MODE;
        if (!OSSL_PARAM_set_uint(p, mode))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

static const OSSL_PARAM afalg_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *afalg_gettable_params(void *provctx)
{
    (void)provctx;
    return afalg_known_gettable_params;
}

static int afalg_set_ctx_octet(OSSL_PARAM *p, const void *buf, size_t len)
{
    if (p == NULL)
        return 1;
    if (p->data_type == OSSL_PARAM_OCTET_STRING)
        return OSSL_PARAM_set_octet_string(p, buf, len);
    if (p->data_type == OSSL_PARAM_OCTET_PTR)
        return OSSL_PARAM_set_octet_ptr(p, buf, len);
    return 1;
}

static int afalg_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->info->key_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->info->iv_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, (unsigned int)ctx->padding))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL) {
        unsigned int num = ctx->num;
        if (ctx->sw_ctx != NULL && ctx->sw_unaligned)
            num = (unsigned int)EVP_CIPHER_CTX_get_num(ctx->sw_ctx);
        if (!OSSL_PARAM_set_uint(p, num))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (!afalg_set_ctx_octet(p, ctx->orig_iv, ctx->info->iv_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL) {
        if (ctx->sw_ctx != NULL && ctx->sw_unaligned) {
            if (!afalg_sync_iv_from_sw(ctx))
                return 0;
        }
        if (!afalg_set_ctx_octet(p, ctx->iv, ctx->info->iv_len))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM afalg_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *afalg_gettable_ctx_params(void *vctx, void *provctx)
{
    (void)vctx;
    (void)provctx;
    return afalg_known_gettable_ctx_params;
}

static int afalg_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        unsigned int pad = 0;
        if (!OSSL_PARAM_get_uint(p, &pad))
            return 0;
        ctx->padding = pad ? 1 : 0;
        if (ctx->sw_ctx != NULL)
            EVP_CIPHER_CTX_set_padding(ctx->sw_ctx, ctx->padding);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL) {
        unsigned int num = 0;
        if (!OSSL_PARAM_get_uint(p, &num))
            return 0;
        ctx->num = num;
        if (ctx->info->is_ctr && num != 0)
            ctx->sw_unaligned = 1;
        if (ctx->sw_ctx != NULL)
            (void)EVP_CIPHER_CTX_set_num(ctx->sw_ctx, (int)num);
    }

    return 1;
}

static const OSSL_PARAM afalg_known_settable_ctx_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *afalg_settable_ctx_params(void *vctx, void *provctx)
{
    (void)vctx;
    (void)provctx;
    return afalg_known_settable_ctx_params;
}

#define IMPLEMENT_AFALG_CIPHER(fn_prefix, idx)                                \
    static void *fn_prefix##_newctx(void *provctx)                            \
    {                                                                         \
        return afalg_newctx_common(provctx, &cipher_table[idx]);              \
    }                                                                         \
    static int fn_prefix##_get_params(OSSL_PARAM params[])                    \
    {                                                                         \
        return afalg_get_params_common(params, &cipher_table[idx]);           \
    }                                                                         \
    static const OSSL_DISPATCH fn_prefix##_functions[] = {                    \
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))fn_prefix##_newctx },      \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))afalg_freectx },          \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))afalg_dupctx },            \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))afalg_einit },       \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))afalg_dinit },       \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))afalg_update },            \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))afalg_final },              \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))afalg_cipher },            \
        { OSSL_FUNC_CIPHER_GET_PARAMS,                                        \
          (void (*)(void))fn_prefix##_get_params },                           \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                   \
          (void (*)(void))afalg_gettable_params },                            \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                    \
          (void (*)(void))afalg_get_ctx_params },                             \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                               \
          (void (*)(void))afalg_gettable_ctx_params },                        \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                    \
          (void (*)(void))afalg_set_ctx_params },                             \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                               \
          (void (*)(void))afalg_settable_ctx_params },                        \
        { 0, NULL }                                                           \
    };

IMPLEMENT_AFALG_CIPHER(aes128ctr, 0)
IMPLEMENT_AFALG_CIPHER(aes192ctr, 1)
IMPLEMENT_AFALG_CIPHER(aes256ctr, 2)

/* =========================================================================
 * PART 2: AES-128 / 192 / 256 - GCM (AEAD, cached sysctl, zero-alloc hot path)
 * ========================================================================= */

typedef struct {
    const char *evp_name;
    size_t key_len;
} AFALG_GCM_INFO;

typedef struct {
    const AFALG_GCM_INFO *info;
    OSSL_LIB_CTX *libctx;

    int tfmfd;
    int opfd;
    size_t max_hw_payload;
    int sock_buf_req;

    uint8_t *cbuf;
    size_t cbuf_len;

    /* Zero-copy single-chunk pointer + fallback heap buffer for multi-chunk decrypt */
    const uint8_t *pending_ct;
    size_t pending_ct_len;
    uint8_t *saved_ct;
    size_t saved_ct_len;
    size_t saved_ct_cap;

    /* AAD input & persistent scratch discard sink (zero-alloc on repeated calls) */
    uint8_t *aad_buf;
    size_t aad_len;
    size_t aad_cap;
    uint8_t *aad_sink;
    size_t aad_sink_cap;

    EVP_CIPHER *sw_cipher;
    EVP_CIPHER_CTX *sw_ctx;
    int force_sw;

    int enc;
    int key_set;
    int iv_set;
    int tag_set;
    size_t iv_len;
    size_t tag_len;
    size_t tls_aad_len;

    uint8_t key[AES_MAX_KEY_SZ];
    uint8_t iv[EVP_MAX_IV_LENGTH];
    uint8_t tag[GCM_TAG_SZ];
} AFALG_GCM_CTX;

static const AFALG_GCM_INFO gcm_table[] = {
    { "AES-128-GCM", 16 },
    { "AES-192-GCM", 24 },
    { "AES-256-GCM", 32 },
};

static void afalg_gcm_reset_hw(AFALG_GCM_CTX *ctx)
{
    if (ctx->opfd >= 0) {
        close(ctx->opfd);
        ctx->opfd = -1;
    }
    if (ctx->tfmfd >= 0) {
        close(ctx->tfmfd);
        ctx->tfmfd = -1;
    }
}

static int afalg_gcm_ensure_hw(AFALG_GCM_CTX *ctx)
{
    struct sockaddr_alg sa;

    if (!ctx->key_set)
        return 0;

    if (ctx->opfd >= 0)
        return 1;

    afalg_gcm_reset_hw(ctx);

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    snprintf((char *)sa.salg_type, sizeof(sa.salg_type), "aead");
    snprintf((char *)sa.salg_name, sizeof(sa.salg_name), "gcm(aes)");

    ctx->tfmfd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (ctx->tfmfd < 0)
        goto err;

    if (bind(ctx->tfmfd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        goto err;

    if (setsockopt(ctx->tfmfd, SOL_ALG, ALG_SET_KEY,
                   ctx->key, (socklen_t)ctx->info->key_len) < 0)
        goto err;

    if (setsockopt(ctx->tfmfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
                   NULL, (socklen_t)ctx->tag_len) < 0)
        goto err;

    ctx->opfd = accept4(ctx->tfmfd, NULL, 0, SOCK_CLOEXEC);
    if (ctx->opfd < 0)
        goto err;

    if (ctx->sock_buf_req > 0) {
        int buf_req = ctx->sock_buf_req;
        (void)setsockopt(ctx->opfd, SOL_SOCKET, SO_SNDBUF, &buf_req, sizeof(buf_req));
        (void)setsockopt(ctx->opfd, SOL_SOCKET, SO_RCVBUF, &buf_req, sizeof(buf_req));
    }

    return 1;

err:
    afalg_gcm_reset_hw(ctx);
    return 0;
}

static int afalg_gcm_ensure_sw(AFALG_GCM_CTX *ctx)
{
    if (!ctx->key_set)
        return 0;

    if (ctx->sw_cipher == NULL) {
        ERR_set_mark();
        ctx->sw_cipher = EVP_CIPHER_fetch(ctx->libctx,
                                          ctx->info->evp_name,
                                          "provider=default");
        if (ctx->sw_cipher != NULL)
            ERR_pop_to_mark();
        else
            ERR_clear_last_mark();
        if (ctx->sw_cipher == NULL)
            return 0;
    }

    if (ctx->sw_ctx == NULL) {
        ctx->sw_ctx = EVP_CIPHER_CTX_new();
        if (ctx->sw_ctx == NULL)
            return 0;
        if (!EVP_CipherInit_ex(ctx->sw_ctx, ctx->sw_cipher, NULL, NULL, NULL, ctx->enc))
            goto err;
        if (!EVP_CIPHER_CTX_ctrl(ctx->sw_ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                 (int)ctx->iv_len, NULL))
            goto err;
        if (!EVP_CipherInit_ex(ctx->sw_ctx, NULL, NULL,
                               ctx->key, ctx->iv_set ? ctx->iv : NULL, ctx->enc))
            goto err;
        if (!ctx->enc && ctx->tag_set) {
            if (!EVP_CIPHER_CTX_ctrl(ctx->sw_ctx, EVP_CTRL_AEAD_SET_TAG,
                                     (int)ctx->tag_len, ctx->tag))
                goto err;
        }
        if (ctx->aad_len > 0) {
            int dummy = 0;
            if (!EVP_CipherUpdate(ctx->sw_ctx, NULL, &dummy,
                                  ctx->aad_buf, (int)ctx->aad_len))
                goto err;
        }
    }

    return 1;

err:
    EVP_CIPHER_CTX_free(ctx->sw_ctx);
    ctx->sw_ctx = NULL;
    return 0;
}

static int afalg_gcm_sw_update(AFALG_GCM_CTX *ctx,
                               unsigned char *out, size_t *outl, size_t outsize,
                               const unsigned char *in, size_t inl)
{
    int step_outl = 0;

    if (!afalg_gcm_ensure_sw(ctx))
        return 0;

    if (out == NULL) {
        if (!EVP_CipherUpdate(ctx->sw_ctx, NULL, &step_outl, in, (int)inl))
            return 0;
        if (outl != NULL)
            *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!EVP_CipherUpdate(ctx->sw_ctx, out, &step_outl, in, (int)inl) || step_outl < 0)
        return 0;

    ctx->force_sw = 1;
    *outl = (size_t)step_outl;
    return 1;
}

static int afalg_gcm_hw_oneshot(AFALG_GCM_CTX *ctx,
                                unsigned char *out,
                                const unsigned char *in,
                                size_t len)
{
    struct msghdr msg;
    struct iovec in_iov[3];
    struct iovec out_iov[3];
    struct cmsghdr *cmsg;
    struct af_alg_iv *alg_iv;
    uint8_t aad_stack_discard[64];
    int in_iovcnt = 0;
    int out_iovcnt = 0;
    size_t total_in = 0;
    size_t total_out = 0;
    size_t total_cmsg_len = CMSG_SPACE(sizeof(uint32_t)) +
                            CMSG_SPACE(sizeof(struct af_alg_iv) + ctx->iv_len) +
                            CMSG_SPACE(sizeof(uint32_t));
    uint32_t op = ctx->enc ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
    uint32_t assoclen = (uint32_t)ctx->aad_len;
    ssize_t sent, recvd;

    if (ctx->aad_len > 0) {
        in_iov[in_iovcnt].iov_base = ctx->aad_buf;
        in_iov[in_iovcnt].iov_len = ctx->aad_len;
        in_iovcnt++;
        total_in += ctx->aad_len;
    }
    if (len > 0) {
        in_iov[in_iovcnt].iov_base = (void *)in;
        in_iov[in_iovcnt].iov_len = len;
        in_iovcnt++;
        total_in += len;
    }
    if (!ctx->enc) {
        in_iov[in_iovcnt].iov_base = ctx->tag;
        in_iov[in_iovcnt].iov_len = ctx->tag_len;
        in_iovcnt++;
        total_in += ctx->tag_len;
    }

    if (ctx->aad_len > 0) {
        if (ctx->aad_len <= sizeof(aad_stack_discard)) {
            out_iov[out_iovcnt].iov_base = aad_stack_discard;
        } else {
            if (ctx->aad_len > ctx->aad_sink_cap) {
                uint8_t *nb = OPENSSL_realloc(ctx->aad_sink, ctx->aad_len);
                if (nb == NULL)
                    return 0;
                ctx->aad_sink = nb;
                ctx->aad_sink_cap = ctx->aad_len;
            }
            out_iov[out_iovcnt].iov_base = ctx->aad_sink;
        }
        out_iov[out_iovcnt].iov_len = ctx->aad_len;
        out_iovcnt++;
        total_out += ctx->aad_len;
    }
    if (len > 0) {
        out_iov[out_iovcnt].iov_base = out;
        out_iov[out_iovcnt].iov_len = len;
        out_iovcnt++;
        total_out += len;
    }
    if (ctx->enc) {
        out_iov[out_iovcnt].iov_base = ctx->tag;
        out_iov[out_iovcnt].iov_len = ctx->tag_len;
        out_iovcnt++;
        total_out += ctx->tag_len;
    }

    memset(ctx->cbuf, 0, total_cmsg_len);
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = in_iov;
    msg.msg_iovlen = (size_t)in_iovcnt;
    msg.msg_control = ctx->cbuf;
    msg.msg_controllen = total_cmsg_len;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    memcpy(CMSG_DATA(cmsg), &op, sizeof(op));

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + ctx->iv_len);
    alg_iv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    alg_iv->ivlen = (uint32_t)ctx->iv_len;
    memcpy(alg_iv->iv, ctx->iv, ctx->iv_len);

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    memcpy(CMSG_DATA(cmsg), &assoclen, sizeof(assoclen));

    for (;;) {
        sent = sendmsg(ctx->opfd, &msg, 0);
        if (sent >= 0)
            break;
        if (errno == EINTR)
            continue;
        return 0;
    }
    if ((size_t)sent != total_in)
        return 0;

    for (;;) {
        recvd = readv(ctx->opfd, out_iov, out_iovcnt);
        if (recvd >= 0)
            break;
        if (errno == EINTR)
            continue;
        return 0;
    }
    if ((size_t)recvd != total_out)
        return 0;

    if (ctx->enc)
        ctx->tag_set = 1;

    return 1;
}

static AFALG_GCM_CTX *afalg_gcm_newctx_common(void *provctx,
                                              const AFALG_GCM_INFO *info)
{
    AFALG_PROV_CTX *pctx = (AFALG_PROV_CTX *)provctx;
    AFALG_GCM_CTX *ctx;

    if (pctx == NULL)
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->info = info;
    ctx->libctx = pctx->libctx;
    ctx->tfmfd = -1;
    ctx->opfd = -1;
    ctx->iv_len = GCM_IV_SZ;
    ctx->tag_len = GCM_TAG_SZ;
    ctx->tls_aad_len = (size_t)-1;
    ctx->max_hw_payload = pctx->gcm_max_hw_payload;
    ctx->sock_buf_req = pctx->sock_buf_req;

    ctx->cbuf_len = CMSG_SPACE(sizeof(uint32_t)) +
                    CMSG_SPACE(sizeof(struct af_alg_iv) + EVP_MAX_IV_LENGTH) +
                    CMSG_SPACE(sizeof(uint32_t));
    ctx->cbuf = OPENSSL_zalloc(ctx->cbuf_len);
    if (ctx->cbuf == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }

    return ctx;
}

static void afalg_gcm_freectx(void *vctx)
{
    AFALG_GCM_CTX *ctx = (AFALG_GCM_CTX *)vctx;
    if (ctx == NULL)
        return;

    afalg_gcm_reset_hw(ctx);

    if (ctx->sw_ctx != NULL)
        EVP_CIPHER_CTX_free(ctx->sw_ctx);
    if (ctx->sw_cipher != NULL)
        EVP_CIPHER_free(ctx->sw_cipher);
    if (ctx->cbuf != NULL)
        OPENSSL_clear_free(ctx->cbuf, ctx->cbuf_len);
    if (ctx->saved_ct != NULL)
        OPENSSL_clear_free(ctx->saved_ct, ctx->saved_ct_cap);
    if (ctx->aad_buf != NULL)
        OPENSSL_clear_free(ctx->aad_buf, ctx->aad_cap);
    if (ctx->aad_sink != NULL)
        OPENSSL_free(ctx->aad_sink);

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

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    dst->info = src->info;
    dst->libctx = src->libctx;
    dst->tfmfd = -1;
    dst->opfd = -1;
    dst->max_hw_payload = src->max_hw_payload;
    dst->sock_buf_req = src->sock_buf_req;
    dst->cbuf_len = src->cbuf_len;
    dst->force_sw = src->force_sw;
    dst->enc = src->enc;
    dst->key_set = src->key_set;
    dst->iv_set = src->iv_set;
    dst->tag_set = src->tag_set;
    dst->iv_len = src->iv_len;
    dst->tag_len = src->tag_len;
    dst->tls_aad_len = src->tls_aad_len;

    memcpy(dst->key, src->key, sizeof(dst->key));
    memcpy(dst->iv, src->iv, sizeof(dst->iv));
    memcpy(dst->tag, src->tag, sizeof(dst->tag));

    dst->cbuf = OPENSSL_zalloc(dst->cbuf_len);
    if (dst->cbuf == NULL) {
        afalg_gcm_freectx(dst);
        return NULL;
    }

    if (src->aad_len > 0) {
        dst->aad_buf = OPENSSL_malloc(src->aad_len);
        if (dst->aad_buf == NULL) {
            afalg_gcm_freectx(dst);
            return NULL;
        }
        memcpy(dst->aad_buf, src->aad_buf, src->aad_len);
        dst->aad_len = src->aad_len;
        dst->aad_cap = src->aad_len;
    }

    if (src->pending_ct != NULL && src->pending_ct_len > 0) {
        dst->saved_ct = OPENSSL_malloc(src->pending_ct_len);
        if (dst->saved_ct == NULL) {
            afalg_gcm_freectx(dst);
            return NULL;
        }
        memcpy(dst->saved_ct, src->pending_ct, src->pending_ct_len);
        dst->saved_ct_len = src->pending_ct_len;
        dst->saved_ct_cap = src->pending_ct_len;
    } else if (src->saved_ct_len > 0) {
        dst->saved_ct = OPENSSL_malloc(src->saved_ct_len);
        if (dst->saved_ct == NULL) {
            afalg_gcm_freectx(dst);
            return NULL;
        }
        memcpy(dst->saved_ct, src->saved_ct, src->saved_ct_len);
        dst->saved_ct_len = src->saved_ct_len;
        dst->saved_ct_cap = src->saved_ct_len;
    }

    if (src->sw_cipher != NULL) {
        if (!EVP_CIPHER_up_ref(src->sw_cipher)) {
            afalg_freectx(dst);
            return NULL;
        }
        dst->sw_cipher = src->sw_cipher;
    }

    if (src->sw_ctx != NULL) {
        dst->sw_ctx = EVP_CIPHER_CTX_dup(src->sw_ctx);
        if (dst->sw_ctx == NULL) {
            afalg_gcm_freectx(dst);
            return NULL;
        }
    }

    return dst;
}

static int afalg_gcm_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int afalg_gcm_init_common(void *vctx,
                                 const unsigned char *key, size_t keylen,
                                 const unsigned char *iv, size_t ivlen,
                                 const OSSL_PARAM params[],
                                 int enc)
{
    AFALG_GCM_CTX *ctx = (AFALG_GCM_CTX *)vctx;
    int key_changed = 0;

    if (ctx == NULL)
        return 0;

    ctx->enc = enc;
    ctx->tag_set = 0;
    ctx->aad_len = 0;
    ctx->pending_ct = NULL;
    ctx->pending_ct_len = 0;
    ctx->saved_ct_len = 0;
    ctx->force_sw = 0;
    ctx->tls_aad_len = (size_t)-1;

    if (params != NULL && !afalg_gcm_set_ctx_params(ctx, params))
        return 0;

    if (iv != NULL) {
        if (ivlen == 0 || ivlen > EVP_MAX_IV_LENGTH) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        memcpy(ctx->iv, iv, ivlen);
        ctx->iv_len = ivlen;
        ctx->iv_set = 1;
    }

    if (key != NULL) {
        if (keylen != ctx->info->key_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        if (!ctx->key_set || CRYPTO_memcmp(ctx->key, key, keylen) != 0) {
            memcpy(ctx->key, key, keylen);
            ctx->key_set = 1;
            key_changed = 1;
        }
    }

    if (key_changed)
        afalg_gcm_reset_hw(ctx);

    if (ctx->sw_ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx->sw_ctx);
        ctx->sw_ctx = NULL;
    }

    return 1;
}

static int afalg_gcm_einit(void *vctx,
                           const unsigned char *key, size_t keylen,
                           const unsigned char *iv, size_t ivlen,
                           const OSSL_PARAM params[])
{
    return afalg_gcm_init_common(vctx, key, keylen, iv, ivlen, params, 1);
}

static int afalg_gcm_dinit(void *vctx,
                           const unsigned char *key, size_t keylen,
                           const unsigned char *iv, size_t ivlen,
                           const OSSL_PARAM params[])
{
    return afalg_gcm_init_common(vctx, key, keylen, iv, ivlen, params, 0);
}

static int afalg_gcm_append_saved_ct(AFALG_GCM_CTX *ctx,
                                     const unsigned char *in,
                                     size_t inl)
{
    size_t existing = (ctx->pending_ct != NULL) ? ctx->pending_ct_len : ctx->saved_ct_len;
    size_t total = existing + inl;

    if (total > ctx->saved_ct_cap) {
        uint8_t *nb = OPENSSL_realloc(ctx->saved_ct, total);
        if (nb == NULL)
            return 0;
        ctx->saved_ct = nb;
        ctx->saved_ct_cap = total;
    }

    if (ctx->pending_ct != NULL) {
        memcpy(ctx->saved_ct, ctx->pending_ct, ctx->pending_ct_len);
        ctx->saved_ct_len = ctx->pending_ct_len;
        ctx->pending_ct = NULL;
        ctx->pending_ct_len = 0;
    }

    memcpy(ctx->saved_ct + ctx->saved_ct_len, in, inl);
    ctx->saved_ct_len += inl;
    return 1;
}

static int afalg_gcm_update(void *vctx,
                            unsigned char *out, size_t *outl, size_t outsize,
                            const unsigned char *in, size_t inl)
{
    AFALG_GCM_CTX *ctx = (AFALG_GCM_CTX *)vctx;

    if (ctx == NULL || outl == NULL || !ctx->key_set || !ctx->iv_set)
        return 0;

    if (out == NULL) {
        if (inl > 0) {
            if (ctx->aad_len + inl > ctx->aad_cap) {
                size_t new_cap = ctx->aad_len + inl;
                uint8_t *nb = OPENSSL_realloc(ctx->aad_buf, new_cap);
                if (nb == NULL)
                    return 0;
                ctx->aad_buf = nb;
                ctx->aad_cap = new_cap;
            }
            memcpy(ctx->aad_buf + ctx->aad_len, in, inl);
            ctx->aad_len += inl;
        }
        if (ctx->sw_ctx != NULL) {
            int dummy = 0;
            if (!EVP_CipherUpdate(ctx->sw_ctx, NULL, &dummy, in, (int)inl))
                return 0;
        }
        *outl = 0;
        return 1;
    }

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (ctx->force_sw ||
        ctx->iv_len != GCM_IV_SZ ||
        inl < AFALG_GCM_MIN_HW_BYTES ||
        inl > ctx->max_hw_payload) {
        if (ctx->pending_ct != NULL || ctx->saved_ct_len > 0) {
            if (!afalg_gcm_append_saved_ct(ctx, in, inl))
                return 0;
            *outl = inl;
            return 1;
        }
        return afalg_gcm_sw_update(ctx, out, outl, outsize, in, inl);
    }

    /*
     * Zero-copy deferred decrypt when tag arrives after DecryptUpdate:
     * keep pointer directly to `in` on single-shot calls; only copy to
     * `saved_ct` if multiple DecryptUpdate chunks arrive before Final.
     */
    if (!ctx->enc && !ctx->tag_set) {
        if (ctx->pending_ct == NULL && ctx->saved_ct_len == 0) {
            ctx->pending_ct = in;
            ctx->pending_ct_len = inl;
        } else {
            if (!afalg_gcm_append_saved_ct(ctx, in, inl))
                return 0;
        }
        *outl = inl;
        return 1;
    }

    if (!afalg_gcm_ensure_hw(ctx))
        return afalg_gcm_sw_update(ctx, out, outl, outsize, in, inl);

    if (!afalg_gcm_hw_oneshot(ctx, out, in, inl)) {
        afalg_gcm_reset_hw(ctx);
        return afalg_gcm_sw_update(ctx, out, outl, outsize, in, inl);
    }

    *outl = inl;
    return 1;
}

static int afalg_gcm_final(void *vctx,
                           unsigned char *out, size_t *outl, size_t outsize)
{
    AFALG_GCM_CTX *ctx = (AFALG_GCM_CTX *)vctx;
    int fin_outl = 0;

    if (ctx == NULL || outl == NULL || !ctx->key_set || !ctx->iv_set)
        return 0;

    /* Deferred decrypt path (either zero-copy `pending_ct` or buffered `saved_ct`) */
    if (!ctx->enc && (ctx->pending_ct != NULL || ctx->saved_ct_len > 0)) {
        const uint8_t *ct_ptr = (ctx->pending_ct != NULL) ? ctx->pending_ct : ctx->saved_ct;
        size_t ct_len = (ctx->pending_ct != NULL) ? ctx->pending_ct_len : ctx->saved_ct_len;

        if (!ctx->tag_set)
            return 0;
        if (out == NULL || outsize < ct_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        if (ct_len >= AFALG_GCM_MIN_HW_BYTES &&
            ct_len <= ctx->max_hw_payload &&
            ctx->iv_len == GCM_IV_SZ &&
            afalg_gcm_ensure_hw(ctx) &&
            afalg_gcm_hw_oneshot(ctx, out, ct_ptr, ct_len)) {
            *outl = ct_len;
            ctx->pending_ct = NULL;
            ctx->pending_ct_len = 0;
            ctx->saved_ct_len = 0;
            return 1;
        }
        afalg_gcm_reset_hw(ctx);
        if (!afalg_gcm_ensure_sw(ctx))
            return 0;
        if (!EVP_CipherUpdate(ctx->sw_ctx, out, &fin_outl, ct_ptr, (int)ct_len))
            return 0;
        ctx->pending_ct = NULL;
        ctx->pending_ct_len = 0;
        ctx->saved_ct_len = 0;
        int tail = 0;
        if (!EVP_CipherFinal_ex(ctx->sw_ctx, out + fin_outl, &tail))
            return 0;
        *outl = (size_t)(fin_outl + tail);
        return 1;
    }

    if (ctx->force_sw || ctx->sw_ctx != NULL) {
        if (!afalg_gcm_ensure_sw(ctx))
            return 0;
        if (!EVP_CipherFinal_ex(ctx->sw_ctx, out, &fin_outl) || fin_outl < 0)
            return 0;
        if (ctx->enc) {
            if (!EVP_CIPHER_CTX_ctrl(ctx->sw_ctx, EVP_CTRL_AEAD_GET_TAG,
                                     (int)ctx->tag_len, ctx->tag))
                return 0;
            ctx->tag_set = 1;
        }
        *outl = (size_t)fin_outl;
        return 1;
    }

    if (!ctx->tag_set) {
        if (!ctx->enc)
            return 0;
        if (afalg_gcm_ensure_hw(ctx) && afalg_gcm_hw_oneshot(ctx, NULL, NULL, 0)) {
            *outl = 0;
            return 1;
        }
        if (!afalg_gcm_ensure_sw(ctx))
            return 0;
        if (!EVP_CipherFinal_ex(ctx->sw_ctx, out, &fin_outl))
            return 0;
        if (!EVP_CIPHER_CTX_ctrl(ctx->sw_ctx, EVP_CTRL_AEAD_GET_TAG,
                                 (int)ctx->tag_len, ctx->tag))
            return 0;
        ctx->tag_set = 1;
        *outl = (size_t)fin_outl;
        return 1;
    }

    *outl = 0;
    return 1;
}

static int afalg_gcm_cipher(void *vctx,
                            unsigned char *out, size_t *outl, size_t outsize,
                            const unsigned char *in, size_t inl)
{
    size_t upd_outl = 0;
    size_t fin_outl = 0;

    if (!afalg_gcm_update(vctx, out, &upd_outl, outsize, in, inl))
        return 0;
    if (!afalg_gcm_final(vctx, out != NULL ? out + upd_outl : NULL,
                         &fin_outl, outsize - upd_outl))
        return 0;

    *outl = upd_outl + fin_outl;
    return 1;
}

static int afalg_gcm_get_params_common(OSSL_PARAM params[],
                                       const AFALG_GCM_INFO *info)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, info->key_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, GCM_IV_SZ))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, EVP_CIPH_GCM_MODE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

static const OSSL_PARAM afalg_gcm_known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *afalg_gcm_gettable_params(void *provctx)
{
    (void)provctx;
    return afalg_gcm_known_gettable_params;
}

static int afalg_gcm_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    AFALG_GCM_CTX *ctx = (AFALG_GCM_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->info->key_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->iv_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tag_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, GCM_TAG_SZ))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (!ctx->enc || !ctx->tag_set)
            return 0;
        if (p->data_size == 0 || p->data_size > GCM_TAG_SZ)
            return 0;
        if (!OSSL_PARAM_set_octet_string(p, ctx->tag, p->data_size))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM afalg_gcm_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *afalg_gcm_gettable_ctx_params(void *vctx, void *provctx)
{
    (void)vctx;
    (void)provctx;
    return afalg_gcm_known_gettable_ctx_params;
}

static int afalg_gcm_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    AFALG_GCM_CTX *ctx = (AFALG_GCM_CTX *)vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if (p != NULL) {
        size_t ivlen = 0;
        if (!OSSL_PARAM_get_size_t(p, &ivlen))
            return 0;
        if (ivlen == 0 || ivlen > EVP_MAX_IV_LENGTH)
            return 0;
        ctx->iv_len = ivlen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        const void *tag_ptr = NULL;
        size_t tag_len = 0;
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        if (!OSSL_PARAM_get_octet_string_ptr(p, &tag_ptr, &tag_len))
            return 0;
        if (tag_len == 0 || tag_len > GCM_TAG_SZ)
            return 0;
        if (!ctx->enc && tag_ptr != NULL) {
            memcpy(ctx->tag, tag_ptr, tag_len);
            ctx->tag_set = 1;
        }
        ctx->tag_len = tag_len;
        if (ctx->sw_ctx != NULL && !ctx->enc && tag_ptr != NULL) {
            if (!EVP_CIPHER_CTX_ctrl(ctx->sw_ctx, EVP_CTRL_AEAD_SET_TAG,
                                     (int)tag_len, (void *)tag_ptr))
                return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        const void *aad_ptr = NULL;
        size_t aad_len = 0;
        if (!OSSL_PARAM_get_octet_string_ptr(p, &aad_ptr, &aad_len))
            return 0;
        ctx->tls_aad_len = aad_len;
        ctx->force_sw = 1;
        if (!afalg_gcm_ensure_sw(ctx))
            return 0;
        if (EVP_CIPHER_CTX_ctrl(ctx->sw_ctx, EVP_CTRL_AEAD_TLS1_AAD,
                                (int)aad_len, (void *)aad_ptr) <= 0)
            return 0;
    }

    return 1;
}

static const OSSL_PARAM afalg_gcm_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *afalg_gcm_settable_ctx_params(void *vctx, void *provctx)
{
    (void)vctx;
    (void)provctx;
    return afalg_gcm_known_settable_ctx_params;
}

#define IMPLEMENT_AFALG_GCM_CIPHER(fn_prefix, idx)                            \
    static void *fn_prefix##_newctx(void *provctx)                            \
    {                                                                         \
        return afalg_gcm_newctx_common(provctx, &gcm_table[idx]);             \
    }                                                                         \
    static int fn_prefix##_get_params(OSSL_PARAM params[])                    \
    {                                                                         \
        return afalg_gcm_get_params_common(params, &gcm_table[idx]);          \
    }                                                                         \
    static const OSSL_DISPATCH fn_prefix##_functions[] = {                    \
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))fn_prefix##_newctx },      \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))afalg_gcm_freectx },      \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))afalg_gcm_dupctx },        \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))afalg_gcm_einit },   \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))afalg_gcm_dinit },   \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))afalg_gcm_update },        \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))afalg_gcm_final },          \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))afalg_gcm_cipher },        \
        { OSSL_FUNC_CIPHER_GET_PARAMS,                                        \
          (void (*)(void))fn_prefix##_get_params },                           \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                   \
          (void (*)(void))afalg_gcm_gettable_params },                        \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                    \
          (void (*)(void))afalg_gcm_get_ctx_params },                         \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                               \
          (void (*)(void))afalg_gcm_gettable_ctx_params },                    \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                    \
          (void (*)(void))afalg_gcm_set_ctx_params },                         \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                               \
          (void (*)(void))afalg_gcm_settable_ctx_params },                    \
        { 0, NULL }                                                           \
    };

IMPLEMENT_AFALG_GCM_CIPHER(afalg_aes128gcm, 0)
IMPLEMENT_AFALG_GCM_CIPHER(afalg_aes192gcm, 1)
IMPLEMENT_AFALG_GCM_CIPHER(afalg_aes256gcm, 2)

/* =========================================================================
 * PART 3: Unified Provider Algorithm Registry & Entry Point
 * ========================================================================= */

static const OSSL_ALGORITHM afalg_algorithms[] = {
    { "AES-128-CTR:id-aes128-CTR", "provider=afalgprov",
      aes128ctr_functions, "NXP LS1024A SPACC AES-128-CTR" },
    { "AES-192-CTR:id-aes192-CTR", "provider=afalgprov",
      aes192ctr_functions, "NXP LS1024A SPACC AES-192-CTR" },
    { "AES-256-CTR:id-aes256-CTR", "provider=afalgprov",
      aes256ctr_functions, "NXP LS1024A SPACC AES-256-CTR" },
    { "AES-128-GCM:id-aes128-GCM:2.16.840.1.101.3.4.1.6", "provider=afalgprov",
      afalg_aes128gcm_functions, "NXP LS1024A SPACC AES-128-GCM" },
    { "AES-192-GCM:id-aes192-GCM:2.16.840.1.101.3.4.1.26", "provider=afalgprov",
      afalg_aes192gcm_functions, "NXP LS1024A SPACC AES-192-GCM" },
    { "AES-256-GCM:id-aes256-GCM:2.16.840.1.101.3.4.1.46", "provider=afalgprov",
      afalg_aes256gcm_functions, "NXP LS1024A SPACC AES-256-GCM" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *afalg_query(void *provctx,
                                         int operation_id,
                                         int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_CIPHER)
        return afalg_algorithms;
    return NULL;
}

static const OSSL_PARAM afalg_prov_known_gettable_params[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
    OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *afalg_prov_gettable_params(void *provctx)
{
    (void)provctx;
    return afalg_prov_known_gettable_params;
}

static int afalg_prov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    (void)provctx;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "NXP LS1024A SPACC AF_ALG Provider"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "3.5"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL 3.5 AF_ALG CTR+GCM (SPACC DMA, zero-alloc hot path)"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

static void afalg_teardown(void *provctx)
{
    AFALG_PROV_CTX *pctx = (AFALG_PROV_CTX *)provctx;
    if (pctx != NULL) {
        if (pctx->libctx != NULL)
            OSSL_LIB_CTX_free(pctx->libctx);
        OPENSSL_free(pctx);
    }
}

static const OSSL_DISPATCH afalg_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))afalg_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))afalg_prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))afalg_prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))afalg_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    OSSL_FUNC_core_get_params_fn *c_get_params = NULL;
    AFALG_PROV_CTX *pctx;

    for (; in->function_id != 0; in++) {
        if (in->function_id == OSSL_FUNC_CORE_GET_PARAMS)
            c_get_params = OSSL_FUNC_core_get_params(in);
    }

    pctx = OPENSSL_zalloc(sizeof(*pctx));
    if (pctx == NULL)
        return 0;

    pctx->libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);
    if (pctx->libctx == NULL) {
        OPENSSL_free(pctx);
        return 0;
    }

    pctx->hw_threshold = SPACC_HW_THRESHOLD;
    afalg_detect_kernel_limits(&pctx->gcm_max_hw_payload, &pctx->sock_buf_req);

    if (c_get_params != NULL) {
        char *thresh_str = NULL;
        OSSL_PARAM core_params[] = {
            OSSL_PARAM_utf8_ptr(AFALG_PROV_PARAM_HW_THRESHOLD, &thresh_str, 0),
            OSSL_PARAM_END
        };
        if (c_get_params(handle, core_params) && thresh_str != NULL) {
            unsigned long val = strtoul(thresh_str, NULL, 10);
            if (val >= SPACC_HW_THRESHOLD)
                pctx->hw_threshold = (size_t)val;
        }
    }

    *provctx = pctx;
    *out = afalg_dispatch_table;
    return 1;
}
