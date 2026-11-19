#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <linux/if_alg.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define SPACC_HW_THRESHOLD 8192
#define MAX_HW_CHUNK       65536

struct afalg_ctx {
    int tfmfd;
    int opfd;
    char alg_type[16];
    char alg_name[32];
    char ossl_name[24];
    size_t keylen;
    size_t ivlen;
    size_t blocksize;
    int is_ctr;
    int pad;
    int enc;

    uint8_t key[32];
    uint8_t iv[16];
    int has_key;
    int has_iv;
    int hw_key_set;
    int sw_key_set;
    int iv_dirty;
    int sw_unaligned;

    EVP_CIPHER *sw_cipher;
    EVP_CIPHER_CTX *sw_ctx;
};

static int afalg_ensure_sw(struct afalg_ctx *ctx)
{
    if (!ctx->sw_cipher) {
        ctx->sw_cipher = EVP_CIPHER_fetch(NULL, ctx->ossl_name, "provider=default");
        if (!ctx->sw_cipher)
            return 0;
    }
    if (!ctx->sw_ctx) {
        ctx->sw_ctx = EVP_CIPHER_CTX_new();
        if (!ctx->sw_ctx)
            return 0;
    }
    if (!ctx->sw_key_set) {
        if (!EVP_CipherInit_ex(ctx->sw_ctx, ctx->sw_cipher, NULL,
                               ctx->has_key ? ctx->key : NULL,
                               ctx->has_iv ? ctx->iv : NULL,
                               ctx->enc))
            return 0;
        EVP_CIPHER_CTX_set_padding(ctx->sw_ctx, ctx->pad);
        ctx->sw_key_set = 1;
        ctx->iv_dirty = 0;
    }
    return 1;
}

static void *afalg_newctx(const char *alg_type, const char *alg, const char *ossl_name,
                          size_t keylen, size_t ivlen, size_t bs, int is_ctr)
{
    struct afalg_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->tfmfd = -1;
    ctx->opfd = -1;
    strncpy(ctx->alg_type, alg_type, sizeof(ctx->alg_type) - 1);
    strncpy(ctx->alg_name, alg, sizeof(ctx->alg_name) - 1);
    strncpy(ctx->ossl_name, ossl_name, sizeof(ctx->ossl_name) - 1);
    ctx->keylen = keylen;
    ctx->ivlen = ivlen;
    ctx->blocksize = bs;
    ctx->is_ctr = is_ctr;
    ctx->pad = (bs > 1) ? 1 : 0;
    return ctx;
}

static void *afalg_dupctx(void *vctx)
{
    struct afalg_ctx *src = vctx;
    if (!src)
        return NULL;
    struct afalg_ctx *dst = calloc(1, sizeof(*dst));
    if (!dst)
        return NULL;
    memcpy(dst, src, sizeof(*dst));
    dst->tfmfd = -1;
    dst->opfd = -1;
    dst->hw_key_set = 0;
    dst->sw_cipher = NULL;
    dst->sw_ctx = NULL;
    if (src->sw_ctx) {
        dst->sw_ctx = EVP_CIPHER_CTX_dup(src->sw_ctx);
        if (!dst->sw_ctx) {
            OPENSSL_cleanse(dst->key, sizeof(dst->key));
            free(dst);
            return NULL;
        }
    }
    return dst;
}

static void afalg_freectx(void *vctx)
{
    struct afalg_ctx *ctx = vctx;
    if (!ctx)
        return;
    if (ctx->sw_ctx)
        EVP_CIPHER_CTX_free(ctx->sw_ctx);
    if (ctx->sw_cipher)
        EVP_CIPHER_free(ctx->sw_cipher);
    if (ctx->opfd >= 0)
        close(ctx->opfd);
    if (ctx->tfmfd >= 0)
        close(ctx->tfmfd);
    OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
    OPENSSL_cleanse(ctx->iv, sizeof(ctx->iv));
    free(ctx);
}

static int afalg_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct afalg_ctx *ctx = vctx;
    const OSSL_PARAM *p;
    if (!params)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p && !OSSL_PARAM_get_size_t(p, &ctx->keylen))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p) {
        unsigned int pv = 0;
        if (!OSSL_PARAM_get_uint(p, &pv))
            return 0;
        ctx->pad = pv ? 1 : 0;
        if (ctx->sw_ctx)
            EVP_CIPHER_CTX_set_padding(ctx->sw_ctx, ctx->pad);
    }
    return 1;
}

static int afalg_init(void *vctx, const unsigned char *key, size_t keylen,
                      const unsigned char *iv, size_t ivlen,
                      const OSSL_PARAM params[], int enc)
{
    struct afalg_ctx *ctx = vctx;
    ctx->enc = enc;
    ctx->iv_dirty = 0;
    ctx->sw_unaligned = 0;

    if (key) {
        if (keylen > sizeof(ctx->key))
            return 0;
        ctx->keylen = keylen;
        memcpy(ctx->key, key, keylen);
        ctx->has_key = 1;
        ctx->hw_key_set = 0;
        ctx->sw_key_set = 0;
        if (ctx->opfd >= 0) {
            close(ctx->opfd);
            ctx->opfd = -1;
        }
    }
    if (iv) {
        if (ivlen > sizeof(ctx->iv))
            return 0;
        ctx->ivlen = ivlen;
        memcpy(ctx->iv, iv, ivlen);
        ctx->has_iv = 1;
        ctx->sw_key_set = 0;
    } else {
        ctx->has_iv = 0;
        ctx->sw_key_set = 0;
    }

    return afalg_set_ctx_params(ctx, params);
}

static int afalg_einit(void *vctx, const unsigned char *k, size_t kl,
                       const unsigned char *iv, size_t ivl, const OSSL_PARAM p[])
{
    return afalg_init(vctx, k, kl, iv, ivl, p, 1);
}

static int afalg_dinit(void *vctx, const unsigned char *k, size_t kl,
                       const unsigned char *iv, size_t ivl, const OSSL_PARAM p[])
{
    return afalg_init(vctx, k, kl, iv, ivl, p, 0);
}

static void afalg_ctr_add_blocks(uint8_t iv[16], uint64_t blocks)
{
    for (int i = 15; i >= 0 && blocks > 0; i--) {
        uint64_t sum = (uint64_t)iv[i] + (blocks & 0xff);
        iv[i] = (uint8_t)(sum & 0xff);
        blocks = (blocks >> 8) + (sum >> 8);
    }
}

static int afalg_sw_skcipher_update(struct afalg_ctx *ctx, unsigned char *out,
                                    size_t *outl, const unsigned char *in, size_t inl)
{
    int len = 0;
    uint8_t next_iv[16];
    int save_dec_iv = (!ctx->is_ctr && !ctx->enc && inl >= 16);

    if (inl > INT_MAX)
        return 0;
    if (!afalg_ensure_sw(ctx))
        return 0;

    if (ctx->iv_dirty) {
        if (!EVP_CipherInit_ex(ctx->sw_ctx, NULL, NULL, NULL, ctx->iv, -1))
            return 0;
        ctx->iv_dirty = 0;
    }

    if ((inl % 16) != 0 || (!ctx->is_ctr && !ctx->enc && ctx->pad))
        ctx->sw_unaligned = 1;

    if (save_dec_iv)
        memcpy(next_iv, in + inl - 16, 16);

    if (!EVP_CipherUpdate(ctx->sw_ctx, out, &len, in, (int)inl))
        return 0;

    if (ctx->is_ctr) {
        afalg_ctr_add_blocks(ctx->iv, inl >> 4);
    } else if (inl >= 16) {
        memcpy(ctx->iv, ctx->enc ? (out + inl - 16) : next_iv, 16);
    }

    *outl = (size_t)len;
    return 1;
}

static int afalg_ensure_hw(struct afalg_ctx *ctx)
{
    if (ctx->tfmfd < 0) {
        struct sockaddr_alg sa = { .salg_family = AF_ALG };
        memcpy(sa.salg_type, ctx->alg_type, strlen(ctx->alg_type) + 1);
        strncpy((char *)sa.salg_name, ctx->alg_name, sizeof(sa.salg_name) - 1);
        ctx->tfmfd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        if (ctx->tfmfd < 0)
            return 0;
        if (bind(ctx->tfmfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            close(ctx->tfmfd);
            ctx->tfmfd = -1;
            return 0;
        }
    }
    if (!ctx->hw_key_set) {
        if (setsockopt(ctx->tfmfd, SOL_ALG, ALG_SET_KEY, ctx->key, ctx->keylen) < 0)
            return 0;
        if (ctx->opfd >= 0) {
            close(ctx->opfd);
            ctx->opfd = -1;
        }
        ctx->hw_key_set = 1;
    }
    if (ctx->opfd < 0) {
        ctx->opfd = accept4(ctx->tfmfd, NULL, 0, SOCK_CLOEXEC);
        if (ctx->opfd < 0)
            return 0;
    }
    return 1;
}

static int afalg_hw_skcipher_exec(struct afalg_ctx *ctx, unsigned char *out,
                                  const unsigned char *in, size_t len, size_t *done_out)
{
    char cbuf[CMSG_SPACE(sizeof(uint32_t)) + CMSG_SPACE(sizeof(struct af_alg_iv) + 16)];
    size_t offset = 0;

    if (!afalg_ensure_hw(ctx))
        return 0;

    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > MAX_HW_CHUNK)
            chunk = MAX_HW_CHUNK;

        uint8_t next_iv[16];
        if (!ctx->is_ctr && !ctx->enc)
            memcpy(next_iv, in + offset + chunk - 16, 16);

        struct msghdr msg = {0};
        struct cmsghdr *cmsg;
        struct af_alg_iv *alg_iv;
        struct iovec iov;

        memset(cbuf, 0, sizeof(cbuf));
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
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + ctx->ivlen);
        alg_iv = (struct af_alg_iv *)CMSG_DATA(cmsg);
        alg_iv->ivlen = ctx->ivlen;
        memcpy(alg_iv->iv, ctx->iv, ctx->ivlen);

        iov.iov_base = (void *)(in + offset);
        iov.iov_len = chunk;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ssize_t sret;
        do {
            sret = sendmsg(ctx->opfd, &msg, 0);
        } while (sret < 0 && errno == EINTR);

        if (sret != (ssize_t)chunk) {
            *done_out = offset;
            return 0;
        }

        size_t rcvd = 0;
        while (rcvd < chunk) {
            ssize_t rret = read(ctx->opfd, out + offset + rcvd, chunk - rcvd);
            if (rret < 0) {
                if (errno == EINTR)
                    continue;
                *done_out = offset;
                return 0;
            }
            if (rret == 0) {
                *done_out = offset;
                return 0;
            }
            rcvd += (size_t)rret;
        }

        if (ctx->is_ctr) {
            afalg_ctr_add_blocks(ctx->iv, chunk >> 4);
        } else {
            memcpy(ctx->iv, ctx->enc ? (out + offset + chunk - 16) : next_iv, 16);
        }

        ctx->iv_dirty = 1;
        offset += chunk;
    }

    *done_out = offset;
    return 1;
}

static int afalg_update(void *vctx, unsigned char *out, size_t *outl,
                        size_t outsize, const unsigned char *in, size_t inl)
{
    struct afalg_ctx *ctx = vctx;
    size_t min_out = (!ctx->is_ctr && !ctx->enc && ctx->pad && inl >= 16)
                     ? (inl - 16) : inl;

    if (!ctx->has_key || outsize < min_out)
        return 0;
    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (inl < SPACC_HW_THRESHOLD || ctx->sw_unaligned)
        return afalg_sw_skcipher_update(ctx, out, outl, in, inl);

    size_t hw_len = inl & ~(size_t)15;
    if (!ctx->is_ctr && !ctx->enc && ctx->pad)
        hw_len -= 16;

    size_t hw_done = 0;
    if (!afalg_hw_skcipher_exec(ctx, out, in, hw_len, &hw_done)) {
        size_t sw_out = 0;
        if (!afalg_sw_skcipher_update(ctx, out + hw_done, &sw_out,
                                      in + hw_done, inl - hw_done))
            return 0;
        *outl = hw_done + sw_out;
        return 1;
    }

    size_t rem = inl - hw_len;
    size_t sw_out = 0;
    if (rem > 0) {
        if (!afalg_sw_skcipher_update(ctx, out + hw_len, &sw_out, in + hw_len, rem))
            return 0;
    }

    *outl = hw_len + sw_out;
    return 1;
}

static int afalg_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    struct afalg_ctx *ctx = vctx;
    int len = 0;

    if (!ctx->is_ctr && ctx->pad) {
        if (ctx->enc && outsize < ctx->blocksize)
            return 0;
        if (!afalg_ensure_sw(ctx))
            return 0;
        if (ctx->iv_dirty) {
            if (!EVP_CipherInit_ex(ctx->sw_ctx, NULL, NULL, NULL, ctx->iv, -1))
                return 0;
            ctx->iv_dirty = 0;
        }
        if (!EVP_CipherFinal_ex(ctx->sw_ctx, out, &len))
            return 0;
        *outl = (size_t)len;
        return 1;
    }

    if (ctx->sw_ctx && ctx->sw_key_set) {
        if (!EVP_CipherFinal_ex(ctx->sw_ctx, out, &len))
            return 0;
        *outl = (size_t)len;
        return 1;
    }

    *outl = 0;
    return 1;
}

static int afalg_get_params(OSSL_PARAM params[], unsigned int mode,
                            size_t keylen, size_t ivlen, size_t bs)
{
    OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE)) && !OSSL_PARAM_set_uint(p, mode))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) && !OSSL_PARAM_set_size_t(p, keylen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) && !OSSL_PARAM_set_size_t(p, ivlen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE)) && !OSSL_PARAM_set_size_t(p, bs))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV)) && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static int afalg_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct afalg_ctx *ctx = vctx;
    OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) && !OSSL_PARAM_set_size_t(p, ctx->keylen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) && !OSSL_PARAM_set_size_t(p, ctx->ivlen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING)) && !OSSL_PARAM_set_uint(p, (unsigned int)ctx->pad))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV))) {
        if (p->data_type == OSSL_PARAM_OCTET_PTR) {
            if (!OSSL_PARAM_set_octet_ptr(p, ctx->iv, ctx->ivlen))
                return 0;
        } else {
            if (!OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen))
                return 0;
        }
    }
    return 1;
}

static const OSSL_PARAM *afalg_gettable_params(void *provctx)
{
    (void)provctx;
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
        OSSL_PARAM_END
    };
    return table;
}

static const OSSL_PARAM *afalg_gettable_ctx_params(void *cctx, void *provctx)
{
    (void)cctx;
    (void)provctx;
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
        OSSL_PARAM_END
    };
    return table;
}

static const OSSL_PARAM *afalg_settable_ctx_params(void *cctx, void *provctx)
{
    (void)cctx;
    (void)provctx;
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_END
    };
    return table;
}

#define DEFINE_CIPHER(name, atype, alg, oname, mode, klen, ivl, bs, is_ctr) \
static void *name##_newctx(void *provctx) { (void)provctx; return afalg_newctx(atype, alg, oname, klen, ivl, bs, is_ctr); } \
static int name##_get_params(OSSL_PARAM params[]) { return afalg_get_params(params, mode, klen, ivl, bs); } \
static const OSSL_DISPATCH name##_functions[] = { \
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))name##_newctx }, \
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))afalg_dupctx }, \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))afalg_freectx }, \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))afalg_einit }, \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))afalg_dinit }, \
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))afalg_update }, \
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))afalg_final }, \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))afalg_update }, \
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))name##_get_params }, \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))afalg_get_ctx_params }, \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))afalg_set_ctx_params }, \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))afalg_gettable_params }, \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))afalg_gettable_ctx_params }, \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))afalg_settable_ctx_params }, \
    { 0, NULL } \
};

DEFINE_CIPHER(aes128ctr, "skcipher", "ctr-aes-ls1024a-spacc", "AES-128-CTR", EVP_CIPH_CTR_MODE, 16, 16, 1, 1)
DEFINE_CIPHER(aes192ctr, "skcipher", "ctr-aes-ls1024a-spacc", "AES-192-CTR", EVP_CIPH_CTR_MODE, 24, 16, 1, 1)
DEFINE_CIPHER(aes256ctr, "skcipher", "ctr-aes-ls1024a-spacc", "AES-256-CTR", EVP_CIPH_CTR_MODE, 32, 16, 1, 1)
DEFINE_CIPHER(aes128cbc, "skcipher", "cbc-aes-ls1024a-spacc", "AES-128-CBC", EVP_CIPH_CBC_MODE, 16, 16, 16, 0)
DEFINE_CIPHER(aes192cbc, "skcipher", "cbc-aes-ls1024a-spacc", "AES-192-CBC", EVP_CIPH_CBC_MODE, 24, 16, 16, 0)
DEFINE_CIPHER(aes256cbc, "skcipher", "cbc-aes-ls1024a-spacc", "AES-256-CBC", EVP_CIPH_CBC_MODE, 32, 16, 16, 0)

static const OSSL_ALGORITHM afalg_ciphers[] = {
    { "AES-128-CTR:aes-128-ctr", "provider=afalgprov", aes128ctr_functions, "AF_ALG AES-128-CTR" },
    { "AES-192-CTR:aes-192-ctr", "provider=afalgprov", aes192ctr_functions, "AF_ALG AES-192-CTR" },
    { "AES-256-CTR:aes-256-ctr", "provider=afalgprov", aes256ctr_functions, "AF_ALG AES-256-CTR" },
    { "AES-128-CBC:aes-128-cbc", "provider=afalgprov", aes128cbc_functions, "AF_ALG AES-128-CBC" },
    { "AES-192-CBC:aes-192-cbc", "provider=afalgprov", aes192cbc_functions, "AF_ALG AES-192-CBC" },
    { "AES-256-CBC:aes-256-cbc", "provider=afalgprov", aes256cbc_functions, "AF_ALG AES-256-CBC" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *afalg_query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    return (operation_id == OSSL_OP_CIPHER) ? afalg_ciphers : NULL;
}

static const OSSL_PARAM *afalg_prov_gettable_params(void *provctx)
{
    (void)provctx;
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
        OSSL_PARAM_int(OSSL_PROV_PARAM_STATUS, NULL),
        OSSL_PARAM_END
    };
    return table;
}

static int afalg_prov_get_params(void *provctx, OSSL_PARAM params[])
{
    (void)provctx;
    OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME)) && !OSSL_PARAM_set_utf8_ptr(p, "AF_ALG SPACC Provider"))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION)) && !OSSL_PARAM_set_utf8_ptr(p, "2.1.0"))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS)) && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static const OSSL_DISPATCH afalg_dispatch[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))afalg_prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))afalg_prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))afalg_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx)
{
    (void)handle;
    (void)in;
    *provctx = NULL;
    *out = afalg_dispatch;
    return 1;
}
