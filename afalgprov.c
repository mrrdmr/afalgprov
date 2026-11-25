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
#define SPACC_MAX_CHUNK_BYTES       65520U
#define SPACC_MAX_SGL_CHUNK_BYTES   (15U * 4096U)
#define SPACC_MIN_TAIL_HW_BYTES     2048U
#define AFALG_SEND_CHUNK            SPACC_MAX_SGL_CHUNK_BYTES

#define AFALG_GCM_MIN_HW_BYTES      8192U
#define AFALG_GCM_L2_OPTIMAL_MAX    (256U * 1024U)
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
    size_t ctr_send_chunk;
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

static void afalg_detect_kernel_limits(size_t *ctr_send_chunk,
                                       size_t *max_hw_payload,
                                       int *sock_buf_req)
{
    size_t wmem = afalg_read_sysctl_size("/proc/sys/net/core/wmem_max",
                                         AFALG_GCM_FALLBACK_WMEM);
    size_t rmem = afalg_read_sysctl_size("/proc/sys/net/core/rmem_max",
                                         AFALG_GCM_FALLBACK_WMEM);
    size_t limit = (wmem < rmem) ? wmem : rmem;
    size_t safe_payload;
    size_t safe_ctr_chunk;

    *sock_buf_req = (limit > (size_t)INT_MAX) ? INT_MAX : (int)limit;

    /* Keep CTR chunk <= limit / 2 (aligned to AES block) and within SGL chunk limit */
    safe_ctr_chunk = ((limit / 2U) / AES_BLOCK_SZ) * AES_BLOCK_SZ;
    if (safe_ctr_chunk < AES_BLOCK_SZ)
        safe_ctr_chunk = AES_BLOCK_SZ;
    if (safe_ctr_chunk > SPACC_MAX_SGL_CHUNK_BYTES)
        safe_ctr_chunk = SPACC_MAX_SGL_CHUNK_BYTES;
    *ctr_send_chunk = safe_ctr_chunk;

    if (limit <= AFALG_GCM_SKB_OVERHEAD) {
        *max_hw_payload = 65536U;
        return;
    }

    safe_payload = limit - AFALG_GCM_SKB_OVERHEAD;
    if (safe_payload > AFALG_GCM_L2_OPTIMAL_MAX)
        safe_payload = AFALG_GCM_L2_OPTIMAL_MAX;

    *max_hw_payload = safe_payload;
}

static int afalg_open_op_socket(const char *alg_type,
                                const char *alg_name,
                                const uint8_t *key,
                                size_t key_len,
                                int set_aead_authsize,
                                size_t authsize,
                                int sock_buf_req,
                                int *out_tfmfd,
                                int *out_opfd)
{
    struct sockaddr_alg sa;
    int tfmfd = -1;
    int opfd = -1;
    int n;

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;

    n = snprintf((char *)sa.salg_type, sizeof(sa.salg_type), "%s", alg_type);
    if (n < 0 || (size_t)n >= sizeof(sa.salg_type))
        goto err;

    n = snprintf((char *)sa.salg_name, sizeof(sa.salg_name), "%s", alg_name);
    if (n < 0 || (size_t)n >= sizeof(sa.salg_name))
        goto err;

    tfmfd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (tfmfd < 0)
        goto err;

    if (bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        goto err;

    if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key, (socklen_t)key_len) < 0)
        goto err;

    if (set_aead_authsize) {
        if (setsockopt(tfmfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
                       NULL, (socklen_t)authsize) < 0)
            goto err;
    }

    opfd = accept4(tfmfd, NULL, 0, SOCK_CLOEXEC);
    if (opfd < 0)
        goto err;

    if (sock_buf_req > 0) {
        int buf_req = sock_buf_req;
        (void)setsockopt(opfd, SOL_SOCKET, SO_SNDBUF, &buf_req, sizeof(buf_req));
        (void)setsockopt(opfd, SOL_SOCKET, SO_RCVBUF, &buf_req, sizeof(buf_req));
    }

    *out_tfmfd = tfmfd;
    *out_opfd = opfd;
    return 1;

err:
    if (opfd >= 0)
        close(opfd);
    if (tfmfd >= 0)
        close(tfmfd);
    *out_tfmfd = -1;
    *out_opfd = -1;
    return 0;
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
} AFALG_CIPHER_INFO;

typedef struct {
    const AFALG_CIPHER_INFO *info;
    OSSL_LIB_CTX *libctx;
    size_t hw_threshold;
    size_t send_chunk;
    int sock_buf_req;

    int tfmfd;
    int opfd;

    uint8_t *cbuf;
    size_t cbuf_len;

    EVP_CIPHER *sw_cipher;
    EVP_CIPHER_CTX *sw_ctx;

    int enc;
    int key_set;
    int iv_set;
    int iv_dirty;
    size_t sw_block_rem;

    uint8_t key[AES_MAX_KEY_SZ];
    uint8_t iv[EVP_MAX_IV_LENGTH];
    uint8_t orig_iv[EVP_MAX_IV_LENGTH];
} AFALG_CTX;

static const AFALG_CIPHER_INFO cipher_table[] = {
    { "AES-128-CTR", "ctr-aes-ls1024a-spacc", 16, AES_IV_SZ, 1 },
    { "AES-192-CTR", "ctr-aes-ls1024a-spacc", 24, AES_IV_SZ, 1 },
    { "AES-256-CTR", "ctr-aes-ls1024a-spacc", 32, AES_IV_SZ, 1 },
};

static void afalg_ctr128_inc(uint8_t iv[AES_IV_SZ], uint64_t blocks)
{
    uint64_t carry = blocks;
    for (int i = AES_IV_SZ - 1; i >= 0 && carry > 0; i--) {
        uint64_t sum = (uint64_t)iv[i] + (carry & 0xffU);
        iv[i] = (uint8_t)(sum & 0xffU);
        carry = (carry >> 8) + (sum >> 8);
    }
}

static void afalg_advance_iv(AFALG_CTX *ctx, size_t bytes)
{
    afalg_ctr128_inc(ctx->iv, bytes / AES_BLOCK_SZ);
    ctx->iv_dirty = 1;
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
    if (!ctx->key_set)
        return 0;

    if (ctx->opfd >= 0)
        return 1;

    afalg_reset_hw_descriptors(ctx);

    return afalg_open_op_socket("skcipher",
                                ctx->info->alg_name,
                                ctx->key,
                                ctx->info->key_len,
                                0, 0,
                                ctx->sock_buf_req,
                                &ctx->tfmfd,
                                &ctx->opfd);
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
                               ctx->key, ctx->iv_set ? ctx->iv : NULL,
                               ctx->enc)) {
            EVP_CIPHER_CTX_free(ctx->sw_ctx);
            ctx->sw_ctx = NULL;
            return 0;
        }
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

    if (total_cmsg_len > ctx->cbuf_len)
        return 0;

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
        size_t got = 0;
        ssize_t sent;

        if (chunk > ctx->send_chunk)
            chunk = ctx->send_chunk;

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

        afalg_advance_iv(ctx, chunk);
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
    ctx->send_chunk = pctx->ctr_send_chunk;
    ctx->sock_buf_req = pctx->sock_buf_req;
    ctx->tfmfd = -1;
    ctx->opfd = -1;

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
    dst->send_chunk = src->send_chunk;
    dst->sock_buf_req = src->sock_buf_req;
    dst->tfmfd = -1;
    dst->opfd = -1;
    dst->cbuf_len = src->cbuf_len;

    dst->enc = src->enc;
    dst->key_set = src->key_set;
    dst->iv_set = src->iv_set;
    dst->iv_dirty = src->iv_dirty;
    dst->sw_block_rem = src->sw_block_rem;

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
    ctx->sw_block_rem = 0;

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
                               ctx->iv_set ? ctx->iv : NULL,
                               enc))
            return 0;
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

        if (step > outsize - total_out) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }

        if (!EVP_CipherUpdate(ctx->sw_ctx, out + total_out, &step_outl,
                              in + offset, (int)step) || step_outl < 0)
            return 0;

        total_out += (size_t)step_outl;
        offset += step;
    }

    ctx->sw_block_rem = (ctx->sw_block_rem + (inl % AES_BLOCK_SZ)) % AES_BLOCK_SZ;

    if (ctx->sw_block_rem == 0) {
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
                               size_t prefix_sw_len,
                               size_t hw_len,
                               size_t tail_sw_len)
{
    size_t pos = 0;
    size_t total = 0;
    size_t part_outl = 0;

    if (prefix_sw_len > 0) {
        if (!afalg_process_sw(ctx, out + pos, &part_outl, outsize - pos,
                              in + pos, prefix_sw_len))
            return 0;
        pos += prefix_sw_len;
        total += part_outl;
    }

    if (hw_len > 0) {
        if (!afalg_process_hw(ctx, out + pos, &part_outl, outsize - pos,
                              in + pos, hw_len))
            return 0;
        pos += hw_len;
        total += part_outl;
    }

    if (tail_sw_len > 0) {
        if (!afalg_process_sw(ctx, out + pos, &part_outl, outsize - pos,
                              in + pos, tail_sw_len))
            return 0;
        total += part_outl;
    }

    *outl = total;
    return 1;
}

static int afalg_update(void *vctx,
                        unsigned char *out, size_t *outl, size_t outsize,
                        const unsigned char *in, size_t inl)
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    size_t prefix_sw_len = 0;
    size_t rem_after_prefix;
    size_t hw_len;
    size_t tail_len;

    if (ctx == NULL || outl == NULL || !ctx->key_set || !ctx->iv_set)
        return 0;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (out == NULL || in == NULL)
        return 0;

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (inl < ctx->hw_threshold)
        return afalg_process_sw(ctx, out, outl, outsize, in, inl);

    if (ctx->sw_block_rem > 0) {
        size_t need = AES_BLOCK_SZ - ctx->sw_block_rem;
        if (inl <= need)
            return afalg_process_sw(ctx, out, outl, outsize, in, inl);
        prefix_sw_len = need;
    }

    rem_after_prefix = inl - prefix_sw_len;
    hw_len = (rem_after_prefix / AES_BLOCK_SZ) * AES_BLOCK_SZ;
    tail_len = rem_after_prefix - hw_len;

    if (tail_len == 0 && hw_len > SPACC_MAX_SGL_CHUNK_BYTES) {
        size_t full_chunks = hw_len / SPACC_MAX_SGL_CHUNK_BYTES;
        size_t chunk_rem = hw_len % SPACC_MAX_SGL_CHUNK_BYTES;

        if (chunk_rem > 0 && chunk_rem < SPACC_MIN_TAIL_HW_BYTES) {
            hw_len = full_chunks * SPACC_MAX_SGL_CHUNK_BYTES;
            tail_len = chunk_rem;
        }
    }

    if (hw_len < ctx->hw_threshold)
        return afalg_process_sw(ctx, out, outl, outsize, in, inl);

    if (prefix_sw_len == 0 && tail_len == 0)
        return afalg_process_hw(ctx, out, outl, outsize, in, hw_len);

    return afalg_process_mixed(ctx, out, outl, outsize, in,
                               prefix_sw_len, hw_len, tail_len);
}

static int afalg_final(void *vctx,
                       unsigned char *out, size_t *outl, size_t outsize)
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    uint8_t dummy_out[AES_BLOCK_SZ];
    unsigned char *dst;
    int fin_outl = 0;

    if (ctx == NULL || outl == NULL || !ctx->key_set || !ctx->iv_set)
        return 0;

    if (ctx->sw_ctx == NULL) {
        *outl = 0;
        return 1;
    }

    if (ctx->iv_dirty) {
        if (!EVP_CipherInit_ex(ctx->sw_ctx, NULL, NULL, NULL, ctx->iv, -1))
            return 0;
        ctx->iv_dirty = 0;
    }

    dst = (out != NULL && outsize > 0) ? out : dummy_out;
    if (!EVP_CipherFinal_ex(ctx->sw_ctx, dst, &fin_outl) || fin_outl < 0)
        return 0;

    if ((size_t)fin_outl > outsize) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (dst == dummy_out && fin_outl > 0) {
        if (out == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        memcpy(out, dummy_out, (size_t)fin_outl);
    }

    if (ctx->sw_block_rem == 0) {
        if (!afalg_sync_iv_from_sw(ctx))
            return 0;
    }

    *outl = (size_t)fin_outl;
    return 1;
}

static int afalg_cipher(void *vctx,
                        unsigned char *out, size_t *outl, size_t outsize,
                        const unsigned char *in, size_t inl)
{
    if (vctx == NULL || outl == NULL)
        return 0;

    return afalg_update(vctx, out, outl, outsize, in, inl);
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
    if (p != NULL && !OSSL_PARAM_set_uint(p, EVP_CIPH_CTR_MODE))
        return 0;

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

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (!afalg_set_ctx_octet(p, ctx->orig_iv, ctx->info->iv_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL) {
        if (ctx->sw_ctx != NULL && ctx->sw_block_rem > 0) {
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
    if (vctx == NULL)
        return 0;
    (void)params;
    return 1;
}

static const OSSL_PARAM afalg_known_settable_ctx_params[] = {
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
 * PART 2: AES-128 / 192 / 256 - GCM (AEAD)
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

    uint8_t *scratch;
    size_t scratch_cap;

    uint8_t *saved_ct;
    size_t saved_ct_len;
    size_t saved_ct_cap;

    uint8_t *aad_buf;
    size_t aad_len;
    size_t aad_cap;
    uint8_t *aad_sink;
    size_t aad_sink_cap;

    EVP_CIPHER *sw_cipher;
    EVP_CIPHER_CTX *sw_ctx;
    int sw_inited;
    int force_sw;
    int used_hw_stream;

    int enc;
    int key_set;
    int iv_set;
    int tag_set;
    size_t iv_len;
    size_t tag_len;
    size_t tls_aad_len;
    int tls_aad_pad;

    uint8_t key[AES_MAX_KEY_SZ];
    uint8_t iv[EVP_MAX_IV_LENGTH];
    uint8_t tag[GCM_TAG_SZ];
} AFALG_GCM_CTX;

static const AFALG_GCM_INFO gcm_table[] = {
    { "AES-128-GCM", 16 },
    { "AES-192-GCM", 24 },
    { "AES-256-GCM", 32 },
};

static uint8_t *afalg_gcm_get_scratch(AFALG_GCM_CTX *ctx, size_t len)
{
    size_t new_cap;
    uint8_t *nb;

    if (len <= ctx->scratch_cap)
        return ctx->scratch;

    new_cap = ctx->scratch_cap ? ctx->scratch_cap : len;
    while (new_cap < len) {
        if (new_cap > SIZE_MAX / 2U) {
            new_cap = len;
            break;
        }
        new_cap *= 2U;
    }

    nb = OPENSSL_realloc(ctx->scratch, new_cap);
    if (nb == NULL)
        return NULL;

    ctx->scratch = nb;
    ctx->scratch_cap = new_cap;
    return ctx->scratch;
}

static int afalg_gcm_fits_hw_payload(const AFALG_GCM_CTX *ctx, size_t payload_len)
{
    size_t total = payload_len;

    if (ctx->aad_len > SIZE_MAX - total)
        return 0;
    total += ctx->aad_len;

    if (ctx->tag_len > SIZE_MAX - total)
        return 0;
    total += ctx->tag_len;

    return total <= ctx->max_hw_payload;
}

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
    if (!ctx->key_set)
        return 0;

    if (ctx->opfd >= 0)
        return 1;

    afalg_gcm_reset_hw(ctx);

    return afalg_open_op_socket("aead",
                                "gcm(aes)",
                                ctx->key,
                                ctx->info->key_len,
                                1,
                                ctx->tag_len,
                                ctx->sock_buf_req,
                                &ctx->tfmfd,
                                &ctx->opfd);
}

static int afalg_gcm_feed_sw(EVP_CIPHER_CTX *sw_ctx,
                             unsigned char *out, int *outl,
                             const unsigned char *in, size_t inl)
{
    size_t offset = 0;
    int total = 0;

    if (outl != NULL)
        *outl = 0;

    if (inl == 0)
        return 1;

    while (offset < inl) {
        size_t step = inl - offset;
        int step_out = 0;
        unsigned char *dst_ptr = (out != NULL) ? (out + total) : NULL;

        if (step > (size_t)INT_MAX)
            step = (size_t)INT_MAX;

        if (!EVP_CipherUpdate(sw_ctx, dst_ptr, &step_out,
                              in + offset, (int)step) || step_out < 0)
            return 0;

        total += step_out;
        offset += step;
    }

    if (outl != NULL)
        *outl = total;
    return 1;
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
        ctx->sw_inited = 0;
    }

    if (!ctx->sw_inited) {
        if (!EVP_CipherInit_ex(ctx->sw_ctx, ctx->sw_cipher, NULL, NULL, NULL, ctx->enc))
            goto err;
        if (!EVP_CIPHER_CTX_ctrl(ctx->sw_ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                 (int)ctx->iv_len, NULL))
            goto err;
        if (!EVP_CipherInit_ex(ctx->sw_ctx, NULL, NULL,
                               ctx->key, ctx->iv_set ? ctx->iv : NULL, ctx->enc))
            goto err;
        if (ctx->aad_len > 0) {
            if (!afalg_gcm_feed_sw(ctx->sw_ctx, NULL, NULL,
                                   ctx->aad_buf, ctx->aad_len))
                goto err;
        }
        ctx->sw_inited = 1;
    }

    return 1;

err:
    EVP_CIPHER_CTX_free(ctx->sw_ctx);
    ctx->sw_ctx = NULL;
    ctx->sw_inited = 0;
    return 0;
}

static int afalg_gcm_sw_final_call(EVP_CIPHER_CTX *sw_ctx,
                                   unsigned char *out,
                                   size_t outsize,
                                   size_t *outl)
{
    uint8_t dummy_out[AES_BLOCK_SZ];
    unsigned char *dst = (out != NULL && outsize > 0) ? out : dummy_out;
    int fin_outl = 0;

    if (!EVP_CipherFinal_ex(sw_ctx, dst, &fin_outl) || fin_outl < 0)
        return 0;

    if ((size_t)fin_outl > outsize) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (dst == dummy_out && fin_outl > 0) {
        if (out == NULL) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        memcpy(out, dummy_out, (size_t)fin_outl);
    }

    *outl = (size_t)fin_outl;
    return 1;
}

static int afalg_gcm_sw_update(AFALG_GCM_CTX *ctx,
                               unsigned char *out, size_t *outl, size_t outsize,
                               const unsigned char *in, size_t inl)
{
    int step_outl = 0;

    if (out != NULL)
        ctx->force_sw = 1;

    if (!afalg_gcm_ensure_sw(ctx))
        return 0;

    if (out == NULL) {
        if (!afalg_gcm_feed_sw(ctx->sw_ctx, NULL, &step_outl, in, inl))
            return 0;
        if (outl != NULL)
            *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!afalg_gcm_feed_sw(ctx->sw_ctx, out, &step_outl, in, inl))
        return 0;

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
    size_t in_iovcnt = 0;
    size_t out_iovcnt = 0;
    size_t total_in = 0;
    size_t total_out = 0;
    size_t total_cmsg_len = CMSG_SPACE(sizeof(uint32_t)) +
                            CMSG_SPACE(sizeof(struct af_alg_iv) + ctx->iv_len) +
                            CMSG_SPACE(sizeof(uint32_t));
    uint32_t op = ctx->enc ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
    uint32_t assoclen;
    ssize_t sent, recvd;

    if (len == 0 || in == NULL || out == NULL)
        return 0;

    if (ctx->aad_len > UINT32_MAX)
        return 0;
    assoclen = (uint32_t)ctx->aad_len;

    if (total_cmsg_len > ctx->cbuf_len)
        return 0;

    if (ctx->aad_len > 0) {
        in_iov[in_iovcnt].iov_base = ctx->aad_buf;
        in_iov[in_iovcnt].iov_len = ctx->aad_len;
        in_iovcnt++;
        total_in += ctx->aad_len;
    }
    in_iov[in_iovcnt].iov_base = (void *)in;
    in_iov[in_iovcnt].iov_len = len;
    in_iovcnt++;
    total_in += len;

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
    out_iov[out_iovcnt].iov_base = out;
    out_iov[out_iovcnt].iov_len = len;
    out_iovcnt++;
    total_out += len;

    if (ctx->enc) {
        out_iov[out_iovcnt].iov_base = ctx->tag;
        out_iov[out_iovcnt].iov_len = ctx->tag_len;
        out_iovcnt++;
        total_out += ctx->tag_len;
    }

    if (out_iovcnt == 0)
        return 0;

    memset(ctx->cbuf, 0, total_cmsg_len);
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = in_iov;
    msg.msg_iovlen = in_iovcnt;
    msg.msg_control = ctx->cbuf;
    msg.msg_controllen = total_cmsg_len;

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL)
        return 0;
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    memcpy(CMSG_DATA(cmsg), &op, sizeof(op));

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    if (cmsg == NULL)
        return 0;
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct af_alg_iv) + ctx->iv_len);
    alg_iv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    alg_iv->ivlen = (uint32_t)ctx->iv_len;
    memcpy(alg_iv->iv, ctx->iv, ctx->iv_len);

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    if (cmsg == NULL)
        return 0;
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
        recvd = readv(ctx->opfd, out_iov, (int)out_iovcnt);
        if (recvd >= 0)
            break;
        if (errno == EINTR)
            continue;
        if (!ctx->enc && errno == EBADMSG)
            return -1;
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
    if (ctx->scratch != NULL)
        OPENSSL_clear_free(ctx->scratch, ctx->scratch_cap);
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
    dst->sw_inited = src->sw_inited;
    dst->force_sw = src->force_sw;
    dst->used_hw_stream = src->used_hw_stream;
    dst->enc = src->enc;
    dst->key_set = src->key_set;
    dst->iv_set = src->iv_set;
    dst->tag_set = src->tag_set;
    dst->iv_len = src->iv_len;
    dst->tag_len = src->tag_len;
    dst->tls_aad_len = src->tls_aad_len;
    dst->tls_aad_pad = src->tls_aad_pad;

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

    if (src->saved_ct_len > 0) {
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
            afalg_gcm_freectx(dst);
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
    ctx->tag_len = GCM_TAG_SZ;
    ctx->aad_len = 0;
    ctx->saved_ct_len = 0;
    ctx->sw_inited = 0;
    ctx->force_sw = 0;
    ctx->used_hw_stream = 0;
    ctx->tls_aad_len = (size_t)-1;
    ctx->tls_aad_pad = 0;

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

    if (params != NULL && !afalg_gcm_set_ctx_params(ctx, params))
        return 0;

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
    size_t total;
    size_t new_cap;
    uint8_t *nb;

    if (inl == 0)
        return 1;
    if (ctx->saved_ct_len > SIZE_MAX - inl)
        return 0;

    total = ctx->saved_ct_len + inl;
    if (total > ctx->saved_ct_cap) {
        new_cap = ctx->saved_ct_cap ? ctx->saved_ct_cap : total;
        while (new_cap < total) {
            if (new_cap > SIZE_MAX / 2U) {
                new_cap = total;
                break;
            }
            new_cap *= 2U;
        }
        nb = OPENSSL_realloc(ctx->saved_ct, new_cap);
        if (nb == NULL)
            return 0;
        ctx->saved_ct = nb;
        ctx->saved_ct_cap = new_cap;
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
    int hw_rc;

    if (ctx == NULL || outl == NULL || !ctx->key_set || !ctx->iv_set)
        return 0;

    if (out == NULL) {
        if (inl > 0) {
            size_t total_aad;
            size_t new_cap;
            uint8_t *nb;

            if (in == NULL || ctx->used_hw_stream || ctx->saved_ct_len > 0 ||
                ctx->aad_len > SIZE_MAX - inl)
                return 0;

            total_aad = ctx->aad_len + inl;
            if (total_aad > ctx->aad_cap) {
                new_cap = ctx->aad_cap ? ctx->aad_cap : total_aad;
                while (new_cap < total_aad) {
                    if (new_cap > SIZE_MAX / 2U) {
                        new_cap = total_aad;
                        break;
                    }
                    new_cap *= 2U;
                }
                nb = OPENSSL_realloc(ctx->aad_buf, new_cap);
                if (nb == NULL)
                    return 0;
                ctx->aad_buf = nb;
                ctx->aad_cap = new_cap;
            }
            memcpy(ctx->aad_buf + ctx->aad_len, in, inl);
            ctx->aad_len = total_aad;
        }
        if (ctx->sw_ctx != NULL && ctx->sw_inited) {
            if (!afalg_gcm_feed_sw(ctx->sw_ctx, NULL, NULL, in, inl))
                return 0;
        }
        *outl = 0;
        return 1;
    }

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (in == NULL)
        return 0;

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (ctx->used_hw_stream)
        return 0;

    if (!ctx->enc && ctx->tls_aad_len == (size_t)-1) {
        if (!afalg_gcm_append_saved_ct(ctx, in, inl))
            return 0;
        *outl = 0;
        return 1;
    }

    if (ctx->force_sw ||
        ctx->iv_len != GCM_IV_SZ ||
        inl < AFALG_GCM_MIN_HW_BYTES ||
        !afalg_gcm_fits_hw_payload(ctx, inl)) {
        return afalg_gcm_sw_update(ctx, out, outl, outsize, in, inl);
    }

    if (!afalg_gcm_ensure_hw(ctx))
        return afalg_gcm_sw_update(ctx, out, outl, outsize, in, inl);

    if (in == out || !ctx->enc) {
        uint8_t *scratch = afalg_gcm_get_scratch(ctx, inl);

        if (scratch == NULL)
            return afalg_gcm_sw_update(ctx, out, outl, outsize, in, inl);

        hw_rc = afalg_gcm_hw_oneshot(ctx, scratch, in, inl);
        if (hw_rc == 1) {
            memcpy(out, scratch, inl);
            ctx->used_hw_stream = 1;
            *outl = inl;
            return 1;
        }

        if (!ctx->enc)
            OPENSSL_cleanse(scratch, inl);
        afalg_gcm_reset_hw(ctx);
        if (hw_rc < 0)
            return 0;

        return afalg_gcm_sw_update(ctx, out, outl, outsize, in, inl);
    }

    hw_rc = afalg_gcm_hw_oneshot(ctx, out, in, inl);
    if (hw_rc == 1) {
        ctx->used_hw_stream = 1;
        *outl = inl;
        return 1;
    }

    afalg_gcm_reset_hw(ctx);
    if (hw_rc < 0)
        return 0;

    return afalg_gcm_sw_update(ctx, out, outl, outsize, in, inl);
}

static int afalg_gcm_final(void *vctx,
                           unsigned char *out, size_t *outl, size_t outsize)
{
    AFALG_GCM_CTX *ctx = (AFALG_GCM_CTX *)vctx;
    size_t fin_outl = 0;

    if (ctx == NULL || outl == NULL || !ctx->key_set || !ctx->iv_set)
        return 0;

    if (!ctx->enc && ctx->saved_ct_len > 0) {
        size_t ct_len = ctx->saved_ct_len;
        size_t total_pt;
        int hw_rc;
        int sw_pt_len = 0;

        if (!ctx->tag_set)
            return 0;
        if (out == NULL)
            return 0;
        if (outsize > 0 && outsize < ct_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }

        if (!ctx->force_sw &&
            !ctx->used_hw_stream &&
            ct_len >= AFALG_GCM_MIN_HW_BYTES &&
            afalg_gcm_fits_hw_payload(ctx, ct_len) &&
            ctx->iv_len == GCM_IV_SZ &&
            afalg_gcm_ensure_hw(ctx)) {
            uint8_t *scratch = afalg_gcm_get_scratch(ctx, ct_len);

            if (scratch != NULL) {
                hw_rc = afalg_gcm_hw_oneshot(ctx, scratch, ctx->saved_ct, ct_len);
                if (hw_rc == 1) {
                    memcpy(out, scratch, ct_len);
                    ctx->saved_ct_len = 0;
                    ctx->used_hw_stream = 1;
                    *outl = ct_len;
                    return 1;
                }
                OPENSSL_cleanse(scratch, ct_len);
                afalg_gcm_reset_hw(ctx);
                if (hw_rc < 0) {
                    ctx->saved_ct_len = 0;
                    return 0;
                }
            }
        }

        if (!afalg_gcm_ensure_sw(ctx))
            return 0;
        if (!afalg_gcm_feed_sw(ctx->sw_ctx, ctx->saved_ct, &sw_pt_len,
                               ctx->saved_ct, ct_len) || sw_pt_len < 0) {
            OPENSSL_cleanse(ctx->saved_ct, ct_len);
            ctx->saved_ct_len = 0;
            return 0;
        }
        if (!EVP_CIPHER_CTX_ctrl(ctx->sw_ctx, EVP_CTRL_AEAD_SET_TAG,
                                 (int)ctx->tag_len, ctx->tag)) {
            OPENSSL_cleanse(ctx->saved_ct, ct_len);
            ctx->saved_ct_len = 0;
            return 0;
        }
        if (!afalg_gcm_sw_final_call(ctx->sw_ctx,
                                     ctx->saved_ct + (size_t)sw_pt_len,
                                     ct_len - (size_t)sw_pt_len,
                                     &fin_outl)) {
            OPENSSL_cleanse(ctx->saved_ct, ct_len);
            ctx->saved_ct_len = 0;
            return 0;
        }
        total_pt = (size_t)sw_pt_len + fin_outl;
        if (outsize > 0 && outsize < total_pt) {
            OPENSSL_cleanse(ctx->saved_ct, ct_len);
            ctx->saved_ct_len = 0;
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
        memcpy(out, ctx->saved_ct, total_pt);
        OPENSSL_cleanse(ctx->saved_ct, ct_len);
        ctx->saved_ct_len = 0;
        *outl = total_pt;
        return 1;
    }

    if (ctx->force_sw || (ctx->sw_ctx != NULL && ctx->sw_inited)) {
        if (!ctx->enc && !ctx->tag_set && ctx->tls_aad_len == (size_t)-1)
            return 0;
        if (!afalg_gcm_ensure_sw(ctx))
            return 0;
        if (!ctx->enc && ctx->tls_aad_len == (size_t)-1) {
            if (!EVP_CIPHER_CTX_ctrl(ctx->sw_ctx, EVP_CTRL_AEAD_SET_TAG,
                                     (int)ctx->tag_len, ctx->tag))
                return 0;
        }
        if (!afalg_gcm_sw_final_call(ctx->sw_ctx, out, outsize, &fin_outl))
            return 0;
        if (ctx->enc) {
            if (!EVP_CIPHER_CTX_ctrl(ctx->sw_ctx, EVP_CTRL_AEAD_GET_TAG,
                                     (int)ctx->tag_len, ctx->tag))
                return 0;
            ctx->tag_set = 1;
        }
        *outl = fin_outl;
        return 1;
    }

    if (!ctx->enc) {
        if (!ctx->tag_set)
            return 0;
        if (!ctx->used_hw_stream) {
            if (!afalg_gcm_ensure_sw(ctx))
                return 0;
            if (!EVP_CIPHER_CTX_ctrl(ctx->sw_ctx, EVP_CTRL_AEAD_SET_TAG,
                                     (int)ctx->tag_len, ctx->tag))
                return 0;
            if (!afalg_gcm_sw_final_call(ctx->sw_ctx, out, outsize, &fin_outl))
                return 0;
            *outl = fin_outl;
            return 1;
        }
        *outl = 0;
        return 1;
    }

    if (!ctx->tag_set) {
        if (!afalg_gcm_ensure_sw(ctx))
            return 0;
        if (!afalg_gcm_sw_final_call(ctx->sw_ctx, out, outsize, &fin_outl))
            return 0;
        if (!EVP_CIPHER_CTX_ctrl(ctx->sw_ctx, EVP_CTRL_AEAD_GET_TAG,
                                 (int)ctx->tag_len, ctx->tag))
            return 0;
        ctx->tag_set = 1;
        *outl = fin_outl;
        return 1;
    }

    *outl = 0;
    return 1;
}

static int afalg_gcm_cipher(void *vctx,
                            unsigned char *out, size_t *outl, size_t outsize,
                            const unsigned char *in, size_t inl)
{
    AFALG_GCM_CTX *ctx = (AFALG_GCM_CTX *)vctx;
    size_t upd_outl = 0;
    size_t fin_outl = 0;
    size_t rem_outsize;
    unsigned char *fin_out;

    if (ctx == NULL || outl == NULL)
        return 0;

    if (!ctx->enc &&
        ctx->key_set &&
        ctx->iv_set &&
        ctx->tag_set &&
        out != NULL &&
        in != NULL &&
        inl >= AFALG_GCM_MIN_HW_BYTES &&
        outsize >= inl &&
        ctx->saved_ct_len == 0 &&
        !ctx->force_sw &&
        !ctx->used_hw_stream &&
        ctx->tls_aad_len == (size_t)-1 &&
        ctx->iv_len == GCM_IV_SZ &&
        afalg_gcm_fits_hw_payload(ctx, inl) &&
        afalg_gcm_ensure_hw(ctx)) {
        uint8_t *scratch = afalg_gcm_get_scratch(ctx, inl);

        if (scratch != NULL) {
            int hw_rc = afalg_gcm_hw_oneshot(ctx, scratch, in, inl);
            if (hw_rc == 1) {
                memcpy(out, scratch, inl);
                ctx->used_hw_stream = 1;
                *outl = inl;
                return 1;
            }
            OPENSSL_cleanse(scratch, inl);
            afalg_gcm_reset_hw(ctx);
            if (hw_rc < 0)
                return 0;
        }
    }

    if (!afalg_gcm_update(vctx, out, &upd_outl, outsize, in, inl))
        return 0;

    if (upd_outl > outsize)
        return 0;

    rem_outsize = outsize - upd_outl;
    fin_out = (out != NULL && rem_outsize > 0) ? (out + upd_outl) : NULL;

    if (!afalg_gcm_final(vctx, fin_out, &fin_outl, rem_outsize))
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
    if (p != NULL && !OSSL_PARAM_set_size_t(p, (size_t)ctx->tls_aad_pad))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) {
        if (!ctx->enc || !ctx->tag_set)
            return 0;
        if (p->data_size == 0 || p->data_size > ctx->tag_len)
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
        if (ivlen != ctx->iv_len) {
            ctx->iv_len = ivlen;
            ctx->used_hw_stream = 0;
            ctx->sw_inited = 0;
            afalg_gcm_reset_hw(ctx);
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL) {
        size_t taglen = 0;
        if (!OSSL_PARAM_get_size_t(p, &taglen))
            return 0;
        if (taglen == 0 || taglen > GCM_TAG_SZ)
            return 0;
        if (taglen != ctx->tag_len) {
            ctx->tag_len = taglen;
            ctx->sw_inited = 0;
            afalg_gcm_reset_hw(ctx);
        }
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
        if (tag_len != ctx->tag_len) {
            ctx->tag_len = tag_len;
            afalg_gcm_reset_hw(ctx);
        }
        if (!ctx->enc && tag_ptr != NULL) {
            memcpy(ctx->tag, tag_ptr, tag_len);
            ctx->tag_set = 1;
        }
        if (ctx->sw_ctx != NULL && ctx->sw_inited && !ctx->enc && tag_ptr != NULL) {
            if (!EVP_CIPHER_CTX_ctrl(ctx->sw_ctx, EVP_CTRL_AEAD_SET_TAG,
                                     (int)tag_len, (void *)tag_ptr))
                return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) {
        const void *aad_ptr = NULL;
        size_t aad_len = 0;
        int pad;
        if (!OSSL_PARAM_get_octet_string_ptr(p, &aad_ptr, &aad_len))
            return 0;
        if (aad_len > (size_t)INT_MAX)
            return 0;
        ctx->tls_aad_len = aad_len;
        ctx->force_sw = 1;
        if (!afalg_gcm_ensure_sw(ctx))
            return 0;
        pad = EVP_CIPHER_CTX_ctrl(ctx->sw_ctx, EVP_CTRL_AEAD_TLS1_AAD,
                                  (int)aad_len, (void *)aad_ptr);
        if (pad <= 0)
            return 0;
        ctx->tls_aad_pad = pad;
    }

    return 1;
}

static const OSSL_PARAM afalg_gcm_known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
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
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL 3.5 AF_ALG CTR+GCM (SPACC DMA, no MSG_MORE)"))
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
    afalg_detect_kernel_limits(&pctx->ctr_send_chunk,
                               &pctx->gcm_max_hw_payload,
                               &pctx->sock_buf_req);

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