/*
 * afalgprov.c - OpenSSL 3.5 AF_ALG Zero-Copy Provider for NXP LS1024A (SPACC DMA)
 *
 * Offloads aligned streaming AES-128/192/256 (CTR and CBC) buffers >= 16384 bytes
 * to the Linux kernel AF_ALG interface via a zero-copy vmsplice + splice pipeline
 * (65536-byte page-aligned chunks), with transparent fallback to OpenSSL's
 * default provider for small buffers, unaligned tails, and padded CBC decryption.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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

/* Tuned for NXP LS1024A SPACC (9b000000.crypto) + Linux ALG_MAX_PAGES (16 * 4096) */
#define SPACC_HW_THRESHOLD  16384U
#define AFALG_SPLICE_CHUNK  65536U
#define AFALG_PIPE_SZ       (4U * AFALG_SPLICE_CHUNK)

#define AES_BLOCK_SZ        16U
#define AES_IV_SZ           16U
#define AES_MAX_KEY_SZ      32U

#define AFALG_PROV_PARAM_HW_THRESHOLD "hw-threshold"

typedef struct {
    const char *evp_name;
    const char *alg_name;
    size_t key_len;
    size_t iv_len;
    size_t block_size; /* 1 for CTR (stream cipher in OpenSSL), 16 for CBC */
    int is_ctr;
} AFALG_CIPHER_INFO;

typedef struct {
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *default_prov;
    size_t hw_threshold;
} AFALG_PROV_CTX;

typedef struct {
    const AFALG_CIPHER_INFO *info;
    OSSL_LIB_CTX *libctx;
    size_t hw_threshold;

    /* Kernel AF_ALG & pipe descriptors (lazily initialized) */
    int tfmfd;
    int opfd;
    int pipe_fds[2];

    /* Pre-allocated CMSG control buffer (heap-free hot path) */
    uint8_t *cbuf;
    size_t cbuf_len;

    /* Software fallback context ("default" provider) */
    EVP_CIPHER *sw_cipher;
    EVP_CIPHER_CTX *sw_ctx;

    /* Cipher state */
    int enc;
    int padding;
    int key_set;
    int iv_set;
    int iv_dirty;           /* 1 if ctx->iv is ahead of sw_ctx and needs resync before SW fallback */
    int sw_unaligned;
    unsigned int num;

    uint8_t key[AES_MAX_KEY_SZ];
    uint8_t iv[EVP_MAX_IV_LENGTH];
    uint8_t orig_iv[EVP_MAX_IV_LENGTH];
} AFALG_CTX;

static const AFALG_CIPHER_INFO cipher_table[] = {
    { "AES-128-CTR", "ctr-aes-ls1024a-spacc", 16, AES_IV_SZ, 1,            1 },
    { "AES-192-CTR", "ctr-aes-ls1024a-spacc", 24, AES_IV_SZ, 1,            1 },
    { "AES-256-CTR", "ctr-aes-ls1024a-spacc", 32, AES_IV_SZ, 1,            1 },
    { "AES-128-CBC", "cbc-aes-ls1024a-spacc", 16, AES_IV_SZ, AES_BLOCK_SZ, 0 },
    { "AES-192-CBC", "cbc-aes-ls1024a-spacc", 24, AES_IV_SZ, AES_BLOCK_SZ, 0 },
    { "AES-256-CBC", "cbc-aes-ls1024a-spacc", 32, AES_IV_SZ, AES_BLOCK_SZ, 0 },
};

/* -------------------------------------------------------------------------
 * Helpers: IV bookkeeping & descriptor management
 * ------------------------------------------------------------------------- */

static void afalg_ctr128_inc(uint8_t iv[AES_IV_SZ], uint64_t blocks)
{
    uint64_t carry = blocks;
    for (int i = AES_IV_SZ - 1; i >= 0 && carry > 0; i--) {
        carry += iv[i];
        iv[i] = (uint8_t)(carry & 0xffU);
        carry >>= 8;
    }
}

/*
 * Advances ctx->iv after `bytes` (a non-zero multiple of AES_BLOCK_SZ) have
 * been completely processed in hardware:
 *   - CTR: increments the 128-bit big-endian counter by (bytes / AES_BLOCK_SZ).
 *   - CBC: copies the last ciphertext block of the stream (`last_ct`) into ctx->iv.
 *
 * Called at the end of every completed DMA chunk so that if a subsequent chunk
 * fails and falls back to software, ctx->iv matches `*done` (`hw_done`).
 */
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
    if (ctx->pipe_fds[0] >= 0) {
        close(ctx->pipe_fds[0]);
        ctx->pipe_fds[0] = -1;
    }
    if (ctx->pipe_fds[1] >= 0) {
        close(ctx->pipe_fds[1]);
        ctx->pipe_fds[1] = -1;
    }
}

static int afalg_ensure_hw(AFALG_CTX *ctx)
{
    struct sockaddr_alg sa;
    int sockbuf = (int)AFALG_PIPE_SZ;

    if (!ctx->key_set)
        return 0;

    if (ctx->opfd >= 0 && ctx->pipe_fds[0] >= 0 && ctx->pipe_fds[1] >= 0)
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

    if (pipe2(ctx->pipe_fds, O_CLOEXEC) < 0)
        goto err;

    /* Optional buffer sizing hints; kernel falls back to defaults if denied */
    (void)fcntl(ctx->pipe_fds[1], F_SETPIPE_SZ, (int)AFALG_PIPE_SZ);
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

/* -------------------------------------------------------------------------
 * Zero-copy vmsplice + splice pipeline
 * ------------------------------------------------------------------------- */

/*
 * Processes `len` bytes (guaranteed to be a multiple of AES_BLOCK_SZ) through
 * AF_ALG using vmsplice -> splice -> read.
 *
 * Contract:
 *   - `*done` always receives the exact number of bytes for which output has
 *     been completely written AND `ctx->iv` has been updated.
 *   - `*inplace_corrupted` is set to 1 if a partial read() overwrote `out`
 *     when `in == out` before an error occurred, indicating that SW fallback
 *     must not re-process the overwritten buffer.
 */
static int afalg_hw_zero_copy(AFALG_CTX *ctx,
                              unsigned char *out,
                              const unsigned char *in,
                              size_t len,
                              size_t *done,
                              int *inplace_corrupted)
{
    struct msghdr msg;
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
    memcpy(alg_iv->iv, ctx->iv, iv_len);

    /* Send operation & IV control header for this hardware request */

    for (;;) {
        ssize_t ret = sendmsg(ctx->opfd, &msg, MSG_MORE);
        if (ret >= 0)
            break;
        if (errno == EINTR)
            continue;
        return 0;
    }
    ctx->iv_dirty = 0;

    while (processed < len) {
        size_t chunk = len - processed;
        int is_last_chunk;
        uint8_t saved_last_in[AES_BLOCK_SZ];
        const uint8_t *last_ct = NULL;
        size_t fed = 0;
        size_t got = 0;

        if (chunk > AFALG_SPLICE_CHUNK)
            chunk = AFALG_SPLICE_CHUNK;
        is_last_chunk = (processed + chunk == len);

        /* For in-place CBC decryption, preserve last ciphertext block before overwrite */
        if (!ctx->info->is_ctr && !ctx->enc) {
            memcpy(saved_last_in, in + processed + chunk - AES_BLOCK_SZ, AES_BLOCK_SZ);
            last_ct = saved_last_in;
        }

        while (fed < chunk) {
            struct iovec iov = {
                .iov_base = (void *)(in + processed + fed),
                .iov_len = chunk - fed
            };
            ssize_t v = vmsplice(ctx->pipe_fds[1], &iov, 1, 0);
            size_t to_splice;
            size_t spliced = 0;

            if (v < 0) {
                if (errno == EINTR)
                    continue;
                goto err;
            }
            if (v == 0)
                goto err;

            to_splice = (size_t)v;
            while (spliced < to_splice) {
                size_t rem_in_vec = to_splice - spliced;
                unsigned int sflags = (!is_last_chunk || (fed + spliced + rem_in_vec < chunk))
                                      ? SPLICE_F_MORE : 0;
                ssize_t s = splice(ctx->pipe_fds[0], NULL, ctx->opfd, NULL,
                                   rem_in_vec, sflags);
                if (s < 0) {
                    if (errno == EINTR)
                        continue;
                    goto err;
                }
                if (s == 0)
                    goto err;
                spliced += (size_t)s;
            }
            fed += to_splice;
        }

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

/* -------------------------------------------------------------------------
 * Context lifecycle
 * ------------------------------------------------------------------------- */

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
    ctx->pipe_fds[0] = -1;
    ctx->pipe_fds[1] = -1;
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
    dst->pipe_fds[0] = -1;
    dst->pipe_fds[1] = -1;
    dst->cbuf_len = src->cbuf_len;

    dst->enc = src->enc;
    dst->padding = src->padding;
    dst->key_set = src->key_set;
    dst->iv_set = src->iv_set;
    dst->iv_dirty = src->iv_dirty;
    dst->sw_unaligned = src->sw_unaligned;
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

/* -------------------------------------------------------------------------
 * Init, Update (SW / HW / Mixed), Final, Cipher
 * ------------------------------------------------------------------------- */

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

    if (iv != NULL) {
        if (ivlen != ctx->info->iv_len) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        memcpy(ctx->iv, iv, ivlen);
        memcpy(ctx->orig_iv, iv, ivlen);
        ctx->iv_set = 1;
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

        if (step > (size_t)INT_MAX)
            step = (size_t)INT_MAX;

        if (!EVP_CipherUpdate(ctx->sw_ctx, out + total_out, &step_outl,
                              in + offset, (int)step))
            return 0;

        if (step_outl < 0 || total_out + (size_t)step_outl > outsize)
            return 0;

        total_out += (size_t)step_outl;
        offset += step;
    }

    if (ctx->info->is_ctr && (inl % AES_BLOCK_SZ != 0)) {
        ctx->sw_unaligned = 1;
    } else if (!ctx->sw_unaligned) {
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

    if (afalg_hw_zero_copy(ctx, out, in, len, &hw_done, &inplace_corrupted)) {
        *outl = hw_done;
        return 1;
    }

    /* Hardware error: tear down stale descriptors */
    afalg_reset_hw_descriptors(ctx);

    /* Abort if in-place buffer was partially overwritten before error */
    if (inplace_corrupted)
        return 0;

    /* Seamless fallback for remaining unprocessed bytes using updated ctx->iv */
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

    /*
     * Route to software provider when:
     *   1. CTR stream already entered unaligned sub-block state in sw_ctx.
     *   2. Padded CBC decryption (OpenSSL buffers final block until Final).
     *   3. Buffer is smaller than empirical DMA threshold.
     */
    if (ctx->sw_unaligned ||
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

    /*
     * If sw_ctx was never touched and no PKCS#7 padding block needs to be
     * emitted (CTR mode or no-padding CBC), finalization is a no-op.
     */
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

/* -------------------------------------------------------------------------
 * OSSL_PARAM getters and setters
 * ------------------------------------------------------------------------- */

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

/* -------------------------------------------------------------------------
 * Per-cipher constructors & dispatch tables
 * ------------------------------------------------------------------------- */

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
        OSSL_DISPATCH_END                                                     \
    }

IMPLEMENT_AFALG_CIPHER(afalg_aes_128_ctr, 0);
IMPLEMENT_AFALG_CIPHER(afalg_aes_192_ctr, 1);
IMPLEMENT_AFALG_CIPHER(afalg_aes_256_ctr, 2);
IMPLEMENT_AFALG_CIPHER(afalg_aes_128_cbc, 3);
IMPLEMENT_AFALG_CIPHER(afalg_aes_192_cbc, 4);
IMPLEMENT_AFALG_CIPHER(afalg_aes_256_cbc, 5);

static const OSSL_ALGORITHM afalg_ciphers[] = {
    { "AES-128-CTR:aes-128-ctr", "provider=afalgprov", afalg_aes_128_ctr_functions,
      "NXP LS1024A SPACC AF_ALG AES-128-CTR" },
    { "AES-192-CTR:aes-192-ctr", "provider=afalgprov", afalg_aes_192_ctr_functions,
      "NXP LS1024A SPACC AF_ALG AES-192-CTR" },
    { "AES-256-CTR:aes-256-ctr", "provider=afalgprov", afalg_aes_256_ctr_functions,
      "NXP LS1024A SPACC AF_ALG AES-256-CTR" },
    { "AES-128-CBC:aes-128-cbc:2.16.840.1.101.3.4.1.2", "provider=afalgprov", afalg_aes_128_cbc_functions,
      "NXP LS1024A SPACC AF_ALG AES-128-CBC" },
    { "AES-192-CBC:aes-192-cbc:2.16.840.1.101.3.4.1.22", "provider=afalgprov", afalg_aes_192_cbc_functions,
      "NXP LS1024A SPACC AF_ALG AES-192-CBC" },
    { "AES-256-CBC:aes-256-cbc:2.16.840.1.101.3.4.1.42", "provider=afalgprov", afalg_aes_256_cbc_functions,
      "NXP LS1024A SPACC AF_ALG AES-256-CBC" },
    { NULL, NULL, NULL, NULL }
};

/* -------------------------------------------------------------------------
 * Provider entry points
 * ------------------------------------------------------------------------- */

static const OSSL_PARAM afalg_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_size_t(AFALG_PROV_PARAM_HW_THRESHOLD, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *afalg_gettable_prov_params(void *provctx)
{
    (void)provctx;
    return afalg_param_types;
}

static int afalg_set_prov_str(OSSL_PARAM *p, const char *val)
{
    if (p == NULL)
        return 1;
    if (p->data_type == OSSL_PARAM_UTF8_PTR)
        return OSSL_PARAM_set_utf8_ptr(p, val);
    if (p->data_type == OSSL_PARAM_UTF8_STRING)
        return OSSL_PARAM_set_utf8_string(p, val);
    return 1;
}

static int afalg_get_prov_params(void *provctx, OSSL_PARAM params[])
{
    AFALG_PROV_CTX *pctx = (AFALG_PROV_CTX *)provctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (!afalg_set_prov_str(p, "NXP LS1024A AF_ALG SPACC Provider"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (!afalg_set_prov_str(p, "3.2.1"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (!afalg_set_prov_str(p, "OpenSSL 3.5 AF_ALG Zero-Copy vmsplice/splice"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    p = OSSL_PARAM_locate(params, AFALG_PROV_PARAM_HW_THRESHOLD);
    if (p != NULL && pctx != NULL &&
        !OSSL_PARAM_set_size_t(p, pctx->hw_threshold))
        return 0;

    return 1;
}

static const OSSL_ALGORITHM *afalg_query_operation(void *provctx,
                                                   int operation_id,
                                                   int *no_cache)
{
    (void)provctx;
    *no_cache = 0;

    if (operation_id == OSSL_OP_CIPHER)
        return afalg_ciphers;

    return NULL;
}

static void afalg_teardown(void *provctx)
{
    AFALG_PROV_CTX *pctx = (AFALG_PROV_CTX *)provctx;
    if (pctx == NULL)
        return;

    if (pctx->default_prov != NULL) {
        OSSL_PROVIDER_unload(pctx->default_prov);
        pctx->default_prov = NULL;
    }
    if (pctx->libctx != NULL) {
        OSSL_LIB_CTX_free(pctx->libctx);
        pctx->libctx = NULL;
    }
    OPENSSL_free(pctx);
}

static const OSSL_DISPATCH afalg_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))afalg_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))afalg_gettable_prov_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))afalg_get_prov_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))afalg_query_operation },
    OSSL_DISPATCH_END
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    AFALG_PROV_CTX *pctx = OPENSSL_zalloc(sizeof(*pctx));
    OSSL_FUNC_core_get_params_fn *c_get_params = NULL;
    const OSSL_DISPATCH *iter;
    const char *env_thresh;

    if (pctx == NULL)
        return 0;

    for (iter = in; iter != NULL && iter->function_id != 0; iter++) {
        if (iter->function_id == OSSL_FUNC_CORE_GET_PARAMS) {
            c_get_params = OSSL_FUNC_core_get_params(iter);
            break;
        }
    }

    pctx->libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);
    if (pctx->libctx == NULL) {
        OPENSSL_free(pctx);
        return 0;
    }

    /* Hold an explicit reference to "default" so it cannot be unloaded under us */
    pctx->default_prov = OSSL_PROVIDER_load(pctx->libctx, "default");
    if (pctx->default_prov == NULL) {
        OSSL_LIB_CTX_free(pctx->libctx);
        OPENSSL_free(pctx);
        return 0;
    }

    pctx->hw_threshold = SPACC_HW_THRESHOLD;

    /* Read optional "hw-threshold" from openssl.cnf provider section */
    if (c_get_params != NULL) {
        const char *cfg_thresh = NULL;
        OSSL_PARAM core_params[] = {
            OSSL_PARAM_utf8_ptr(AFALG_PROV_PARAM_HW_THRESHOLD, &cfg_thresh, 0),
            OSSL_PARAM_END
        };
        if (c_get_params(handle, core_params) && cfg_thresh != NULL) {
            char *end = NULL;
            unsigned long val = strtoul(cfg_thresh, &end, 10);
            if (end != cfg_thresh && *end == '\0' && val >= AES_BLOCK_SZ)
                pctx->hw_threshold = (size_t)val;
        }
    }

    env_thresh = getenv("AFALG_HW_THRESHOLD");
    if (env_thresh != NULL && *env_thresh != '\0') {
        char *end = NULL;
        unsigned long val = strtoul(env_thresh, &end, 10);
        if (end != env_thresh && *end == '\0' && val >= AES_BLOCK_SZ)
            pctx->hw_threshold = (size_t)val;
    }
    *provctx = pctx;
    *out = afalg_dispatch_table;
    return 1;
}