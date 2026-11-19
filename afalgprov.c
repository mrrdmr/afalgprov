/*
 * afalgprov.c - OpenSSL 3.x provider over AF_ALG (vmsplice/splice)
 * with a software fallback through EVP. Tuned for NXP LS1024A SPACC.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <endian.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>

#ifndef SPACC_HW_THRESHOLD
#define SPACC_HW_THRESHOLD 16384
#endif

#define AFALG_SPLICE_CHUNK 65536
#define AFALG_PIPE_SZ (4 * AFALG_SPLICE_CHUNK)
#define AFALG_SOCKBUF (4 * AFALG_SPLICE_CHUNK)
#define MAX_KEY_LEN 64
#define MAX_IV_LEN  16

typedef struct {
    const char *alg_name;   /* Algorithm name in the Linux Crypto API ("ctr(aes)") */
    const char *evp_name;   /* Algorithm name in OpenSSL EVP ("AES-128-CTR") */
    size_t keylen;          /* Fixed key length in bytes */
    size_t ivlen;           /* IV length in bytes */
    size_t blocksize;       /* OpenSSL block size (1 for CTR, 16 for CBC) */
    size_t ctr_step_bytes;  /* CTR counter step in bytes (16 for AES-CTR, 0 for CBC) */
    unsigned int mode;      /* OpenSSL mode (EVP_CIPH_CTR_MODE / EVP_CIPH_CBC_MODE) */
    int is_ctr;             /* CTR mode flag */
} AFALG_CIPHER_INFO;

typedef struct {
    const AFALG_CIPHER_INFO *info;
    OSSL_LIB_CTX *libctx;

    /* Kernel descriptors and reusable control buffer */
    int tfmfd;
    int opfd;
    int pipe_fds[2];        /* Pre-created pipe for vmsplice/splice */
    char *cbuf;             /* Pre-allocated CMSG control buffer for sendmsg() */
    size_t cbuf_len;

    /* Cryptographic state */
    uint8_t key[MAX_KEY_LEN];
    size_t keylen;
    int key_initialized;    /* 1 = key was set by init */
    uint8_t iv[MAX_IV_LEN];
    size_t ivlen;
    int enc;                /* 1 = encrypt, 0 = decrypt */
    int pad;                /* 1 = PKCS#7 padding enabled, 0 = disabled */
    int hw_key_set;
    int iv_dirty;           /* 1 = IV advanced in HW and must be synced to SW */
    int sw_unaligned;       /* 1 = SW handled a non-block-aligned piece (stay in SW) */

    /* Software fallback context */
    EVP_CIPHER *sw_cipher;
    EVP_CIPHER_CTX *sw_ctx;
} AFALG_CTX;

static int afalg_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

/* =========================================================================
 * Crypto helpers and kernel plumbing
 * ========================================================================= */

static int afalg_check_key(const AFALG_CTX *ctx)
{
    return ctx->key_initialized;
}

static void afalg_ctr_add_blocks(uint8_t *iv, uint64_t blocks)
{
    uint64_t high, low, next_low;
    memcpy(&high, iv, sizeof(uint64_t));
    memcpy(&low, iv + sizeof(uint64_t), sizeof(uint64_t));

    high = be64toh(high);
    low  = be64toh(low);

    next_low = low + blocks;
    if (next_low < low) {
        high++;
    }

    high = htobe64(high);
    next_low = htobe64(next_low);

    memcpy(iv, &high, sizeof(uint64_t));
    memcpy(iv + sizeof(uint64_t), &next_low, sizeof(uint64_t));
}

/* Single ctx->iv update for aligned blocks (used by both HW and SW) */
static void afalg_advance_iv(AFALG_CTX *ctx, const uint8_t *in_block,
                             const uint8_t *out_block, size_t len)
{
    if (ctx->info->is_ctr) {
        afalg_ctr_add_blocks(ctx->iv, len / ctx->info->ctr_step_bytes);
    } else {
        size_t blk = ctx->info->blocksize;
        if (ctx->ivlen >= blk && len >= blk) {
            if (ctx->enc) {
                memcpy(ctx->iv, out_block, blk);
            } else {
                memcpy(ctx->iv, in_block, blk);
            }
        }
    }
}

static int afalg_ensure_sw(AFALG_CTX *ctx)
{
    if (ctx->sw_ctx == NULL) {
        ctx->sw_cipher = EVP_CIPHER_fetch(ctx->libctx, ctx->info->evp_name, "provider=default");
        if (ctx->sw_cipher == NULL)
            return 0;

        ctx->sw_ctx = EVP_CIPHER_CTX_new();
        if (ctx->sw_ctx == NULL)
            goto err;

        if (!EVP_CipherInit_ex(ctx->sw_ctx, ctx->sw_cipher, NULL, ctx->key, ctx->iv, ctx->enc))
            goto err;

        EVP_CIPHER_CTX_set_padding(ctx->sw_ctx, ctx->pad);
        ctx->iv_dirty = 0;
    } else if (ctx->iv_dirty) {
        if (!EVP_CipherInit_ex(ctx->sw_ctx, NULL, NULL, NULL, ctx->iv, -1))
            return 0;
        EVP_CIPHER_CTX_set_padding(ctx->sw_ctx, ctx->pad);
        ctx->iv_dirty = 0;
    }
    return 1;

err:
    EVP_CIPHER_CTX_free(ctx->sw_ctx);
    ctx->sw_ctx = NULL;
    EVP_CIPHER_free(ctx->sw_cipher);
    ctx->sw_cipher = NULL;
    return 0;
}

static int afalg_init_hw(AFALG_CTX *ctx)
{
    if (ctx->opfd >= 0 && ctx->hw_key_set)
        return 1;

    if (ctx->pipe_fds[0] < 0) {
        if (pipe2(ctx->pipe_fds, O_CLOEXEC) < 0)
            return 0;
        fcntl(ctx->pipe_fds[1], F_SETPIPE_SZ, AFALG_PIPE_SZ);
    }

    if (ctx->tfmfd < 0) {
        struct sockaddr_alg sa = {
            .salg_family = AF_ALG,
            .salg_type   = "skcipher",
        };
        OPENSSL_strlcpy((char *)sa.salg_name, ctx->info->alg_name, sizeof(sa.salg_name));

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
        ctx->hw_key_set = 1;
    }

    if (ctx->opfd < 0) {
        int sz = AFALG_SOCKBUF;

        ctx->opfd = accept4(ctx->tfmfd, NULL, 0, SOCK_CLOEXEC);
        if (ctx->opfd < 0)
            return 0;
        setsockopt(ctx->opfd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
        setsockopt(ctx->opfd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    }

    return 1;
}

static void afalg_reset_hw_descriptors(AFALG_CTX *ctx)
{
    if (ctx->opfd >= 0) {
        close(ctx->opfd);
        ctx->opfd = -1;
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

/*
 * Transfer through vmsplice(..., 0) + splice(), handling partial operations,
 * EINTR, pre-allocated CMSG buffer, and reporting actually processed bytes (*done).
 */
static int afalg_hw_zero_copy(AFALG_CTX *ctx, const uint8_t *in, uint8_t *out,
                              size_t len, size_t *done)
{
    int ret = 0;
    size_t req_cbuf = 0;
    size_t processed = 0;

    *done = 0;

    if (!afalg_init_hw(ctx))
        return 0;

    req_cbuf = CMSG_SPACE(sizeof(uint32_t));
    if (ctx->ivlen > 0) {
        req_cbuf += CMSG_SPACE(sizeof(struct af_alg_iv) + ctx->ivlen);
    }

    if (ctx->cbuf == NULL || req_cbuf > ctx->cbuf_len)
        return 0;

    memset(ctx->cbuf, 0, req_cbuf);

    struct msghdr msg = {0};
    struct cmsghdr *cmsg;

    msg.msg_control = ctx->cbuf;
    msg.msg_controllen = req_cbuf;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type  = ALG_SET_OP;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(uint32_t));
    *(uint32_t *)CMSG_DATA(cmsg) = ctx->enc ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;

    if (ctx->ivlen > 0) {
        cmsg = CMSG_NXTHDR(&msg, cmsg);
        cmsg->cmsg_level = SOL_ALG;
        cmsg->cmsg_type  = ALG_SET_IV;
        cmsg->cmsg_len   = CMSG_LEN(sizeof(struct af_alg_iv) + ctx->ivlen);

        struct af_alg_iv *alg_iv = (struct af_alg_iv *)CMSG_DATA(cmsg);
        alg_iv->ivlen = ctx->ivlen;
        memcpy(alg_iv->iv, ctx->iv, ctx->ivlen);
    }

    while (processed < len) {
        size_t chunk = len - processed;
        if (chunk > AFALG_SPLICE_CHUNK)
            chunk = AFALG_SPLICE_CHUNK;

        uint8_t saved_last_in[EVP_MAX_BLOCK_LENGTH];
        size_t blk = ctx->info->blocksize;
        if (!ctx->info->is_ctr && !ctx->enc && blk <= sizeof(saved_last_in) && chunk >= blk) {
            memcpy(saved_last_in, in + processed + chunk - blk, blk);
        }

        if (processed == 0) {
            ssize_t sc;
            do {
                sc = sendmsg(ctx->opfd, &msg, MSG_MORE);
            } while (sc < 0 && errno == EINTR);
            if (sc < 0)
                goto cleanup;
        }

        /*
         * Feed and drain in portions: the pipe may accept fewer
         * pages than vmsplice asks for when the buffer is unaligned,
         * and accumulating the whole chunk before draining would block forever.
         */
        size_t submitted = 0;
        while (submitted < chunk) {
            struct iovec iov = {
                .iov_base = (void *)(in + processed + submitted),
                .iov_len  = chunk - submitted
            };
            ssize_t rc = vmsplice(ctx->pipe_fds[1], &iov, 1, 0);
            if (rc < 0) {
                if (errno == EINTR)
                    continue;
                goto cleanup;
            }
            if (rc == 0)
                goto cleanup;

            size_t got = (size_t)rc;
            size_t forwarded = 0;
            while (forwarded < got) {
                int flags = (processed + submitted + got < len) ? SPLICE_F_MORE : 0;
                ssize_t sp = splice(ctx->pipe_fds[0], NULL, ctx->opfd, NULL,
                                    got - forwarded, flags);
                if (sp < 0) {
                    if (errno == EINTR)
                        continue;
                    goto cleanup;
                }
                if (sp == 0)
                    goto cleanup;
                forwarded += (size_t)sp;
            }
            submitted += got;
        }

        /* 3. Read the result from opfd until the chunk is complete */
        size_t read_bytes = 0;
        while (read_bytes < chunk) {
            ssize_t r = read(ctx->opfd, out + processed + read_bytes, chunk - read_bytes);
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                goto cleanup;
            }
            if (r == 0)
                goto cleanup;
            read_bytes += (size_t)r;
        }

        /* Advance the IV only after the chunk is fully processed */
        afalg_advance_iv(ctx, saved_last_in, out + processed + chunk - blk, chunk);
        ctx->iv_dirty = 1;
        processed += chunk;
    }

    ret = 1;

cleanup:
    *done = processed;
    return ret;
}

/* =========================================================================
 * OpenSSL provider context lifecycle
 * ========================================================================= */

static void *afalg_newctx(void *provctx, const AFALG_CIPHER_INFO *info)
{
    AFALG_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->cbuf_len = CMSG_SPACE(sizeof(uint32_t));
    if (info->ivlen > 0) {
        ctx->cbuf_len += CMSG_SPACE(sizeof(struct af_alg_iv) + info->ivlen);
    }

    ctx->cbuf = OPENSSL_zalloc(ctx->cbuf_len);
    if (ctx->cbuf == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }

    ctx->info            = info;
    ctx->libctx          = (OSSL_LIB_CTX *)provctx;
    ctx->tfmfd           = -1;
    ctx->opfd            = -1;
    ctx->pipe_fds[0]     = -1;
    ctx->pipe_fds[1]     = -1;
    ctx->keylen          = info->keylen;
    ctx->key_initialized = 0;
    ctx->ivlen           = info->ivlen;
    ctx->pad             = 1;

    return ctx;
}

static void afalg_freectx(void *vctx)
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    if (ctx == NULL)
        return;

    afalg_reset_hw_descriptors(ctx);
    if (ctx->tfmfd >= 0)
        close(ctx->tfmfd);

    EVP_CIPHER_CTX_free(ctx->sw_ctx);
    EVP_CIPHER_free(ctx->sw_cipher);

    if (ctx->cbuf != NULL) {
        OPENSSL_cleanse(ctx->cbuf, ctx->cbuf_len);
        OPENSSL_free(ctx->cbuf);
    }

    OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
    OPENSSL_cleanse(ctx->iv, sizeof(ctx->iv));
    OPENSSL_free(ctx);
}

static void *afalg_dupctx(void *vctx)
{
    AFALG_CTX *src = (AFALG_CTX *)vctx;
    if (src == NULL)
        return NULL;

    AFALG_CTX *dst = OPENSSL_malloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    memcpy(dst, src, sizeof(*dst));

    dst->tfmfd       = -1;
    dst->opfd        = -1;
    dst->pipe_fds[0] = -1;
    dst->pipe_fds[1] = -1;
    dst->hw_key_set  = 0;
    dst->cbuf        = NULL;
    dst->sw_cipher   = NULL;
    dst->sw_ctx      = NULL;

    if (dst->cbuf_len > 0) {
        dst->cbuf = OPENSSL_zalloc(dst->cbuf_len);
        if (dst->cbuf == NULL) {
            afalg_freectx(dst);
            return NULL;
        }
    }

    if (src->sw_ctx != NULL) {
        dst->sw_ctx = EVP_CIPHER_CTX_dup(src->sw_ctx);
        if (dst->sw_ctx == NULL) {
            afalg_freectx(dst);
            return NULL;
        }
    }
    if (src->sw_cipher != NULL) {
        if (!EVP_CIPHER_up_ref(src->sw_cipher)) {
            afalg_freectx(dst);
            return NULL;
        }
        dst->sw_cipher = src->sw_cipher;
    }

    return dst;
}

/* =========================================================================
 * Cipher operations (Init / Update / Final)
 * ========================================================================= */

static int afalg_init_common(void *vctx, const unsigned char *key, size_t keylen,
                             const unsigned char *iv, size_t ivlen,
                             const OSSL_PARAM params[], int enc)
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    ctx->enc = enc;

    if (key != NULL) {
        if (keylen != ctx->info->keylen || keylen > sizeof(ctx->key))
            return 0;

        OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
        memcpy(ctx->key, key, keylen);
        ctx->keylen = keylen;
        ctx->key_initialized = 1;
        ctx->hw_key_set = 0;

        if (ctx->opfd >= 0) {
            close(ctx->opfd);
            ctx->opfd = -1;
        }
    }

    if (iv != NULL) {
        if (ivlen != ctx->info->ivlen || ivlen > sizeof(ctx->iv))
            return 0;
        memcpy(ctx->iv, iv, ivlen);
        ctx->ivlen = ivlen;
    }

    if (ctx->sw_ctx != NULL) {
        if (!EVP_CipherInit_ex(ctx->sw_ctx, ctx->sw_cipher, NULL,
                               key ? ctx->key : NULL, iv ? ctx->iv : NULL, enc))
            return 0;
    }
    ctx->iv_dirty = 0;
    ctx->sw_unaligned = 0;

    return afalg_set_ctx_params(ctx, params);
}

static int afalg_einit(void *vctx, const unsigned char *key, size_t keylen,
                       const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
    return afalg_init_common(vctx, key, keylen, iv, ivlen, params, 1);
}

static int afalg_dinit(void *vctx, const unsigned char *key, size_t keylen,
                       const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
    return afalg_init_common(vctx, key, keylen, iv, ivlen, params, 0);
}

static int afalg_sw_only_update(AFALG_CTX *ctx, unsigned char *out, size_t *outl,
                                size_t outsize, const unsigned char *in, size_t inl)
{
    size_t required = inl + (ctx->info->blocksize > 1 ? ctx->info->blocksize : 0);
    if (outsize < required)
        return 0;

    if (!afalg_ensure_sw(ctx))
        return 0;

    int sw_outl = 0;
    if (!EVP_CipherUpdate(ctx->sw_ctx, out, &sw_outl, in, (int)inl))
        return 0;

    *outl = (size_t)sw_outl;
    return 1;
}

static int afalg_update(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                        const unsigned char *in, size_t inl)
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    *outl = 0;

    if (!afalg_check_key(ctx))
        return 0;

    if (inl == 0)
        return 1;

    /*
     * 1. A stream that already went to SW on an unaligned piece stays in SW.
     * 2. CBC DECRYPT with padding runs entirely in SW: EVP buffers the
     *    last block internally, which is incompatible with HW zero-copy.
     * 3. CBC ENCRYPT with padding uses HW safely for full blocks.
     */
    if (ctx->sw_unaligned || (!ctx->info->is_ctr && ctx->pad && !ctx->enc)) {
        return afalg_sw_only_update(ctx, out, outl, outsize, in, inl);
    }

    size_t hw_align = ctx->info->is_ctr ? ctx->info->ctr_step_bytes : ctx->info->blocksize;
    size_t hw_len = 0;

    if (inl >= SPACC_HW_THRESHOLD) {
        hw_len = inl & ~(hw_align - 1);
    }

    size_t hw_written = 0;
    if (hw_len > 0) {
        if (outsize < hw_len)
            return 0;

        if (!afalg_hw_zero_copy(ctx, in, out, hw_len, &hw_written)) {
            afalg_reset_hw_descriptors(ctx);
            if (hw_written > 0) {
                if (!afalg_ensure_sw(ctx))
                    return 0;
                if (!EVP_CipherInit_ex(ctx->sw_ctx, NULL, NULL, NULL, ctx->iv, -1))
                    return 0;
                ctx->iv_dirty = 0;
            }
        }
    }

    size_t rem_len = inl - hw_written;
    if (rem_len > 0) {
        size_t required = hw_written + rem_len + (ctx->info->blocksize > 1 ? ctx->info->blocksize : 0);
        if (outsize < required)
            return 0;

        uint8_t saved_last_in[EVP_MAX_BLOCK_LENGTH];
        size_t blk = ctx->info->blocksize;
        if (!ctx->info->is_ctr && !ctx->enc && blk <= sizeof(saved_last_in) && rem_len >= blk) {
            memcpy(saved_last_in, in + hw_written + rem_len - blk, blk);
        }

        if (!afalg_ensure_sw(ctx))
            return 0;

        int sw_outl = 0;
        if (!EVP_CipherUpdate(ctx->sw_ctx, out + hw_written, &sw_outl, in + hw_written, (int)rem_len))
            return 0;

        if ((rem_len & (hw_align - 1)) == 0) {
            afalg_advance_iv(ctx, saved_last_in, out + hw_written + rem_len - blk, rem_len);
        } else {
            ctx->sw_unaligned = 1;
        }
        *outl = hw_written + (size_t)sw_outl;
    } else {
        *outl = hw_written;
    }

    return 1;
}

static int afalg_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    *outl = 0;

    if (!afalg_check_key(ctx))
        return 0;

    if (ctx->sw_ctx == NULL && (ctx->info->is_ctr || !ctx->pad))
        return 1;

    size_t blk = ctx->info->blocksize;
    if (ctx->enc && ctx->pad && blk > 1 && outsize < blk)
        return 0;

    if (!afalg_ensure_sw(ctx))
        return 0;

    int sw_outl = 0;
    if (!EVP_CipherFinal_ex(ctx->sw_ctx, out, &sw_outl))
        return 0;

    *outl = (size_t)sw_outl;
    return 1;
}

/* =========================================================================
 * Algorithm and context parameters (OSSL_PARAM)
 * ========================================================================= */

static int afalg_get_params(OSSL_PARAM params[], const AFALG_CIPHER_INFO *info)
{
    OSSL_PARAM *p;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE)) != NULL &&
        !OSSL_PARAM_set_size_t(p, info->blocksize))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, info->keylen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, info->ivlen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE)) != NULL &&
        !OSSL_PARAM_set_uint(p, info->mode))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV)) != NULL &&
        !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static int afalg_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ctx->keylen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL &&
        !OSSL_PARAM_set_size_t(p, ctx->ivlen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING)) != NULL &&
        !OSSL_PARAM_set_uint(p, ctx->pad))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV)) != NULL &&
        !OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen))
        return 0;
    return 1;
}

static int afalg_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    AFALG_CTX *ctx = (AFALG_CTX *)vctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING)) != NULL) {
        unsigned int pad = 0;
        if (!OSSL_PARAM_get_uint(p, &pad))
            return 0;
        ctx->pad = pad ? 1 : 0;
        if (ctx->sw_ctx != NULL)
            EVP_CIPHER_CTX_set_padding(ctx->sw_ctx, ctx->pad);
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL) {
        size_t req_keylen = 0;
        if (!OSSL_PARAM_get_size_t(p, &req_keylen) || req_keylen != ctx->info->keylen)
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *afalg_gettable_params(void *provctx)
{
    (void)provctx;
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
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
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
        OSSL_PARAM_END
    };
    return table;
}

static const OSSL_PARAM *afalg_settable_ctx_params(void *cctx, void *provctx)
{
    (void)cctx;
    (void)provctx;
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_END
    };
    return table;
}

/* =========================================================================
 * Cipher dispatch tables and provider metadata
 * ========================================================================= */

#define IMPLEMENT_CIPHER(name, alg, evp, klen, ivl, blk, ctr_step, cmode, ctr) \
    static const AFALG_CIPHER_INFO info_##name = { alg, evp, klen, ivl, blk, ctr_step, cmode, ctr }; \
    static void *newctx_##name(void *provctx) { return afalg_newctx(provctx, &info_##name); } \
    static int get_params_##name(OSSL_PARAM params[]) { return afalg_get_params(params, &info_##name); } \
    static const OSSL_DISPATCH dispatch_##name[] = { \
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))newctx_##name }, \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))afalg_freectx }, \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))afalg_dupctx }, \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))afalg_einit }, \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))afalg_dinit }, \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))afalg_update }, \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))afalg_final }, \
        { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))get_params_##name }, \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))afalg_get_ctx_params }, \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))afalg_set_ctx_params }, \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))afalg_gettable_params }, \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))afalg_gettable_ctx_params }, \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))afalg_settable_ctx_params }, \
        { 0, NULL } \
    };

IMPLEMENT_CIPHER(aes128ctr, "ctr(aes)", "AES-128-CTR", 16, 16, 1,  16, EVP_CIPH_CTR_MODE, 1)
IMPLEMENT_CIPHER(aes192ctr, "ctr(aes)", "AES-192-CTR", 24, 16, 1,  16, EVP_CIPH_CTR_MODE, 1)
IMPLEMENT_CIPHER(aes256ctr, "ctr(aes)", "AES-256-CTR", 32, 16, 1,  16, EVP_CIPH_CTR_MODE, 1)
IMPLEMENT_CIPHER(aes128cbc, "cbc(aes)", "AES-128-CBC", 16, 16, 16, 0,  EVP_CIPH_CBC_MODE, 0)
IMPLEMENT_CIPHER(aes192cbc, "cbc(aes)", "AES-192-CBC", 24, 16, 16, 0,  EVP_CIPH_CBC_MODE, 0)
IMPLEMENT_CIPHER(aes256cbc, "cbc(aes)", "AES-256-CBC", 32, 16, 16, 0,  EVP_CIPH_CBC_MODE, 0)

static const OSSL_ALGORITHM afalg_ciphers[] = {
    { "AES-128-CTR:id-aes128-CTR", "provider=afalgprov", dispatch_aes128ctr, "AF_ALG AES-128-CTR" },
    { "AES-192-CTR:id-aes192-CTR", "provider=afalgprov", dispatch_aes192ctr, "AF_ALG AES-192-CTR" },
    { "AES-256-CTR:id-aes256-CTR", "provider=afalgprov", dispatch_aes256ctr, "AF_ALG AES-256-CTR" },
    { "AES-128-CBC:AES128",        "provider=afalgprov", dispatch_aes128cbc, "AF_ALG AES-128-CBC" },
    { "AES-192-CBC:AES192",        "provider=afalgprov", dispatch_aes192cbc, "AF_ALG AES-192-CBC" },
    { "AES-256-CBC:AES256",        "provider=afalgprov", dispatch_aes256cbc, "AF_ALG AES-256-CBC" },
    { NULL, NULL, NULL, NULL }
};

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

static int afalg_set_str(OSSL_PARAM *p, const char *val)
{
    if (p->data_type == OSSL_PARAM_UTF8_PTR)
        return OSSL_PARAM_set_utf8_ptr(p, val);
    return OSSL_PARAM_set_utf8_string(p, val);
}

static int afalg_prov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    (void)provctx;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !afalg_set_str(p, "AF_ALG SPACC Provider"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !afalg_set_str(p, "3.0"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

static const OSSL_ALGORITHM *afalg_query(void *provctx, int operation_id, int *no_cache)
{
    (void)provctx;
    *no_cache = 0;
    if (operation_id == OSSL_OP_CIPHER)
        return afalg_ciphers;
    return NULL;
}

static OSSL_PROVIDER *afalg_default_prov;

static void afalg_teardown(void *provctx)
{
    if (afalg_default_prov != NULL) {
        OSSL_PROVIDER_unload(afalg_default_prov);
        afalg_default_prov = NULL;
    }
    OSSL_LIB_CTX_free((OSSL_LIB_CTX *)provctx);
}

static const OSSL_DISPATCH afalg_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))afalg_prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))afalg_prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))afalg_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))afalg_teardown },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx)
{
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);
    if (libctx == NULL)
        return 0;

    /* default is needed by the SW fallback; keep the ref until teardown */
    afalg_default_prov = OSSL_PROVIDER_load(libctx, "default");
    if (afalg_default_prov == NULL) {
        OSSL_LIB_CTX_free(libctx);
        return 0;
    }

    *provctx = libctx;
    *out = afalg_dispatch_table;
    return 1;
}
