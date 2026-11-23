#ifndef AFALG_GCM_H
#define AFALG_GCM_H

#include <openssl/core_dispatch.h>

extern const OSSL_DISPATCH afalg_aes128gcm_functions[];
extern const OSSL_DISPATCH afalg_aes192gcm_functions[];
extern const OSSL_DISPATCH afalg_aes256gcm_functions[];

#endif /* AFALG_GCM_H */
