# afalgprov — OpenSSL 3.5 AF_ALG Provider for NXP LS1024A

Hardware-accelerated **OpenSSL 3.5+** provider built on the Linux `AF_ALG` socket interface for **NXP QorIQ LS1024A (Comcerto 2000, Dual ARMv7 Cortex-A9)**. It offloads symmetric and authenticated encryption to the **Elliptic SPACC** DMA crypto engine and **ARMv7 NEON `ghash-ce`** accelerator for both privileged and unprivileged users (`nobody`, `www-data`, `nginx`) without requiring kernel `sysctl` tuning.

## Supported Algorithms

* **AES-128-CTR / AES-192-CTR / AES-256-CTR** (`skcipher` -> `ctr-aes-ls1024a-spacc`, SPACC DMA)
* **AES-128-GCM / AES-192-GCM / AES-256-GCM** (`aead` -> `gcm(aes)`, SPACC CTR DMA + ARMv7 NEON `ghash-ce`)

## Build and Installation

### Prerequisites

* Linux kernel with `CONFIG_CRYPTO_USER_API_SKCIPHER`, `CONFIG_CRYPTO_USER_API_AEAD`, and the `elp_spacc` driver (`ctr-aes-ls1024a-spacc`, `ghash-ce`) enabled.
* `gcc` and OpenSSL 3.x development headers (`libssl-dev`).

### Compile and Install

~~~bash
gcc -O2 -Wall -Wextra -fPIC -shared afalgprov.c -o afalgprov.so -lcrypto
install -m 0755 afalgprov.so "$(openssl version -m | awk -F'"' '{print $2}')/"
~~~

### Enable in `/etc/ssl/openssl.cnf`

Add `afalgprov` to `[provider_sect]`. Ensure `/etc/ssl/openssl.cnf` has `0644` permissions so unprivileged users can load the configuration:

~~~ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
afalgprov = afalgprov_sect
default = default_sect

[afalgprov_sect]
activate = 1
# Optional: minimum payload size in bytes for CTR hardware offload (default: 8192)
# hw-threshold = 8192

[default_sect]
activate = 1
~~~

### Verify Provider Loading

~~~bash
su -s /bin/sh nobody -c "openssl list -providers"
~~~

Expected output:

~~~text
Providers:
  afalgprov
    name: NXP LS1024A SPACC AF_ALG Provider
    version: 3.5
    status: active
  default
    name: OpenSSL Default Provider
    version: 3.5.9
    status: active
~~~

## Benchmarks

Measured on **NXP LS1024A (Dual ARMv7 Cortex-A9 @ 1.2 GHz)** as unprivileged user `nobody` under default kernel buffer limits (`net.core.wmem_max = 212992`, `net.core.rmem_max = 212992`) with **128 KiB (`131072` bytes)** blocks:

| Algorithm & Mode | Threads | Provider | Throughput | `user` + `sys` (3.07s) | Total CPU Load (2 Cores) |
| :--- | :---: | :--- | :---: | :---: | :---: |
| **AES-256-GCM Encrypt** | 1T | `afalgprov` | **30.47 MB/s** (`30466.57k`) | `0.07s + 0.36s` | **7.0%** (0.14 core) |
| **AES-256-GCM Encrypt** | 4T | `afalgprov` | **32.66 MB/s** (`32664.11k`) | `0.11s + 0.63s` | **11.9%** (0.24 core) |
| **AES-256-GCM Decrypt** | 1T | `afalgprov` | **29.63 MB/s** (`29633.67k`) | `0.11s + 1.91s` | **32.9%** (0.66 core) |
| **AES-256-GCM Decrypt** | 4T | `afalgprov` | **49.28 MB/s** (`49275.02k`) | `0.20s + 3.85s` | **64.9%** (1.30 cores) |
| **AES-256-CTR Encrypt** | 1T | `afalgprov` | **44.52 MB/s** (`44520.79k`) | `0.06s + 0.79s` | **13.8%** (0.28 core) |
| **AES-256-GCM Encrypt** | 1T | `default` (SW baseline) | **11.02 MB/s** (`11017.02k`) | `3.04s + 0.02s` | **49.8%** (1.00 core) |

### Summary

* **Single-thread `AES-256-GCM` Encrypt:** **2.77x** higher throughput with **7.1x** lower CPU utilization compared to the software baseline.
* **Multi-thread `AES-256-GCM` Decrypt (4T):** Reaches **49.28 MB/s** running unprivileged under stock kernel limits.
