# afalgprov v3.4 — OpenSSL 3.x AF_ALG Provider for NXP LS1024A

High-throughput OpenSSL 3.5+ `EVP_CIPHER` provider for the **NXP LS1024A** (Dual-core ARM Cortex-A9) hardware SPACC DMA engine (`ctr-aes-ls1024a-spacc`).

## Key Architecture Highlights
* **Hardware Offload:** `AES-128-CTR` and `AES-256-CTR` via Linux `AF_ALG` (`ctr-aes-ls1024a-spacc`).
* **Direct `sendmsg()` I/O:** Uses scatter-gather `msg_iov` chunks up to **56 KiB** (`57344` bytes), eliminating `pipe`/`vmsplice` syscalls and extra page copies.
* **TLS 1.3 Pairing:** Designed to run alongside OpenSSL's `default` provider (`ChaCha20-Poly1305` via ARMv7 NEON) and Linux `kTLS` (`AES-GCM` CTR offload).

---

## Core Benchmarks (NXP LS1024A, Linux 6.18, OpenSSL 3.5)

| Cipher / Mode | Block | Threads | Throughput | Dual-Core CPU | Role |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **`AES-128/256-CTR`** *(Pure CPU)* | `64 KiB` | 1 | `29.40 MB/s` | `50.0%` | Baseline software AES. |
| **`AES-128/256-CTR`** *(`afalgprov` v3.4)* | `64 KiB` | 1 | **`42.20 MB/s`** | **`14.7%`** | **-71% CPU** vs software AES. |
| **`AES-128/256-CTR`** *(`afalgprov` v3.4)* | `64 KiB` | 2 (`-multi 2`) | **`57.65 MB/s`** | **`27.1%`** | Multi-stream SSH/SFTP/bulk transfer. |
| **`AES-128/256-CTR`** *(`afalgprov` v3.4)* | `64 KiB` | 4 (`-multi 4`) | **`64.30 MB/s`** | **`37.4%`** | Peak hardware SPACC throughput. |
| **`ChaCha20-Poly1305`** *(NEON `default`)* | `16 KiB` | 2 (`-multi 2`) | **`141.36 MB/s`** | `98.7%` | Optimal TLS 1.3 / HTTPS AEAD cipher. |
| **`AES-128-GCM`** *(Unidirectional `kTLS TX`)* | `16 KiB` | 1 | **`11.90 MB/s`** | **`19.2%`** | `CTR` offloaded to SPACC; `GHASH` on CPU. |

---

## Build & Install

```bash
gcc -O3 -march=armv7-a -mfpu=neon -mfloat-abi=hard -fPIC -shared \
    afalgprov.c -o afalgprov.so -lcrypto

MODULES_DIR=$(openssl version -m | awk -F'"' '{print $2}')
install -m 0755 afalgprov.so "$MODULES_DIR/afalgprov.so"

modprobe tls
echo "tls" > /etc/modules-load.d/tls.conf
```

---

## Configuration (`/etc/ssl/openssl.cnf`)

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect

[provider_sect]
afalgprov = afalgprov_sect
default = default_sect

[afalgprov_sect]
activate = 1

[default_sect]
activate = 1

[ssl_sect]
system_default = ssl_default_sect

[ssl_default_sect]
Options = KTLS
Ciphersuites = TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
```

---

## 5. Verification

```bash
# 1. Confirm afalgprov and default are both active
openssl list -providers

# 2. Verify AES-128-CTR hardware offload and IRQ 45 (crypto) increments
grep crypto /proc/interrupts && \
/usr/bin/time -p openssl speed -elapsed -provider afalgprov -provider default -evp aes-128-ctr -bytes 65536 && \
grep crypto /proc/interrupts

# 3. Verify multi-core throughput (-multi 4)
/usr/bin/time -p openssl speed -elapsed -multi 4 -provider afalgprov -provider default -evp aes-128-ctr -bytes 65536
```
