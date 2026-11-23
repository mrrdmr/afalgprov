# afalgprov v3.4 — OpenSSL 3.x AF_ALG Provider for NXP LS1024A

High-throughput OpenSSL 3.5+ `EVP_CIPHER` provider for the **NXP LS1024A** (Dual-core ARM Cortex-A9) hardware SPACC DMA engine (`ctr-aes-ls1024a-spacc`).

## Key Architecture Highlights
* **Hardware Offload:** `AES-128-CTR` and `AES-256-CTR` via Linux `AF_ALG` (`ctr-aes-ls1024a-spacc`).
* **Direct `sendmsg()` I/O:** Uses scatter-gather `msg_iov` chunks up to **56 KiB** (`57344` bytes), eliminating `pipe`/`vmsplice` syscalls and extra page copies.
* **TLS 1.3 Pairing:** Designed to run alongside OpenSSL's `default` provider (`ChaCha20-Poly1305` via ARMv7 NEON) and Linux `kTLS` (`AES-GCM` CTR offload).

---

## Core Benchmarks (NXP LS1024A, Linux 6.18, OpenSSL 3.5.9)

*CPU Load is normalized to **1 Cortex-A9 Core (`100%` = 1 full core; `200%` = both cores fully saturated)**.*

| Cipher / Mode | Block | Threads | Throughput | CPU Load (1 Core = 100%) | Role |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **`AES-128/256-CTR`** *(Pure CPU)* | `64 KiB` | 1 | `29.40 MB/s` | `100.0%` | Baseline software AES (saturates 1 core). |
| **`AES-128/256-CTR`** *(`afalgprov` v3.4)* | `64 KiB` | 1 | **`42.20 MB/s`** | **`29.3%`** | **-71% CPU** vs software AES (`+43.5%` speed). |
| **`AES-128/256-CTR`** *(`afalgprov` v3.4)* | `64 KiB` | 2 (`-multi 2`) | **`57.65 MB/s`** | **`54.2%`** | Multi-stream SSH/SFTP/bulk transfer. |
| **`AES-128/256-CTR`** *(`afalgprov` v3.4)* | `64 KiB` | 4 (`-multi 4`) | **`65.82 MB/s`** | **`63.3%`** | Peak hardware SPACC throughput (`>1.36` cores free). |
| **`ChaCha20-Poly1305`** *(NEON `default`)* | `16 KiB` | 2 (`-multi 2`) | **`141.36 MB/s`** | **`197.4%` (both cores)** | Optimal TLS 1.3 / HTTPS AEAD cipher (~98.7% per core across 2 cores). |
| **`AES-128-GCM`** *(Unidirectional `kTLS TX`)* | `16 KiB` | 1 | **`11.90 MB/s`** | **`38.3%`** | `CTR` offloaded to SPACC; `GHASH` on CPU. |

---

## Build & Install

```bash
# 1. Install build dependencies (OpenSSL headers and compiler)
apt-get update && apt-get install -y build-essential libssl-dev

# 2. Build and install afalgprov.so
make
make install

# 3. Enable kernel TLS module
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

## Verification

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
