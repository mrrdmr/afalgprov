# afalgprov v3.5 — OpenSSL 3.x AF_ALG Provider for NXP LS1024A

High-throughput OpenSSL 3.5+ `EVP_CIPHER` provider for the **NXP LS1024A** (Dual-core ARM Cortex-A9) hardware SPACC DMA engine (`ctr-aes-ls1024a-spacc`) and Linux kernel hybrid AEAD pipeline (`gcm_base(ctr-aes-ls1024a-spacc,ghash-ce)`).

## Key Architecture Highlights
* **Hardware Offload (`CTR` & `GCM`):**
  * **`AES-128/192/256-CTR` (`skcipher`):** Direct `sendmsg()` (`msg_iov` + `msg_control`) + `read()` I/O using scatter-gather chunks up to **56 KiB** (`57344` bytes, ≤ 15 SG pages per SPACC DMA descriptor) with transparent software fallback below `8192` bytes.
  * **`AES-128/192/256-GCM` (`aead`):** Zero-copy scatter-gather (`sendmsg` + `readv`) offloading `CTR` encryption to SPACC DMA and `GHASH` authentication to ARMv7 NEON (`ghash-ce`), with `SO_SNDBUFFORCE` / `SO_RCVBUFFORCE` socket buffer scaling and zero performance penalty for 256-bit keys.
* **TLS 1.3 Pairing:** Runs alongside OpenSSL's `default` provider (`ChaCha20-Poly1305` via ARMv7 NEON) and Linux `kTLS` (`AES-GCM` CTR offload).

---

## Core Benchmarks (NXP LS1024A, Linux 6.18, OpenSSL 3.5.9)

*CPU Load is normalized to **1 Cortex-A9 Core (`100%` = 1 full core; `200%` = both cores fully saturated)**.*

| Cipher / Mode | Block | Threads | Throughput | CPU Load (1 Core = 100%) | Role |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **`AES-128-CTR`** *(Pure CPU)* | `64 KiB` | 1 | `29.40 MB/s` | `100.0%` | Baseline software AES (saturates 1 core). |
| **`AES-128-CTR`** *(`afalgprov`)* | `64 KiB` | 1 | **`42.20 MB/s`** | **`29.3%`** | **-71% CPU** vs software AES (`+43.5%` speed). |
| **`AES-128-CTR`** *(`afalgprov`)* | `64 KiB` | 4 (`-multi 4`) | **`65.82 MB/s`** | **`63.3%`** | Multi-stream SSH/SFTP/bulk transfer. |
| **`AES-128-CTR`** *(`afalgprov`)* | `256 KiB` | 1 | **`45.96 MB/s`** | **`24.3%`** | Peak single-stream efficiency (`1.89 MB/s` per 1% core). |
| **`AES-128-CTR`** *(`afalgprov`)* | `256 KiB` | 4 (`-multi 4`) | **`68.89 MB/s`** | **`71.2%`** | Saturates SPACC DMA (`>1.28` cores free). |
| **`AES-256-CTR`** *(`afalgprov`)* | `256 KiB` | 1 | **`45.70 MB/s`** | **`23.7%`** | Zero penalty for 256-bit keys (`1.93 MB/s` per 1% core). |
| **`AES-256-CTR`** *(`afalgprov`)* | `256 KiB` | 4 (`-multi 4`) | **`69.21 MB/s`** | **`72.8%`** | Peak multi-stream `AES-256-CTR` SPACC throughput. |
| **`AES-128-GCM`** *(Pure CPU)* | `256 KiB` | 1 | `12.76 MB/s` | `99.7%` | Baseline software AEAD (saturates 1 core). |
| **`AES-128-GCM` Encrypt** *(`afalgprov`)* | `256 KiB` | 1 / 4 | **`31.53` / `32.54 MB/s`** | **`16.2%` / `33.3%`** | **2.47×** faster, **6.1×** lower CPU load (`SPACC + ghash-ce`). |
| **`AES-128-GCM` Decrypt** *(`afalgprov`)* | `256 KiB` | 4 (`-multi 4`) | **`52.03 MB/s`** | **`127.8%`** | Parallel NEON `GHASH` + SPACC `CTR` overlap (**4.08×** vs SW). |
| **`AES-256-GCM` Encrypt** *(`afalgprov`)* | `256 KiB` | 1 / 4 | **`31.46` / `32.40 MB/s`** | **`15.6%` / `31.6%`** | Zero penalty for 256-bit GCM (`>1.84` cores free on 1T). |
| **`AES-256-GCM` Decrypt** *(`afalgprov`)* | `256 KiB` | 1 / 4 | **`31.02` / `51.59 MB/s`** | **`69.7%` / `127.6%`** | Full hardware 16-byte tag verification via `readv()`. |
| **`ChaCha20-Poly1305`** *(NEON `default`)* | `16 KiB` | 2 (`-multi 2`) | **`141.36 MB/s`** | **`197.4%` (both cores)** | Peak TLS 1.3 record throughput (~98.7% per core). |
| **`ChaCha20-Poly1305`** *(NEON `default`)* | `256 KiB` | 1 / 4 | **`57.83` / `110.19 MB/s`** | **`99.7%` / `196.5%` (both cores)** | Large-block TLS 1.3 / HTTPS AEAD throughput. |
| **`AES-128-GCM`** *(Unidirectional `kTLS TX`)* | `16 KiB` | 1 | **`11.90 MB/s`** | **`38.3%`** | `CTR` offloaded to SPACC; `GHASH` on CPU (`2.6×` less CPU than pure CPU GCM). |

> **Why multi-stream GCM Decrypt (`~52 MB/s`) outpaces Encrypt (`~32.5 MB/s`):** During encryption, `GHASH` depends on the ciphertext output of `CTR` and must wait for the SPACC DMA interrupt (`IRQ 45`) sequentially. During decryption, ciphertext is available upfront, allowing both Cortex-A9 NEON units to compute `GHASH` in parallel while SPACC DMA decrypts `CTR` concurrently.

---

## Build & Install

```bash
# 1. Install build dependencies (OpenSSL headers and compiler)
apt-get update && apt-get install -y build-essential libssl-dev

# 2. Build and install afalgprov.so
make clean && make
make install

# 3. Enable kernel TLS module and raise socket buffer ceiling for unprivileged AEAD services
modprobe tls
echo "tls" > /etc/modules-load.d/tls.conf

cat << 'EOF' > /etc/sysctl.d/99-afalg.conf
net.core.wmem_max = 2097152
net.core.rmem_max = 2097152
EOF
sysctl -p /etc/sysctl.d/99-afalg.conf
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
# Optional: minimum block size in bytes for SPACC CTR offload (default: 8192)
# hw-threshold = 8192

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
# 1. Confirm afalgprov and default are both active and list offloaded ciphers
openssl list -providers
openssl list -cipher-algorithms -provider afalgprov

# 2. Verify AES-256-CTR hardware offload and IRQ 45 (crypto) increments (256 KiB blocks)
grep crypto /proc/interrupts && \
/usr/bin/time -p openssl speed -elapsed -provider afalgprov -provider default -evp aes-256-ctr -bytes 262144 && \
grep crypto /proc/interrupts

# 3. Verify AES-256-GCM AEAD encrypt & decrypt offload (-multi 4, 256 KiB blocks)
/usr/bin/time -p openssl speed -elapsed -multi 4 -provider afalgprov -provider default -evp aes-256-gcm -bytes 262144
/usr/bin/time -p openssl speed -elapsed -multi 4 -provider afalgprov -provider default -evp aes-256-gcm -decrypt -bytes 262144
```
