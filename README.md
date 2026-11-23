# afalgprov — High-Performance OpenSSL 3.5 AF_ALG Provider for NXP LS1024A (SPACC DMA)

`afalgprov` is a lightweight, zero-copy-oriented OpenSSL 3.5 provider written in C that offloads symmetric cipher operations (`AES-128-CTR`, `AES-192-CTR`, `AES-256-CTR`) to the Linux kernel `AF_ALG` interface (`skcipher`) backed by the **NXP LS1024A SPACC hardware DMA engine** (`ctr-aes-ls1024a-spacc`).

Version **3.4.1** replaces the legacy `pipe`/`vmsplice`/`splice` pipeline with a direct single-syscall `sendmsg()` (`msg_iov` + control messages) submission architecture, eliminating intermediate page-pipe overhead, halving SPACC DMA interrupt pressure, and reducing total CPU utilization by **60–70%** compared to pure software execution.

---

## Key Architectural Highlights (v3.4.1)

* **Direct `sendmsg()` DMA Submission:** Eliminates `pipe2()`, `vmsplice()`, and `splice()` overhead. Each cipher chunk (up to `57,344` bytes / `56 KiB` aligned to AES block boundaries) is submitted in a single `sendmsg()` call with `ALG_SET_OP` and `ALG_SET_IV` ancillary control messages, followed by a direct `read()` into the destination buffer.
* **Adaptive Hardware Offload Threshold (`hw-threshold`):** Small buffers below the configured threshold (default `8192` bytes, configurable via `openssl.cnf`) are transparently routed to OpenSSL's built-in NEON software implementation (`default` provider) to avoid syscall/DMA setup latency on tiny handshake or control packets.
* **Soft Global Priority (`?provider=afalgprov`):** Integrates cleanly with OpenSSL 3.5 `default_properties` so existing binaries (`openssl`, `ssh`, `sftp`, `scp`) automatically prefer `afalgprov` for `AES-CTR` while falling back seamlessly to `default` for hashes, public-key crypto, and AEAD ciphers.
* **Complementary TLS 1.3 Strategy (`ChaCha20-Poly1305` + `kTLS`):** Combines ARMv7 NEON `ChaCha20-Poly1305` for maximum TLS 1.3 throughput (~141 MB/s across 2 cores) with Linux `kTLS` (`Options = KTLS`) for `AES-GCM` clients requiring hardware `CTR` offload.

---

## Hardware & Software Environment

* **SoC / CPU:** NXP LS1024A (Dual-core ARM Cortex-A9, ARMv7-A with NEON, no ARMv8 Crypto/PMULL extensions)
* **RAM:** 236 MiB DDR3
* **Kernel:** Linux 6.18.x (`CONFIG_CRYPTO_DEV_LS1024A_SPACC`, `CONFIG_TLS=y`, `CONFIG_CRYPTO_USER_API_SKCIPHER=y`)
* **Kernel Crypto Driver:** `ctr-aes-ls1024a-spacc` (IRQ 45)
* **Userspace:** Debian / OpenSSL 3.5.x (`libssl3t64`)

---

## Benchmark Results (NXP LS1024A)

### 1. `AES-128-CTR` & `AES-256-CTR` (`64 KiB` blocks, `openssl speed -elapsed`)

Comparison between Pure CPU (`default` provider), legacy `vmsplice` pipeline (`v3.3`), and direct `sendmsg` (`v3.4.1` via SPACC DMA):

| Cipher | Implementation | Threads | Throughput | CPU Time (`user+sys` / `real`) | CPU Load (2 cores) | SPACC IRQs (`IRQ 45`) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **`AES-128-CTR`** | Pure CPU (`default`) | 1 | `31.85 MB/s` | `3.05s / 3.06s` | `~50%` (1 core 100%) | `0` |
| **`AES-128-CTR`** | `afalgprov` v3.3 (`vmsplice`) | 1 | `30.89 MB/s` | `1.39s / 3.09s` | `~22.5%` | `~4,600` |
| **`AES-128-CTR`** | **`afalgprov` v3.4 (`sendmsg`)** | **1** | **`42.10 MB/s`** | **`0.88s / 3.08s`** | **`~14.3%`** | **`~2,300`** |
| **`AES-128-CTR`** | Pure CPU (`default`) | 2 | `61.42 MB/s` | `6.08s / 3.07s` | `~99.0%` | `0` |
| **`AES-128-CTR`** | **`afalgprov` v3.4 (`sendmsg`)** | **2** | **`57.70 MB/s`** | **`1.68s / 3.09s`** | **`~27.2%`** | **`~3,160`** |
| **`AES-128-CTR`** | **`afalgprov` v3.4 (`sendmsg`)** | **4** | **`64.31 MB/s`** | **`2.32s / 3.10s`** | **`~37.4%`** | **`~3,530`** |
| **`AES-256-CTR`** | Pure CPU (`default`) | 1 | `26.14 MB/s` | `3.05s / 3.06s` | `~50%` (1 core 100%) | `0` |
| **`AES-256-CTR`** | **`afalgprov` v3.4 (`sendmsg`)** | **1** | **`41.85 MB/s`** | **`0.89s / 3.08s`** | **`~14.4%`** | **`~2,290`** |
| **`AES-256-CTR`** | **`afalgprov` v3.4 (`sendmsg`)** | **4** | **`63.64 MB/s`** | **`2.29s / 3.10s`** | **`~36.9%`** | **`~3,490`** |

> **Takeaway:** On single-threaded `AES-256-CTR`, `afalgprov` v3.4 is **+60% faster** than Pure CPU (`41.85` vs `26.14 MB/s`) while cutting CPU usage by **71%** (`14.4%` vs `50%` of total dual-core capacity).

---

### 2. AEAD & TLS 1.3 Profiling (`ChaCha20-Poly1305` vs `AES-GCM` / `kTLS`)

Because the ARM Cortex-A9 lacks ARMv8 `PMULL` instructions and the LS1024A SPACC driver accelerates `ctr(aes)` rather than full `gcm(aes)`, `AES-GCM` relies on software `ghash-generic` in the kernel (`TlsTxSw`). Conversely, OpenSSL's ARMv7 NEON implementation of `ChaCha20-Poly1305` executes entirely in NEON vector registers without DMA interrupt latency:

| Cipher / Mode | Block / Record Size | Threads | Throughput | CPU Time (`user+sys` / `real`) | CPU Load (2 cores) | Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **`ChaCha20-Poly1305`** *(NEON)* | `16 KiB` (TLS record) | 2 | **`141.36 MB/s`** | `6.08s / 3.08s` | `~98.7%` | Optimal L1-cache fit; **~6x faster** than `AES-GCM` |
| **`ChaCha20-Poly1305`** *(NEON)* | `16 KiB` (TLS record) | 4 | **`138.81 MB/s`** | `6.12s / 3.10s` | `~98.7%` | Peak TLS 1.3 AEAD throughput across both cores |
| **`ChaCha20-Poly1305`** *(NEON)* | `64 KiB` | 2 | **`120.53 MB/s`** | `6.08s / 3.08s` | `~98.7%` | Sustained bulk NEON AEAD throughput |
| **`ChaCha20-Poly1305`** *(NEON)* | `64 KiB` | 4 | **`116.49 MB/s`** | `6.12s / 3.10s` | `~98.7%` | Multi-client bulk NEON AEAD throughput |
| **Kernel `AF_ALG gcm(aes)`** | `16 KiB` (`32 MiB`) | 1 | `15.53 MB/s` | `0.62s / 2.06s` | `~15.0%` | `gcm_base(ctr-aes-ls1024a-spacc, ghash-generic)` |
| **`kTLS TX` (`AES-128-GCM`)** | `16 KiB` (`SSL_sendfile`) | 1 | **`11.90 MB/s`** | `8.25s / 21.52s` | `~19.2%` | Unidirectional `256 MiB` TX; `CTR` offloaded to SPACC |
| **`kTLS TX` (`AES-256-GCM`)** | `16 KiB` (`SSL_sendfile`) | 1 | **`11.88 MB/s`** | `8.24s / 21.55s` | `~19.1%` | Key size has zero penalty due to SPACC `CTR` offload |

> **Why `kTLS AES-GCM` caps at ~11.9 MB/s per stream:** TLS 1.3 fragments data into `≤ 16 KiB` records. For each 16 KiB record, the kernel computes `GHASH` on the Cortex-A9 (~0.30 ms) and synchronously waits (`crypto_wait_req`) for SPACC DMA + IRQ 45 completion (~0.71 ms). Enabling `Options = KTLS` is still recommended for `AES-GCM` compatibility because it reduces total dual-core CPU load from ~100% down to **~19%**, leaving >80% of CPU capacity free for application and network tasks.

---

## Build & Installation

### Prerequisites

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev
```

Verify that the kernel SPACC driver is registered:

```bash
grep -A 6 "ctr(aes)" /proc/crypto
```
Expected driver: `ctr-aes-ls1024a-spacc` (priority `300`).

### Compile & Install Provider Module

```bash
gcc -O3 -march=armv7-a -mfpu=neon -mfloat-abi=hard -fPIC -shared \
    afalgprov.c -o afalgprov.so -lcrypto

sudo install -m 0755 afalgprov.so /usr/lib/arm-linux-gnueabihf/ossl-modules/afalgprov.so
```

---

## System-Wide OpenSSL 3.5 Configuration (`/etc/ssl/openssl.cnf`)

Configure `/etc/ssl/openssl.cnf` to:
1. Automatically load `default` and `afalgprov` with a `8192`-byte hardware offload threshold.
2. Prefer `afalgprov` globally via soft `default_properties = ?provider=afalgprov`.
3. Enable `Options = KTLS` and prioritize `TLS_CHACHA20_POLY1305_SHA256` ahead of `AES-GCM` for TLS 1.3 connections.

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
alg_section = evp_properties
ssl_conf = ssl_sect

[provider_sect]
default = default_sect
afalgprov = afalgprov_sect

[default_sect]
activate = 1

[afalgprov_sect]
module = /usr/lib/arm-linux-gnueabihf/ossl-modules/afalgprov.so
activate = 1
hw-threshold = 8192

[evp_properties]
default_properties = ?provider=afalgprov

[ssl_sect]
system_default = ssl_default_sect

[ssl_default_sect]
Options = KTLS
Ciphersuites = TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
```

### Verification

1. **Confirm active providers:**
   ```bash
   openssl list -providers
   ```
   Both `default` and `afalgprov` must appear as `status: active`.

2. **Verify SPACC hardware offload (`AES-256-CTR`):**
   ```bash
   grep crypto /proc/interrupts && \
   openssl speed -elapsed -evp aes-256-ctr -bytes 65536 && \
   grep crypto /proc/interrupts
   ```
   Confirm throughput around `~41.8 MB/s` (1 thread) and an increase in `IRQ 45` (`9b000000.crypto`) interrupts.

3. **Verify OpenSSH integration:**
   ```bash
   ssh -Q cipher | grep ctr
   ```
   `aes128-ctr`, `aes192-ctr`, and `aes256-ctr` automatically inherit `afalgprov` through OpenSSL 3.5 `EVP_CipherInit_ex()`.
