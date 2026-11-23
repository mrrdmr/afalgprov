# afalgprov v3.4 — High-Throughput OpenSSL 3.x AF_ALG Provider for NXP LS1024A

`afalgprov` is a zero-copy-inspired, low-overhead OpenSSL 3.5+ `EVP_CIPHER` provider engineered specifically for the **NXP LS1024A** (Dual-core ARM Cortex-A9) hardware cryptographic accelerator (`ctr-aes-ls1024a-spacc` via SPACC DMA).

By replacing legacy `pipe` / `vmsplice` / `splice` chains with direct `sendmsg()` scatter-gather I/O (`struct iovec` chunks up to **56 KiB**), `afalgprov` v3.4 minimizes syscall frequency, DMA descriptor setup overhead, and `IRQ 45` (`crypto`) interrupt rates while reducing CPU usage by **60–70%** compared to software AES.

---

## 1. Architecture Overview

| Component | Implementation | Purpose |
| :--- | :--- | :--- |
| **Algorithm Offload** | `AES-128-CTR`, `AES-256-CTR` | Delegated to `ctr-aes-ls1024a-spacc` (SPACC DMA engine). |
| **I/O Transport** | Direct `sendmsg()` (`msg_iov`) | Eliminates pipe creation (`pipe2`), `vmsplice`, and extra kernel page copies. |
| **Chunking Strategy** | 56 KiB (`57344` bytes) max per `sendmsg()` | Fits cleanly within default socket `SNDBUF` limits while maximizing DMA burst efficiency. |
| **AEAD / TLS 1.3 Strategy** | Hybrid (`ChaCha20-Poly1305` NEON + `kTLS` `AES-GCM`) | Uses ARMv7 NEON for maximum TLS throughput and Linux `kTLS` + SPACC `CTR` for `AES-GCM` CPU offload. |

---

## 2. Benchmark Results (NXP LS1024A, Linux 6.18, OpenSSL 3.5)

### A. Stream Cipher Throughput (`AES-128-CTR` / `AES-256-CTR`, 64 KiB blocks)

| Mode | Threads | Throughput | Wall Time | Total CPU (`user+sys`) | Dual-Core CPU Load |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Pure CPU (Software)** | 1 | `29.40 MB/s` | `3.00s` | `3.00s` | `50.0%` (1 core 100%) |
| **`afalgprov` v3.4 (SPACC)** | 1 | **`42.20 MB/s`** | `3.00s` | **`0.88s`** | **`14.7%`** (**-71% CPU**) |
| **`afalgprov` v3.4 (SPACC)** | 2 (`-multi 2`) | **`57.65 MB/s`** | `3.10s` | **`1.68s`** | **`27.1%`** |
| **`afalgprov` v3.4 (SPACC)** | 4 (`-multi 4`) | **`64.30 MB/s`** | `3.10s` | **`2.32s`** | **`37.4%`** |

### B. TLS 1.3 AEAD Performance: `ChaCha20-Poly1305` (NEON) vs. Kernel `kTLS` (`AES-GCM`)

| Cipher Suite / Backend | Block Size | Threads | Throughput | Dual-Core CPU Load | Notes |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **`TLS_CHACHA20_POLY1305_SHA256`** *(Pure CPU NEON)* | `16 KiB` | 2 (`-multi 2`) | **`141.36 MB/s`** | `98.7%` (`6.08s / 3.08s`) | Optimal for TLS 1.3 / HTTPS / WireGuard on Cortex-A9. |
| **`TLS_CHACHA20_POLY1305_SHA256`** *(Pure CPU NEON)* | `64 KiB` | 2 (`-multi 2`) | **`120.53 MB/s`** | `98.7%` (`6.08s / 3.08s`) | High-speed bulk AEAD across both Cortex-A9 cores. |
| **`TLS_CHACHA20_POLY1305_SHA256`** *(Pure CPU NEON)* | `16 KiB` | 4 (`-multi 4`) | **`138.81 MB/s`** | `98.7%` (`6.12s / 3.10s`) | Scales smoothly under concurrent connections. |
| **Kernel `gcm(aes)` (`AF_ALG` raw)** | `16 KiB` | 1 | `15.53 MB/s` | `15.0%` (`0.62s / 2.06s`) | Hybrid `gcm_base(ctr-aes-ls1024a-spacc, ghash-generic)`. |
| **`TLS_AES_128_GCM_SHA256`** *(Unidirectional `kTLS TX` `SSL_sendfile`)* | `16 KiB` | 1 | **`11.90 MB/s`** | **`19.2%`** (`8.25s / 21.52s`) | Offloads `CTR` to SPACC; saves ~65% CPU vs software GCM. |
| **`TLS_AES_256_GCM_SHA384`** *(Unidirectional `kTLS TX` `SSL_sendfile`)* | `16 KiB` | 1 | **`11.06 MB/s`** | **`20.5%`** (`9.52s / 23.15s`) | Identical hardware throughput regardless of AES key length. |

> **Why `kTLS` `AES-GCM` tops out at ~11.9 MB/s per stream on LS1024A:**
> ARM Cortex-A9 (ARMv7-A) lacks ARMv8 `PMULL` carryless multiplication instructions, so the authentication tag (`GHASH`) runs in software (`ghash-generic`), while `ctr(aes)` is dispatched to SPACC per 16 KiB TLS record (`+32,768` SPACC IRQs per 256 MiB). Prioritizing `ChaCha20-Poly1305` for TLS 1.3 unlocks up to **141 MB/s** via NEON, while `Options = KTLS` offloads `AES-GCM` clients with minimal CPU overhead.

---

## 3. Build & Installation

### Build `afalgprov.so`
```bash
gcc -O3 -march=armv7-a -mfpu=neon -mfloat-abi=hard -fPIC -shared \
    afalgprov.c -o afalgprov.so -lcrypto
