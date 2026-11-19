# afalgprov — OpenSSL 3.5 AF_ALG Zero-Copy Provider for NXP LS1024A (SPACC DMA)

A dynamic cryptographic provider for **OpenSSL 3.5** on the **NXP LS1024A** platform (ARM Cortex-A9, `OPENSSL_armcap=0x1`, Debian `arm-linux-gnueabihf`), providing hardware offloading of symmetric encryption via the Linux kernel **`AF_ALG`** socket interface (`vmsplice`/`splice` pipeline) and the **SPACC (`9b000000.crypto`)** cryptographic DMA engine.

---

## 1. Purpose and Architecture

ARM Cortex-A9 processors lack hardware AES cryptographic instructions (ARMv8 Crypto Extensions), causing software encryption in user space to fully saturate a single CPU core. The **`afalgprov` (v3.0)** module integrates globally into OpenSSL 3.5 with a soft system-wide preference (`?provider=afalgprov`) and implements a hybrid execution model: large streaming buffers are offloaded to the hardware DMA accelerator via a `vmsplice` + `splice` pipeline, while small packets, unaligned tails, padded CBC decryptions, and AEAD modes are handled by the optimized user-space `default` provider.

### Registered Algorithms and Buffer Routing

| OpenSSL Name | Kernel Driver Name (`AF_ALG`) | Key Size (bits) | Buffer `< 16384` B / `% 16` Remainder | Buffer `≥ 16384` B (16-Byte Aligned) | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`AES-128-CTR`** (`aes-128-ctr`) | `ctr-aes-ls1024a-spacc` | 128 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | `OpenSSH`, `SFTP`, `SCP` (`aes128-ctr`) |
| **`AES-192-CTR`** (`aes-192-ctr`) | `ctr-aes-ls1024a-spacc` | 192 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | Streaming channels (192-bit) |
| **`AES-256-CTR`** (`aes-256-ctr`) | `ctr-aes-ls1024a-spacc` | 256 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | `OpenSSH` (`aes256-ctr`), `openssl enc` |
| **`AES-128-CBC`** (`aes-128-cbc`) | `cbc-aes-ls1024a-spacc` | 128 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | `openssl enc`, file encryption, VPN |
| **`AES-192-CBC`** (`aes-192-cbc`) | `cbc-aes-ls1024a-spacc` | 192 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | Data encryption (192-bit) |
| **`AES-256-CBC`** (`aes-256-cbc`) | `cbc-aes-ls1024a-spacc` | 256 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | `openssl enc -aes-256-cbc`, TLS 1.3 Session Tickets |

*(All other algorithms — `AES-GCM`, `ChaCha20-Poly1305`, `RSA`, `ECDSA`, `Ed25519`, `SHA-256`, etc. — are intentionally excluded from `afalgprov` and handled directly by the `default` provider.)*

### Key Mechanisms and Design Decisions

* **Zero-Copy `vmsplice` + `splice` Pipeline (`65536`-Byte Chunks):**
  Instead of copying plaintext through user-space socket buffers on every write, `afalgprov` maps input pages directly into an internal kernel pipe via `vmsplice(..., 0)` and forwards them into the `AF_ALG` operation socket via `splice()` (`SPLICE_F_MORE` for intermediate chunks). Both pipe capacity (`AFALG_PIPE_SZ`) and socket buffers (`SO_SNDBUF`/`SO_RCVBUF`) are tuned to **256 KiB** (`4 × 65536` bytes), avoiding mid-transfer stalls.
* **Empirical Threshold (`16384` Bytes) & Heap-Free Hot Path:**
  Invoking `AF_ALG` incurs `sendmsg`/`vmsplice`/`splice`/`read` syscall overhead and hardware interrupt handling on IRQ 45 (`9b000000.crypto`). Below **`SPACC_HW_THRESHOLD` (16 KiB)**, software AES in `default` outperforms DMA setup; starting at 16 KiB, requests are routed to SPACC. The `CMSG` control buffer (`cbuf`) is pre-allocated once per `AFALG_CTX` lifecycle (`afalg_newctx` / `afalg_dupctx`), eliminating heap allocations during encryption.
* **In-Place Safety (`out == in`) and IV Synchronization (`iv_dirty` / `sw_unaligned`):**
  During `AES-CBC` decryption, the next 16-byte IV is saved from the input ciphertext before the buffer is overwritten. The `iv_dirty` flag synchronizes the updated IV back to `sw_ctx` only when transitioning from DMA to software or when finalizing PKCS#7 padding (`afalg_final`). Padded `AES-CBC` decryption runs entirely in software because OpenSSL buffers the final block internally until `EVP_CipherFinal_ex`.
* **Lazy Kernel Descriptor Initialization:**
  `AF_ALG` sockets (`tfmfd`, `opfd`) and internal pipe descriptors (`pipe2(..., O_CLOEXEC)`) are allocated lazily only when a buffer `≥ 16384` bytes is processed, preventing file descriptor exhaustion on short-lived connections.
* **Why `AES-GCM` Is Excluded from `afalgprov`:**
  1. OpenSSL's streaming `EVP` API (`EVP_CipherUpdate` + separate `OSSL_CIPHER_PARAM_AEAD_TAG`) conflicts with the atomic packet interface of `algif_aead` (`AAD + payload + tag` in a single `sendmsg`), which would require buffering entire packets in user space.
  2. Intermediate Galois Field (`GHASH`) multiplier states cannot be exported/imported between `default` and SPACC DMA during hybrid fallback switching.
  3. `libssl` relies on internal TLS IV management parameters (`AEAD_TLS1_AAD`, `AEAD_IV_GEN`) for TLS 1.2/1.3, and TLS records are capped at `≤ 16` KB where kernel context-switch overhead outweighs DMA acceleration.
  4. On ARMv7 NEON, software `ChaCha20-Poly1305` is **4.7x** faster than `AES-128-GCM` (**61.2 MB/s** vs. **12.9 MB/s**).

---

### Performance Benchmarks on NXP LS1024A

Measured throughput and CPU utilization on the **NXP LS1024A** board (OpenSSL 3.5.7, ARM Cortex-A9, `OPENSSL_armcap=0x1`) using `65,536`-byte (64 KB) blocks with `-elapsed` (wall-clock time) and `/usr/bin/time -p`:

| Algorithm and Mode | Pure CPU (`OPENSSL_CONF=/dev/null`, `default` only) | Hardware SPACC (`afalgprov`, DMA IRQ 45) | Throughput Gain | CPU Time (`user + sys` over ~3.07s run) | Role in System |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`AES-128-CTR`** | **29.0 MB/s** (`29,011 k`) | **45.6 MB/s** (`45,613 k`) | **+57.2% (1.57x)** | Reduced from **100%** (`3.04s + 0.02s`) to **26.7%** (`0.06s + 0.76s`) — **3.7x less CPU** | `OpenSSH`, `SFTP`, `SCP` (`aes128-ctr`) |
| **`AES-128-CBC`** | **22.3 MB/s** (`22,348 k`) | **45.7 MB/s** (`45,744 k`) | **+104.7% (2.05x)** | Reduced from **100%** (`3.03s + 0.03s`) to **26.7%** (`0.06s + 0.76s`) — **3.7x less CPU** | `openssl enc`, file/backup encryption |
| **`AES-192-CTR`** | **24.5 MB/s** (`24,510 k`) | **45.7 MB/s** (`45,722 k`) | **+86.5% (1.87x)** | Reduced from **100%** (`3.04s + 0.02s`) to **25.4%** (`0.06s + 0.72s`) — **3.9x less CPU** | Streaming channels (192-bit) |
| **`AES-192-CBC`** | **19.6 MB/s** (`19,639 k`) | **45.9 MB/s** (`45,941 k`) | **+133.9% (2.34x)** | Reduced from **100%** (`3.04s + 0.02s`) to **25.7%** (`0.07s + 0.72s`) — **3.9x less CPU** | Data encryption (192-bit) |
| **`AES-256-CTR`** | **21.3 MB/s** (`21,272 k`) | **45.6 MB/s** (`45,635 k`) | **+114.5% (2.15x)** | Reduced from **100%** (`3.04s + 0.02s`) to **25.1%** (`0.07s + 0.70s`) — **4.0x less CPU** | `OpenSSH` (`aes256-ctr`), `openssl enc` |
| **`AES-256-CBC`** | **17.1 MB/s** (`17,127 k`) | **45.8 MB/s** (`45,810 k`) | **+167.5% (2.67x)** | Reduced from **100%** (`3.05s + 0.01s`) to **27.0%** (`0.08s + 0.75s`) — **3.7x less CPU** | `openssl enc -aes-256-cbc`, TLS 1.3 Session Tickets |
| **`ChaCha20-Poly1305`** | **61.2 MB/s** (`61,211 k`) | *Not supported by SPACC* | Fastest AEAD on CPU | ~100% of 1 CPU core (ARMv7 NEON) | Primary cipher for TLS 1.3 / HTTPS |
| **`AES-128-GCM`** | **12.9 MB/s** (`12,867 k`) | *Excluded by design* | Baseline fallback | ~100% of 1 CPU core (table AES + GHASH) | Legacy TLS compatibility |

### Key Takeaways from Benchmarks
1. **Constant ~45.6–45.9 MB/s Hardware Ceiling Across All Key Lengths (128/192/256-bit):**
   While software AES slows down significantly as key length increases from 128 to 256 bits (`29.0 → 21.3 MB/s` in CTR; `22.3 → 17.1 MB/s` in CBC), SPACC DMA maintains a flat **45.6–45.9 MB/s** across all modes—delivering up to **2.67x throughput** on `AES-256-CBC` while cutting user-space CPU time from **3.04s down to 0.06–0.08s** (~73–75% total CPU offload).
2. **Verified 1:1 Hardware Offload Ratio:**
   During 64 KB benchmark runs (e.g., `2,093` AES-192-CTR ops + `2,103` AES-192-CBC ops = `4,196` ops), the `9b000000.crypto` interrupt counter (IRQ 45) incremented by exactly **`+4,196`** (`206,477` → `210,673`), confirming zero software fallback on aligned large buffers.
3. **Optimal System-Wide Split:**
   Combining `afalgprov` for streaming `AES-CTR` / `AES-CBC` with `ChaCha20-Poly1305` priority for TLS 1.3 (**61.2 MB/s** vs. **12.9 MB/s** for `AES-128-GCM`) maximizes throughput across all workloads on NXP LS1024A.

### Reproducing Benchmarks (`OPENSSL_CONF=/dev/null` vs. `afalgprov`)
```bash
echo "=== 0. IRQ BASELINE ===" && \
grep crypto /proc/interrupts && \
echo "=== 1. PURE CPU (OPENSSL_CONF=/dev/null, default only) ===" && \
for alg in aes-128-ctr aes-128-cbc aes-192-ctr aes-192-cbc aes-256-ctr aes-256-cbc; do
  OPENSSL_CONF=/dev/null /usr/bin/time -p openssl speed -elapsed -provider default -evp "$alg" -bytes 65536 2>&1 | grep -E "Doing|AES-|real|user|sys"
done && \
grep crypto /proc/interrupts && \
echo "=== 2. HARDWARE SPACC DMA (afalgprov) ===" && \
for alg in aes-128-ctr aes-128-cbc aes-192-ctr aes-192-cbc aes-256-ctr aes-256-cbc; do
  /usr/bin/time -p openssl speed -elapsed -provider afalgprov -evp "$alg" -bytes 65536 2>&1 | grep -E "Doing|AES-|real|user|sys"
done && \
grep crypto /proc/interrupts && \
echo "=== 3. CPU AEAD: ChaCha20-Poly1305 vs AES-128-GCM ===" && \
OPENSSL_CONF=/dev/null openssl speed -elapsed -provider default -evp chacha20-poly1305 -bytes 65536 2>&1 | grep -E "Doing|ChaCha20" && \
OPENSSL_CONF=/dev/null openssl speed -elapsed -provider default -evp aes-128-gcm -bytes 65536 2>&1 | grep -E "Doing|AES-"
