# afalgprov — OpenSSL 3.5 AF_ALG Provider for NXP LS1024A (SPACC cryptographic engine)

A dynamic cryptographic provider for **OpenSSL 3.5** on the **NXP LS1024A** platform (ARM Cortex-A9, `OPENSSL_armcap=0x1`, Debian `arm-linux-gnueabihf`), providing hardware offloading of `AES-CTR` encryption via the Linux kernel **`AF_ALG`** socket interface (`vmsplice`/`splice` pipeline) and the **SPACC (`9b000000.crypto`)** cryptographic engine.

- **Target Kernel Tree:** [symops/MCG1-6.18](https://github.com/symops/MCG1-6.18) with SPACC/crypto updates from [PR #13](https://github.com/symops/MCG1-6.18/pull/13).

---

## 1. Purpose and Architecture

ARM Cortex-A9 processors lack hardware AES cryptographic instructions (ARMv8 Crypto Extensions), causing software encryption in user space to fully saturate a single CPU core (or both cores under concurrent load). The **`afalgprov` (v3.3)** module integrates globally into OpenSSL 3.5 with a soft system-wide preference (`?provider=afalgprov`) and implements a hybrid execution model: large streaming `AES-CTR` buffers (`≥ 8192` bytes) are offloaded to the hardware DMA accelerator via a `vmsplice` + `splice` pipeline, while small packets, unaligned tails, `AES-CBC`, and AEAD modes are handled by the optimized user-space `default` provider (with **Kernel TLS (`kTLS`)** offloading for `AES-GCM`, which uses `ctr(aes)` under the hood).

### Registered Algorithms and Buffer Routing

| OpenSSL Name | Kernel Driver Name (`AF_ALG`) | Key Size (bits) | Buffer `< 8192` B / `% 16` Remainder | Buffer `≥ 8192` B (16-Byte Aligned) | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`AES-128-CTR`** (`aes-128-ctr`) | `ctr-aes-ls1024a-spacc` | 128 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | `OpenSSH`, `SFTP`, `SCP` (`aes128-ctr`), `openssl enc` |
| **`AES-192-CTR`** (`aes-192-ctr`) | `ctr-aes-ls1024a-spacc` | 192 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | Streaming channels (192-bit) |
| **`AES-256-CTR`** (`aes-256-ctr`) | `ctr-aes-ls1024a-spacc` | 256 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | `OpenSSH` (`aes256-ctr`), `openssl enc` |

*(All other algorithms — `AES-CBC`, `AES-GCM`, `ChaCha20-Poly1305`, `RSA`, `ECDSA`, `Ed25519`, `SHA-256`, etc. — are intentionally excluded from `afalgprov` and handled directly by the `default` provider or Linux kTLS.)*

### Key Mechanisms and Design Decisions

- **Zero-Copy `vmsplice` + `splice` Pipeline (`57344`-Byte Page-Aligned Chunks):**
  Instead of copying plaintext through user-space socket buffers on every write, `afalgprov` maps input pages directly into an internal kernel pipe via `vmsplice(..., 0)` and forwards them into the `AF_ALG` operation socket via `splice()` (`SPLICE_F_MORE` for intermediate chunks).
- **Scatter-Gather Limit Alignment (`AFALG_SPLICE_CHUNK = 57344`):**
  A `57,344`-byte (`14 × 4096`) chunk is an exact multiple of 32 bytes (`2 × AES_BLOCK_SIZE`) and stays strictly below the single-command cap (`SPACC_MAX_CHUNK_BYTES = 65520`). Even when user-space buffers are not page-aligned, 14 data pages span at most **15** scatterlist entries—matching the hardware DDT prefetcher limit (`SPACC_MAX_SG_ENTS = 15`) so each `splice` executes as a single DMA command without splitting or triggering small-tail software fallbacks.
- **Pipe and Socket Buffer Sizing:**
  Both internal pipe capacity (`AFALG_PIPE_SZ`) and socket buffers (`SO_SNDBUF`/`SO_RCVBUF`) are tuned to **224 KiB** (`4 × 57344` bytes), preventing mid-transfer stalls while remaining well within the default `fs.pipe-max-size` limit.
- **Configurable Empirical Threshold (`hw-threshold = 8192`) & Heap-Free Hot Path:**
  With zero-copy scatterlist mapping, pre-allocated DDT descriptors, and SRAM key caching in the updated `ls1024a_spacc` driver (`SPACC_MIN_HW_BYTES = 8192`), hardware DMA outperforms user-space software AES starting at **`8192` bytes** (configurable via `hw-threshold` in `openssl.cnf`, minimum `8192`). The `CMSG` control buffer (`cbuf`) is pre-allocated once per `AFALG_CTX` lifecycle (`afalg_newctx` / `afalg_dupctx`), eliminating heap allocations during encryption.
- **128-Bit Counter Bookkeeping & Seamless Hybrid Fallback (`iv_dirty` / `sw_unaligned`):**
  After every completed DMA chunk, `afalgprov` advances its 128-bit big-endian counter (`ctx->iv`) by `bytes / 16` blocks and marks `iv_dirty = 1`. If a request ends with an unaligned sub-16-byte tail or encounters a hardware error, `ctx->iv` is synchronized into `sw_ctx` so OpenSSL's `default` provider resumes seamlessly from the exact keystream offset.
- **Lazy Kernel Descriptor Initialization:**
  `AF_ALG` sockets (`tfmfd`, `opfd`) and internal pipe descriptors (`pipe2(..., O_CLOEXEC)`) are allocated lazily only when a buffer `≥ hw-threshold` bytes is processed, preventing file descriptor exhaustion on short-lived connections.
- **Why `AES-GCM` Is Excluded from `afalgprov` (and Accelerated via kTLS + SPACC `ctr(aes)`):**
  1. The NXP LS1024A SPACC kernel driver (`9b000000.crypto`) registers **`ctr(aes)`** (`ctr-aes-ls1024a-spacc`), **not** `gcm(aes)` (`TlsTxDevice` remains `0`).
  2. OpenSSL's streaming `EVP` API (`EVP_CipherUpdate` + separate `OSSL_CIPHER_PARAM_AEAD_TAG`) conflicts with the atomic packet interface of `algif_aead` (`AAD + payload + tag` in a single `sendmsg`), which would require buffering entire packets in user space.
  3. Intermediate Galois Field (`GHASH`) multiplier states cannot be exported/imported between `default` and SPACC DMA during hybrid fallback switching.
  4. **Recommended Solution — Kernel TLS (`kTLS`):** Enabling `Options = KTLS` in `/etc/ssl/openssl.cnf` (with the Linux `tls` module loaded) lets OpenSSL hand off established TLS 1.3 `AES-128-GCM` / `AES-256-GCM` sockets to the kernel (`SOL_TLS`). Inside the kernel, Linux `tls` (`TlsTxSw` / `TlsRxSw`) computes `GHASH` and delegates the underlying **`ctr(aes)`** payload encryption to the kernel crypto API (`ctr-aes-ls1024a-spacc`, priority `300`), eliminating user/kernel copy overhead, enabling `SSL_sendfile()` zero-copy, and cutting total loopback CPU time by **~61–66%**.
  5. For maximum TLS 1.3 throughput on ARMv7 NEON without kTLS, prioritizing `TLS_CHACHA20_POLY1305_SHA256` delivers **60.9 MB/s** vs. **12.9 MB/s** for software `AES-128-GCM` (**4.7x** faster).

---

### Performance Benchmarks on NXP LS1024A

#### Single-Thread Throughput & CPU Utilization (`-multi 1`, 64 KiB Blocks)

Measured throughput and CPU utilization on the **NXP LS1024A** board (OpenSSL 3.5.7, dual-core ARM Cortex-A9, `OPENSSL_armcap=0x1`) using `65,536`-byte (64 KiB) blocks with `-elapsed` (wall-clock time) and `/usr/bin/time -p` (**`10,984`** SPACC DMA interrupts recorded across all 3 hardware runs: `210,082 → 221,066`, matching `5,492` 64 KiB blocks split into `57,344 + 8,192`-byte chunks = 2 hardware commands per block):

| Algorithm and Mode | Pure CPU (`OPENSSL_CONF=/dev/null`, `default` only) | Hardware SPACC (`afalgprov`, DMA IRQ 45) | Throughput Gain | CPU Time (`user + sys` over ~3.06–3.07s run) | Role in System |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`AES-128-CTR`** | **29.0 MB/s** (`28,967 k`) | **40.1 MB/s** (`40,064 k`) | **+38.3% (1.38x)** | Reduced from **100%** (`3.04s + 0.02s`) to **29.3%** (`0.07s + 0.83s`) — **3.4x less CPU** | `OpenSSH`, `SFTP`, `SCP` (`aes128-ctr`) |
| **`AES-192-CTR`** | **24.4 MB/s** (`24,423 k`) | **39.9 MB/s** (`39,933 k`) | **+63.5% (1.64x)** | Reduced from **100%** (`3.04s + 0.02s`) to **30.6%** (`0.08s + 0.86s`) — **3.3x less CPU** | Streaming channels (192-bit) |
| **`AES-256-CTR`** | **21.3 MB/s** (`21,277 k`) | **40.0 MB/s** (`39,977 k`) | **+87.9% (1.88x)** | Reduced from **100%** (`3.04s + 0.02s`) to **28.0%** (`0.08s + 0.78s`) — **3.6x less CPU** | `OpenSSH` (`aes256-ctr`), `openssl enc` |
| **`ChaCha20-Poly1305`** | **60.7 MB/s** (`60,730 k`) | *Not supported by SPACC* | Fastest AEAD on CPU | ~100% of 1 CPU core (ARMv7 NEON) | Primary cipher for TLS 1.3 / HTTPS |
| **`AES-128-GCM`** | **12.8 MB/s** (`12,823 k`) | *Offloaded to Kernel via `kTLS` (`ctr(aes)`)* | **-61.0% CPU** via kTLS | Total process CPU cut from `25.82s` to `10.08s` (128 MiB TLS 1.3 transfer) | TLS 1.3 compatibility (`Options = KTLS`) |

#### Multi-Threaded Scaling (`-multi 2` and `-multi 4`, 64 KiB Blocks, Dual-Core Cortex-A9)

Measured under concurrent multi-process workloads (`openssl speed -multi 2` and `-multi 4`) across both ARM Cortex-A9 cores (`~6.16–6.24s` maximum combined dual-core CPU budget per `~3.08–3.12s` wall-clock run; **`+15,092`** SPACC IRQs across `-multi 2` [`221,066 → 236,158`] and **`+16,303`** SPACC IRQs across `-multi 4` [`236,158 → 252,461`]):

| Concurrency (`-multi`) | Algorithm | Pure CPU (`default` — 2 Cortex-A9 Cores) | Hardware SPACC DMA (`afalgprov`) | Throughput Gain | Dual-Core CPU Utilization (`user + sys` vs. ~6.2s budget) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`-multi 2`** *(2 workers)* | **`AES-128-CTR`** | 57.0 MB/s (`56,951 k`) | **55.6 MB/s** (`55,575 k`) | -2.4% *(equal speed, 3.3x less CPU)* | `1.82s` (**29%**) vs. `6.07s` (**99%**) — **3.3x less CPU** |
| **`-multi 2`** *(2 workers)* | **`AES-192-CTR`** | 47.2 MB/s (`47,242 k`) | **54.4 MB/s** (`54,395 k`) | **+15.1%** | `1.85s` (**30%**) vs. `5.95s` (**97%**) — **3.2x less CPU** |
| **`-multi 2`** *(2 workers)* | **`AES-256-CTR`** | 41.9 MB/s (`41,856 k`) | **54.9 MB/s** (`54,876 k`) | **+31.1%** | `1.89s` (**31%**) vs. `6.07s` (**99%**) — **3.2x less CPU** |
| **`-multi 4`** *(4 workers)* | **`AES-128-CTR`** | 54.5 MB/s (`54,502 k`) | **59.3 MB/s** (`59,313 k`) | **+8.8%** | `2.37s` (**38%**) vs. `6.03s` (**97%**) — **2.5x less CPU** |
| **`-multi 4`** *(4 workers)* | **`AES-192-CTR`** | 47.0 MB/s (`47,040 k`) | **59.9 MB/s** (`59,928 k`) | **+27.4%** | `2.41s` (**39%**) vs. `6.10s` (**98%**) — **2.5x less CPU** |
| **`-multi 4`** *(4 workers)* | **`AES-256-CTR`** | 40.5 MB/s (`40,546 k`) | **59.2 MB/s** (`59,227 k`) | **+46.1%** | `2.42s` (**39%**) vs. `6.07s` (**98%**) — **2.5x less CPU** |

#### TLS 1.3 `AES-GCM` Loopback Benchmark (128 MiB Transfer, 64 KiB Chunks, Client + Server)

| TLS 1.3 Ciphersuite & Configuration | kTLS State (`TX / RX`) | Loopback Throughput | Transfer Time | Process CPU Time (`user + sys`, client + server) |
| :--- | :--- | :--- | :--- | :--- |
| **`TLS_AES_128_GCM_SHA256` (`kTLS OFF`)** | `0 / 0` (`+0` SPACC IRQs) | 9.40 MB/s | 13.61 s | **25.82 s** (~190% across 2 cores) |
| **`TLS_AES_128_GCM_SHA256` (`Options = KTLS`)** | `2 / 2` (`TlsTxSw`/`TlsRxSw` → `ctr(aes)`, `+16,278` SPACC IRQs) | **10.24 MB/s** (+8.9%) | **12.50 s** | **10.08 s** (**-61.0% CPU** — **2.56x less CPU**) |
| **`TLS_AES_256_GCM_SHA384` (`kTLS OFF`)** | `0 / 0` (`+0` SPACC IRQs) | 8.31 MB/s | 15.41 s | **29.28 s** (~190% across 2 cores) |
| **`TLS_AES_256_GCM_SHA384` (`Options = KTLS`)** | `2 / 2` (`TlsTxSw`/`TlsRxSw` → `ctr(aes)`, `+16,306` SPACC IRQs) | **10.07 MB/s** (+21.2%) | **12.72 s** | **9.98 s** (**-65.9% CPU** — **2.93x less CPU**) |

### Key Takeaways from Benchmarks
1. **Constant ~40.0 MB/s Single-Stream Ceiling & ~59.9 MB/s Multi-Stream DMA Saturation:**
   In single-threaded mode (`-multi 1`), synchronous `sendmsg → splice → read` round-trips cap throughput at **39.9–40.1 MB/s** across all key lengths (**1.88x** faster than software `AES-256-CTR`). Under concurrent load (`-multi 2` and `-multi 4`), queued descriptors keep the SPACC DMA pipeline continuously busy between interrupts, scaling aggregate hardware throughput up to **55.6 MB/s** (2 workers) and **59.9 MB/s** (4 workers)—surpassing both Cortex-A9 cores running at 100% saturation (`54.5 MB/s` for 128-bit and `40.5 MB/s` for 256-bit).
2. **Zero Key-Length Penalty Under Concurrent Load (128 / 192 / 256-bit):**
   With 4 workers on pure CPU, increasing key length from 128 to 256 bits drops total throughput by 25.6% (`54.5 → 40.5 MB/s`). SPACC DMA sustains a flat **59.2–59.9 MB/s** regardless of key size (**+46.1%** faster than dual-core CPU on `AES-256-CTR`).
3. **60–71% Dual-Core CPU Headroom Preserved Under Heavy Encryption:**
   Pure software encryption saturates **97–99%** of total dual-core CPU capacity (`~5.95–6.10s` out of `~6.2s`). `afalgprov` reduces combined dual-core CPU utilization to **29–39%**, leaving **1.2–1.4+ CPU cores free** for network packet processing, storage I/O, and application logic.
4. **Verified 1:1 Hardware Offload Ratio & kTLS `AES-GCM` Acceleration:**
   Across the single-thread `AES-CTR` runs (`1,834 + 1,828 + 1,830 = 5,492` 64 KiB ops = `10,984` hardware chunks), IRQ 45 incremented by exact **`+10,984`** (`210,082 → 221,066`). Similarly, `Options = KTLS` offloads `AES-GCM`'s `CTR` stage to `ctr-aes-ls1024a-spacc` (`+16,278` to `+16,306` SPACC IRQs), eliminating key-size penalties (`10.24 MB/s` vs. `10.07 MB/s`) and cutting combined client+server CPU usage by **61–66%**.

### Reproducing Benchmarks (`OPENSSL_CONF=/dev/null` vs. `afalgprov`)

~~~bash
echo "=== 0. IRQ BASELINE ===" && \
grep crypto /proc/interrupts && \
echo "=== 1. PURE CPU (-multi 1, OPENSSL_CONF=/dev/null, default only) ===" && \
for alg in aes-128-ctr aes-192-ctr aes-256-ctr; do
  OPENSSL_CONF=/dev/null /usr/bin/time -p openssl speed -elapsed -provider default -evp "$alg" -bytes 65536 2>&1 | grep -iE "Doing|^AES-|real|user|sys"
done && \
grep crypto /proc/interrupts && \
echo "=== 2. HARDWARE SPACC DMA (-multi 1, afalgprov) ===" && \
for alg in aes-128-ctr aes-192-ctr aes-256-ctr; do
  /usr/bin/time -p openssl speed -elapsed -provider afalgprov -provider default -evp "$alg" -bytes 65536 2>&1 | grep -iE "Doing|^AES-|real|user|sys"
done && \
grep crypto /proc/interrupts && \
echo "=== 3. MULTI-THREADED SCALING (-multi 2 & -multi 4) ===" && \
for threads in 2 4; do
  echo "--- PURE CPU (-multi $threads) ---"
  for alg in aes-128-ctr aes-192-ctr aes-256-ctr; do
    OPENSSL_CONF=/dev/null /usr/bin/time -p openssl speed -elapsed -multi "$threads" -provider default -evp "$alg" -bytes 65536 2>&1 | grep -iE "^AES-|real|user|sys"
  done
  echo "--- HARDWARE SPACC DMA (-multi $threads) ---"
  for alg in aes-128-ctr aes-192-ctr aes-256-ctr; do
    /usr/bin/time -p openssl speed -elapsed -multi "$threads" -provider afalgprov -provider default -evp "$alg" -bytes 65536 2>&1 | grep -iE "^AES-|real|user|sys"
  done
  grep crypto /proc/interrupts
done && \
echo "=== 4. CPU AEAD: ChaCha20-Poly1305 vs AES-128-GCM ===" && \
OPENSSL_CONF=/dev/null openssl speed -elapsed -provider default -evp chacha20-poly1305 -bytes 65536 2>&1 | grep -E "Doing|ChaCha20" && \
OPENSSL_CONF=/dev/null openssl speed -elapsed -provider default -evp aes-128-gcm -bytes 65536 2>&1 | grep -E "Doing|AES-"
~~~

---

## 2. System Preparation and Dependencies

### 2.1. Install Build Packages

~~~bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev
~~~

### 2.2. Verify Kernel Version (`MCG1-6.18` + `PR #13`) and Crypto Modules

This provider targets the custom Linux kernel from **[symops/MCG1-6.18](https://github.com/symops/MCG1-6.18)** with the SPACC DMA / `AF_ALG` patches applied in **[PR #13](https://github.com/symops/MCG1-6.18/pull/13)**.

~~~bash
uname -a
grep crypto /proc/interrupts
grep -B 1 -A 14 -E "name\s*:\s*ctr\(aes\)" /proc/crypto
lsmod | grep -E "af_alg|algif_skcipher|ls1024a_spacc"

# Enable Linux Kernel TLS (kTLS) for AES-GCM offloading via ctr(aes) in TLS 1.3
sudo modprobe tls
echo "tls" | sudo tee /etc/modules-load.d/ktls.conf >/dev/null
ls -d /sys/module/tls
~~~

*(Expected kernel driver: `ctr-aes-ls1024a-spacc` with `priority : 300`, `min keysize : 16`, `max keysize : 32`, plus `/sys/module/tls` active.)*

---

## 3. Compile and Install into `ossl-modules`

~~~bash
sudo make clean all
sudo make install
~~~

### 3.1. Verify the Installed Shared Library and Backup Configuration

Before editing `/etc/ssl/openssl.cnf`, create a backup copy (preserving permissions and timestamps). A malformed `openssl.cnf` can prevent `openssl`, `ssh`, `apt`, and `curl` from initializing TLS/crypto:

~~~bash
ls -l /usr/lib/arm-linux-gnueabihf/ossl-modules/afalgprov.so
ldd /usr/lib/arm-linux-gnueabihf/ossl-modules/afalgprov.so
sudo cp -an /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.bak
ls -l /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.bak
~~~

*(Using `cp -an` ensures an existing original backup `/etc/ssl/openssl.cnf.bak` is never overwritten on subsequent updates. To test a modified configuration safely before replacing the system file, validate it first via `OPENSSL_CONF=/tmp/openssl.cnf.test openssl list -providers`.)*

### 3.2. Global `/etc/ssl/openssl.cnf` Configuration (with kTLS for AES-GCM)

Ensure `openssl_conf = openssl_init` is defined at the top level of `/etc/ssl/openssl.cnf` (before any `[section]` headers). Enabling `Options = KTLS` in `[ssl_default_sect]` allows OpenSSL 3.5 to offload TLS 1.3 `AES-GCM` sockets to the Linux kernel automatically (which accelerates the `CTR` cipher stage using `ctr-aes-ls1024a-spacc`):

~~~ini
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
~~~

*(Optional: To prioritize faster NEON `ChaCha20-Poly1305` while retaining kTLS acceleration for `AES-GCM` clients, add `Ciphersuites = TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384` under `[ssl_default_sect]`. Note that custom C applications using `SSL_CTX_new()` must call `OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL)` or `SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS)` to activate kTLS.)*

### 3.3. Per-Service Isolation (Optional)

To enable SPACC offloading only for specific services (e.g., OpenVPN, `stunnel`, or custom daemons) without modifying `/etc/ssl/openssl.cnf`, save the configuration above to `/etc/ssl/openssl-spacc.cnf` and pass `OPENSSL_CONF=/etc/ssl/openssl-spacc.cnf` (or `Environment="OPENSSL_CONF=/etc/ssl/openssl-spacc.cnf"` inside the systemd unit). Sandboxed services with `SystemCallFilter` must allow `socket`, `bind`, `accept4`, `pipe2`, `vmsplice`, and `splice` (plus `setsockopt` for `SOL_TLS` if kTLS is enabled).

---

## 4. Restart Services, Verification and Diagnostics

~~~bash
sudo systemctl restart ssh
openssl list -providers
openssl list -cipher-algorithms -provider afalgprov | grep "@ afalgprov"
openssl ciphers -v -s -tls1_3
~~~

### Verify kTLS Offloading for `TLS_AES_128_GCM_SHA256`

~~~bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /tmp/ktls_key.pem -out /tmp/ktls_cert.pem \
  -days 1 -subj "/CN=localhost" 2>/dev/null

openssl s_server -accept 14434 -cert /tmp/ktls_cert.pem -key /tmp/ktls_key.pem \
  -ciphersuites TLS_AES_128_GCM_SHA256 -ktls -www >/dev/null 2>&1 &
SRV_PID=$!
sleep 0.5

(printf "GET / HTTP/1.0\r\n\r\n"; sleep 0.2) | \
  openssl s_client -connect 127.0.0.1:14434 \
  -ciphersuites TLS_AES_128_GCM_SHA256 -ktls -brief

grep -E "Tls(Tx|Rx)Sw|TlsDecryptError" /proc/net/tls_stat
kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null
rm -f /tmp/ktls_key.pem /tmp/ktls_cert.pem
~~~

*(Expected output includes `Using Kernel TLS for sending`, `Using Kernel TLS for receiving`, and incremented `TlsTxSw` / `TlsRxSw` counters with `TlsDecryptError` remaining `0`.)*

### End-to-End Byte-Exactness Check (`AES-128 / 192 / 256-CTR`)

~~~bash
dd if=/dev/urandom bs=65536 count=4 of=/tmp/test_in.bin status=none && \
for bits in 128 192 256; do
  KEY=$(head -c $((bits / 8)) /dev/urandom | od -An -tx1 | tr -d ' \n')
  IV="00112233445566778899aabbccddeeff"
  openssl enc -aes-${bits}-ctr -bufsize 65536 -provider afalgprov -provider default -K "$KEY" -iv "$IV" -in /tmp/test_in.bin -out /tmp/test_enc.bin && \
  openssl enc -d -aes-${bits}-ctr -bufsize 65536 -provider default -K "$KEY" -iv "$IV" -in /tmp/test_enc.bin -out /tmp/test_dec.bin && \
  cmp -s /tmp/test_in.bin /tmp/test_dec.bin && echo "AES-${bits}-CTR: OK" || echo "AES-${bits}-CTR: FAIL"
done && \
rm -f /tmp/test_in.bin /tmp/test_enc.bin /tmp/test_dec.bin
~~~

---

## 5. Reverting Changes (Uninstall)

Restore the original `/etc/ssl/openssl.cnf` from `/etc/ssl/openssl.cnf.bak`, remove the installed provider module and kTLS autoload rule, and restart dependent services:

~~~bash
sudo cp -a /etc/ssl/openssl.cnf.bak /etc/ssl/openssl.cnf
sudo rm -f /etc/modules-load.d/ktls.conf
sudo make -C uninstall
sudo systemctl restart ssh
openssl list -providers
~~~
