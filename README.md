# afalgprov — OpenSSL 3.5 AF_ALG Provider for NXP LS1024A (SPACC cryptographic engine)

A dynamic cryptographic provider for **OpenSSL 3.5** on the **NXP LS1024A** platform (ARM Cortex-A9, `OPENSSL_armcap=0x1`, Debian `arm-linux-gnueabihf`), providing hardware offloading of symmetric encryption via the Linux kernel **`AF_ALG`** socket interface (`vmsplice`/`splice` pipeline) and the **SPACC (`9b000000.crypto`)** cryptographic engine.

- **Target Kernel Tree:** [symops/MCG1-6.18](https://github.com/symops/MCG1-6.18) with SPACC/crypto updates from [PR #13](https://github.com/symops/MCG1-6.18/pull/13).

---

## 1. Purpose and Architecture

ARM Cortex-A9 processors lack hardware AES cryptographic instructions (ARMv8 Crypto Extensions), causing software encryption in user space to fully saturate a single CPU core. The **`afalgprov` (v3.2)** module integrates globally into OpenSSL 3.5 with a soft system-wide preference (`?provider=afalgprov`) and implements a hybrid execution model: large streaming buffers are offloaded to the hardware DMA accelerator via a `vmsplice` + `splice` pipeline, while small packets, unaligned tails, padded CBC decryptions, and AEAD modes are handled by the optimized user-space `default` provider (with optional **Kernel TLS (`kTLS`)** offloading for `AES-GCM`).

### Registered Algorithms and Buffer Routing

| OpenSSL Name | Kernel Driver Name (`AF_ALG`) | Key Size (bits) | Buffer `< 16384` B / `% 16` Remainder | Buffer `≥ 16384` B (16-Byte Aligned) | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`AES-128-CTR`** (`aes-128-ctr`) | `ctr-aes-ls1024a-spacc` | 128 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | `OpenSSH`, `SFTP`, `SCP` (`aes128-ctr`) |
| **`AES-192-CTR`** (`aes-192-ctr`) | `ctr-aes-ls1024a-spacc` | 192 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | Streaming channels (192-bit) |
| **`AES-256-CTR`** (`aes-256-ctr`) | `ctr-aes-ls1024a-spacc` | 256 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | `OpenSSH` (`aes256-ctr`), `openssl enc` |
| **`AES-128-CBC`** (`aes-128-cbc`) | `cbc-aes-ls1024a-spacc` | 128 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | `openssl enc`, file encryption, VPN |
| **`AES-192-CBC`** (`aes-192-cbc`) | `cbc-aes-ls1024a-spacc` | 192 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | Data encryption (192-bit) |
| **`AES-256-CBC`** (`aes-256-cbc`) | `cbc-aes-ls1024a-spacc` | 256 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | `openssl enc -aes-256-cbc`, TLS 1.3 Session Tickets |

*(All other algorithms — `AES-GCM`, `ChaCha20-Poly1305`, `RSA`, `ECDSA`, `Ed25519`, `SHA-256`, etc. — are intentionally excluded from `afalgprov` and handled directly by the `default` provider or Linux kTLS.)*

### Key Mechanisms and Design Decisions

- **Zero-Copy `vmsplice` + `splice` Pipeline (`65536`-Byte Page-Aligned Chunks):**
  Instead of copying plaintext through user-space socket buffers on every write, `afalgprov` maps input pages directly into an internal kernel pipe via `vmsplice(..., 0)` and forwards them into the `AF_ALG` operation socket via `splice()` (`SPLICE_F_MORE` for intermediate chunks).
- **Page Alignment vs. Hardware Descriptor Chaining (`AFALG_SPLICE_CHUNK = 65536`):** A `65,536`-byte (64 KiB) chunk matches exact 4 KiB page boundaries (`16 × 4096` bytes, aligning with Linux `af_alg`'s `ALG_MAX_PAGES = 16`) and avoids splitting standard 64 KiB OpenSSL application buffers into multiple user-space syscall loops. Although the `ls1024a_spacc` kernel driver has a single-descriptor cap of `SPACC_MAX_CHUNK_BYTES = 65520` (`round_down(SZ_64K - 1, AES_BLOCK_SIZE)`), it transparently chains the `65520 + 16`-byte descriptors in kernel space under a single DMA interrupt (IRQ 45).
- **Pipe and Socket Buffer Sizing:** Both internal pipe capacity (`AFALG_PIPE_SZ`) and socket buffers (`SO_SNDBUF`/`SO_RCVBUF`) are tuned to **256 KiB** (`4 × 65536` bytes), avoiding mid-transfer stalls.
- **Configurable Empirical Threshold (`hw-threshold = 16384`) & Heap-Free Hot Path:**
  Invoking `AF_ALG` incurs `sendmsg`/`vmsplice`/`splice`/`read` syscall overhead and hardware interrupt handling on IRQ 45 (`9b000000.crypto`). Below **`SPACC_HW_THRESHOLD` (default 16 KiB, configurable via `hw-threshold` in `openssl.cnf`)**, software AES in `default` outperforms DMA setup; starting at the threshold, requests are routed to SPACC. The `CMSG` control buffer (`cbuf`) is pre-allocated once per `AFALG_CTX` lifecycle (`afalg_newctx` / `afalg_dupctx`), eliminating heap allocations during encryption.
- **In-Place Safety (`out == in`) and IV Synchronization (`iv_dirty` / `sw_unaligned`):**
  During `AES-CBC` decryption, the next 16-byte IV is saved from the input ciphertext before the buffer is overwritten. The `iv_dirty` flag synchronizes the updated IV back to `sw_ctx` only when transitioning from DMA to software or when finalizing PKCS#7 padding (`afalg_final`). Padded `AES-CBC` decryption runs entirely in software because OpenSSL buffers the final block internally until `EVP_CipherFinal_ex`.
- **Lazy Kernel Descriptor Initialization:**
  `AF_ALG` sockets (`tfmfd`, `opfd`) and internal pipe descriptors (`pipe2(..., O_CLOEXEC)`) are allocated lazily only when a buffer `≥ hw-threshold` bytes is processed, preventing file descriptor exhaustion on short-lived connections.
- **Why `AES-GCM` Is Excluded from `afalgprov` (and How to Accelerate It via kTLS):**
  1. The NXP LS1024A SPACC kernel driver (`9b000000.crypto`) exports `cbc(aes)`, `ctr(aes)`, and `ecb(aes)`, **not** `gcm(aes)` (`TlsTxDevice` remains `0`).
  2. OpenSSL's streaming `EVP` API (`EVP_CipherUpdate` + separate `OSSL_CIPHER_PARAM_AEAD_TAG`) conflicts with the atomic packet interface of `algif_aead` (`AAD + payload + tag` in a single `sendmsg`), which would require buffering entire packets in user space.
  3. Intermediate Galois Field (`GHASH`) multiplier states cannot be exported/imported between `default` and SPACC DMA during hybrid fallback switching.
  4. **Recommended Solution — Kernel TLS (`kTLS`):** Enabling `Options = KTLS` in `/etc/ssl/openssl.cnf` (with the Linux `tls` module loaded) lets OpenSSL hand off established TLS 1.3 `AES-128-GCM` / `AES-256-GCM` sockets to the kernel (`SOL_TLS`). The kernel performs record framing and `AES-GCM` encryption in kernel space (`TlsTxSw` / `TlsRxSw`), eliminating user/kernel copy overhead, enabling `SSL_sendfile()` zero-copy, and cutting client CPU time by **~58%**.
  5. For maximum TLS 1.3 throughput on ARMv7 NEON, prioritizing `TLS_CHACHA20_POLY1305_SHA256` delivers **61.2 MB/s** vs. **12.9 MB/s** for software `AES-128-GCM` (**4.7x** faster).

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
| **`AES-128-GCM`** | **12.9 MB/s** (`12,867 k`) | *Offloaded to Kernel via `kTLS`* | **-58% CPU** via kTLS | User-space CPU cut from `11.36s` to `0.45s` (128 MB TLS 1.3 transfer) | TLS 1.3 compatibility (`Options = KTLS`) |

#### TLS 1.3 `AES-128-GCM` Loopback Benchmark (128 MiB Transfer, 64 KiB Chunks)

| TLS 1.3 Configuration | kTLS State (`TX / RX`) | Loopback Throughput | Transfer Time | Client CPU Time (`user + sys`) |
| :--- | :--- | :--- | :--- | :--- |
| **User-Space OpenSSL (`kTLS OFF`)** | `0 / 0` | 10.41 MB/s | 12.29 s | **11.94 s** (`11.36s user + 0.58s sys`) |
| **Kernel TLS (`Options = KTLS`)** | `1 / 1` (`TlsTxSw`/`TlsRxSw`) | **11.19 MB/s** (+7.5%) | **11.44 s** | **5.02 s** (`0.45s user + 4.57s sys` — **-58% CPU**) |

### Key Takeaways from Benchmarks
1. **Constant ~45.6–45.9 MB/s Hardware Ceiling Across All Key Lengths (128/192/256-bit):**
   While software AES slows down significantly as key length increases from 128 to 256 bits (`29.0 → 21.3 MB/s` in CTR; `22.3 → 17.1 MB/s` in CBC), SPACC DMA maintains a flat **45.6–45.9 MB/s** across all modes—delivering up to **2.67x throughput** on `AES-256-CBC` while cutting user-space CPU time from **3.04s down to 0.06–0.08s** (~73–75% total CPU offload).
2. **Verified 1:1 Hardware Offload Ratio:**
   During 64 KB benchmark runs (e.g., `2,093` AES-192-CTR ops + `2,103` AES-192-CBC ops = `4,196` ops), the `9b000000.crypto` interrupt counter (IRQ 45) incremented by exactly **`+4,196`** (`206,477` → `210,673`), confirming zero software fallback on aligned large buffers.
3. **Optimal System-Wide Split (`afalgprov` + `kTLS` + `ChaCha20-Poly1305`):**
   Combining `afalgprov` for streaming `AES-CTR` / `AES-CBC` with **`Options = KTLS`** for `AES-GCM` (cutting user-space TLS CPU overhead by 58% and enabling `SSL_sendfile()`) and `ChaCha20-Poly1305` priority for TLS 1.3 (**61.2 MB/s** vs. **12.9 MB/s** for `AES-128-GCM`) maximizes efficiency across all workloads on NXP LS1024A.

### Reproducing Benchmarks (`OPENSSL_CONF=/dev/null` vs. `afalgprov`)

~~~bash
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
grep -B 1 -A 14 -E "name\s*:\s*(cbc|ctr)\(aes\)" /proc/crypto
lsmod | grep -E "af_alg|algif_skcipher|ls1024a_spacc"

# Enable Linux Kernel TLS (kTLS) for AES-GCM offloading in TLS 1.3
sudo modprobe tls
echo "tls" | sudo tee /etc/modules-load.d/ktls.conf >/dev/null
ls -d /sys/module/tls
~~~

*(Expected kernel drivers: `ctr-aes-ls1024a-spacc` and `cbc-aes-ls1024a-spacc` with `priority : 300`, `min keysize : 16`, `max keysize : 32`, plus `/sys/module/tls` active.)*

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

Ensure `openssl_conf = openssl_init` is defined at the top level of `/etc/ssl/openssl.cnf` (before any `[section]` headers). Enabling `Options = KTLS` in `[ssl_default_sect]` allows OpenSSL 3.5 to offload TLS 1.3 `AES-GCM` sockets to the Linux kernel automatically:

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

### End-to-End Byte-Exactness Check (`AES-128 / 192 / 256`)

~~~bash
dd if=/dev/urandom bs=65536 count=4 of=/tmp/test_in.bin status=none && \
for bits in 128 192 256; do
  KEY=$(head -c $((bits / 8)) /dev/urandom | od -An -tx1 | tr -d ' \n')
  IV="00112233445566778899aabbccddeeff"
  for mode in ctr cbc; do
    openssl enc -aes-${bits}-${mode} -bufsize 65536 -provider afalgprov -K "$KEY" -iv "$IV" -in /tmp/test_in.bin -out /tmp/test_enc.bin && \
    openssl enc -d -aes-${bits}-${mode} -bufsize 65536 -provider default -K "$KEY" -iv "$IV" -in /tmp/test_enc.bin -out /tmp/test_dec.bin && \
    cmp -s /tmp/test_in.bin /tmp/test_dec.bin && echo "AES-${bits}-${mode^^}: OK" || echo "AES-${bits}-${mode^^}: FAIL"
  done
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
