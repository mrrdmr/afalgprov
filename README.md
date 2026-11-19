# afalgprov — OpenSSL 3.5 AF_ALG Provider for NXP LS1024A (SPACC DMA)

A dynamic cryptographic provider for **OpenSSL 3.5** on the **NXP LS1024A** platform (ARM Cortex-A9, `OPENSSL_armcap=0x1`, Debian `arm-linux-gnueabihf`), providing hardware offloading of symmetric encryption via the Linux kernel **`AF_ALG`** socket interface and the **SPACC (`9b000000.crypto`)** cryptographic DMA engine.

---

## 1. Purpose and Architecture

ARM Cortex-A9 processors lack hardware AES cryptographic instructions (ARMv8 Crypto Extensions), causing software encryption in user space to fully saturate a single CPU core. The **`afalgprov` (v2.1.0)** module integrates globally into OpenSSL 3.5 with a soft system-wide preference (`?provider=afalgprov`) and implements a hybrid execution model: large streaming buffers are offloaded to the hardware DMA accelerator, while small packets and AEAD modes are handled by the optimized user-space `default` provider.

### Registered Algorithms and Buffer Routing

| OpenSSL Name | Kernel Driver Name (`AF_ALG`) | Key Size (bits) | Buffer `< 8192` B / `% 16` Remainder | Buffer `? 8192` B (16-Byte Aligned) | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`AES-128-CTR`** (`aes-128-ctr`) | `ctr-aes-ls1024a-spacc` | 128 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | `OpenSSH`, `SFTP`, `SCP` (`aes128-ctr`) |
| **`AES-192-CTR`** (`aes-192-ctr`) | `ctr-aes-ls1024a-spacc` | 192 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | Streaming channels (192-bit) |
| **`AES-256-CTR`** (`aes-256-ctr`) | `ctr-aes-ls1024a-spacc` | 256 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | `OpenSSH` (`aes256-ctr`), `openssl enc` |
| **`AES-128-CBC`** (`aes-128-cbc`) | `cbc-aes-ls1024a-spacc` | 128 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | `openssl enc`, file encryption, VPN |
| **`AES-192-CBC`** (`aes-192-cbc`) | `cbc-aes-ls1024a-spacc` | 192 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | Data encryption (192-bit) |
| **`AES-256-CBC`** (`aes-256-cbc`) | `cbc-aes-ls1024a-spacc` | 256 | Software fallback (`default`) | **Hardware SPACC (`AF_ALG`)** | `openssl enc -aes-256-cbc`, TLS 1.3 Session Tickets |

*(All other algorithms — `AES-GCM`, `ChaCha20-Poly1305`, `RSA`, `ECDSA`, `Ed25519`, `SHA-256`, etc. — are intentionally excluded from `afalgprov` and handled directly by the `default` provider.)*

### Key Mechanisms and Design Decisions

* **Block-Size Threshold (`8192` bytes) and Chunking (`65536` bytes):**
  Invoking an `AF_ALG` socket incurs system call overhead (`sendmsg` / `read`), user-kernel memory copies, and hardware interrupt handling on IRQ 45 (`9b000000.crypto`). For chunks smaller than 8 KB, the module delegates operations to an internal software context (`sw_ctx` from `default`). Starting at 8 KB, it switches to SPACC DMA, splitting large buffers into 64 KB chunks (`MAX_HW_CHUNK`) to stay within kernel socket buffer limits.
* **16-Byte Alignment for `AES-CTR`:**
  The `ctr-aes-ls1024a-spacc` kernel driver and hardware DMA maintain only the 16-byte counter between calls and do not cache unused keystream bytes. For buffers `? 8192` bytes, the aligned portion (`len & ~15`) is sent to SPACC DMA, while the trailing remainder (`1–15` bytes) is processed by `sw_ctx` while preserving intra-block offset state (`sw_unaligned`).
* **In-Place Safety (`out == in`) and IV Synchronization (`iv_dirty`):**
  During `AES-CBC` decryption, the next 16-byte IV is saved from the input ciphertext before the buffer is overwritten. The `iv_dirty` flag synchronizes the IV back to the software context only when transitioning from DMA to `sw_ctx` or when finalizing PKCS#7 padding (`afalg_final` for TLS 1.3 Session Tickets).
* **Lazy Kernel Descriptor Initialization:**
  `AF_ALG` sockets are opened with `SOCK_CLOEXEC` only when a buffer `? 8192` bytes is actually processed, preventing file descriptor exhaustion on short-lived connections.
* **Why `AES-GCM` Is Excluded from `afalgprov`:**
  1. OpenSSL's streaming `EVP` API (`EVP_CipherUpdate` + separate `OSSL_CIPHER_PARAM_AEAD_TAG`) conflicts with the atomic packet interface of `algif_aead` (`AAD + payload + tag` in a single `sendmsg`), which would require buffering entire packets in user space.
  2. Intermediate Galois Field (`GHASH`) multiplier states cannot be exported/imported between `default` and SPACC DMA during hybrid fallback switching.
  3. `libssl` relies on internal TLS IV management parameters (`AEAD_TLS1_AAD`, `AEAD_IV_GEN`) for TLS 1.2/1.3, and TLS records are capped at `? 16` KB where kernel context-switch overhead outweighs DMA acceleration.
  4. On ARMv7 NEON, software `ChaCha20-Poly1305` is 4.7x–5.5x faster than `AES-128-GCM` (**60.9–71.1 MB/s** vs. **12.8–13.0 MB/s**).

---

## 2. System Preparation and Dependencies

### 2.1. Install Build Packages
```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev
```

### 2.2. Verify Hardware Crypto Engine and Kernel Modules
```bash
grep crypto /proc/interrupts
lsmod | grep -E "af_alg|algif_skcipher"
```
## 3. Compile and Install into ossl-modules
```bash
sudo make clean all
sudo make install
```
### 3.1. Verify the installed shared library, OpenSSL Configuration
```bash
ls -l /usr/lib/arm-linux-gnueabihf/ossl-modules/afalgprov.so
ldd /usr/lib/arm-linux-gnueabihf/ossl-modules/afalgprov.so
sudo cp -a /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.bak
```
Sample /etc/ssl/openssl.cnf provided

## 4. Restart Services, Verification and Diagnostics
```bash
sudo systemctl restart ssh
openssl list -providers
openssl list -cipher-algorithms -provider afalgprov
openssl ciphers -v -tls1_3
```
## 5. Reverting Changes (Uninstall)
```bash
sudo cp -a /etc/ssl/openssl.cnf.bak /etc/ssl/openssl.cnf
sudo make -C /usr/local/src/afalgprov uninstall
sudo systemctl restart ssh
```
