# afalgprov — OpenSSL 3.5 AF_ALG Provider for NXP LS1024A (SPACC cryptographic engine)

A dynamic cryptographic provider for **OpenSSL 3.5** on the **NXP LS1024A** platform
(ARM Cortex-A9, `OPENSSL_armcap=0x1`, Debian `arm-linux-gnueabihf`), offloading
symmetric encryption to the **SPACC (`9b000000.crypto`)** engine through the Linux
kernel **`AF_ALG`** socket interface (`vmsplice`/`splice` pipeline).

---

## 1. Purpose and Architecture

Cortex-A9 has no ARMv8 crypto extensions, so software AES saturates one core.
`afalgprov` registers into OpenSSL 3.5 with a soft preference
(`?provider=afalgprov`) and routes large streaming buffers to the engine, while
small packets, unaligned tails, padded CBC decryption and AEAD stay in the
`default` provider (with optional **kTLS** for `AES-GCM`).

### Registered Algorithms and Buffer Routing

| OpenSSL Name | Kernel Driver Name (`AF_ALG`) | Key Size | Buffer `< 16384` B | Buffer `≥ 16384` B | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`AES-128-CTR`** | `ctr-aes-ls1024a-spacc` | 128 | `default` | **SPACC** | OpenSSH, SFTP, SCP |
| **`AES-192-CTR`** | `ctr-aes-ls1024a-spacc` | 192 | `default` | **SPACC** | streaming channels |
| **`AES-256-CTR`** | `ctr-aes-ls1024a-spacc` | 256 | `default` | **SPACC** | OpenSSH, `openssl enc` |
| **`AES-128-CBC`** | `cbc-aes-ls1024a-spacc` | 128 | `default` | **SPACC** | `openssl enc`, backups, VPN |
| **`AES-192-CBC`** | `cbc-aes-ls1024a-spacc` | 192 | `default` | **SPACC** | data encryption |
| **`AES-256-CBC`** | `cbc-aes-ls1024a-spacc` | 256 | `default` | **SPACC** | `openssl enc`, TLS 1.3 tickets |

Everything else (`AES-GCM`, `ChaCha20-Poly1305`, RSA, ECDSA, SHA-2) is left to
`default` or kTLS.

### Key Mechanisms and Design Decisions

- **`vmsplice` + `splice` pipeline, 57 344-byte chunks.**
  Input pages are mapped into an internal pipe with `vmsplice()` and forwarded
  to the `AF_ALG` operation socket with `splice()` (`SPLICE_F_MORE` between
  chunks), so the provider itself adds no data copies.

- **Why 57 344 and not 65 536.**
  The kernel driver accepts a command only if the source fits **15 DDT entries**
  (the descriptor prefetcher stops at 16 including the terminator). 57 344 B =
  14 pages, and even an unaligned buffer spans at most 15 pages. A 65 536-byte
  request spans 16 pages and is rejected to software. Consequently a 64 KiB
  OpenSSL buffer becomes **two commands — 57 344 + 8 192 — and two interrupts**,
  not one. Measured on hardware: 9 875 blocks produced exactly 19 750 SPACC
  interrupts (2.00 per block).

- **The driver never writes into user pages.**
  The source scatterlist is mapped read-only; the destination is a per-slot
  bounce buffer in driver memory, and the CPU copies the result into the request
  after `dma_sync`. This is not an optimisation: writing into pages the CPU had
  dirtied corrupted the final 8–24 bytes of a command under memory-bus
  contention (~1 % of commands, measured), and the bounce buffer is the only
  configuration that is clean under load — 0 failures in 3 480 commands with
  eight threads hammering the engine. The price is exactly one `memcpy` per
  command, about 13 % of throughput, and it is included in the numbers below.
  The provider's own path stays zero-copy; the copy happens in the kernel
  driver, by design.

- **Pipe and socket sizing.** Internal pipe (`F_SETPIPE_SZ`) and
  `SO_SNDBUF`/`SO_RCVBUF` are set to `4 × 57 344 = 229 376` bytes, enough to
  keep a full chunk in flight without stalls.

- **Threshold (`hw-threshold`, default 16 384).**
  Below the threshold the syscall and interrupt overhead outweighs the engine,
  and the `default` provider is faster; from 16 KiB upward requests go to SPACC.
  The `CMSG` control buffer is allocated once per context, so the hot path has
  no heap traffic.

- **In-place safety and IV synchronisation (`iv_dirty` / `sw_unaligned`).**
  For CBC decryption the next IV is taken from the input ciphertext before the
  buffer is overwritten; the updated IV is pushed back into `sw_ctx` only when
  switching from DMA to software or at `afalg_final`. Padded CBC decryption runs
  entirely in software because OpenSSL keeps the final block until
  `EVP_CipherFinal_ex`.

- **Lazy descriptor initialisation.** `AF_ALG` sockets and the pipe are created
  only when a buffer at or above the threshold is processed, avoiding descriptor
  exhaustion on short-lived connections.

- **Why `AES-GCM` is not offloaded (and how kTLS covers it).**
  1. The driver exports `cbc(aes)`, `ctr(aes)` and `ecb(aes)`, not `gcm(aes)`.
  2. OpenSSL's streaming `EVP` interface does not match `algif_aead`'s atomic
     `AAD + payload + tag` packet model without buffering whole records.
  3. GHASH state cannot be exported between `default` and the engine during a
     hybrid switch.
  4. **kTLS** (`Options = KTLS`, `tls` module loaded) hands established TLS 1.3
     `AES-GCM` sockets to the kernel, removes the user/kernel copy and enables
     `SSL_sendfile()`; measured client CPU time dropped from 13.28 s to 3.47 s
     (−73.9 %) on a 128 MiB loopback transfer.
  5. For maximum TLS 1.3 throughput prefer `TLS_CHACHA20_POLY1305_SHA256`:
     **61.1 MB/s** versus **12.8 MB/s** for software `AES-128-GCM`.

---

### Performance Benchmarks on NXP LS1024A

OpenSSL 3.5, 65 536-byte blocks, `-elapsed`, `/usr/bin/time -p`. The hardware
column includes the driver's bounce copy. IRQ counter (`9b000000.crypto`,
IRQ 45) went from **21 645** to **41 395** across the six hardware runs, i.e.
+19 750 interrupts for 9 875 blocks.

| Algorithm | Pure CPU (`OPENSSL_CONF=/dev/null`) | SPACC + `afalgprov` | Gain | CPU time, user+sys (3 s run) |
| :--- | ---: | ---: | ---: | :--- |
| **AES-128-CTR** | 28 892 k | **36 110 k** | +25 % (1.25×) | 0.07 + 0.85 s |
| **AES-128-CBC** | 22 326 k | **35 957 k** | +61 % (1.61×) | 0.09 + 0.76 s |
| **AES-192-CTR** | 24 510 k | **35 979 k** | +47 % (1.47×) | 0.07 + 0.82 s |
| **AES-192-CBC** | 19 617 k | **35 870 k** | +83 % (1.83×) | 0.08 + 0.82 s |
| **AES-256-CTR** | 21 228 k | **35 957 k** | +69 % (1.69×) | 0.08 + 0.81 s |
| **AES-256-CBC** | 17 149 k | **35 848 k** | +109 % (2.09×) | 0.08 + 0.81 s |
| **ChaCha20-Poly1305** | 61 058 k | — (not supported) | — | ~1 core |
| **AES-128-GCM** | 12 845 k | — (use kTLS) | — | — |

#### TLS 1.3 `AES-128-GCM` loopback, 128 MiB

| Configuration | kTLS (TX/RX) | Throughput | Client CPU |
| :--- | :--- | ---: | ---: |
| user-space OpenSSL | 0 / 0 | 9.20 MB/s | 13.28 s |
| `Options = KTLS` | 2 / 2 | **9.84 MB/s** | **3.47 s** (−73.9 %) |

### Key takeaways

1. **Flat 35.8–36.1 MB/s across all key lengths.** Software AES degrades with
   key size (28.9 → 17.1 MB/s), the engine does not, so the relative gain grows
   to **2.09× on AES-256-CBC** while user-space CPU drops from ~3.0 s to
   ~0.08 s.
2. **Exactly two interrupts per 64 KiB block**, matching the 57 344 + 8 192
   split. Any claim of one interrupt per block predates the 15-entry limit.
3. **The ceiling moved from 44.9 to ~36 MB/s on purpose.** The earlier 40–41
   MB/s figures were measured on a driver that wrote straight into user pages;
   that driver silently corrupted the tail of ~1 % of commands under load. The
   bounce buffer costs the 13 % and buys correctness.
4. **Best system-wide split:** `afalgprov` for streaming AES-CTR/CBC, kTLS for
   `AES-GCM`, and `ChaCha20-Poly1305` first in the TLS 1.3 ciphersuite list.

### Reproducing the numbers

~~~bash
grep crypto /proc/interrupts

echo "=== pure CPU ==="
for alg in aes-128-ctr aes-128-cbc aes-192-ctr aes-192-cbc aes-256-ctr aes-256-cbc; do
  OPENSSL_CONF=/dev/null /usr/bin/time -p openssl speed -elapsed -provider default \
    -evp "$alg" -bytes 65536 2>&1 | grep -E "Doing|AES-|real|user|sys"
done

grep crypto /proc/interrupts

echo "=== SPACC ==="
for alg in aes-128-ctr aes-128-cbc aes-192-ctr aes-192-cbc aes-256-ctr aes-256-cbc; do
  /usr/bin/time -p openssl speed -elapsed -provider afalgprov \
    -evp "$alg" -bytes 65536 2>&1 | grep -E "Doing|AES-|real|user|sys"
done

grep crypto /proc/interrupts
~~~

---

## 2. System Preparation

~~~bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev

uname -a
grep crypto /proc/interrupts
grep -B 1 -A 14 -E "name\s*:\s*(cbc|ctr)\(aes\)" /proc/crypto
lsmod | grep -E "af_alg|algif_skcipher|ls1024a_spacc"

sudo modprobe tls
echo "tls" | sudo tee /etc/modules-load.d/ktls.conf >/dev/null
ls -d /sys/module/tls
~~~

Expected drivers: `ctr-aes-ls1024a-spacc` and `cbc-aes-ls1024a-spacc`,
`priority : 500`, key sizes 16–32. The kernel driver has no module parameter:
the engine is always enabled, and requests below 8 KiB fall back to software on
their own.

## 3. Build and Install

~~~bash
sudo make clean all
sudo make install

ls -l /usr/lib/arm-linux-gnueabihf/ossl-modules/afalgprov.so
ldd /usr/lib/arm-linux-gnueabihf/ossl-modules/afalgprov.so
sudo cp -an /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.bak
~~~

### Global configuration

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
hw-threshold = 16384

[evp_properties]
default_properties = ?provider=afalgprov

[ssl_sect]
system_default = ssl_default_sect

[ssl_default_sect]
Options = KTLS
Ciphersuites = TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
~~~

Validate before replacing the system file:
`OPENSSL_CONF=/tmp/openssl.cnf.test openssl list -providers`.

### Per-service isolation

Save the same block to `/etc/ssl/openssl-spacc.cnf` and start the service with
`OPENSSL_CONF=/etc/ssl/openssl-spacc.cnf`, or set it in the unit's
`Environment=`. Sandboxes must allow `socket`, `bind`, `accept4`, `pipe2`,
`vmsplice`, `splice` (plus `setsockopt` for `SOL_TLS`).

## 4. Verification

~~~bash
sudo systemctl restart ssh
openssl list -providers
openssl list -cipher-algorithms -provider afalgprov | grep "@ afalgprov"
~~~

### kTLS offload check

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

### Byte-exactness, all key sizes

~~~bash
dd if=/dev/urandom bs=65536 count=4 of=/tmp/test_in.bin status=none
for bits in 128 192 256; do
  KEY=$(head -c $((bits / 8)) /dev/urandom | od -An -tx1 | tr -d ' \n')
  IV="00112233445566778899aabbccddeeff"
  for mode in ctr cbc; do
    openssl enc -aes-${bits}-${mode} -bufsize 65536 -provider afalgprov \
      -K "$KEY" -iv "$IV" -in /tmp/test_in.bin -out /tmp/test_enc.bin &&
    openssl enc -d -aes-${bits}-${mode} -bufsize 65536 -provider default \
      -K "$KEY" -iv "$IV" -in /tmp/test_enc.bin -out /tmp/test_dec.bin &&
    cmp -s /tmp/test_in.bin /tmp/test_dec.bin &&
      echo "AES-${bits}-${mode^^}: OK" || echo "AES-${bits}-${mode^^}: FAIL"
  done
done
rm -f /tmp/test_in.bin /tmp/test_enc.bin /tmp/test_dec.bin
~~~

## 5. Uninstall

~~~bash
sudo cp -a /etc/ssl/openssl.cnf.bak /etc/ssl/openssl.cnf
sudo rm -f /etc/modules-load.d/ktls.conf
sudo make -C uninstall
sudo systemctl restart ssh
openssl list -providers
~~~
