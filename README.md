# afalgprov — OpenSSL 3.5 AF_ALG Provider for NXP LS1024A

Hardware-accelerated **OpenSSL 3.5+** provider built on the Linux `AF_ALG` socket interface for **NXP QorIQ LS1024A (Comcerto 2000, Dual ARMv7 Cortex-A9)**. It offloads symmetric and authenticated encryption to the **Elliptic SPACC** DMA crypto engine and **ARMv7 NEON `ghash-ce`** accelerator.
## Supported Algorithms

* **AES-128-CTR / AES-192-CTR / AES-256-CTR** (`skcipher` -> `ctr-aes-ls1024a-spacc`, SPACC DMA)
* **AES-128-GCM / AES-192-GCM / AES-256-GCM** (`aead` -> `gcm(aes)`, SPACC CTR DMA + ARMv7 NEON `ghash-ce`)

## Build and Installation

### Prerequisites

`gcc` and OpenSSL 3.x development headers (`libssl-dev`).

### Compile and Install

~~~bash
gcc -O2 -Wall -Wextra -fPIC -shared afalgprov.c -o afalgprov.so -lcrypto
install -m 0755 afalgprov.so "$(openssl version -m | awk -F'"' '{print $2}')/"
~~~

### Enable in `/etc/ssl/openssl.cnf`

Add `afalgprov` to `[provider_sect]`. Ensure `/etc/ssl/openssl.cnf` has `0644` permissions so unprivileged users can load the configuration:

~~~ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
afalgprov = afalgprov_sect
default = default_sect

[afalgprov_sect]
activate = 1
# Optional: minimum payload size in bytes for CTR hardware offload (default: 8192)
# hw-threshold = 8192

[default_sect]
activate = 1
~~~

### Verify Provider Loading

~~~bash
su -s /bin/sh nobody -c "openssl list -providers"
~~~

Expected output:

~~~text
Providers:
  afalgprov
    name: NXP LS1024A SPACC AF_ALG Provider
    version: 3.5
    status: active
  default
    name: OpenSSL Default Provider
    version: 3.5.9
    status: active
~~~

## Benchmarks

Measured on **NXP LS1024A (Dual ARMv7 Cortex-A9)** under default kernel buffer limits (`net.core.wmem_max = 212992`, `net.core.rmem_max = 212992`) with **64 KiB (`65536` bytes)** blocks (`openssl speed -elapsed`, `~3.07s–3.11s` wall time):

### CTR Throughput and CPU Usage (64 KiB)

| Algorithm | Threads | Provider | Throughput | `user` + `sys` | Gain vs Pure CPU |
| :--- | :---: | :--- | :---: | :---: | :---: |
| **AES-128-CTR** | 1T | `default` (Pure CPU) | **29.03 MB/s** (`29032.45k`) | `3.04s + 0.03s` | — |
| **AES-192-CTR** | 1T | `default` (Pure CPU) | **24.58 MB/s** (`24576.00k`) | `3.04s + 0.02s` | — |
| **AES-256-CTR** | 1T | `default` (Pure CPU) | **21.30 MB/s** (`21299.20k`) | `3.04s + 0.02s` | — |
| **AES-128-CTR** | 1T | `afalgprov` (SPACC) | **41.94 MB/s** (`41943.04k`) | `0.07s + 0.73s` | **+44.5%** (`1.44x`) |
| **AES-192-CTR** | 1T | `afalgprov` (SPACC) | **41.75 MB/s** (`41746.43k`) | `0.06s + 0.76s` | **+69.9%** (`1.70x`) |
| **AES-256-CTR** | 1T | `afalgprov` (SPACC) | **41.62 MB/s** (`41615.36k`) | `0.05s + 0.78s` | **+95.4%** (`1.95x`) |
| **AES-128-CTR** | 2T | `afalgprov` (SPACC) | **58.37 MB/s** (`58370.73k`) | `0.10s + 1.65s` | **+2.0%** vs 2T CPU (`57.23k`) |
| **AES-192-CTR** | 2T | `afalgprov` (SPACC) | **58.84 MB/s** (`58840.88k`) | `0.08s + 1.62s` | **+21.7%** vs 2T CPU (`48.34k`) |
| **AES-256-CTR** | 2T | `afalgprov` (SPACC) | **58.73 MB/s** (`58731.00k`) | `0.11s + 1.58s` | **+40.0%** vs 2T CPU (`41.94k`) |
| **AES-128-CTR** | 4T | `afalgprov` (SPACC) | **64.50 MB/s** (`64495.75k`) | `0.20s + 2.42s` | **+16.4%** vs 4T CPU (`55.41k`) |
| **AES-192-CTR** | 4T | `afalgprov` (SPACC) | **64.51 MB/s** (`64506.27k`) | `0.20s + 2.37s` | **+37.2%** vs 4T CPU (`47.03k`) |
| **AES-256-CTR** | 4T | `afalgprov` (SPACC) | **64.29 MB/s** (`64288.68k`) | `0.18s + 2.44s` | **+57.5%** vs 4T CPU (`40.83k`) |

### GCM & AEAD Throughput (64 KiB)

| Algorithm & Mode | Threads | Provider | Throughput | `user` + `sys` / Notes |
| :--- | :---: | :--- | :---: | :--- |
| **AES-128-GCM** | 1T | `default` (Pure CPU) | **12.87 MB/s** (`12866.90k`) | `3.04s + 0.02s` |
| **AES-192-GCM** | 1T | `default` (Pure CPU) | **11.91 MB/s** (`11905.71k`) | `3.04s + 0.02s` |
| **AES-256-GCM** | 1T | `default` (Pure CPU) | **11.08 MB/s** (`11075.58k`) | `3.04s + 0.02s` |
| **AES-128-GCM** | 1T | `afalgprov` (SPACC) | **26.63 MB/s** (`26629.46k`) | `0.08s + 0.39s` (**+107.0%**, `2.07x`) |
| **AES-192-GCM** | 1T | `afalgprov` (SPACC) | **26.59 MB/s** (`26585.77k`) | `0.05s + 0.40s` (**+123.3%**, `2.23x`) |
| **AES-256-GCM** | 1T | `afalgprov` (SPACC) | **26.43 MB/s** (`26432.85k`) | `0.10s + 0.39s` (**+138.7%**, `2.39x`) |
| **ChaCha20-Poly1305** | 1T | `default` (Pure CPU) | **61.73 MB/s** (`61734.91k`) | `2826 ops / 3.00s` (SW reference) |

### Summary

* **Single-thread `AES-128/192/256-GCM`:** **2.07x–2.39x** faster than pure CPU (`26.43–26.63 MB/s` vs `11.08–12.87 MB/s`) with ~**6.5x** lower `user + sys` CPU time.
* **Multi-thread `AES-CTR` Scaling:** Scales from **~41.6–41.9 MB/s** (`1T`) to **~58.4–58.8 MB/s** (`2T`) and **~64.3–64.5 MB/s** (`4T`), with matching IRQ 45 (`9b000000.crypto`) activity on SPACC.
