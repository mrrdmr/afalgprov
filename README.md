# afalgprov — OpenSSL 3.5 AF_ALG Provider for NXP LS1024A

Hardware-accelerated **OpenSSL 3.5+** provider built on the Linux `AF_ALG` socket interface for **NXP QorIQ LS1024A (Comcerto 2000, Dual ARMv7 Cortex-A9)** on Linux kernel [`symops/MCG1-6.18`](https://github.com/symops/MCG1-6.18) ([PR #13](https://github.com/symops/MCG1-6.18/pull/13)). It offloads symmetric and authenticated encryption to the **Elliptic SPACC** DMA crypto engine and **ARMv7 NEON `ghash-ce`** accelerator.
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

Measured on **NXP LS1024A (Dual ARMv7 Cortex-A9)** under default kernel buffer limits (`net.core.wmem_max = 212992`, `net.core.rmem_max = 212992`) with **64 KiB (`65536` bytes)** blocks (`openssl speed -elapsed`, `~3.06s–3.11s` wall time).

### How Total CPU Load Is Calculated (2 Cores)

Total CPU load is computed across **both Cortex-A9 physical cores** as:

`Total CPU Load = (user + sys) / (2 * real)`

* **100% total CPU load** means **both cores** are saturated (`user + sys ≈ 2 * real`, e.g. `~6.07s` across `~3.07s` elapsed time).
* A single saturated thread on a dual-core chip therefore equals **~50% total CPU load** (`~3.06s / (2 * 3.06s) ≈ 50.0%`), which is why `1T` pure CPU sits around `~49.8%–50.0%`, while `2T` and `4T` pure CPU reach `~98.2%–99.4%` as threads contend for the 2 available cores.
* With `afalgprov` offload, DMA transfers and SPACC hardware execution reduce `user` time while `sys` reflects `AF_ALG` socket/syscall and IRQ 45 (`9b000000.crypto`) handling, lowering total 2-core utilization even as multi-thread concurrency increases.

### CTR Throughput and CPU Usage (64 KiB)

| Algorithm | Threads | Provider | Throughput | Gain vs Pure CPU | CPU Load | CPU Load Delta |
| :--- | :---: | :--- | :---: | :---: | :---: | :---: |
| **AES-128-CTR** | 1T | `default` (Pure CPU) | **29.03 MB/s** (`29032.45k`) | — | `50.0%` (`3.07s`) | — |
| **AES-192-CTR** | 1T | `default` (Pure CPU) | **24.58 MB/s** (`24576.00k`) | — | `50.0%` (`3.06s`) | — |
| **AES-256-CTR** | 1T | `default` (Pure CPU) | **21.30 MB/s** (`21299.20k`) | — | `49.8%` (`3.06s`) | — |
| **AES-128-CTR** | 1T | `afalgprov` (SPACC) | **41.94 MB/s** (`41943.04k`) | **+44.5%** (`1.44x`) | `13.0%` (`0.80s`) | **-73.9%** (`-37.0` pp) |
| **AES-192-CTR** | 1T | `afalgprov` (SPACC) | **41.75 MB/s** (`41746.43k`) | **+69.9%** (`1.70x`) | `13.4%` (`0.82s`) | **-73.2%** (`-36.6` pp) |
| **AES-256-CTR** | 1T | `afalgprov` (SPACC) | **41.62 MB/s** (`41615.36k`) | **+95.4%** (`1.95x`) | `13.5%` (`0.83s`) | **-72.9%** (`-36.3` pp) |
| **AES-128-CTR** | 2T | `default` (Pure CPU) | **57.23 MB/s** (`57228.93k`) | — | `98.9%` (`6.07s`) | — |
| **AES-192-CTR** | 2T | `default` (Pure CPU) | **48.34 MB/s** (`48336.71k`) | — | `98.9%` (`6.07s`) | — |
| **AES-256-CTR** | 2T | `default` (Pure CPU) | **41.94 MB/s** (`41943.04k`) | — | `99.2%` (`6.09s`) | — |
| **AES-128-CTR** | 2T | `afalgprov` (SPACC) | **58.37 MB/s** (`58370.73k`) | **+2.0%** vs 2T CPU | `28.5%` (`1.75s`) | **-71.2%** (`-70.4` pp) |
| **AES-192-CTR** | 2T | `afalgprov` (SPACC) | **58.84 MB/s** (`58840.88k`) | **+21.7%** vs 2T CPU | `27.7%` (`1.70s`) | **-72.0%** (`-71.2` pp) |
| **AES-256-CTR** | 2T | `afalgprov` (SPACC) | **58.73 MB/s** (`58731.00k`) | **+40.0%** vs 2T CPU | `27.5%` (`1.69s`) | **-72.2%** (`-71.7` pp) |
| **AES-128-CTR** | 4T | `default` (Pure CPU) | **55.41 MB/s** (`55405.32k`) | — | `99.4%` (`6.12s`) | — |
| **AES-192-CTR** | 4T | `default` (Pure CPU) | **47.03 MB/s** (`47028.25k`) | — | `99.4%` (`6.12s`) | — |
| **AES-256-CTR** | 4T | `default` (Pure CPU) | **40.83 MB/s** (`40828.93k`) | — | `99.4%` (`6.12s`) | — |
| **AES-128-CTR** | 4T | `afalgprov` (SPACC) | **64.50 MB/s** (`64495.75k`) | **+16.4%** vs 4T CPU | `42.5%` (`2.62s`) | **-57.2%** (`-56.8` pp) |
| **AES-192-CTR** | 4T | `afalgprov` (SPACC) | **64.51 MB/s** (`64506.27k`) | **+37.2%** vs 4T CPU | `41.7%` (`2.57s`) | **-58.0%** (`-57.6` pp) |
| **AES-256-CTR** | 4T | `afalgprov` (SPACC) | **64.29 MB/s** (`64288.68k`) | **+57.5%** vs 4T CPU | `42.5%` (`2.62s`) | **-57.2%** (`-56.8` pp) |

### GCM & AEAD Throughput and CPU Load (64 KiB)

| Algorithm & Mode | Threads | Provider | Throughput | Gain vs CPU | CPU Load | CPU Load Delta |
| :--- | :---: | :--- | :---: | :---: | :---: | :---: |
| **AES-128-GCM** | 1T | `default` (Pure CPU) | **12.87 MB/s** (`12866.90k`) | — | `49.9%` (`3.06s`) | — |
| **AES-192-GCM** | 1T | `default` (Pure CPU) | **11.91 MB/s** (`11905.71k`) | — | `49.8%` (`3.06s`) | — |
| **AES-256-GCM** | 1T | `default` (Pure CPU) | **11.08 MB/s** (`11075.58k`) | — | `49.8%` (`3.06s`) | — |
| **AES-128-GCM** | 1T | `afalgprov` (SPACC) | **26.63 MB/s** (`26629.46k`) | **+107.0%** (`2.07x`) | `7.7%` (`0.47s`) | **-84.6%** (`-42.2` pp) |
| **AES-192-GCM** | 1T | `afalgprov` (SPACC) | **26.59 MB/s** (`26585.77k`) | **+123.3%** (`2.23x`) | `7.3%` (`0.45s`) | **-85.3%** (`-42.5` pp) |
| **AES-256-GCM** | 1T | `afalgprov` (SPACC) | **26.43 MB/s** (`26432.85k`) | **+138.7%** (`2.39x`) | `8.0%` (`0.49s`) | **-84.0%** (`-41.8` pp) |
| **AES-128-GCM** | 2T | `default` (Pure CPU) | **25.45 MB/s** (`25448.43k`) | — | `98.4%` (`6.08s`) | — |
| **AES-192-GCM** | 2T | `default` (Pure CPU) | **23.53 MB/s** (`23527.42k`) | — | `98.4%` (`6.08s`) | — |
| **AES-256-GCM** | 2T | `default` (Pure CPU) | **21.87 MB/s** (`21867.18k`) | — | `98.5%` (`6.09s`) | — |
| **AES-128-GCM** | 2T | `afalgprov` (SPACC) | **32.03 MB/s** (`32025.26k`) | **+25.8%** vs 2T CPU | `13.4%` (`0.83s`) | **-86.3%** (`-85.0` pp) |
| **AES-192-GCM** | 2T | `afalgprov` (SPACC) | **31.96 MB/s** (`31959.72k`) | **+35.8%** vs 2T CPU | `12.8%` (`0.79s`) | **-87.0%** (`-85.6` pp) |
| **AES-256-GCM** | 2T | `afalgprov` (SPACC) | **31.89 MB/s** (`31894.19k`) | **+45.9%** vs 2T CPU | `12.5%` (`0.77s`) | **-87.4%** (`-86.1` pp) |
| **AES-128-GCM** | 4T | `default` (Pure CPU) | **24.90 MB/s** (`24902.20k`) | — | `98.7%` (`6.14s`) | — |
| **AES-192-GCM** | 4T | `default` (Pure CPU) | **22.91 MB/s** (`22912.98k`) | — | `98.2%` (`6.11s`) | — |
| **AES-256-GCM** | 4T | `default` (Pure CPU) | **21.42 MB/s** (`21416.26k`) | — | `98.6%` (`6.13s`) | — |
| **AES-128-GCM** | 4T | `afalgprov` (SPACC) | **32.54 MB/s** (`32543.41k`) | **+30.7%** vs 4T CPU | `15.3%` (`0.95s`) | **-84.5%** (`-83.4` pp) |
| **AES-192-GCM** | 4T | `afalgprov` (SPACC) | **32.39 MB/s** (`32385.09k`) | **+41.3%** vs 4T CPU | `14.3%` (`0.89s`) | **-85.4%** (`-83.9` pp) |
| **AES-256-GCM** | 4T | `afalgprov` (SPACC) | **32.36 MB/s** (`32358.13k`) | **+51.1%** vs 4T CPU | `14.5%` (`0.90s`) | **-85.3%** (`-84.1` pp) |

### Summary

* **Single-thread `AES-128/192/256-GCM`:** **2.07x–2.39x** faster than pure CPU (`26.43–26.63 MB/s` vs `11.08–12.87 MB/s`) while cutting total 2-core CPU load from **~49.8–49.9%** down to **~7.3–8.0%** (`-84.0%` to `-85.3%`).
* **Multi-thread `AES-128/192/256-GCM`:** Reaches **~31.9–32.0 MB/s** (`2T`) and plateaus at **~32.4–32.5 MB/s** (`4T`), reducing total 2-core CPU load from **~98.2–98.7%** to **~12.5–13.4%** (`2T`, `-86.3%` to `-87.4%`) and **~14.3–15.3%** (`4T`, `-84.5%` to `-85.4%`).
* **Multi-thread `AES-CTR` Scaling:** Scales from **~41.6–41.9 MB/s** (`1T`) to **~58.4–58.8 MB/s** (`2T`) and **~64.3–64.5 MB/s** (`4T`), cutting 2-core CPU load to **~13.0–13.5%** (`1T`, `-72.9%` to `-73.9%`), **~27.5–28.5%** (`2T`, `-71.2%` to `-72.2%`), and **~41.7–42.5%** (`4T`, `-57.2%` to `-58.0%`) with matching IRQ 45 (`9b000000.crypto`) activity on SPACC.
