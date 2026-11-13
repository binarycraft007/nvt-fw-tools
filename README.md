# Novatek Firmware Tools (Open-Source C Implementation)

This project contains standalone, portable, open-source C implementations of Novatek's proprietary firmware packaging, checksumming, and signing tools for the **Novatek NT9853x / NT9668x** SoC families.

These tools completely eliminate all dependencies on vendor closed-source binaries (`encrypt_sign_tool`, `nvt-ld-op`, `encrypt_bin`, and `nvtpack`).

---

## Tools Overview

| Open-Source Tool | Vendor Binary Replaced | Purpose | Dependencies |
| :--- | :--- | :--- | :--- |
| **`nvt_sign`** | `encrypt_sign_tool` | Computes raw RSA-2048 SHA-256 signatures, constructs Novatek 128-byte `HEADINFO` headers (offset `0x2C0` container), and calculates running compensation checksums. | Standard C, OpenSSL `libcrypto` |
| **`nvt_cksm`** | `nvt-ld-op`, `encrypt_bin` | Generates 64-byte `CKSM` (`NVTPACK_CHKSUM_HDR`) headers prepended to UBI filesystem partitions and patches `SUM` headers with Novatek's 16-bit running checksum. | Standard C (linked with `libcrypto` in `build.zig`) |
| **`nvtpack`** | `nvtpack` | Unpacks and repacks full all-in-one NAND factory images (`FW98538A.bin`) with `GUID_FW2`, partition table descriptors, and 64-byte payload alignment. | Standard C (linked with `libcrypto` in `build.zig`) |

---

## Directory Structure

```
nvt-fw-tools/
├── build.zig              # Zig build script for all three C executables
├── build.zig.zon          # Zig package manifest (minimum Zig 0.17.1)
├── README.md              # This documentation
├── include/
│   └── nvt_types.h        # Binary header structs, GUIDs, and checksum inlines
└── src
    ├── nvt_cksm.c         # nvt-ld-op / encrypt_bin replacement
    ├── nvt_sign.c         # encrypt_sign_tool replacement (RSA-2048 / HEADINFO)
    └── nvtpack.c          # nvtpack replacement (unpack, pack, list)
```

---

## Building and Installing

### Prerequisites

- **Zig** `>= 0.17.1` (compiles the C sources directly via `zig build`; `gcc` and `make` are not required)
- **OpenSSL development headers** (`libssl-dev` on Debian/Ubuntu) so Zig can link system `libcrypto`:
```bash
sudo apt-get install libssl-dev
```

### Build

```bash
zig build --release=fast
```

Standard debug builds also work with `zig build`, and Zig's `-Dtarget=<triple>` flag can be used to cross-compile if needed.

Compiled binaries are placed in `zig-out/bin/`:
- `zig-out/bin/nvt_sign`
- `zig-out/bin/nvt_cksm`
- `zig-out/bin/nvtpack`

---

## Command Reference & Usage Examples

### 1. `nvt_sign` (Signing & HEADINFO Container)

#### Modern CLI syntax:
```bash
# Sign an image:
nvt_sign -k rsa_priv.txt -p rsa_pub.txt -i uImage.bin -o uImage.signed.bin

# Verify a signed image:
nvt_sign -v uImage.signed.bin
```

#### Vendor `encrypt_sign_tool` compatible syntax:
```bash
encrypt_sign_tool 1 rsa_pub.txt rsa_priv.txt aes.txt input.bin output.signed.bin 0 0 0
```

### 2. `nvt_cksm` (Checksum Header)

#### Modern CLI syntax:
```bash
# Add 64-byte CKSM header:
nvt_cksm -i appfs.raw -o PAT15.bin -t 0x9

# Verify checksum of any Novatek binary:
nvt_cksm -c PAT15.bin
```

#### Vendor `nvt-ld-op` compatible syntax:
```bash
nvt-ld-op --packsum-src=appfs.raw --packsum-dst=PAT15.bin --packsum-type=0x9
```

### 3. `nvtpack` (Firmware Container)

#### Inspect image:
```bash
nvtpack -list FW98538A.bin
```

#### Unpack all partitions:
```bash
nvtpack -unpack FW98538A.bin -o ./extracted/
```
Extracts `PAT01.bin` .. `PAT20.bin` and generates `extracted/FW98538A.ini`.

#### Repack using INI file:
```bash
nvtpack -fw ./extracted/FW98538A.ini -o FW98538A.repacked.bin
```

#### Repack directly from partition binaries:
```bash
nvtpack -pack FW98538A.repacked.bin ./extracted/PAT*.bin
```

---

## Technical Specifications

### Secure Boot RSA-2048 Signing Layout
Novatek's U-Boot bootloader (`nvt_chk_signature_on_uboot` in `nvt_ivot_soc_utils.c`) enforces the following layout:
- **`0x000 - 0x07F` (128 bytes)**: `HEADINFO` container header (entry point, size, checksum at offset `0x6C`).
- **`0x080 - 0x19F` (288 bytes)**: Public Key blob ($N$: 256 bytes Big Endian, $E$: 32 bytes Big Endian).
- **`0x1A0 - 0x29F` (256 bytes)**: Raw RSA signature $s = m^d \pmod n$ over block $m = [\text{224 zero bytes}] + [\text{32-byte SHA-256 digest of payload padded to 64 bytes}]$.
- **`0x2A0 - 0x2BF` (32 bytes)**: Zero padding to align payload to offset `0x2C0` (704 bytes).
- **`0x2C0 - ...`**: Original binary payload (U-Boot, Kernel, or RootFS).
