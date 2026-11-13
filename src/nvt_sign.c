/**
 * nvt_sign - Open-source C replacement for Novatek's closed-source
 *            "encrypt_sign_tool" utility.
 *
 * Implements Novatek secure boot RSA-2048 signing for kernel, rootfs,
 * bootloader, and other partition images.
 *
 * Compatible with Novatek's rsa_priv.txt / rsa_pub.txt and standard OpenSSL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "nvt_types.h"

typedef struct {
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
} rsa_key_pair_t;

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  -i, --input <file>        Input binary image to sign\n"
        "  -o, --output <file>       Output signed Novatek container image\n"
        "  -k, --privkey <file>      RSA private key (Novatek rsa_priv.txt or PEM)\n"
        "  -p, --pubkey <file>       RSA public key (Novatek rsa_pub.txt, optional)\n"
        "  -v, --verify <file>       Verify signature and checksum of a signed binary\n"
        "  -h, --help                Show this help message\n"
        "\n"
        "encrypt_sign_tool Compatible Syntax:\n"
        "  %s <encrypt> <pub_key> <priv_key> <aes_key> <in_bin> <out_bin> [sig_opt] [meta_loc] [sha_sz]\n",
        prog, prog);
}

static char *trim_whitespace(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static int parse_novatek_key_file(const char *path, rsa_key_pair_t *keys) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key_name = trim_whitespace(line);
        char *key_val = trim_whitespace(eq + 1);

        if (strcasecmp(key_name, "N") == 0) {
            if (!keys->n) BN_hex2bn(&keys->n, key_val);
        } else if (strcasecmp(key_name, "E") == 0) {
            if (!keys->e) BN_hex2bn(&keys->e, key_val);
        } else if (strcasecmp(key_name, "D") == 0) {
            if (!keys->d) BN_hex2bn(&keys->d, key_val);
        }
    }

    fclose(fp);
    return 0;
}

static int load_keys(const char *priv_path, const char *pub_path, rsa_key_pair_t *keys) {
    memset(keys, 0, sizeof(*keys));

    /* 1. Try parsing priv_path as Novatek txt format */
    parse_novatek_key_file(priv_path, keys);

    /* 2. Try parsing pub_path if provided */
    if (pub_path) {
        parse_novatek_key_file(pub_path, keys);
    }

    /* 3. If private exponent D was not found, try OpenSSL PEM format */
    if (!keys->d) {
        FILE *fp = fopen(priv_path, "r");
        if (fp) {
            EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
            fclose(fp);
            if (pkey) {
                BIGNUM *n = NULL, *e = NULL, *d = NULL;
                if (EVP_PKEY_get_bn_param(pkey, "n", &n) &&
                    EVP_PKEY_get_bn_param(pkey, "e", &e) &&
                    EVP_PKEY_get_bn_param(pkey, "d", &d)) {
                    keys->n = n;
                    keys->e = e;
                    keys->d = d;
                }
                EVP_PKEY_free(pkey);
            }
        }
    }

    /* Default exponent E = 65537 if not specified */
    if (!keys->e) {
        keys->e = BN_new();
        BN_set_word(keys->e, 65537);
    }

    if (!keys->n || !keys->d) {
        fprintf(stderr, "Error: Failed to extract RSA modulus (N) and private exponent (D) from '%s'\n", priv_path);
        return -1;
    }

    return 0;
}

static void free_keys(rsa_key_pair_t *keys) {
    if (keys->n) BN_free(keys->n);
    if (keys->e) BN_free(keys->e);
    if (keys->d) BN_free(keys->d);
    memset(keys, 0, sizeof(*keys));
}

static int compute_sha256(const uint8_t *data, size_t len, uint8_t *digest) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

static int do_verify(const char *file_path) {
    FILE *fp = fopen(file_path, "rb");
    if (!fp) {
        fprintf(stderr, "Error opening '%s': %s\n", file_path, strerror(errno));
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (sz < NVT_SIGN_META_TOTAL) {
        fprintf(stderr, "Error: File size (%ld) smaller than minimum signed metadata (%d)\n", sz, NVT_SIGN_META_TOTAL);
        fclose(fp);
        return 1;
    }

    uint8_t *data = malloc(sz);
    if (!data) {
        fclose(fp);
        return 1;
    }

    if (fread(data, 1, sz, fp) != (size_t)sz) {
        free(data);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    /* Verify overall checksum */
    uint16_t total_sum = nvt_calc_chksum16(data, (uint32_t)sz);
    nvt_headinfo_t *head = (nvt_headinfo_t *)data;

    printf("=== Novatek Signed Binary Verification ===\n");
    printf("File:            %s (%ld bytes)\n", file_path, sz);
    printf("Reported Length: %u bytes\n", head->BinLength);
    printf("Checksum Field:  0x%04X (Total verification sum: 0x%04X, %s)\n",
           head->Checksum, total_sum, total_sum == 0 ? "OK" : "FAILED");

    printf("Key Info:        Offset 0x%X, Size %u bytes\n", head->KeyOffset, head->KeySize);
    printf("Signature Info:  Offset 0x%X, Size %u bytes\n", head->SigOffset, head->SigSize);
    printf("Crypto Info:     Offset 0x%X, Size %u bytes\n", head->CryptoOffset, head->CryptoSize);
    printf("BinCtrl:         0x%X\n", head->BinCtrl);

    if (head->KeyOffset + head->KeySize > (uint32_t)sz ||
        head->SigOffset + head->SigSize > (uint32_t)sz ||
        head->CryptoOffset > (uint32_t)sz) {
        fprintf(stderr, "Error: Invalid offsets in HEADINFO\n");
        free(data);
        return 1;
    }

    /* Extract Public Key (Modulus N: 256 bytes, Exponent E: 32 bytes) */
    uint8_t *key_blob = data + head->KeyOffset;
    BIGNUM *bn_n = BN_bin2bn(key_blob, 256, NULL);
    BIGNUM *bn_e = BN_bin2bn(key_blob + 256, 32, NULL);

    /* Extract Signature (256 bytes) */
    uint8_t *sig_blob = data + head->SigOffset;
    BIGNUM *bn_sig = BN_bin2bn(sig_blob, 256, NULL);

    /* Decrypt signature: m = s^e mod n */
    BIGNUM *bn_m = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(bn_m, bn_sig, bn_e, bn_n, ctx);

    uint8_t dec_block[256];
    BN_bn2binpad(bn_m, dec_block, 256);

    /* Compute SHA256 of payload (padded to 64 bytes) */
    uint32_t payload_len = head->BinLength - head->CryptoOffset;
    uint32_t pad_len = (64 - (payload_len % 64)) % 64;
    uint32_t padded_payload_len = payload_len + pad_len;

    uint8_t *payload_buf = calloc(1, padded_payload_len);
    memcpy(payload_buf, data + head->CryptoOffset, payload_len);

    uint8_t calc_digest[32];
    compute_sha256(payload_buf, padded_payload_len, calc_digest);
    free(payload_buf);

    /* Compare last 32 bytes of decrypted block with calculated digest */
    int sig_ok = (memcmp(dec_block + 224, calc_digest, 32) == 0);
    printf("Signature Check: %s\n", sig_ok ? "VALID (SHA-256 matches)" : "FAILED (Hash mismatch)");

    BN_CTX_free(ctx);
    BN_free(bn_m);
    BN_free(bn_sig);
    BN_free(bn_e);
    BN_free(bn_n);
    free(data);

    return (total_sum == 0 && sig_ok) ? 0 : 1;
}

int main(int argc, char *argv[]) {
    const char *in_file = NULL;
    const char *out_file = NULL;
    const char *priv_file = NULL;
    const char *pub_file = NULL;
    const char *verify_file = NULL;

    /* Check for vendor encrypt_sign_tool positional syntax:
     * encrypt_sign_tool [encrypt] [pub_key] [priv_key] [aes_key] [in_bin] [out_bin] [sig_opt] [meta_loc] [sha_size]
     */
    if (argc >= 7 && (strcmp(argv[1], "0") == 0 || strcmp(argv[1], "1") == 0 || strcmp(argv[1], "2") == 0)) {
        pub_file = argv[2];
        priv_file = argv[3];
        /* argv[4] is aes_key (ignored for signature-only mode) */
        in_file = argv[5];
        out_file = argv[6];
    } else {
        static struct option long_options[] = {
            {"input",   required_argument, 0, 'i'},
            {"output",  required_argument, 0, 'o'},
            {"privkey", required_argument, 0, 'k'},
            {"pubkey",  required_argument, 0, 'p'},
            {"verify",  required_argument, 0, 'v'},
            {"help",    no_argument,       0, 'h'},
            {0, 0, 0, 0}
        };

        int opt;
        while ((opt = getopt_long(argc, argv, "i:o:k:p:v:h", long_options, NULL)) != -1) {
            switch (opt) {
                case 'i': in_file = optarg; break;
                case 'o': out_file = optarg; break;
                case 'k': priv_file = optarg; break;
                case 'p': pub_file = optarg; break;
                case 'v': verify_file = optarg; break;
                case 'h': print_usage(argv[0]); return 0;
                default: print_usage(argv[0]); return 1;
            }
        }
    }

    if (verify_file) {
        return do_verify(verify_file);
    }

    if (!in_file || !out_file || !priv_file) {
        fprintf(stderr, "Error: Missing required arguments.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Load RSA Keys */
    rsa_key_pair_t keys;
    if (load_keys(priv_file, pub_file, &keys) != 0) {
        return 1;
    }

    /* Read input file */
    FILE *fin = fopen(in_file, "rb");
    if (!fin) {
        fprintf(stderr, "Error opening input file '%s': %s\n", in_file, strerror(errno));
        free_keys(&keys);
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long payload_sz = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    if (payload_sz < 0) {
        fprintf(stderr, "Error checking size of '%s'\n", in_file);
        fclose(fin);
        free_keys(&keys);
        return 1;
    }

    /* 64-byte align payload buffer for SHA-256 calculation */
    uint32_t pad_len = (64 - (payload_sz % 64)) % 64;
    uint32_t padded_payload_len = (uint32_t)payload_sz + pad_len;

    uint8_t *payload_buf = calloc(1, padded_payload_len);
    if (!payload_buf) {
        fprintf(stderr, "Out of memory allocating %u bytes for payload\n", padded_payload_len);
        fclose(fin);
        free_keys(&keys);
        return 1;
    }

    if (fread(payload_buf, 1, payload_sz, fin) != (size_t)payload_sz) {
        fprintf(stderr, "Error reading %ld bytes from '%s'\n", payload_sz, in_file);
        free(payload_buf);
        fclose(fin);
        free_keys(&keys);
        return 1;
    }
    fclose(fin);

    /* 1. Compute SHA-256 over 64-byte aligned payload */
    uint8_t digest[32];
    if (compute_sha256(payload_buf, padded_payload_len, digest) != 0) {
        fprintf(stderr, "Error computing SHA-256 digest\n");
        free(payload_buf);
        free_keys(&keys);
        return 1;
    }

    /* 2. Format 256-byte RSA block: 224 zero bytes + 32-byte digest */
    uint8_t m_block[256];
    memset(m_block, 0, sizeof(m_block));
    memcpy(m_block + 224, digest, 32);

    /* 3. Compute raw RSA signature: s = m^d mod n */
    BIGNUM *bn_m = BN_bin2bn(m_block, 256, NULL);
    BIGNUM *bn_s = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_mod_exp(bn_s, bn_m, keys.d, keys.n, ctx);

    uint8_t sig_block[256];
    BN_bn2binpad(bn_s, sig_block, 256);

    BN_CTX_free(ctx);
    BN_free(bn_s);
    BN_free(bn_m);

    /* 4. Prepare output buffer:
     *   0x000 - 0x07F (128 B): HEADINFO
     *   0x080 - 0x19F (288 B): Public Key (N 256B + E 32B)
     *   0x1A0 - 0x29F (256 B): Signature s (256B)
     *   0x2A0 - 0x2BF ( 32 B): Zero padding to 64-byte boundary (0x2C0 = 704)
     *   0x2C0 - ...          : Original Payload
     */
    uint32_t total_out_sz = NVT_SIGN_META_TOTAL + (uint32_t)payload_sz;
    uint8_t *out_buf = calloc(1, total_out_sz);
    if (!out_buf) {
        fprintf(stderr, "Out of memory allocating %u bytes for output\n", total_out_sz);
        free(payload_buf);
        free_keys(&keys);
        return 1;
    }

    /* Copy Public Key blob at offset 0x80 */
    BN_bn2binpad(keys.n, out_buf + 0x80, 256);
    BN_bn2binpad(keys.e, out_buf + 0x80 + 256, 32);

    /* Copy Signature at offset 0x1A0 */
    memcpy(out_buf + 0x1A0, sig_block, 256);

    /* Copy Payload at offset 0x2C0 */
    memcpy(out_buf + NVT_SIGN_META_TOTAL, payload_buf, payload_sz);
    free(payload_buf);

    /* Fill HEADINFO at offset 0x00 */
    nvt_headinfo_t *head = (nvt_headinfo_t *)out_buf;
    head->KeyOffset = 0x80;
    head->KeySize = NVT_RSA_PUBKEY_BLOB;       /* 288 bytes */
    head->SigOffset = 0x1A0;
    head->SigSize = NVT_RSA_SIGNATURE_LEN;     /* 256 bytes */
    head->CryptoOffset = NVT_SIGN_META_TOTAL;  /* 0x2C0 = 704 */
    head->CryptoSize = 0xFFFFFFFF;             /* 0xFFFFFFFF indicates unencrypted payload */
    head->BinLength = total_out_sz;
    head->BinCtrl = SIGN_BINCTRL_NO_ENCRYPTIONDATA; /* 0x2 */
    head->Checksum = 0;

    /* 5. Calculate Novatek compensation checksum so nvt_calc_chksum16(out_buf, total_out_sz) == 0 */
    uint16_t chk_val = nvt_calc_compensate_chksum16(out_buf, total_out_sz);
    head->Checksum = (uint32_t)chk_val;

    /* Verify checksum over the resulting buffer */
    uint16_t verify_sum = nvt_calc_chksum16(out_buf, total_out_sz);
    if (verify_sum != 0) {
        fprintf(stderr, "Internal error: Checksum calculation failed (0x%04X != 0)\n", verify_sum);
        free(out_buf);
        free_keys(&keys);
        return 1;
    }

    /* 6. Write signed output file */
    FILE *fout = fopen(out_file, "wb");
    if (!fout) {
        fprintf(stderr, "Error opening output file '%s': %s\n", out_file, strerror(errno));
        free(out_buf);
        free_keys(&keys);
        return 1;
    }

    if (fwrite(out_buf, 1, total_out_sz, fout) != total_out_sz) {
        fprintf(stderr, "Error writing %u bytes to '%s'\n", total_out_sz, out_file);
        free(out_buf);
        fclose(fout);
        free_keys(&keys);
        return 1;
    }

    fclose(fout);
    free(out_buf);
    free_keys(&keys);

    printf("Successfully signed Novatek image:\n");
    printf("  Input:    %s (%ld bytes)\n", in_file, payload_sz);
    printf("  Output:   %s (%u bytes)\n", out_file, total_out_sz);
    printf("  Checksum: 0x%04X\n", chk_val);

    return 0;
}
