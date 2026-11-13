/**
 * nvt_cksm - Open-source C replacement for Novatek's closed-source
 *            "nvt-ld-op --packsum" utility.
 *
 * Prepends the 64-byte CKSM header (NVTPACK_CHKSUM_HDR) to partition
 * and filesystem binaries, computing Novatek's 16-bit running checksum.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <strings.h>

#include "nvt_types.h"

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Modern Options:\n"
        "  -i, --input <file>        Input raw partition/filesystem image\n"
        "  -o, --output <file>       Output signed/checksummed binary\n"
        "  -t, --type <hex|dec>      Embedded type (e.g. 0x9 for app/log/dat, 0xA for rootfs)\n"
        "  -r, --reversed <string>   Optional string in reserved field (max 31 chars)\n"
        "  -c, --checksum <file>     Compute and print Novatek checksum of file\n"
        "  -h, --help                Show this help message\n"
        "\n"
        "encrypt_bin Compatible Mode:\n"
        "  %s SUM <binary> <offset> <tag>   Patch 32-byte header with zero-sum compensation\n"
        "\n"
        "nvt-ld-op Compatible Options:\n"
        "  --packsum-src=<file>\n"
        "  --packsum-dst=<file>\n"
        "  --packsum-type=<hex|dec>\n"
        "  --packsum-reversed=<string>\n"
        "  --checksum-src=<file>\n",
        prog, prog);
}

static int do_patch_sum(const char *path, uint32_t offset, const char *tag) {
    FILE *fp = fopen(path, "r+b");
    if (!fp) {
        fprintf(stderr, "Error opening '%s': %s\n", path, strerror(errno));
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz < 0 || (size_t)sz < offset + 32) {
        fprintf(stderr, "Error: file size (%ld) is too small for offset 0x%X\n", sz, offset);
        fclose(fp);
        return 1;
    }

    uint32_t pad = (sz & 1) ? 1 : 0;
    uint32_t total_sz = (uint32_t)sz + pad;

    uint8_t *buf = calloc(1, total_sz);
    if (!buf) {
        fprintf(stderr, "Out of memory allocating %u bytes\n", total_sz);
        fclose(fp);
        return 1;
    }

    fseek(fp, 0, SEEK_SET);
    if (fread(buf, 1, sz, fp) != (size_t)sz) {
        fprintf(stderr, "Failed reading '%s'\n", path);
        free(buf);
        fclose(fp);
        return 1;
    }

    /* Clear the 32-byte header block at offset */
    memset(buf + offset, 0, 32);

    /* Bytes 0..7: Tag (space-padded if shorter than 8 chars, like stock 'ub02302 ') */
    memset(buf + offset, ' ', 8);
    size_t tag_len = strlen(tag);
    if (tag_len > 8) tag_len = 8;
    memcpy(buf + offset, tag, tag_len);

    /* Bytes 8..15: Dummy ID */
    memcpy(buf + offset + 8, "FFFFFFFF", 8);

    /* Bytes 16..23: Date YYYYMMDD */
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char date_str[32];
    if (tm_info) {
        strftime(date_str, sizeof(date_str), "%Y%m%d", tm_info);
    } else {
        strncpy(date_str, "20260126", sizeof(date_str));
    }
    memcpy(buf + offset + 16, date_str, 8);

    /* Bytes 24..27: File length */
    uint32_t fsize = (uint32_t)sz;
    memcpy(buf + offset + 24, &fsize, 4);

    /* Bytes 28..29: Magic 0xAA55 */
    buf[offset + 28] = 0x55;
    buf[offset + 29] = 0xAA;

    /* Bytes 30..31: Initially zero for checksum calculation */
    buf[offset + 30] = 0x00;
    buf[offset + 31] = 0x00;

    /* Compute compensation word so overall nvt_calc_chksum16 == 0 */
    uint16_t s_zero = nvt_calc_chksum16(buf, total_sz);
    uint16_t comp_val = (uint16_t)((-s_zero) & 0xFFFF);
    memcpy(buf + offset + 30, &comp_val, 2);

    /* Verify */
    uint16_t verify_sum = nvt_calc_chksum16(buf, total_sz);
    if (verify_sum != 0) {
        fprintf(stderr, "Internal error: Checksum verification failed (0x%04X != 0)\n", verify_sum);
        free(buf);
        fclose(fp);
        return 1;
    }

    /* Write back */
    fseek(fp, 0, SEEK_SET);
    if (fwrite(buf, 1, total_sz, fp) != total_sz) {
        fprintf(stderr, "Error writing updated binary to '%s'\n", path);
        free(buf);
        fclose(fp);
        return 1;
    }

    fclose(fp);
    free(buf);

    printf("Successfully patched checksum tag (encrypt_bin SUM compatible):\n");
    printf("  File:       %s (%u bytes)\n", path, total_sz);
    printf("  Offset:     0x%X\n", offset);
    printf("  Tag:        %.8s\n", tag);
    printf("  Comp Word:  0x%04X\n", comp_val);
    printf("  Final Sum:  0x%04X (OK)\n", verify_sum);
    return 0;
}

static int do_checksum_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "Error opening '%s': %s\n", path, strerror(errno));
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (sz < 0) {
        fclose(fp);
        return 1;
    }

    uint8_t *buf = malloc(sz + 1);
    if (!buf) {
        fprintf(stderr, "Out of memory allocating %ld bytes\n", sz);
        fclose(fp);
        return 1;
    }

    if (fread(buf, 1, sz, fp) != (size_t)sz) {
        fprintf(stderr, "Failed to read '%s'\n", path);
        free(buf);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    if (sz & 1) {
        buf[sz] = 0;
        sz++;
    }

    uint16_t sum = nvt_calc_chksum16(buf, (uint32_t)sz);
    printf("File: %s\nSize: %ld bytes\nChecksum: 0x%04X (%u)\n", path, sz, sum, sum);

    free(buf);
    return 0;
}

int main(int argc, char *argv[]) {
    /* Support encrypt_bin SUM <main_bin> <offset> <model_name> */
    if (argc >= 5 && (strcasecmp(argv[1], "SUM") == 0 || strcasecmp(argv[1], "CRC") == 0)) {
        const char *bin_path = argv[2];
        uint32_t offset = (uint32_t)strtoul(argv[3], NULL, 0);
        const char *tag = argv[4];
        return do_patch_sum(bin_path, offset, tag);
    }

    const char *src_file = NULL;
    const char *dst_file = NULL;
    const char *chk_file = NULL;
    const char *reversed_str = NULL;
    uint32_t emb_type = 0x9; /* Default 0x9 */

    static struct option long_options[] = {
        {"input",            required_argument, 0, 'i'},
        {"output",           required_argument, 0, 'o'},
        {"type",             required_argument, 0, 't'},
        {"reversed",         required_argument, 0, 'r'},
        {"checksum",         required_argument, 0, 'c'},
        {"help",             no_argument,       0, 'h'},
        /* nvt-ld-op compatibility aliases */
        {"packsum-src",      required_argument, 0, 1001},
        {"packsum-dst",      required_argument, 0, 1002},
        {"packsum-type",     required_argument, 0, 1003},
        {"packsum-reversed", required_argument, 0, 1004},
        {"checksum-src",     required_argument, 0, 1005},
        {"arc-sha1",         required_argument, 0, 1006},
        {"symvers-src",      required_argument, 0, 1007},
        {"symvers-dst",      required_argument, 0, 1008},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:o:t:r:c:hj:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
            case 1001:
                src_file = optarg;
                break;
            case 'o':
            case 1002:
                dst_file = optarg;
                break;
            case 't':
            case 1003:
                emb_type = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'r':
            case 1004:
                reversed_str = optarg;
                break;
            case 'c':
            case 1005:
                chk_file = optarg;
                break;
            case 1006:
            case 1007:
            case 1008:
            case 'j':
                /* Vendor Makefile stubs for symbol checks; return success */
                return 0;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (chk_file) {
        return do_checksum_file(chk_file);
    }

    if (!src_file || !dst_file) {
        fprintf(stderr, "Error: Missing input or output file.\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Open source file */
    FILE *fin = fopen(src_file, "rb");
    if (!fin) {
        fprintf(stderr, "Error opening input file '%s': %s\n", src_file, strerror(errno));
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long src_len = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    if (src_len < 0) {
        fprintf(stderr, "Error determining file size for '%s'\n", src_file);
        fclose(fin);
        return 1;
    }

    /* Align payload size if needed */
    uint32_t pad_size = (src_len & 1) ? 1 : 0;
    uint32_t total_len = sizeof(nvtpack_chksum_hdr_t) + (uint32_t)src_len + pad_size;

    uint8_t *buf = calloc(1, total_len);
    if (!buf) {
        fprintf(stderr, "Error: Out of memory allocating %u bytes\n", total_len);
        fclose(fin);
        return 1;
    }

    /* Fill CKSM Header */
    nvtpack_chksum_hdr_t *hdr = (nvtpack_chksum_hdr_t *)buf;
    hdr->uiFourCC = NVTPACK_CHKSUM_FOURCC;
    hdr->uiVersion = NVTPACK_CHKSUM_HDR_VERSION;
    hdr->uiChkMethod = 0;
    hdr->uiChkValue = 0;
    hdr->uiDataOffset = sizeof(nvtpack_chksum_hdr_t);
    hdr->uiDataSize = (uint32_t)src_len;
    hdr->uiPaddingSize = pad_size;
    hdr->uiEmbType = emb_type;

    if (reversed_str) {
        strncpy((char *)hdr->uiReserved, reversed_str, sizeof(hdr->uiReserved) - 1);
    }

    /* Read payload directly after header */
    if (fread(buf + sizeof(nvtpack_chksum_hdr_t), 1, src_len, fin) != (size_t)src_len) {
        fprintf(stderr, "Error reading %ld bytes from '%s'\n", src_len, src_file);
        free(buf);
        fclose(fin);
        return 1;
    }
    fclose(fin);

    /* Compute 16-bit compensation checksum so nvt_calc_chksum16(buf, total_len) == 0 */
    uint16_t chk_val = nvt_calc_compensate_chksum16(buf, total_len);
    hdr->uiChkValue = (uint32_t)chk_val;

    /* Verify checksum over the resulting buffer */
    uint16_t verify_sum = nvt_calc_chksum16(buf, total_len);
    if (verify_sum != 0) {
        fprintf(stderr, "Internal error: Checksum verification failed (0x%04X != 0)\n", verify_sum);
        free(buf);
        return 1;
    }

    /* Write output file */
    FILE *fout = fopen(dst_file, "wb");
    if (!fout) {
        fprintf(stderr, "Error opening output file '%s': %s\n", dst_file, strerror(errno));
        free(buf);
        return 1;
    }

    if (fwrite(buf, 1, total_len, fout) != total_len) {
        fprintf(stderr, "Error writing %u bytes to '%s'\n", total_len, dst_file);
        free(buf);
        fclose(fout);
        return 1;
    }
    fclose(fout);
    free(buf);

    printf("Successfully packed checksum header:\n");
    printf("  Input:    %s (%ld bytes)\n", src_file, src_len);
    printf("  Output:   %s (%u bytes)\n", dst_file, total_len);
    printf("  EmbType:  0x%X\n", emb_type);
    printf("  Checksum: 0x%04X\n", chk_val);

    return 0;
}
