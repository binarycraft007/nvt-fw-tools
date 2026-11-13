#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>
#include <unistd.h>

#include "nvt_types.h"

#define MAX_PARTITIONS 64
#define PATH_MAX_LEN   2048

typedef struct {
    uint32_t id;
    char path[PATH_MAX_LEN];
    uint8_t *data;
    uint32_t size;
} partition_item_t;

static void print_usage(const char *progname) {
    fprintf(stderr,
        "Open-source nvtpack replacement for Novatek NT9853x / NT9668x\n"
        "Usage: %s -unpack <all-in-one file> [-o <out_dir>]\n"
        "       %s -fw <ini file> [-o <out_bin>]\n"
        "       %s -pack <out_bin> <pat1.bin> [pat2.bin ...]\n"
        "       %s -list <all-in-one file>\n"
        "\n"
        "Options:\n"
        "  -unpack <file> [-o dir]   Extract all partitions and generate INI file\n"
        "  -fw <ini> [-o file]       Pack partitions defined in INI into all-in-one binary\n"
        "  -pack <out> <files...>    Pack partitions directly from PAT*.bin files\n"
        "  -list, -l <file>          Display partition table and verify checksum\n",
        progname, progname, progname, progname);
}

static int mkdir_p(const char *path) {
    char tmp[PATH_MAX_LEN];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (len == 0) return 0;
    if (tmp[len - 1] == '/') tmp[len - 1] = 0;

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static uint8_t *read_file_to_buffer(const char *path, uint32_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open '%s': %s\n", path, strerror(errno));
        return NULL;
    }

    if (fseeko(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    off_t sz = ftello(f);
    if (sz < 0 || (uint64_t)sz > 0xFFFFFFFFULL) {
        fprintf(stderr, "Error: file '%s' invalid size %lld\n", path, (long long)sz);
        fclose(f);
        return NULL;
    }
    rewind(f);

    uint8_t *buf = (uint8_t *)malloc((size_t)sz + 1);
    if (!buf) {
        fprintf(stderr, "Error: memory allocation failed for %lld bytes\n", (long long)sz);
        fclose(f);
        return NULL;
    }

    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) {
        fprintf(stderr, "Error: reading '%s' failed (expected %zu, got %zu)\n", path, (size_t)sz, rd);
        free(buf);
        return NULL;
    }

    *out_size = (uint32_t)sz;
    return buf;
}

static int compare_partition_items(const void *a, const void *b) {
    const partition_item_t *pa = (const partition_item_t *)a;
    const partition_item_t *pb = (const partition_item_t *)b;
    if (pa->id < pb->id) return -1;
    if (pa->id > pb->id) return 1;
    return 0;
}

/* -------------------------------------------------------------------------
 * UNPACK IMPLEMENTATION
 * ------------------------------------------------------------------------- */
static int do_unpack(const char *fw_path, const char *out_dir) {
    uint32_t fw_size = 0;
    uint8_t *fw_data = read_file_to_buffer(fw_path, &fw_size);
    if (!fw_data) return -1;

    if (fw_size < sizeof(nvtpack_fw_hdr2_t)) {
        fprintf(stderr, "Error: '%s' is too small (%u bytes) to contain header\n", fw_path, fw_size);
        free(fw_data);
        return -1;
    }

    const nvtpack_fw_hdr2_t *hdr2 = (const nvtpack_fw_hdr2_t *)fw_data;
    if (!nvt_guid_equal(&hdr2->guid, &GUID_FW2)) {
        fprintf(stderr, "Error: unsupported or invalid GUID in '%s'\n", fw_path);
        free(fw_data);
        return -1;
    }

    if (hdr2->uiVersion != NVTPACK_FW_HDR2_VERSION) {
        fprintf(stderr, "Warning: unexpected header version 0x%08X (expected 0x%08X)\n",
                hdr2->uiVersion, NVTPACK_FW_HDR2_VERSION);
    }

    uint32_t total_res = hdr2->TotalRes;
    uint32_t total_size = hdr2->TotalSize;

    if (total_size > fw_size) {
        fprintf(stderr, "Error: header TotalSize (%u) exceeds file size (%u)\n", total_size, fw_size);
        free(fw_data);
        return -1;
    }

    /* Check checksum */
    uint16_t cksm = nvt_calc_chksum16(fw_data, total_size);
    if (cksm != 0) {
        fprintf(stderr, "Warning: checksum verification failed (sum=0x%04X, stored=0x%04X)\n",
                cksm, hdr2->uiChkValue);
    }

    size_t table_offset = hdr2->uiHdrSize;
    if (table_offset + total_res * sizeof(nvtpack_partition_hdr_t) > fw_size) {
        fprintf(stderr, "Error: partition table overflows file\n");
        free(fw_data);
        return -1;
    }

    const nvtpack_partition_hdr_t *entries = (const nvtpack_partition_hdr_t *)(fw_data + table_offset);

    /* Setup output directory */
    char dir_buf[PATH_MAX_LEN];
    if (out_dir && strlen(out_dir) > 0) {
        snprintf(dir_buf, sizeof(dir_buf), "%s", out_dir);
    } else {
        /* Default to directory containing fw_path */
        char path_copy[PATH_MAX_LEN];
        snprintf(path_copy, sizeof(path_copy), "%s", fw_path);
        snprintf(dir_buf, sizeof(dir_buf), "%s", dirname(path_copy));
    }

    if (mkdir_p(dir_buf) != 0) {
        fprintf(stderr, "Error: failed to create output directory '%s': %s\n", dir_buf, strerror(errno));
        free(fw_data);
        return -1;
    }

    /* Determine base name for output INI file */
    char fw_copy[PATH_MAX_LEN];
    snprintf(fw_copy, sizeof(fw_copy), "%s", fw_path);
    char *base = basename(fw_copy);
    char ini_name[PATH_MAX_LEN * 2];
    char *dot = strrchr(base, '.');
    if (dot) *dot = '\0';
    snprintf(ini_name, sizeof(ini_name), "%s/%s.ini", dir_buf, base);

    FILE *f_ini = fopen(ini_name, "w");
    if (f_ini) {
        fprintf(f_ini, "[NVTPACK_FW_INI_16072017]\n");
        fprintf(f_ini, "GEN %s.bin\n", base);
        fprintf(f_ini, "CHIP_SELECT 1\n");
    }

    /* Extract partitions */
    for (uint32_t i = 0; i < total_res; i++) {
        uint32_t pid = entries[i].PartitionID;
        uint32_t off = entries[i].Offset;
        uint32_t sz  = entries[i].Size;

        printf("checking partition[%u]\n", pid);

        if (off + sz > fw_size) {
            fprintf(stderr, "Error: partition %u [%u..%u] exceeds image size %u\n", pid, off, off + sz, fw_size);
            continue;
        }

        char pat_filename[64];
        snprintf(pat_filename, sizeof(pat_filename), "PAT%02u.bin", pid);

        char out_file_path[PATH_MAX_LEN * 2];
        snprintf(out_file_path, sizeof(out_file_path), "%s/%s", dir_buf, pat_filename);

        printf("extracting... \"%s\"\n", pat_filename);

        FILE *f_out = fopen(out_file_path, "wb");
        if (!f_out) {
            fprintf(stderr, "Error: cannot create '%s': %s\n", out_file_path, strerror(errno));
            continue;
        }

        size_t wr = fwrite(fw_data + off, 1, sz, f_out);
        fclose(f_out);

        if (wr != sz) {
            fprintf(stderr, "Error: failed writing '%s'\n", out_file_path);
        }

        if (f_ini) {
            fprintf(f_ini, "ITEM%02u 1 %s\n", pid, pat_filename);
        }
    }

    if (f_ini) {
        fclose(f_ini);
        printf("Generated INI descriptor: %s\n", ini_name);
    }

    free(fw_data);
    return 0;
}

/* -------------------------------------------------------------------------
 * PACK IMPLEMENTATION
 * ------------------------------------------------------------------------- */
static int pack_partitions(partition_item_t *items, uint32_t num_items, const char *out_file) {
    if (num_items == 0) {
        fprintf(stderr, "Error: no partitions to pack\n");
        return -1;
    }

    /* Sort partitions by ID */
    qsort(items, num_items, sizeof(partition_item_t), compare_partition_items);

    /* Compute total binary size and partition offsets */
    uint32_t cur_offset = sizeof(nvtpack_fw_hdr2_t) + num_items * sizeof(nvtpack_partition_hdr_t);

    for (uint32_t i = 0; i < num_items; i++) {
        uint32_t aligned_size = (items[i].size + 63U) & ~63U;
        cur_offset += aligned_size;
    }

    uint32_t total_size = cur_offset;

    uint8_t *out_buf = (uint8_t *)calloc(1, total_size);
    if (!out_buf) {
        fprintf(stderr, "Error: memory allocation failed for %u bytes\n", total_size);
        return -1;
    }

    /* Fill Header */
    nvtpack_fw_hdr2_t *hdr2 = (nvtpack_fw_hdr2_t *)out_buf;
    memcpy(&hdr2->guid, &GUID_FW2, sizeof(nvt_guid_t));
    hdr2->uiVersion = NVTPACK_FW_HDR2_VERSION;
    hdr2->uiHdrSize = sizeof(nvtpack_fw_hdr2_t);
    hdr2->TotalRes = num_items;
    hdr2->TotalSize = total_size;
    hdr2->uiChkMethod = 0;
    hdr2->uiChkValue = 0;

    nvtpack_partition_hdr_t *entries = (nvtpack_partition_hdr_t *)(out_buf + sizeof(nvtpack_fw_hdr2_t));

    cur_offset = sizeof(nvtpack_fw_hdr2_t) + num_items * sizeof(nvtpack_partition_hdr_t);

    for (uint32_t i = 0; i < num_items; i++) {
        entries[i].Offset = cur_offset;
        entries[i].Size = items[i].size;
        entries[i].PartitionID = items[i].id;

        memcpy(out_buf + cur_offset, items[i].data, items[i].size);

        uint32_t aligned_size = (items[i].size + 63U) & ~63U;
        cur_offset += aligned_size;
    }

    /* Compute running checksum compensation value */
    uint16_t chk_val = nvt_calc_compensate_chksum16(out_buf, total_size);
    hdr2->uiChkValue = chk_val;

    /* Write out file */
    printf("Writing all-in-one: %s\n", out_file);
    FILE *f_out = fopen(out_file, "wb");
    if (!f_out) {
        fprintf(stderr, "Error: cannot create output file '%s': %s\n", out_file, strerror(errno));
        free(out_buf);
        return -1;
    }

    size_t wr = fwrite(out_buf, 1, total_size, f_out);
    fclose(f_out);
    free(out_buf);

    if (wr != total_size) {
        fprintf(stderr, "Error: wrote %zu bytes out of %u to '%s'\n", wr, total_size, out_file);
        return -1;
    }

    printf("Finish.\n");
    return 0;
}

static char *trim_whitespace(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static int do_pack_ini(const char *ini_path, const char *out_file_override) {
    FILE *f_ini = fopen(ini_path, "r");
    if (!f_ini) {
        fprintf(stderr, "Error: cannot open INI file '%s': %s\n", ini_path, strerror(errno));
        return -1;
    }

    char ini_dir[PATH_MAX_LEN];
    snprintf(ini_dir, sizeof(ini_dir), "%s", ini_path);
    char *dir = dirname(ini_dir);

    char gen_name[PATH_MAX_LEN] = "FW.bin";
    partition_item_t items[MAX_PARTITIONS];
    uint32_t num_items = 0;

    char line[PATH_MAX_LEN];
    bool in_section = false;

    while (fgets(line, sizeof(line), f_ini)) {
        char *p = trim_whitespace(line);
        if (*p == '\0' || *p == '#' || *p == ';') continue;

        if (*p == '[') {
            if (strcasestr(p, "NVTPACK_FW_INI")) {
                in_section = true;
            } else {
                in_section = false;
            }
            continue;
        }

        if (!in_section) continue;

        if (strncasecmp(p, "GEN", 3) == 0 && isspace((unsigned char)p[3])) {
            char *val = trim_whitespace(p + 3);
            if (*val) snprintf(gen_name, sizeof(gen_name), "%s", val);
        } else if (strncasecmp(p, "ITEM", 4) == 0) {
            /* Format: ITEM01 1 PAT01.bin */
            int id = 0, enable = 0;
            char pat_path[PATH_MAX_LEN] = {0};

            if (sscanf(p + 4, "%02d %d %1023s", &id, &enable, pat_path) == 3 ||
                sscanf(p + 4, "%d %d %1023s", &id, &enable, pat_path) == 3) {
                if (enable != 0 && num_items < MAX_PARTITIONS) {
                    char full_path[PATH_MAX_LEN];
                    if (pat_path[0] == '/') {
                        snprintf(full_path, sizeof(full_path), "%s", pat_path);
                    } else {
                        snprintf(full_path, sizeof(full_path), "%s/%s", dir, pat_path);
                    }

                    printf("Preparing partition[%d] Path: %s\n", id, pat_path);

                    uint32_t sz = 0;
                    uint8_t *data = read_file_to_buffer(full_path, &sz);
                    if (!data) {
                        fprintf(stderr, "Error: cannot read partition file '%s'\n", full_path);
                        fclose(f_ini);
                        for (uint32_t j = 0; j < num_items; j++) free(items[j].data);
                        return -1;
                    }

                    items[num_items].id = (uint32_t)id;
                    snprintf(items[num_items].path, sizeof(items[num_items].path), "%s", pat_path);
                    items[num_items].data = data;
                    items[num_items].size = sz;
                    num_items++;
                }
            }
        }
    }

    fclose(f_ini);

    char final_out[PATH_MAX_LEN];
    if (out_file_override) {
        snprintf(final_out, sizeof(final_out), "%s", out_file_override);
    } else {
        if (gen_name[0] == '/') {
            snprintf(final_out, sizeof(final_out), "%s", gen_name);
        } else {
            snprintf(final_out, sizeof(final_out), "%s/%s", dir, gen_name);
        }
    }

    printf("all-in-one path: %s\n", final_out);
    int ret = pack_partitions(items, num_items, final_out);

    for (uint32_t i = 0; i < num_items; i++) {
        free(items[i].data);
    }

    return ret;
}

static int do_pack_direct(const char *out_file, int argc, char **argv) {
    partition_item_t items[MAX_PARTITIONS];
    uint32_t num_items = 0;

    for (int i = 0; i < argc; i++) {
        const char *path = argv[i];
        char path_copy[PATH_MAX_LEN];
        snprintf(path_copy, sizeof(path_copy), "%s", path);
        char *fname = basename(path_copy);

        int id = 0;
        /* Look for pattern PAT<digits>.bin */
        if (sscanf(fname, "PAT%d", &id) != 1 && sscanf(fname, "pat%d", &id) != 1) {
            fprintf(stderr, "Warning: could not infer partition ID from '%s', skipping\n", fname);
            continue;
        }

        printf("Preparing partition[%d] Path: %s\n", id, path);
        uint32_t sz = 0;
        uint8_t *data = read_file_to_buffer(path, &sz);
        if (!data) {
            for (uint32_t j = 0; j < num_items; j++) free(items[j].data);
            return -1;
        }

        items[num_items].id = (uint32_t)id;
        snprintf(items[num_items].path, sizeof(items[num_items].path), "%s", path);
        items[num_items].data = data;
        items[num_items].size = sz;
        num_items++;
    }

    int ret = pack_partitions(items, num_items, out_file);

    for (uint32_t i = 0; i < num_items; i++) {
        free(items[i].data);
    }

    return ret;
}

/* -------------------------------------------------------------------------
 * LIST IMPLEMENTATION
 * ------------------------------------------------------------------------- */
static int do_list(const char *fw_path) {
    uint32_t fw_size = 0;
    uint8_t *fw_data = read_file_to_buffer(fw_path, &fw_size);
    if (!fw_data) return -1;

    if (fw_size < sizeof(nvtpack_fw_hdr2_t)) {
        fprintf(stderr, "Error: file too small for header\n");
        free(fw_data);
        return -1;
    }

    const nvtpack_fw_hdr2_t *hdr = (const nvtpack_fw_hdr2_t *)fw_data;
    if (!nvt_guid_equal(&hdr->guid, &GUID_FW2)) {
        fprintf(stderr, "Error: not a valid GUID_FW2 image\n");
        free(fw_data);
        return -1;
    }

    uint16_t cksm = nvt_calc_chksum16(fw_data, hdr->TotalSize);
    printf("Image: %s\n", fw_path);
    printf("Version: 0x%08X, Header Size: %u bytes\n", hdr->uiVersion, hdr->uiHdrSize);
    printf("Total Partitions: %u, Total Size: %u bytes (%u MB)\n",
           hdr->TotalRes, hdr->TotalSize, hdr->TotalSize / (1024 * 1024));
    printf("Checksum Check: %s (sum=0x%04X, hdr_val=0x%04X)\n",
           (cksm == 0) ? "OK (Valid)" : "MISMATCH (Corrupted)", cksm, hdr->uiChkValue);

    printf("\nPartition Table:\n");
    printf("  # | ID |      Offset |        Size | Name\n");
    printf("----+----+-------------+-------------+------------\n");

    const nvtpack_partition_hdr_t *entries =
        (const nvtpack_partition_hdr_t *)(fw_data + hdr->uiHdrSize);

    for (uint32_t i = 0; i < hdr->TotalRes; i++) {
        printf(" %2u | %2u |  0x%08X | %11u | PAT%02u.bin\n",
               i, entries[i].PartitionID, entries[i].Offset, entries[i].Size, entries[i].PartitionID);
    }

    free(fw_data);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-unpack") == 0) {
        if (argc < 3) {
            print_usage(argv[0]);
            return 1;
        }
        const char *fw_file = argv[2];
        const char *out_dir = NULL;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
                out_dir = argv[++i];
            }
        }
        return do_unpack(fw_file, out_dir);
    } else if (strcmp(argv[1], "-fw") == 0) {
        if (argc < 3) {
            print_usage(argv[0]);
            return 1;
        }
        const char *ini_file = argv[2];
        const char *out_file = NULL;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
                out_file = argv[++i];
            }
        }
        return do_pack_ini(ini_file, out_file);
    } else if (strcmp(argv[1], "-pack") == 0) {
        if (argc < 4) {
            print_usage(argv[0]);
            return 1;
        }
        const char *out_file = argv[2];
        return do_pack_direct(out_file, argc - 3, argv + 3);
    } else if (strcmp(argv[1], "-list") == 0 || strcmp(argv[1], "-l") == 0) {
        if (argc < 3) {
            print_usage(argv[0]);
            return 1;
        }
        return do_list(argv[2]);
    } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    } else {
        fprintf(stderr, "Unknown option: %s\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }
}
