#ifndef _NVT_TYPES_H_
#define _NVT_TYPES_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define NVTPACK_CHKSUM_FOURCC       0x4D534B43U  /* 'C','K','S','M' */
#define NVTPACK_CHKSUM_HDR_VERSION  0x16040719U
#define NVTPACK_FW_HDR2_VERSION     0x16071515U

#define SIGN_BINCTRL_LIMITED_SIZE       0x1
#define SIGN_BINCTRL_NO_ENCRYPTIONDATA  0x2

#define NVT_RSA_MODULUS_LEN   256  /* 2048-bit RSA */
#define NVT_RSA_EXPONENT_LEN  32   /* 32-byte exponent field */
#define NVT_RSA_PUBKEY_BLOB   288  /* 256 + 32 bytes */
#define NVT_RSA_SIGNATURE_LEN 256  /* 2048-bit signature */
#define NVT_HEADINFO_LEN      128  /* HEADINFO header size */
#define NVT_SIGN_META_TOTAL   704  /* 128 (head) + 288 (pub) + 256 (sig) + 32 (pad) = 0x2C0 */

#pragma pack(push, 1)

typedef struct {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t  Data4[8];
} nvt_guid_t;

/* GUID_FW2: {D6012E07-10BC-4F91-B28A-352F82261A50} */
static const nvt_guid_t GUID_FW2 = {
    0xD6012E07, 0x10BC, 0x4F91,
    { 0xB2, 0x8A, 0x35, 0x2F, 0x82, 0x26, 0x1A, 0x50 }
};

/* GUID_FW: {8827BE90-36CD-4FC2-A987-73A8484E84B1} */
static const nvt_guid_t GUID_FW = {
    0x8827BE90, 0x36CD, 0x4FC2,
    { 0xA9, 0x87, 0x73, 0xA8, 0x48, 0x4E, 0x84, 0xB1 }
};

/* GUID_RES: {B5CB64AE-05DD-46FA-B906-0C62D22958D6} */
static const nvt_guid_t GUID_RES = {
    0xB5CB64AE, 0x05DD, 0x46FA,
    { 0xB9, 0x06, 0x0C, 0x62, 0xD2, 0x29, 0x58, 0xD6 }
};

static inline bool nvt_guid_equal(const nvt_guid_t *a, const nvt_guid_t *b) {
    return memcmp(a, b, sizeof(nvt_guid_t)) == 0;
}

/* 128-byte Novatek FW98538A.bin All-in-One Container Header */
typedef struct {
    nvt_guid_t guid;          /* [0x00..0x0F] GUID_FW2 */
    uint32_t   uiVersion;     /* [0x10..0x13] NVTPACK_FW_HDR2_VERSION (0x16071515) */
    uint32_t   uiHdrSize;     /* [0x14..0x17] sizeof(nvtpack_fw_hdr2_t) = 128 */
    uint32_t   TotalRes;      /* [0x18..0x1B] Total resource / partition count */
    uint32_t   TotalSize;     /* [0x1C..0x1F] Total binary size in bytes */
    uint32_t   uiChkMethod;   /* [0x20..0x23] 0 = Checksum */
    uint32_t   uiChkValue;    /* [0x24..0x27] 16-bit checksum value */
    uint32_t   uiUserData[4]; /* [0x28..0x37] User defined data */
    uint32_t   uiReserved[18];/* [0x38..0x7F] Reserved padding to 128 bytes */
} nvtpack_fw_hdr2_t;

/* 12-byte Partition Table Entry */
typedef struct {
    uint32_t Offset;          /* Offset within all-in-one image */
    uint32_t Size;            /* Actual size of partition image */
    uint32_t PartitionID;     /* Partition index (e.g. 1, 3, 4, 10, 15, ...) */
} nvtpack_partition_hdr_t;

/* 64-byte CKSM Checksum Header (used by nvt-ld-op --packsum and prepended to UBI partitions) */
typedef struct {
    uint32_t uiFourCC;        /* [0x00..0x03] 'C','K','S','M' (0x4D534B43) */
    uint32_t uiVersion;       /* [0x04..0x07] NVTPACK_CHKSUM_HDR_VERSION (0x16040719) */
    uint32_t uiChkMethod;     /* [0x08..0x0B] 0 = Checksum */
    uint32_t uiChkValue;      /* [0x0C..0x0F] 16-bit checksum value */
    uint32_t uiDataOffset;    /* [0x10..0x13] Payload offset from start of header (0x40 = 64) */
    uint32_t uiDataSize;      /* [0x14..0x17] Payload size in bytes */
    uint32_t uiPaddingSize;   /* [0x18..0x1B] Checksum padding bytes (typically 0) */
    uint32_t uiEmbType;       /* [0x1C..0x1F] EMBTYPE (e.g. 0x9 for appfs/logfs, 0xA for rootfs) */
    uint8_t  uiReserved[32];  /* [0x20..0x3F] Reserved padding (or custom reversed string) */
} nvtpack_chksum_hdr_t;

/* 128-byte HEADINFO Header (used by encrypt_sign_tool) */
typedef struct {
    uint32_t CodeEntry;       /* [0x00..0x03] Code entry point */
    uint32_t Resv1[19];       /* [0x04..0x4F] Reserved */
    uint32_t KeyOffset;       /* [0x50..0x53] Public key offset (typically 0x80) */
    uint32_t KeySize;         /* [0x54..0x57] Public key size (typically 0x120 = 288) */
    uint32_t SigOffset;       /* [0x58..0x5B] Signature offset (typically 0x1A0) */
    uint32_t SigSize;         /* [0x5C..0x5F] Signature size (typically 0x100 = 256) */
    uint32_t CryptoOffset;    /* [0x60..0x63] Payload offset (typically 0x2C0) */
    uint32_t CryptoSize;      /* [0x64..0x67] Payload size or 0xFFFFFFFF */
    uint32_t BinLength;       /* [0x68..0x6B] Total file size in bytes */
    uint32_t Checksum;        /* [0x6C..0x6F] 16-bit checksum value */
    uint32_t CRCLenCheck;     /* [0x70..0x73] Length check for CRC */
    uint32_t Resv2;           /* [0x74..0x77] Reserved */
    uint32_t BinCtrl;         /* [0x78..0x7B] Flag: 0x2 = SIGN_BINCTRL_NO_ENCRYPTIONDATA */
    uint32_t CRCBinaryTag;    /* [0x7C..0x7F] Tag */
} nvt_headinfo_t;

#pragma pack(pop)

/*
 * Novatek 16-bit word checksum algorithm.
 * Sums all 16-bit words plus word index:
 *   sum = sum((val[i] + i) for i in range(len // 2)) & 0xFFFF
 */
static inline uint16_t nvt_calc_chksum16(const void *data, uint32_t len) {
    uint32_t i, sum = 0;
    const uint16_t *val = (const uint16_t *)data;
    uint32_t words = len >> 1;

    for (i = 0; i < words; i++) {
        sum += (uint32_t)(val[i] + i);
    }

    return (uint16_t)(sum & 0xFFFF);
}

/*
 * Calculate compensation value so that:
 *   (nvt_calc_chksum16(data, len) + comp_val) & 0xFFFF == 0
 */
static inline uint16_t nvt_calc_compensate_chksum16(const void *data, uint32_t len) {
    uint16_t sum = nvt_calc_chksum16(data, len);
    return (uint16_t)((~sum + 1) & 0xFFFF);
}

#endif /* _NVT_TYPES_H_ */
