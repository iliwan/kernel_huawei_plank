#ifndef __SOC_ONCHIP_H__
#define __SOC_ONCHIP_H__ 
#include "bsp_memmap.h"
#define M3_TCM_ADDR (0x10000000)
#define M3_TCM_SIZE (64*1024)
#define SRAM_ADDR (0x4FE00000)
#define SRAM_SIZE (128*1024)
#define M3_TCM_SHARE_DATA_SIZE sizeof(tOcrShareData)
#define M3_TCM_SHARE_DATA_ADDR (SRAM_ADDR + SRAM_SIZE - M3_TCM_SHARE_DATA_SIZE)
#define OCR_INITED_FLAG_ADDR (SRAM_ADDR + SRAM_SIZE - 4)
#define OCR_AUTO_ENUM_FLAG_ADDR (SRAM_ADDR + SRAM_SIZE - 8)
#define OCR_INITED_FLAG_VALUE (0x23456789)
#define OCR_UNINITED_FLAG_VALUE (0xA55A6789)
#define AUTO_ENUM_FLAG_VALUE 0x82822828
#define KEY_OEMID_INDEX sizeof(KEY_STRUCT)
#define KEY_HWID_INDEX (KEY_OEMID_INDEX+0x04)
#define BL_LEN_INDEX (144 * 4)
#define ROOT_CA_INDEX (BL_LEN_INDEX + 4)
#define ROOT_CA_LEN 260
#define OEM_CA_LEN 268
#define IDIO_LEN 128
#define MAX_N_LENGTH 32
#define SHA256_HASH_SIZE 8
#define MD5_HASH_SIZE 4
#ifndef __ASSEMBLY__
typedef struct
{
    unsigned short eLen;
    unsigned short nLen;
    unsigned int e[MAX_N_LENGTH];
    unsigned int n[MAX_N_LENGTH];
}KEY_STRUCT;
typedef int (*idioIdentifyPtr)(unsigned int dataAddr, unsigned int dataLen, KEY_STRUCT *pKey, unsigned int* pIdio);
typedef int (*SHA256HashPtr)(unsigned int dataAddr, unsigned int dataLen, unsigned int* hash);
typedef int (*RSAPtr)(KEY_STRUCT *pKey, unsigned int* pIndata, unsigned int* pOutdata);
typedef struct tagOcrShareData
{
}tOcrShareData;
#endif
#endif
