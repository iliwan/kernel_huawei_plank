#ifndef __SOC_BASEADDR_INTERFACE_H__
#define __SOC_BASEADDR_INTERFACE_H__ 
#include "bsp_memmap.h"
#ifdef __cplusplus
    #if __cplusplus
        extern "C" {
    #endif
#endif
#define SOC_BBP_COMM_BASE_ADDR HI_CTU_BASE_ADDR
#define SOC_BBP_COMM_ON_BASE_ADDR HI_BBP_COMM_ON_BASE_ADDR
#define SOC_BBP_GSM_BASE_ADDR HI_GBBP_REG_BASE_ADDR
#define SOC_BBP_GSM_ON_BASE_ADDR HI_GBBP_DRX_REG_BASE_ADDR
#define SOC_BBP_GSM1_BASE_ADDR HI_GBBP1_REG_BASE_ADDR
#define SOC_BBP_GSM1_ON_BASE_ADDR HI_GBBP1_DRX_REG_BASE_ADDR
#define SOC_BBP_WCDMA_BASE_ADDR HI_WBBP_REG_BASE_ADDR
#define SOC_BBP_WCDMA_ON_BASE_ADDR HI_WBBP_DRX_REG_BASE_ADDR
#define SOC_UPACC_BASE_ADDR HI_UPACC_BASE_ADDR
#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif
#endif
