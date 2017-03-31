#ifndef __HI_BBP_UL_H__
#define __HI_BBP_UL_H__ 
#ifndef HI_SET_GET
#define HI_SET_GET(a0,a1,a2,a3,a4) 
#endif
#define HI_BBP_UL_UL_TA_REG_OFFSET (0x250)
typedef union
{
    struct
    {
        unsigned int nta_value : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_UL_UL_TA_REG_T;
HI_SET_GET(hi_bbp_ul_ul_ta_reg_nta_value,nta_value,HI_BBP_UL_UL_TA_REG_T,HI_BBP_UL_BASE_ADDR, HI_BBP_UL_UL_TA_REG_OFFSET)
HI_SET_GET(hi_bbp_ul_ul_ta_reg_reserved,reserved,HI_BBP_UL_UL_TA_REG_T,HI_BBP_UL_BASE_ADDR, HI_BBP_UL_UL_TA_REG_OFFSET)
#endif
