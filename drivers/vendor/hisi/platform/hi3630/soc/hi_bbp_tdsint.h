#ifndef __HI_BBP_TDSINT_H__
#define __HI_BBP_TDSINT_H__ 
#ifndef HI_SET_GET
#define HI_SET_GET(a0,a1,a2,a3,a4) 
#endif
#define HI_BBP_TDSINT_PUB_INT_MSK_OFFSET (0xA0)
#define HI_BBP_TDSINT_DSP_INT_MSK_OFFSET (0xA4)
#define HI_BBP_TDSINT_PUB_INT_CLEAR_OFFSET (0xA8)
#define HI_BBP_TDSINT_DSP_INT_CLEAR_OFFSET (0xAC)
#define HI_BBP_TDSINT_PUB_INT_ALM_OFFSET (0xB0)
#define HI_BBP_TDSINT_DSP_INT_ALM_OFFSET (0xB4)
#ifndef __ASSEMBLY__
typedef union
{
    struct
    {
        unsigned int hifi_sfrm_int_msk : 1;
        unsigned int arm_sfrm_int_msk : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_TDSINT_PUB_INT_MSK_T;
typedef union
{
    struct
    {
        unsigned int slot_int_msk : 23;
        unsigned int dsp_sfrm_int_msk : 1;
        unsigned int reserved : 8;
    } bits;
    unsigned int u32;
}HI_BBP_TDSINT_DSP_INT_MSK_T;
typedef union
{
    struct
    {
        unsigned int hifi_sfrm_int_clear : 1;
        unsigned int arm_sfrm_int_clear : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_TDSINT_PUB_INT_CLEAR_T;
typedef union
{
    struct
    {
        unsigned int slot_int_clear : 23;
        unsigned int dsp_sfrm_int_clear : 1;
        unsigned int reserved : 8;
    } bits;
    unsigned int u32;
}HI_BBP_TDSINT_DSP_INT_CLEAR_T;
typedef union
{
    struct
    {
        unsigned int hifi_sfrm_int_alm : 1;
        unsigned int arm_sfrm_int_alm : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_TDSINT_PUB_INT_ALM_T;
typedef union
{
    struct
    {
        unsigned int slot_int_alm : 23;
        unsigned int dsp_sfrm_int_alm : 1;
        unsigned int reserved : 8;
    } bits;
    unsigned int u32;
}HI_BBP_TDSINT_DSP_INT_ALM_T;
HI_SET_GET(hi_bbp_tdsint_pub_int_msk_hifi_sfrm_int_msk,hifi_sfrm_int_msk,HI_BBP_TDSINT_PUB_INT_MSK_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_PUB_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tdsint_pub_int_msk_arm_sfrm_int_msk,arm_sfrm_int_msk,HI_BBP_TDSINT_PUB_INT_MSK_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_PUB_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tdsint_pub_int_msk_reserved,reserved,HI_BBP_TDSINT_PUB_INT_MSK_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_PUB_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tdsint_dsp_int_msk_slot_int_msk,slot_int_msk,HI_BBP_TDSINT_DSP_INT_MSK_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_DSP_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tdsint_dsp_int_msk_dsp_sfrm_int_msk,dsp_sfrm_int_msk,HI_BBP_TDSINT_DSP_INT_MSK_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_DSP_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tdsint_dsp_int_msk_reserved,reserved,HI_BBP_TDSINT_DSP_INT_MSK_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_DSP_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tdsint_pub_int_clear_hifi_sfrm_int_clear,hifi_sfrm_int_clear,HI_BBP_TDSINT_PUB_INT_CLEAR_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_PUB_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tdsint_pub_int_clear_arm_sfrm_int_clear,arm_sfrm_int_clear,HI_BBP_TDSINT_PUB_INT_CLEAR_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_PUB_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tdsint_pub_int_clear_reserved,reserved,HI_BBP_TDSINT_PUB_INT_CLEAR_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_PUB_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tdsint_dsp_int_clear_slot_int_clear,slot_int_clear,HI_BBP_TDSINT_DSP_INT_CLEAR_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_DSP_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tdsint_dsp_int_clear_dsp_sfrm_int_clear,dsp_sfrm_int_clear,HI_BBP_TDSINT_DSP_INT_CLEAR_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_DSP_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tdsint_dsp_int_clear_reserved,reserved,HI_BBP_TDSINT_DSP_INT_CLEAR_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_DSP_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tdsint_pub_int_alm_hifi_sfrm_int_alm,hifi_sfrm_int_alm,HI_BBP_TDSINT_PUB_INT_ALM_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_PUB_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_tdsint_pub_int_alm_arm_sfrm_int_alm,arm_sfrm_int_alm,HI_BBP_TDSINT_PUB_INT_ALM_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_PUB_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_tdsint_pub_int_alm_reserved,reserved,HI_BBP_TDSINT_PUB_INT_ALM_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_PUB_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_tdsint_dsp_int_alm_slot_int_alm,slot_int_alm,HI_BBP_TDSINT_DSP_INT_ALM_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_DSP_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_tdsint_dsp_int_alm_dsp_sfrm_int_alm,dsp_sfrm_int_alm,HI_BBP_TDSINT_DSP_INT_ALM_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_DSP_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_tdsint_dsp_int_alm_reserved,reserved,HI_BBP_TDSINT_DSP_INT_ALM_T,HI_BBP_TDSINT_BASE_ADDR, HI_BBP_TDSINT_DSP_INT_ALM_OFFSET)
#endif
#endif
