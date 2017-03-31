#ifndef __HI_BBP_TSTU_H__
#define __HI_BBP_TSTU_H__ 
#ifndef HI_SET_GET
#define HI_SET_GET(a0,a1,a2,a3,a4) 
#endif
#define HI_BBP_TSTU_SOFT_RST_OFFSET (0x0)
#define HI_BBP_TSTU_SFN_OFFSET (0x10)
#define HI_BBP_TSTU_SFN_OFT_OFFSET (0x14)
#define HI_BBP_TSTU_SFRM_FRAML_OFFSET (0x18)
#define HI_BBP_TSTU_SFRM_FRAML_SET_OFFSET (0x1C)
#define HI_BBP_TSTU_SLOT_INT_POS_OFFSET (0x20)
#define HI_BBP_TSTU_TIME_ADJ_START_OFFSET (0x24)
#define HI_BBP_TSTU_TIME_ADJ_ALM_OFFSET (0x28)
#define HI_BBP_TSTU_DBG_TIME_SEL_OFFSET (0x2C)
#define HI_BBP_TSTU_CLK_MSR_PRD_OFFSET (0x40)
#define HI_BBP_TSTU_CLK_STATE_CLEAR_OFFSET (0x44)
#define HI_BBP_TSTU_CLK_MSR_START_OFFSET (0x48)
#define HI_BBP_TSTU_LAYOUT_TIME_OFFSET (0x70)
#define HI_BBP_TSTU_LAYOUT_CHIP_OFFSET (0x74)
#define HI_BBP_TSTU_LAYOUT_START_OFFSET (0x78)
#define HI_BBP_TSTU_PUB_INT_MSK_OFFSET (0xA0)
#define HI_BBP_TSTU_DSP_INT_MSK_OFFSET (0xA4)
#define HI_BBP_TSTU_PUB_INT_CLEAR_OFFSET (0xA8)
#define HI_BBP_TSTU_DSP_INT_CLEAR_OFFSET (0xAC)
#define HI_BBP_TSTU_PUB_INT_ALM_OFFSET (0xB0)
#define HI_BBP_TSTU_DSP_INT_ALM_OFFSET (0xB4)
#define HI_BBP_TSTU_STU_CFG1_OFFSET (0x100)
#define HI_BBP_TSTU_STU_CFG2_OFFSET (0x104)
#define HI_BBP_TSTU_STU_CFG3_OFFSET (0x108)
#define HI_BBP_TSTU_STU_CFG4_OFFSET (0x10C)
#define HI_BBP_TSTU_TDS_STU_FRAMC_OFFSET (0x200)
#define HI_BBP_TSTU_TDS_STU_SFN_OFFSET (0x204)
#define HI_BBP_TSTU_TDS_STU_FRAML_OFFSET (0x208)
#define HI_BBP_TSTU_TDS_STU_SLOT_OFFSET (0x20C)
#define HI_BBP_TSTU_CLK_MSR_CNT_OFFSET (0x220)
#define HI_BBP_TSTU_CLK_MSR_STATE_OFFSET (0x224)
#define HI_BBP_TSTU_LAYOUT_CUR_TIME_OFFSET (0x230)
#define HI_BBP_TSTU_LAYOUT_STATE_OFFSET (0x234)
#define HI_BBP_TSTU_PUB_INT_STATE_OFFSET (0x240)
#define HI_BBP_TSTU_DSP_INT_STATE_OFFSET (0x244)
#define HI_BBP_TSTU_DBG_SNF_PRE_STU_OFFSET (0x300)
#define HI_BBP_TSTU_DBG_SFN_POST_OFFSET (0x304)
#define HI_BBP_TSTU_DBG_FRAMC_PRE_STU_OFFSET (0x308)
#define HI_BBP_TSTU_DBG_FRAMC_POST_DRX_OFFSET (0x30C)
#define HI_BBP_TSTU_DBG_FRAMC_POST_STU_OFFSET (0x310)
typedef union
{
    struct
    {
        unsigned int soft_rst : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_SOFT_RST_T;
typedef union
{
    struct
    {
        unsigned int sfn : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_SFN_T;
typedef union
{
    struct
    {
        unsigned int sfn_oft : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_SFN_OFT_T;
typedef union
{
    struct
    {
        unsigned int sfrm_framl : 20;
        unsigned int reserved : 12;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_SFRM_FRAML_T;
typedef union
{
    struct
    {
        unsigned int sfrm_framl_set : 20;
        unsigned int reserved : 12;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_SFRM_FRAML_SET_T;
typedef union
{
    struct
    {
        unsigned int spec_slot_int_pos : 16;
        unsigned int norm_slot_int_pos : 16;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_SLOT_INT_POS_T;
typedef union
{
    struct
    {
        unsigned int time_track_start : 1;
        unsigned int time_switch_start : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_TIME_ADJ_START_T;
typedef union
{
    struct
    {
        unsigned int time_adj_alm : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_TIME_ADJ_ALM_T;
typedef union
{
    struct
    {
        unsigned int dbg_time_sel : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_DBG_TIME_SEL_T;
typedef union
{
    struct
    {
        unsigned int clk_msr_prd : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_CLK_MSR_PRD_T;
typedef union
{
    struct
    {
        unsigned int clk_state_clear : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_CLK_STATE_CLEAR_T;
typedef union
{
    struct
    {
        unsigned int clk_msr_start : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_CLK_MSR_START_T;
typedef union
{
    struct
    {
        unsigned int layout_time : 32;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_LAYOUT_TIME_T;
typedef union
{
    struct
    {
        unsigned int layout_chip : 15;
        unsigned int reserved : 17;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_LAYOUT_CHIP_T;
typedef union
{
    struct
    {
        unsigned int layout_start : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_LAYOUT_START_T;
typedef union
{
    struct
    {
        unsigned int hifi_sfrm_int_msk : 1;
        unsigned int arm_sfrm_int_msk : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_PUB_INT_MSK_T;
typedef union
{
    struct
    {
        unsigned int slot_int_msk : 23;
        unsigned int dsp_sfrm_int_msk : 1;
        unsigned int reserved : 8;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_DSP_INT_MSK_T;
typedef union
{
    struct
    {
        unsigned int hifi_sfrm_int_clear : 1;
        unsigned int arm_sfrm_int_clear : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_PUB_INT_CLEAR_T;
typedef union
{
    struct
    {
        unsigned int slot_int_clear : 23;
        unsigned int dsp_sfrm_int_clear : 1;
        unsigned int reserved : 8;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_DSP_INT_CLEAR_T;
typedef union
{
    struct
    {
        unsigned int hifi_sfrm_int_alm : 1;
        unsigned int arm_sfrm_int_alm : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_PUB_INT_ALM_T;
typedef union
{
    struct
    {
        unsigned int slot_int_alm : 23;
        unsigned int dsp_sfrm_int_alm : 1;
        unsigned int reserved : 8;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_DSP_INT_ALM_T;
typedef union
{
    struct
    {
        unsigned int stu_cfg1 : 32;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_STU_CFG1_T;
typedef union
{
    struct
    {
        unsigned int stu_cfg2 : 32;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_STU_CFG2_T;
typedef union
{
    struct
    {
        unsigned int stu_cfg3 : 32;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_STU_CFG3_T;
typedef union
{
    struct
    {
        unsigned int stu_cfg4 : 32;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_STU_CFG4_T;
typedef union
{
    struct
    {
        unsigned int tds_stu_framc : 20;
        unsigned int reserved : 12;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_TDS_STU_FRAMC_T;
typedef union
{
    struct
    {
        unsigned int tds_stu_sfn : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_TDS_STU_SFN_T;
typedef union
{
    struct
    {
        unsigned int tds_stu_framl : 20;
        unsigned int reserved : 12;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_TDS_STU_FRAML_T;
typedef union
{
    struct
    {
        unsigned int tds_stu_slot : 3;
        unsigned int reserved : 29;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_TDS_STU_SLOT_T;
typedef union
{
    struct
    {
        unsigned int clk_msr_cnt : 32;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_CLK_MSR_CNT_T;
typedef union
{
    struct
    {
        unsigned int clk_msr_state : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_CLK_MSR_STATE_T;
typedef union
{
    struct
    {
        unsigned int layout_cur_time : 32;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_LAYOUT_CUR_TIME_T;
typedef union
{
    struct
    {
        unsigned int layout_state : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_LAYOUT_STATE_T;
typedef union
{
    struct
    {
        unsigned int hifi_sfrm_int_state : 1;
        unsigned int arm_sfrm_int_state : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_PUB_INT_STATE_T;
typedef union
{
    struct
    {
        unsigned int slot_int_state : 23;
        unsigned int dsp_sfrm_int_state : 1;
        unsigned int reserved : 8;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_DSP_INT_STATE_T;
typedef union
{
    struct
    {
        unsigned int dbg_sfn_pre_stu : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_DBG_SNF_PRE_STU_T;
typedef union
{
    struct
    {
        unsigned int dbg_sfn_post_stu : 16;
        unsigned int dbg_sfn_post_drx : 16;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_DBG_SFN_POST_T;
typedef union
{
    struct
    {
        unsigned int dbg_framc_pre_stu : 20;
        unsigned int reserved : 12;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_DBG_FRAMC_PRE_STU_T;
typedef union
{
    struct
    {
        unsigned int dbg_framc_post_drx : 20;
        unsigned int reserved : 12;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_DBG_FRAMC_POST_DRX_T;
typedef union
{
    struct
    {
        unsigned int dbg_framc_post_stu : 20;
        unsigned int reserved : 12;
    } bits;
    unsigned int u32;
}HI_BBP_TSTU_DBG_FRAMC_POST_STU_T;
HI_SET_GET(hi_bbp_tstu_soft_rst_soft_rst,soft_rst,HI_BBP_TSTU_SOFT_RST_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_SOFT_RST_OFFSET)
HI_SET_GET(hi_bbp_tstu_soft_rst_reserved,reserved,HI_BBP_TSTU_SOFT_RST_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_SOFT_RST_OFFSET)
HI_SET_GET(hi_bbp_tstu_sfn_sfn,sfn,HI_BBP_TSTU_SFN_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_SFN_OFFSET)
HI_SET_GET(hi_bbp_tstu_sfn_reserved,reserved,HI_BBP_TSTU_SFN_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_SFN_OFFSET)
HI_SET_GET(hi_bbp_tstu_sfn_oft_sfn_oft,sfn_oft,HI_BBP_TSTU_SFN_OFT_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_SFN_OFT_OFFSET)
HI_SET_GET(hi_bbp_tstu_sfn_oft_reserved,reserved,HI_BBP_TSTU_SFN_OFT_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_SFN_OFT_OFFSET)
HI_SET_GET(hi_bbp_tstu_sfrm_framl_sfrm_framl,sfrm_framl,HI_BBP_TSTU_SFRM_FRAML_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_SFRM_FRAML_OFFSET)
HI_SET_GET(hi_bbp_tstu_sfrm_framl_reserved,reserved,HI_BBP_TSTU_SFRM_FRAML_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_SFRM_FRAML_OFFSET)
HI_SET_GET(hi_bbp_tstu_sfrm_framl_set_sfrm_framl_set,sfrm_framl_set,HI_BBP_TSTU_SFRM_FRAML_SET_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_SFRM_FRAML_SET_OFFSET)
HI_SET_GET(hi_bbp_tstu_sfrm_framl_set_reserved,reserved,HI_BBP_TSTU_SFRM_FRAML_SET_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_SFRM_FRAML_SET_OFFSET)
HI_SET_GET(hi_bbp_tstu_slot_int_pos_spec_slot_int_pos,spec_slot_int_pos,HI_BBP_TSTU_SLOT_INT_POS_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_SLOT_INT_POS_OFFSET)
HI_SET_GET(hi_bbp_tstu_slot_int_pos_norm_slot_int_pos,norm_slot_int_pos,HI_BBP_TSTU_SLOT_INT_POS_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_SLOT_INT_POS_OFFSET)
HI_SET_GET(hi_bbp_tstu_time_adj_start_time_track_start,time_track_start,HI_BBP_TSTU_TIME_ADJ_START_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_TIME_ADJ_START_OFFSET)
HI_SET_GET(hi_bbp_tstu_time_adj_start_time_switch_start,time_switch_start,HI_BBP_TSTU_TIME_ADJ_START_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_TIME_ADJ_START_OFFSET)
HI_SET_GET(hi_bbp_tstu_time_adj_start_reserved,reserved,HI_BBP_TSTU_TIME_ADJ_START_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_TIME_ADJ_START_OFFSET)
HI_SET_GET(hi_bbp_tstu_time_adj_alm_time_adj_alm,time_adj_alm,HI_BBP_TSTU_TIME_ADJ_ALM_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_TIME_ADJ_ALM_OFFSET)
HI_SET_GET(hi_bbp_tstu_time_adj_alm_reserved,reserved,HI_BBP_TSTU_TIME_ADJ_ALM_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_TIME_ADJ_ALM_OFFSET)
HI_SET_GET(hi_bbp_tstu_dbg_time_sel_dbg_time_sel,dbg_time_sel,HI_BBP_TSTU_DBG_TIME_SEL_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DBG_TIME_SEL_OFFSET)
HI_SET_GET(hi_bbp_tstu_dbg_time_sel_reserved,reserved,HI_BBP_TSTU_DBG_TIME_SEL_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DBG_TIME_SEL_OFFSET)
HI_SET_GET(hi_bbp_tstu_clk_msr_prd_clk_msr_prd,clk_msr_prd,HI_BBP_TSTU_CLK_MSR_PRD_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_CLK_MSR_PRD_OFFSET)
HI_SET_GET(hi_bbp_tstu_clk_msr_prd_reserved,reserved,HI_BBP_TSTU_CLK_MSR_PRD_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_CLK_MSR_PRD_OFFSET)
HI_SET_GET(hi_bbp_tstu_clk_state_clear_clk_state_clear,clk_state_clear,HI_BBP_TSTU_CLK_STATE_CLEAR_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_CLK_STATE_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tstu_clk_state_clear_reserved,reserved,HI_BBP_TSTU_CLK_STATE_CLEAR_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_CLK_STATE_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tstu_clk_msr_start_clk_msr_start,clk_msr_start,HI_BBP_TSTU_CLK_MSR_START_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_CLK_MSR_START_OFFSET)
HI_SET_GET(hi_bbp_tstu_clk_msr_start_reserved,reserved,HI_BBP_TSTU_CLK_MSR_START_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_CLK_MSR_START_OFFSET)
HI_SET_GET(hi_bbp_tstu_layout_time_layout_time,layout_time,HI_BBP_TSTU_LAYOUT_TIME_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_LAYOUT_TIME_OFFSET)
HI_SET_GET(hi_bbp_tstu_layout_chip_layout_chip,layout_chip,HI_BBP_TSTU_LAYOUT_CHIP_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_LAYOUT_CHIP_OFFSET)
HI_SET_GET(hi_bbp_tstu_layout_chip_reserved,reserved,HI_BBP_TSTU_LAYOUT_CHIP_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_LAYOUT_CHIP_OFFSET)
HI_SET_GET(hi_bbp_tstu_layout_start_layout_start,layout_start,HI_BBP_TSTU_LAYOUT_START_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_LAYOUT_START_OFFSET)
HI_SET_GET(hi_bbp_tstu_layout_start_reserved,reserved,HI_BBP_TSTU_LAYOUT_START_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_LAYOUT_START_OFFSET)
HI_SET_GET(hi_bbp_tstu_pub_int_msk_hifi_sfrm_int_msk,hifi_sfrm_int_msk,HI_BBP_TSTU_PUB_INT_MSK_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_PUB_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tstu_pub_int_msk_arm_sfrm_int_msk,arm_sfrm_int_msk,HI_BBP_TSTU_PUB_INT_MSK_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_PUB_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tstu_pub_int_msk_reserved,reserved,HI_BBP_TSTU_PUB_INT_MSK_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_PUB_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tstu_dsp_int_msk_slot_int_msk,slot_int_msk,HI_BBP_TSTU_DSP_INT_MSK_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DSP_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tstu_dsp_int_msk_dsp_sfrm_int_msk,dsp_sfrm_int_msk,HI_BBP_TSTU_DSP_INT_MSK_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DSP_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tstu_dsp_int_msk_reserved,reserved,HI_BBP_TSTU_DSP_INT_MSK_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DSP_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tstu_pub_int_clear_hifi_sfrm_int_clear,hifi_sfrm_int_clear,HI_BBP_TSTU_PUB_INT_CLEAR_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_PUB_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tstu_pub_int_clear_arm_sfrm_int_clear,arm_sfrm_int_clear,HI_BBP_TSTU_PUB_INT_CLEAR_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_PUB_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tstu_pub_int_clear_reserved,reserved,HI_BBP_TSTU_PUB_INT_CLEAR_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_PUB_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tstu_dsp_int_clear_slot_int_clear,slot_int_clear,HI_BBP_TSTU_DSP_INT_CLEAR_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DSP_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tstu_dsp_int_clear_dsp_sfrm_int_clear,dsp_sfrm_int_clear,HI_BBP_TSTU_DSP_INT_CLEAR_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DSP_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tstu_dsp_int_clear_reserved,reserved,HI_BBP_TSTU_DSP_INT_CLEAR_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DSP_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tstu_pub_int_alm_hifi_sfrm_int_alm,hifi_sfrm_int_alm,HI_BBP_TSTU_PUB_INT_ALM_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_PUB_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_tstu_pub_int_alm_arm_sfrm_int_alm,arm_sfrm_int_alm,HI_BBP_TSTU_PUB_INT_ALM_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_PUB_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_tstu_pub_int_alm_reserved,reserved,HI_BBP_TSTU_PUB_INT_ALM_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_PUB_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_tstu_dsp_int_alm_slot_int_alm,slot_int_alm,HI_BBP_TSTU_DSP_INT_ALM_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DSP_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_tstu_dsp_int_alm_dsp_sfrm_int_alm,dsp_sfrm_int_alm,HI_BBP_TSTU_DSP_INT_ALM_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DSP_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_tstu_dsp_int_alm_reserved,reserved,HI_BBP_TSTU_DSP_INT_ALM_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DSP_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_tstu_stu_cfg1_stu_cfg1,stu_cfg1,HI_BBP_TSTU_STU_CFG1_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_STU_CFG1_OFFSET)
HI_SET_GET(hi_bbp_tstu_stu_cfg2_stu_cfg2,stu_cfg2,HI_BBP_TSTU_STU_CFG2_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_STU_CFG2_OFFSET)
HI_SET_GET(hi_bbp_tstu_stu_cfg3_stu_cfg3,stu_cfg3,HI_BBP_TSTU_STU_CFG3_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_STU_CFG3_OFFSET)
HI_SET_GET(hi_bbp_tstu_stu_cfg4_stu_cfg4,stu_cfg4,HI_BBP_TSTU_STU_CFG4_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_STU_CFG4_OFFSET)
HI_SET_GET(hi_bbp_tstu_tds_stu_framc_tds_stu_framc,tds_stu_framc,HI_BBP_TSTU_TDS_STU_FRAMC_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_TDS_STU_FRAMC_OFFSET)
HI_SET_GET(hi_bbp_tstu_tds_stu_framc_reserved,reserved,HI_BBP_TSTU_TDS_STU_FRAMC_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_TDS_STU_FRAMC_OFFSET)
HI_SET_GET(hi_bbp_tstu_tds_stu_sfn_tds_stu_sfn,tds_stu_sfn,HI_BBP_TSTU_TDS_STU_SFN_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_TDS_STU_SFN_OFFSET)
HI_SET_GET(hi_bbp_tstu_tds_stu_sfn_reserved,reserved,HI_BBP_TSTU_TDS_STU_SFN_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_TDS_STU_SFN_OFFSET)
HI_SET_GET(hi_bbp_tstu_tds_stu_framl_tds_stu_framl,tds_stu_framl,HI_BBP_TSTU_TDS_STU_FRAML_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_TDS_STU_FRAML_OFFSET)
HI_SET_GET(hi_bbp_tstu_tds_stu_framl_reserved,reserved,HI_BBP_TSTU_TDS_STU_FRAML_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_TDS_STU_FRAML_OFFSET)
HI_SET_GET(hi_bbp_tstu_tds_stu_slot_tds_stu_slot,tds_stu_slot,HI_BBP_TSTU_TDS_STU_SLOT_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_TDS_STU_SLOT_OFFSET)
HI_SET_GET(hi_bbp_tstu_tds_stu_slot_reserved,reserved,HI_BBP_TSTU_TDS_STU_SLOT_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_TDS_STU_SLOT_OFFSET)
HI_SET_GET(hi_bbp_tstu_clk_msr_cnt_clk_msr_cnt,clk_msr_cnt,HI_BBP_TSTU_CLK_MSR_CNT_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_CLK_MSR_CNT_OFFSET)
HI_SET_GET(hi_bbp_tstu_clk_msr_state_clk_msr_state,clk_msr_state,HI_BBP_TSTU_CLK_MSR_STATE_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_CLK_MSR_STATE_OFFSET)
HI_SET_GET(hi_bbp_tstu_clk_msr_state_reserved,reserved,HI_BBP_TSTU_CLK_MSR_STATE_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_CLK_MSR_STATE_OFFSET)
HI_SET_GET(hi_bbp_tstu_layout_cur_time_layout_cur_time,layout_cur_time,HI_BBP_TSTU_LAYOUT_CUR_TIME_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_LAYOUT_CUR_TIME_OFFSET)
HI_SET_GET(hi_bbp_tstu_layout_state_layout_state,layout_state,HI_BBP_TSTU_LAYOUT_STATE_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_LAYOUT_STATE_OFFSET)
HI_SET_GET(hi_bbp_tstu_layout_state_reserved,reserved,HI_BBP_TSTU_LAYOUT_STATE_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_LAYOUT_STATE_OFFSET)
HI_SET_GET(hi_bbp_tstu_pub_int_state_hifi_sfrm_int_state,hifi_sfrm_int_state,HI_BBP_TSTU_PUB_INT_STATE_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_PUB_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_tstu_pub_int_state_arm_sfrm_int_state,arm_sfrm_int_state,HI_BBP_TSTU_PUB_INT_STATE_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_PUB_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_tstu_pub_int_state_reserved,reserved,HI_BBP_TSTU_PUB_INT_STATE_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_PUB_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_tstu_dsp_int_state_slot_int_state,slot_int_state,HI_BBP_TSTU_DSP_INT_STATE_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DSP_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_tstu_dsp_int_state_dsp_sfrm_int_state,dsp_sfrm_int_state,HI_BBP_TSTU_DSP_INT_STATE_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DSP_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_tstu_dsp_int_state_reserved,reserved,HI_BBP_TSTU_DSP_INT_STATE_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DSP_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_tstu_dbg_snf_pre_stu_dbg_sfn_pre_stu,dbg_sfn_pre_stu,HI_BBP_TSTU_DBG_SNF_PRE_STU_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DBG_SNF_PRE_STU_OFFSET)
HI_SET_GET(hi_bbp_tstu_dbg_snf_pre_stu_reserved,reserved,HI_BBP_TSTU_DBG_SNF_PRE_STU_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DBG_SNF_PRE_STU_OFFSET)
HI_SET_GET(hi_bbp_tstu_dbg_sfn_post_dbg_sfn_post_stu,dbg_sfn_post_stu,HI_BBP_TSTU_DBG_SFN_POST_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DBG_SFN_POST_OFFSET)
HI_SET_GET(hi_bbp_tstu_dbg_sfn_post_dbg_sfn_post_drx,dbg_sfn_post_drx,HI_BBP_TSTU_DBG_SFN_POST_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DBG_SFN_POST_OFFSET)
HI_SET_GET(hi_bbp_tstu_dbg_framc_pre_stu_dbg_framc_pre_stu,dbg_framc_pre_stu,HI_BBP_TSTU_DBG_FRAMC_PRE_STU_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DBG_FRAMC_PRE_STU_OFFSET)
HI_SET_GET(hi_bbp_tstu_dbg_framc_pre_stu_reserved,reserved,HI_BBP_TSTU_DBG_FRAMC_PRE_STU_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DBG_FRAMC_PRE_STU_OFFSET)
HI_SET_GET(hi_bbp_tstu_dbg_framc_post_drx_dbg_framc_post_drx,dbg_framc_post_drx,HI_BBP_TSTU_DBG_FRAMC_POST_DRX_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DBG_FRAMC_POST_DRX_OFFSET)
HI_SET_GET(hi_bbp_tstu_dbg_framc_post_drx_reserved,reserved,HI_BBP_TSTU_DBG_FRAMC_POST_DRX_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DBG_FRAMC_POST_DRX_OFFSET)
HI_SET_GET(hi_bbp_tstu_dbg_framc_post_stu_dbg_framc_post_stu,dbg_framc_post_stu,HI_BBP_TSTU_DBG_FRAMC_POST_STU_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DBG_FRAMC_POST_STU_OFFSET)
HI_SET_GET(hi_bbp_tstu_dbg_framc_post_stu_reserved,reserved,HI_BBP_TSTU_DBG_FRAMC_POST_STU_T,HI_BBP_TSTU_BASE_ADDR, HI_BBP_TSTU_DBG_FRAMC_POST_STU_OFFSET)
#endif
