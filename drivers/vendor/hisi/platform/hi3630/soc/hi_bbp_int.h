#ifndef __HI_BBP_INT_H__
#define __HI_BBP_INT_H__ 
#ifndef HI_SET_GET
#define HI_SET_GET(a0,a1,a2,a3,a4) 
#endif
#define HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET (0x0)
#define HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET (0x4)
#define HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET (0x8)
#define HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET (0xC)
#define HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET (0x10)
#define HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET (0x14)
#define HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET (0x18)
#define HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET (0x1C)
#define HI_BBP_INT_WARN_INT_MSK_OFFSET (0x20)
#define HI_BBP_INT_WARN_INT_CLS_OFFSET (0x24)
#define HI_BBP_INT_WARN_INT_TYP_OFFSET (0x28)
#define HI_BBP_INT_ARM_INT_MSK_OFFSET (0x30)
#define HI_BBP_INT_ARM_INT_CLS_OFFSET (0x34)
#define HI_BBP_INT_ARM_INT_TYP_OFFSET (0x38)
#define HI_BBP_INT_ARM_INT_ALM_OFFSET (0x3C)
#define HI_BBP_INT_APP_ARM_INT_MSK_OFFSET (0x40)
#define HI_BBP_INT_APP_ARM_INT_CLS_OFFSET (0x44)
#define HI_BBP_INT_APP_ARM_INT_TYP_OFFSET (0x48)
#define HI_BBP_INT_PRIOR_LEVEL_OFFSET (0x50)
#define HI_BBP_INT_INT2OUT_BAK1_OFFSET (0x60)
#define HI_BBP_INT_INT2OUT_BAK2_OFFSET (0x64)
#define HI_BBP_INT_INT2OUT_BAK3_OFFSET (0x68)
#define HI_BBP_INT_INT2OUT_BAK4_OFFSET (0x6C)
#define HI_BBP_INT_INT2OUT_BAK5_OFFSET (0x70)
#define HI_BBP_INT_INT2OUT_BAK6_OFFSET (0x74)
#define HI_BBP_INT_INT2OUT_BAK7_OFFSET (0x78)
#define HI_BBP_INT_INT2OUT_BAK8_OFFSET (0x7C)
#define HI_BBP_INT_CLK_EN_SEL_OFFSET (0x160)
#define HI_BBP_INT_AHB2LBUS_CLK_SEL_OFFSET (0x164)
#define HI_BBP_INT_RFIN_SRST_EN_OFFSET (0x178)
#define HI_BBP_INT_FPU_SRST_EN_OFFSET (0x17C)
#define HI_BBP_INT_UL_SRST_EN_OFFSET (0x180)
#define HI_BBP_INT_VDL_SRST_EN_OFFSET (0x184)
#define HI_BBP_INT_PB_SRST_EN_OFFSET (0x188)
#define HI_BBP_INT_DBG_SRST_EN_OFFSET (0x18C)
#define HI_BBP_INT_AXIM_SRST_EN_OFFSET (0x190)
#define HI_BBP_INT_AXIS_SRST_EN_OFFSET (0x194)
#define HI_BBP_INT_AHBS_SRST_EN_OFFSET (0x198)
#define HI_BBP_INT_INT_SRST_EN_OFFSET (0x1A4)
#define HI_BBP_INT_STU_SRST_EN_OFFSET (0x1A8)
#define HI_BBP_INT_PDM_SRST_EN_OFFSET (0x1B4)
#define HI_BBP_INT_ATPRAM_CTRL_OFFSET (0x200)
#ifndef __ASSEMBLY__
typedef union
{
    struct
    {
        unsigned int dsp_sym_int_msk_0 : 1;
        unsigned int dsp_sym_int_msk_1 : 1;
        unsigned int dsp_sym_int_msk_2 : 1;
        unsigned int dsp_sym_int_msk_3 : 1;
        unsigned int dsp_sym_int_msk_4 : 1;
        unsigned int dsp_sym_int_msk_5 : 1;
        unsigned int dsp_sym_int_msk_6 : 1;
        unsigned int dsp_sym_int_msk_7 : 1;
        unsigned int dsp_sym_int_msk_8 : 1;
        unsigned int dsp_sym_int_msk_9 : 1;
        unsigned int dsp_sym_int_msk_10 : 1;
        unsigned int dsp_sym_int_mask_11 : 1;
        unsigned int dsp_sym_int_msk_12 : 1;
        unsigned int dsp_sym_int_msk_13 : 1;
        unsigned int Reserved : 18;
    } bits;
    unsigned int u32;
}HI_BBP_INT_DSP_SYM_INT_MSK_T;
typedef union
{
    struct
    {
        unsigned int dsp_sym_int_cls_0 : 1;
        unsigned int dsp_sym_int_cls_1 : 1;
        unsigned int dsp_sym_int_cls_2 : 1;
        unsigned int dsp_sym_int_cls_3 : 1;
        unsigned int dsp_sym_int_cls_4 : 1;
        unsigned int dsp_sym_int_cls_5 : 1;
        unsigned int dsp_sym_int_cls_6 : 1;
        unsigned int dsp_sym_int_cls_7 : 1;
        unsigned int dsp_sym_int_cls_8 : 1;
        unsigned int dsp_sym_int_cls_9 : 1;
        unsigned int dsp_sym_int_cls_10 : 1;
        unsigned int dsp_sym_int_cls_11 : 1;
        unsigned int dsp_sym_int_cls_12 : 1;
        unsigned int dsp_sym_int_cls_13 : 1;
        unsigned int Reserved : 18;
    } bits;
    unsigned int u32;
}HI_BBP_INT_DSP_SYM_INT_CLS_T;
typedef union
{
    struct
    {
        unsigned int dsp_sym_int_typ_0 : 1;
        unsigned int dsp_sym_int_typ_1 : 1;
        unsigned int dsp_sym_int_typ_2 : 1;
        unsigned int dsp_sym_int_typ_3 : 1;
        unsigned int dsp_sym_int_typ_4 : 1;
        unsigned int dsp_sym_int_typ_5 : 1;
        unsigned int dsp_sym_int_typ_6 : 1;
        unsigned int dsp_sym_int_typ_7 : 1;
        unsigned int dsp_sym_int_typ_8 : 1;
        unsigned int dsp_sym_int_typ_9 : 1;
        unsigned int dsp_sym_int_typ_10 : 1;
        unsigned int dsp_sym_int_typ_11 : 1;
        unsigned int dsp_sym_int_typ_12 : 1;
        unsigned int dsp_sym_int_typ_13 : 1;
        unsigned int Reserved : 18;
    } bits;
    unsigned int u32;
}HI_BBP_INT_DSP_SYM_INT_TYP_T;
typedef union
{
    struct
    {
        unsigned int dsp_sym_int_alm_0 : 1;
        unsigned int dsp_sym_int_alm_1 : 1;
        unsigned int dsp_sym_int_alm_2 : 1;
        unsigned int dsp_sym_int_alm_3 : 1;
        unsigned int dsp_sym_int_alm_4 : 1;
        unsigned int dsp_sym_int_alm_5 : 1;
        unsigned int dsp_sym_int_alm_6 : 1;
        unsigned int dsp_sym_int_alm_7 : 1;
        unsigned int dsp_sym_int_alm_8 : 1;
        unsigned int dsp_sym_int_alm_9 : 1;
        unsigned int dsp_sym_int_alm_10 : 1;
        unsigned int dsp_sym_int_alm_11 : 1;
        unsigned int dsp_sym_int_alm_12 : 1;
        unsigned int dsp_sym_int_alm_13 : 1;
        unsigned int Reserved : 18;
    } bits;
    unsigned int u32;
}HI_BBP_INT_DSP_SYM_INT_ALM_T;
typedef union
{
    struct
    {
        unsigned int dsp_cells_int_msk : 1;
        unsigned int dsp_pwrm_int_msk : 1;
        unsigned int dsp_cqi_int_msk : 1;
        unsigned int dsp_pb_int_msk : 1;
        unsigned int dsp_pdu0_int_msk : 1;
        unsigned int dsp_pdu1_int_msk : 1;
        unsigned int dsp_pdu2_int_msk : 1;
        unsigned int dsp_cmu_int_msk : 1;
        unsigned int dsp_vdl_int_msk : 1;
        unsigned int dsp_cfi_int_msk : 1;
        unsigned int dsp_dma_int_msk : 1;
        unsigned int dsp_tdl_int_mask : 1;
        unsigned int dsp_dcf_int_msk : 1;
        unsigned int dsp_ul_int_msk : 1;
        unsigned int dsp_fpu_int_msk : 1;
        unsigned int dsp_aagc_int_msk : 1;
        unsigned int dsp_rstd_int_msk : 1;
        unsigned int dsp_dma_anten0_int_msk : 1;
        unsigned int dsp_dma_anten1_int_msk : 1;
        unsigned int dsp_wlan_priority_int_msk : 1;
        unsigned int dsp_wlan_tx_active_int_msk : 1;
        unsigned int Reserved : 11;
    } bits;
    unsigned int u32;
}HI_BBP_INT_DSP_MOD_INT_MSK_T;
typedef union
{
    struct
    {
        unsigned int dsp_cells_int_cls : 1;
        unsigned int dsp_pwrm_int_cls : 1;
        unsigned int dsp_cqi_int_cls : 1;
        unsigned int dsp_pb_int_cls : 1;
        unsigned int dsp_pdu0_int_cls : 1;
        unsigned int dsp_pdu1_int_cls : 1;
        unsigned int dsp_pdu2_int_cls : 1;
        unsigned int dsp_cmu_int_cls : 1;
        unsigned int dsp_vdl_int_cls : 1;
        unsigned int dsp_cfi_int_cls : 1;
        unsigned int dsp_dma_int_cls : 1;
        unsigned int dsp_tdl_int_cls : 1;
        unsigned int dsp_dcf_int_cls : 1;
        unsigned int dsp_ul_int_cls : 1;
        unsigned int dsp_fpu_int_cls : 1;
        unsigned int dsp_aagc_int_cls : 1;
        unsigned int dsp_rstd_int_cls : 1;
        unsigned int dsp_dma_anten0_int_cls : 1;
        unsigned int dsp_dma_anten1_int_cls : 1;
        unsigned int dsp_wlan_priority_int_cls : 1;
        unsigned int dsp_wlan_tx_active_int_cls : 1;
        unsigned int Reserved : 11;
    } bits;
    unsigned int u32;
}HI_BBP_INT_DSP_MOD_INT_CLS_T;
typedef union
{
    struct
    {
        unsigned int dsp_cells_int_typ : 1;
        unsigned int dsp_pwrm_int_typ : 1;
        unsigned int dsp_cqi_int_typ : 1;
        unsigned int dsp_pb_int_typ : 1;
        unsigned int dsp_pdu0_int_typ : 1;
        unsigned int dsp_pdu1_int_typ : 1;
        unsigned int dsp_pdu2_int_typ : 1;
        unsigned int dsp_cmu_int_typ : 1;
        unsigned int dsp_vdl_int_typ : 1;
        unsigned int dsp_cfi_int_typ : 1;
        unsigned int dsp_dma_int_typ : 1;
        unsigned int dsp_tdl_int_typ : 1;
        unsigned int dsp_dcf_int_typ : 1;
        unsigned int dsp_ul_int_typ : 1;
        unsigned int dsp_fpu_int_typ : 1;
        unsigned int dsp_aagc_int_typ : 1;
        unsigned int dsp_rstd_int_typ : 1;
        unsigned int dsp_dma_anten0_int_typ : 1;
        unsigned int dsp_dma_anten1_int_typ : 1;
        unsigned int dsp_wlan_priority_int_typ : 1;
        unsigned int dsp_wlan_tx_active_int_typ : 1;
        unsigned int Reserved : 11;
    } bits;
    unsigned int u32;
}HI_BBP_INT_DSP_MOD_INT_TYP_T;
typedef union
{
    struct
    {
        unsigned int dsp_cells_int_alm : 1;
        unsigned int dsp_pwrm_int_alm : 1;
        unsigned int dsp_cqi_int_alm : 1;
        unsigned int dsp_pb_int_alm : 1;
        unsigned int dsp_pdu0_int_alm : 1;
        unsigned int dsp_pdu1_int_alm : 1;
        unsigned int dsp_pdu2_int_alm : 1;
        unsigned int dsp_cmu_int_alm : 1;
        unsigned int dsp_vdl_int_alm : 1;
        unsigned int dsp_cfi_int_alm : 1;
        unsigned int dsp_dma_int_alm : 1;
        unsigned int dsp_tdl_int_alm : 1;
        unsigned int dsp_dcf_int_alm : 1;
        unsigned int dsp_ul_int_alm : 1;
        unsigned int dsp_fpu_int_alm : 1;
        unsigned int dsp_aagc_int_alm : 1;
        unsigned int dsp_rstd_int_alm : 1;
        unsigned int dsp_dma_anten0_int_alm : 1;
        unsigned int dsp_dma_anten1_int_alm : 1;
        unsigned int dsp_wlan_priority_int_alm : 1;
        unsigned int dsp_wlan_tx_active_int_alm : 1;
        unsigned int Reserved : 11;
    } bits;
    unsigned int u32;
}HI_BBP_INT_DSP_MOD_INT_ALM_T;
typedef union
{
    struct
    {
        unsigned int rfin_warn_int_msk : 1;
        unsigned int fpu_warn_int_msk : 1;
        unsigned int ul_warn_int_msk : 1;
        unsigned int cqi_warn_int_msk : 1;
        unsigned int pb_warn_int_msk : 1;
        unsigned int vdl_warn_int_msk : 1;
        unsigned int pdu_warn_int_msk : 1;
        unsigned int tdl_warn_int_msk : 1;
        unsigned int dma_warn_int_msk : 1;
        unsigned int Reserved : 23;
    } bits;
    unsigned int u32;
}HI_BBP_INT_WARN_INT_MSK_T;
typedef union
{
    struct
    {
        unsigned int rfin_warn_int_cls : 1;
        unsigned int fpu_warn_int_cls : 1;
        unsigned int ul_warn_int_cls : 1;
        unsigned int cqi_warn_int_cls : 1;
        unsigned int pb_warn_int_cls : 1;
        unsigned int vdl_warn_int_cls : 1;
        unsigned int pdu_warn_int_cls : 1;
        unsigned int tdl_warn_int_cls : 1;
        unsigned int dma_warn_int_cls : 1;
        unsigned int Reserved : 23;
    } bits;
    unsigned int u32;
}HI_BBP_INT_WARN_INT_CLS_T;
typedef union
{
    struct
    {
        unsigned int rfin_warn_int_typ : 1;
        unsigned int fpu_warn_int_typ : 1;
        unsigned int ul_warn_int_typ : 1;
        unsigned int cqi_warn_int_typ : 1;
        unsigned int pb_warn_int_typ : 1;
        unsigned int vdl_warn_int_typ : 1;
        unsigned int pdu_warn_int_typ : 1;
        unsigned int tdl_warn_int_typ : 1;
        unsigned int dma_warn_int_typ : 1;
        unsigned int Reserved : 23;
    } bits;
    unsigned int u32;
}HI_BBP_INT_WARN_INT_TYP_T;
typedef union
{
    struct
    {
        unsigned int arm_position_int_msk : 1;
        unsigned int arm_dl_dma_int_msk : 1;
        unsigned int Reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_INT_ARM_INT_MSK_T;
typedef union
{
    struct
    {
        unsigned int arm_position_int_cls : 1;
        unsigned int arm_dl_dma_int_cls : 1;
        unsigned int Reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_INT_ARM_INT_CLS_T;
typedef union
{
    struct
    {
        unsigned int arm_position_int_typ : 1;
        unsigned int arm_dl_dma_int_typ : 1;
        unsigned int Reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_INT_ARM_INT_TYP_T;
typedef union
{
    struct
    {
        unsigned int arm_position_int_alm : 1;
        unsigned int arm_dl_dma_int_alm : 1;
        unsigned int Reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_INT_ARM_INT_ALM_T;
typedef union
{
    struct
    {
        unsigned int aarm_dbg_msk : 1;
        unsigned int aarm_dma_msk : 1;
        unsigned int Reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_INT_APP_ARM_INT_MSK_T;
typedef union
{
    struct
    {
        unsigned int aarm_dbg_cls : 1;
        unsigned int aarm_dma_cls : 1;
        unsigned int Reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_INT_APP_ARM_INT_CLS_T;
typedef union
{
    struct
    {
        unsigned int aarm_dbg_typ : 1;
        unsigned int aarm_dma_typ : 1;
        unsigned int Reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_INT_APP_ARM_INT_TYP_T;
typedef union
{
    struct
    {
        unsigned int prior_level : 2;
        unsigned int Reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_INT_PRIOR_LEVEL_T;
typedef union
{
    struct
    {
        unsigned int xs_rs_gated_en : 1;
        unsigned int hs_rs_gated_en : 1;
        unsigned int xm_gated_en : 1;
        unsigned int xs_gs_gated_en : 1;
        unsigned int hs_gs_gated_en : 1;
        unsigned int int2out_bak1 : 11;
        unsigned int Reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_INT_INT2OUT_BAK1_T;
typedef union
{
    struct
    {
        unsigned int int2out_bak2 : 16;
        unsigned int Reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_INT_INT2OUT_BAK2_T;
typedef union
{
    struct
    {
        unsigned int int2out_bak3 : 16;
        unsigned int Reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_INT_INT2OUT_BAK3_T;
typedef union
{
    struct
    {
        unsigned int dt0_int_typ : 1;
        unsigned int dt1_int_typ : 1;
        unsigned int dt2_int_typ : 1;
        unsigned int dt3_int_typ : 1;
        unsigned int dt4_int_typ : 1;
        unsigned int dt5_int_typ : 1;
        unsigned int dt6_int_typ : 1;
        unsigned int dt7_int_typ : 1;
        unsigned int dt0_int_alm : 1;
        unsigned int dt1_int_alm : 1;
        unsigned int dt2_int_alm : 1;
        unsigned int dt3_int_alm : 1;
        unsigned int dt4_int_alm : 1;
        unsigned int dt5_int_alm : 1;
        unsigned int dt6_int_alm : 1;
        unsigned int dt7_int_alm : 1;
        unsigned int Reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_INT_INT2OUT_BAK4_T;
typedef union
{
    struct
    {
        unsigned int Reserved_1 : 8;
        unsigned int dt_int_msk : 1;
        unsigned int Reserved_0 : 23;
    } bits;
    unsigned int u32;
}HI_BBP_INT_INT2OUT_BAK5_T;
typedef union
{
    struct
    {
        unsigned int int2out_bak6 : 16;
        unsigned int Reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_INT_INT2OUT_BAK6_T;
typedef union
{
    struct
    {
        unsigned int int2out_bak7 : 16;
        unsigned int Reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_INT_INT2OUT_BAK7_T;
typedef union
{
    struct
    {
        unsigned int int2out_bak8 : 16;
        unsigned int Reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_INT_INT2OUT_BAK8_T;
typedef union
{
    struct
    {
        unsigned int Reserved_4 : 1;
        unsigned int Reserved_3 : 1;
        unsigned int rfin_clk_sel : 1;
        unsigned int fpu_clk_sel : 1;
        unsigned int ul_clk_sel : 1;
        unsigned int vdl_clk_sel : 1;
        unsigned int pb_clk_sel : 1;
        unsigned int dbg_clk_sel : 1;
        unsigned int axim_clk_sel : 1;
        unsigned int axis_clk_sel : 1;
        unsigned int ahbs_clk_sel : 1;
        unsigned int Reserved_2 : 1;
        unsigned int Reserved_1 : 1;
        unsigned int pdm_clk_sel : 1;
        unsigned int Reserved_0 : 18;
    } bits;
    unsigned int u32;
}HI_BBP_INT_CLK_EN_SEL_T;
typedef union
{
    struct
    {
        unsigned int ahb2lbus_clk_sel : 1;
        unsigned int Reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_INT_AHB2LBUS_CLK_SEL_T;
typedef union
{
    struct
    {
        unsigned int rfin_srst_en : 1;
        unsigned int Reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_INT_RFIN_SRST_EN_T;
typedef union
{
    struct
    {
        unsigned int fpu_srst_en : 1;
        unsigned int Reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_INT_FPU_SRST_EN_T;
typedef union
{
    struct
    {
        unsigned int ul_srst_en : 1;
        unsigned int Reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_INT_UL_SRST_EN_T;
typedef union
{
    struct
    {
        unsigned int vdl_srst_en : 1;
        unsigned int Reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_INT_VDL_SRST_EN_T;
typedef union
{
    struct
    {
        unsigned int pb_srst_en : 1;
        unsigned int Reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_INT_PB_SRST_EN_T;
typedef union
{
    struct
    {
        unsigned int dbg_srst_en : 1;
        unsigned int Reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_INT_DBG_SRST_EN_T;
typedef union
{
    struct
    {
        unsigned int axim_srst_en : 1;
        unsigned int Reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_INT_AXIM_SRST_EN_T;
typedef union
{
    struct
    {
        unsigned int axis_srst_en : 1;
        unsigned int Reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_INT_AXIS_SRST_EN_T;
typedef union
{
    struct
    {
        unsigned int ahbs_srst_en : 1;
        unsigned int Reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_INT_AHBS_SRST_EN_T;
typedef union
{
    struct
    {
        unsigned int int_srst_en : 1;
        unsigned int Reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_INT_INT_SRST_EN_T;
typedef union
{
    struct
    {
        unsigned int stu_srst_en : 1;
        unsigned int Reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_INT_STU_SRST_EN_T;
typedef union
{
    struct
    {
        unsigned int pdm_srst_en : 1;
        unsigned int Reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_INT_PDM_SRST_EN_T;
typedef union
{
    struct
    {
        unsigned int atpram_ctrl : 16;
        unsigned int Reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_INT_ATPRAM_CTRL_T;
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_dsp_sym_int_msk_0,dsp_sym_int_msk_0,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_dsp_sym_int_msk_1,dsp_sym_int_msk_1,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_dsp_sym_int_msk_2,dsp_sym_int_msk_2,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_dsp_sym_int_msk_3,dsp_sym_int_msk_3,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_dsp_sym_int_msk_4,dsp_sym_int_msk_4,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_dsp_sym_int_msk_5,dsp_sym_int_msk_5,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_dsp_sym_int_msk_6,dsp_sym_int_msk_6,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_dsp_sym_int_msk_7,dsp_sym_int_msk_7,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_dsp_sym_int_msk_8,dsp_sym_int_msk_8,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_dsp_sym_int_msk_9,dsp_sym_int_msk_9,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_dsp_sym_int_msk_10,dsp_sym_int_msk_10,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_dsp_sym_int_mask_11,dsp_sym_int_mask_11,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_dsp_sym_int_msk_12,dsp_sym_int_msk_12,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_dsp_sym_int_msk_13,dsp_sym_int_msk_13,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_msk_reserved,Reserved,HI_BBP_INT_DSP_SYM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_dsp_sym_int_cls_0,dsp_sym_int_cls_0,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_dsp_sym_int_cls_1,dsp_sym_int_cls_1,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_dsp_sym_int_cls_2,dsp_sym_int_cls_2,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_dsp_sym_int_cls_3,dsp_sym_int_cls_3,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_dsp_sym_int_cls_4,dsp_sym_int_cls_4,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_dsp_sym_int_cls_5,dsp_sym_int_cls_5,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_dsp_sym_int_cls_6,dsp_sym_int_cls_6,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_dsp_sym_int_cls_7,dsp_sym_int_cls_7,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_dsp_sym_int_cls_8,dsp_sym_int_cls_8,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_dsp_sym_int_cls_9,dsp_sym_int_cls_9,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_dsp_sym_int_cls_10,dsp_sym_int_cls_10,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_dsp_sym_int_cls_11,dsp_sym_int_cls_11,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_dsp_sym_int_cls_12,dsp_sym_int_cls_12,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_dsp_sym_int_cls_13,dsp_sym_int_cls_13,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_cls_reserved,Reserved,HI_BBP_INT_DSP_SYM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_dsp_sym_int_typ_0,dsp_sym_int_typ_0,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_dsp_sym_int_typ_1,dsp_sym_int_typ_1,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_dsp_sym_int_typ_2,dsp_sym_int_typ_2,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_dsp_sym_int_typ_3,dsp_sym_int_typ_3,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_dsp_sym_int_typ_4,dsp_sym_int_typ_4,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_dsp_sym_int_typ_5,dsp_sym_int_typ_5,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_dsp_sym_int_typ_6,dsp_sym_int_typ_6,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_dsp_sym_int_typ_7,dsp_sym_int_typ_7,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_dsp_sym_int_typ_8,dsp_sym_int_typ_8,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_dsp_sym_int_typ_9,dsp_sym_int_typ_9,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_dsp_sym_int_typ_10,dsp_sym_int_typ_10,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_dsp_sym_int_typ_11,dsp_sym_int_typ_11,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_dsp_sym_int_typ_12,dsp_sym_int_typ_12,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_dsp_sym_int_typ_13,dsp_sym_int_typ_13,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_typ_reserved,Reserved,HI_BBP_INT_DSP_SYM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_dsp_sym_int_alm_0,dsp_sym_int_alm_0,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_dsp_sym_int_alm_1,dsp_sym_int_alm_1,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_dsp_sym_int_alm_2,dsp_sym_int_alm_2,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_dsp_sym_int_alm_3,dsp_sym_int_alm_3,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_dsp_sym_int_alm_4,dsp_sym_int_alm_4,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_dsp_sym_int_alm_5,dsp_sym_int_alm_5,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_dsp_sym_int_alm_6,dsp_sym_int_alm_6,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_dsp_sym_int_alm_7,dsp_sym_int_alm_7,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_dsp_sym_int_alm_8,dsp_sym_int_alm_8,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_dsp_sym_int_alm_9,dsp_sym_int_alm_9,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_dsp_sym_int_alm_10,dsp_sym_int_alm_10,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_dsp_sym_int_alm_11,dsp_sym_int_alm_11,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_dsp_sym_int_alm_12,dsp_sym_int_alm_12,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_dsp_sym_int_alm_13,dsp_sym_int_alm_13,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_sym_int_alm_reserved,Reserved,HI_BBP_INT_DSP_SYM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_SYM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_cells_int_msk,dsp_cells_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_pwrm_int_msk,dsp_pwrm_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_cqi_int_msk,dsp_cqi_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_pb_int_msk,dsp_pb_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_pdu0_int_msk,dsp_pdu0_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_pdu1_int_msk,dsp_pdu1_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_pdu2_int_msk,dsp_pdu2_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_cmu_int_msk,dsp_cmu_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_vdl_int_msk,dsp_vdl_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_cfi_int_msk,dsp_cfi_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_dma_int_msk,dsp_dma_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_tdl_int_mask,dsp_tdl_int_mask,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_dcf_int_msk,dsp_dcf_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_ul_int_msk,dsp_ul_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_fpu_int_msk,dsp_fpu_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_aagc_int_msk,dsp_aagc_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_rstd_int_msk,dsp_rstd_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_dma_anten0_int_msk,dsp_dma_anten0_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_dma_anten1_int_msk,dsp_dma_anten1_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_wlan_priority_int_msk,dsp_wlan_priority_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_dsp_wlan_tx_active_int_msk,dsp_wlan_tx_active_int_msk,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_msk_reserved,Reserved,HI_BBP_INT_DSP_MOD_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_cells_int_cls,dsp_cells_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_pwrm_int_cls,dsp_pwrm_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_cqi_int_cls,dsp_cqi_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_pb_int_cls,dsp_pb_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_pdu0_int_cls,dsp_pdu0_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_pdu1_int_cls,dsp_pdu1_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_pdu2_int_cls,dsp_pdu2_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_cmu_int_cls,dsp_cmu_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_vdl_int_cls,dsp_vdl_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_cfi_int_cls,dsp_cfi_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_dma_int_cls,dsp_dma_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_tdl_int_cls,dsp_tdl_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_dcf_int_cls,dsp_dcf_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_ul_int_cls,dsp_ul_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_fpu_int_cls,dsp_fpu_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_aagc_int_cls,dsp_aagc_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_rstd_int_cls,dsp_rstd_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_dma_anten0_int_cls,dsp_dma_anten0_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_dma_anten1_int_cls,dsp_dma_anten1_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_wlan_priority_int_cls,dsp_wlan_priority_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_dsp_wlan_tx_active_int_cls,dsp_wlan_tx_active_int_cls,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_cls_reserved,Reserved,HI_BBP_INT_DSP_MOD_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_cells_int_typ,dsp_cells_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_pwrm_int_typ,dsp_pwrm_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_cqi_int_typ,dsp_cqi_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_pb_int_typ,dsp_pb_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_pdu0_int_typ,dsp_pdu0_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_pdu1_int_typ,dsp_pdu1_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_pdu2_int_typ,dsp_pdu2_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_cmu_int_typ,dsp_cmu_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_vdl_int_typ,dsp_vdl_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_cfi_int_typ,dsp_cfi_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_dma_int_typ,dsp_dma_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_tdl_int_typ,dsp_tdl_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_dcf_int_typ,dsp_dcf_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_ul_int_typ,dsp_ul_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_fpu_int_typ,dsp_fpu_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_aagc_int_typ,dsp_aagc_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_rstd_int_typ,dsp_rstd_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_dma_anten0_int_typ,dsp_dma_anten0_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_dma_anten1_int_typ,dsp_dma_anten1_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_wlan_priority_int_typ,dsp_wlan_priority_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_dsp_wlan_tx_active_int_typ,dsp_wlan_tx_active_int_typ,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_typ_reserved,Reserved,HI_BBP_INT_DSP_MOD_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_cells_int_alm,dsp_cells_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_pwrm_int_alm,dsp_pwrm_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_cqi_int_alm,dsp_cqi_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_pb_int_alm,dsp_pb_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_pdu0_int_alm,dsp_pdu0_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_pdu1_int_alm,dsp_pdu1_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_pdu2_int_alm,dsp_pdu2_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_cmu_int_alm,dsp_cmu_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_vdl_int_alm,dsp_vdl_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_cfi_int_alm,dsp_cfi_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_dma_int_alm,dsp_dma_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_tdl_int_alm,dsp_tdl_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_dcf_int_alm,dsp_dcf_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_ul_int_alm,dsp_ul_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_fpu_int_alm,dsp_fpu_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_aagc_int_alm,dsp_aagc_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_rstd_int_alm,dsp_rstd_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_dma_anten0_int_alm,dsp_dma_anten0_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_dma_anten1_int_alm,dsp_dma_anten1_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_wlan_priority_int_alm,dsp_wlan_priority_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_dsp_wlan_tx_active_int_alm,dsp_wlan_tx_active_int_alm,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_dsp_mod_int_alm_reserved,Reserved,HI_BBP_INT_DSP_MOD_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DSP_MOD_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_msk_rfin_warn_int_msk,rfin_warn_int_msk,HI_BBP_INT_WARN_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_msk_fpu_warn_int_msk,fpu_warn_int_msk,HI_BBP_INT_WARN_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_msk_ul_warn_int_msk,ul_warn_int_msk,HI_BBP_INT_WARN_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_msk_cqi_warn_int_msk,cqi_warn_int_msk,HI_BBP_INT_WARN_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_msk_pb_warn_int_msk,pb_warn_int_msk,HI_BBP_INT_WARN_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_msk_vdl_warn_int_msk,vdl_warn_int_msk,HI_BBP_INT_WARN_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_msk_pdu_warn_int_msk,pdu_warn_int_msk,HI_BBP_INT_WARN_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_msk_tdl_warn_int_msk,tdl_warn_int_msk,HI_BBP_INT_WARN_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_msk_dma_warn_int_msk,dma_warn_int_msk,HI_BBP_INT_WARN_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_msk_reserved,Reserved,HI_BBP_INT_WARN_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_cls_rfin_warn_int_cls,rfin_warn_int_cls,HI_BBP_INT_WARN_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_cls_fpu_warn_int_cls,fpu_warn_int_cls,HI_BBP_INT_WARN_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_cls_ul_warn_int_cls,ul_warn_int_cls,HI_BBP_INT_WARN_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_cls_cqi_warn_int_cls,cqi_warn_int_cls,HI_BBP_INT_WARN_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_cls_pb_warn_int_cls,pb_warn_int_cls,HI_BBP_INT_WARN_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_cls_vdl_warn_int_cls,vdl_warn_int_cls,HI_BBP_INT_WARN_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_cls_pdu_warn_int_cls,pdu_warn_int_cls,HI_BBP_INT_WARN_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_cls_tdl_warn_int_cls,tdl_warn_int_cls,HI_BBP_INT_WARN_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_cls_dma_warn_int_cls,dma_warn_int_cls,HI_BBP_INT_WARN_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_cls_reserved,Reserved,HI_BBP_INT_WARN_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_typ_rfin_warn_int_typ,rfin_warn_int_typ,HI_BBP_INT_WARN_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_typ_fpu_warn_int_typ,fpu_warn_int_typ,HI_BBP_INT_WARN_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_typ_ul_warn_int_typ,ul_warn_int_typ,HI_BBP_INT_WARN_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_typ_cqi_warn_int_typ,cqi_warn_int_typ,HI_BBP_INT_WARN_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_typ_pb_warn_int_typ,pb_warn_int_typ,HI_BBP_INT_WARN_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_typ_vdl_warn_int_typ,vdl_warn_int_typ,HI_BBP_INT_WARN_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_typ_pdu_warn_int_typ,pdu_warn_int_typ,HI_BBP_INT_WARN_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_typ_tdl_warn_int_typ,tdl_warn_int_typ,HI_BBP_INT_WARN_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_typ_dma_warn_int_typ,dma_warn_int_typ,HI_BBP_INT_WARN_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_warn_int_typ_reserved,Reserved,HI_BBP_INT_WARN_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_WARN_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_arm_int_msk_arm_position_int_msk,arm_position_int_msk,HI_BBP_INT_ARM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_ARM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_arm_int_msk_arm_dl_dma_int_msk,arm_dl_dma_int_msk,HI_BBP_INT_ARM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_ARM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_arm_int_msk_reserved,Reserved,HI_BBP_INT_ARM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_ARM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_arm_int_cls_arm_position_int_cls,arm_position_int_cls,HI_BBP_INT_ARM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_ARM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_arm_int_cls_arm_dl_dma_int_cls,arm_dl_dma_int_cls,HI_BBP_INT_ARM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_ARM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_arm_int_cls_reserved,Reserved,HI_BBP_INT_ARM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_ARM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_arm_int_typ_arm_position_int_typ,arm_position_int_typ,HI_BBP_INT_ARM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_ARM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_arm_int_typ_arm_dl_dma_int_typ,arm_dl_dma_int_typ,HI_BBP_INT_ARM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_ARM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_arm_int_typ_reserved,Reserved,HI_BBP_INT_ARM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_ARM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_arm_int_alm_arm_position_int_alm,arm_position_int_alm,HI_BBP_INT_ARM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_ARM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_arm_int_alm_arm_dl_dma_int_alm,arm_dl_dma_int_alm,HI_BBP_INT_ARM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_ARM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_arm_int_alm_reserved,Reserved,HI_BBP_INT_ARM_INT_ALM_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_ARM_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_int_app_arm_int_msk_aarm_dbg_msk,aarm_dbg_msk,HI_BBP_INT_APP_ARM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_APP_ARM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_app_arm_int_msk_aarm_dma_msk,aarm_dma_msk,HI_BBP_INT_APP_ARM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_APP_ARM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_app_arm_int_msk_reserved,Reserved,HI_BBP_INT_APP_ARM_INT_MSK_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_APP_ARM_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_int_app_arm_int_cls_aarm_dbg_cls,aarm_dbg_cls,HI_BBP_INT_APP_ARM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_APP_ARM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_app_arm_int_cls_aarm_dma_cls,aarm_dma_cls,HI_BBP_INT_APP_ARM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_APP_ARM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_app_arm_int_cls_reserved,Reserved,HI_BBP_INT_APP_ARM_INT_CLS_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_APP_ARM_INT_CLS_OFFSET)
HI_SET_GET(hi_bbp_int_app_arm_int_typ_aarm_dbg_typ,aarm_dbg_typ,HI_BBP_INT_APP_ARM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_APP_ARM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_app_arm_int_typ_aarm_dma_typ,aarm_dma_typ,HI_BBP_INT_APP_ARM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_APP_ARM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_app_arm_int_typ_reserved,Reserved,HI_BBP_INT_APP_ARM_INT_TYP_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_APP_ARM_INT_TYP_OFFSET)
HI_SET_GET(hi_bbp_int_prior_level_prior_level,prior_level,HI_BBP_INT_PRIOR_LEVEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_PRIOR_LEVEL_OFFSET)
HI_SET_GET(hi_bbp_int_prior_level_reserved,Reserved,HI_BBP_INT_PRIOR_LEVEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_PRIOR_LEVEL_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak1_xs_rs_gated_en,xs_rs_gated_en,HI_BBP_INT_INT2OUT_BAK1_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK1_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak1_hs_rs_gated_en,hs_rs_gated_en,HI_BBP_INT_INT2OUT_BAK1_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK1_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak1_xm_gated_en,xm_gated_en,HI_BBP_INT_INT2OUT_BAK1_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK1_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak1_xs_gs_gated_en,xs_gs_gated_en,HI_BBP_INT_INT2OUT_BAK1_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK1_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak1_hs_gs_gated_en,hs_gs_gated_en,HI_BBP_INT_INT2OUT_BAK1_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK1_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak1_int2out_bak1,int2out_bak1,HI_BBP_INT_INT2OUT_BAK1_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK1_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak1_reserved,Reserved,HI_BBP_INT_INT2OUT_BAK1_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK1_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak2_int2out_bak2,int2out_bak2,HI_BBP_INT_INT2OUT_BAK2_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK2_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak2_reserved,Reserved,HI_BBP_INT_INT2OUT_BAK2_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK2_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak3_int2out_bak3,int2out_bak3,HI_BBP_INT_INT2OUT_BAK3_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK3_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak3_reserved,Reserved,HI_BBP_INT_INT2OUT_BAK3_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK3_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt0_int_typ,dt0_int_typ,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt1_int_typ,dt1_int_typ,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt2_int_typ,dt2_int_typ,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt3_int_typ,dt3_int_typ,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt4_int_typ,dt4_int_typ,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt5_int_typ,dt5_int_typ,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt6_int_typ,dt6_int_typ,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt7_int_typ,dt7_int_typ,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt0_int_alm,dt0_int_alm,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt1_int_alm,dt1_int_alm,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt2_int_alm,dt2_int_alm,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt3_int_alm,dt3_int_alm,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt4_int_alm,dt4_int_alm,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt5_int_alm,dt5_int_alm,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt6_int_alm,dt6_int_alm,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_dt7_int_alm,dt7_int_alm,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak4_reserved,Reserved,HI_BBP_INT_INT2OUT_BAK4_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK4_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak5_reserved_1,Reserved_1,HI_BBP_INT_INT2OUT_BAK5_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK5_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak5_dt_int_msk,dt_int_msk,HI_BBP_INT_INT2OUT_BAK5_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK5_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak5_reserved_0,Reserved_0,HI_BBP_INT_INT2OUT_BAK5_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK5_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak6_int2out_bak6,int2out_bak6,HI_BBP_INT_INT2OUT_BAK6_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK6_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak6_reserved,Reserved,HI_BBP_INT_INT2OUT_BAK6_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK6_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak7_int2out_bak7,int2out_bak7,HI_BBP_INT_INT2OUT_BAK7_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK7_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak7_reserved,Reserved,HI_BBP_INT_INT2OUT_BAK7_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK7_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak8_int2out_bak8,int2out_bak8,HI_BBP_INT_INT2OUT_BAK8_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK8_OFFSET)
HI_SET_GET(hi_bbp_int_int2out_bak8_reserved,Reserved,HI_BBP_INT_INT2OUT_BAK8_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT2OUT_BAK8_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_reserved_4,Reserved_4,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_reserved_3,Reserved_3,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_rfin_clk_sel,rfin_clk_sel,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_fpu_clk_sel,fpu_clk_sel,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_ul_clk_sel,ul_clk_sel,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_vdl_clk_sel,vdl_clk_sel,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_pb_clk_sel,pb_clk_sel,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_dbg_clk_sel,dbg_clk_sel,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_axim_clk_sel,axim_clk_sel,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_axis_clk_sel,axis_clk_sel,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_ahbs_clk_sel,ahbs_clk_sel,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_reserved_2,Reserved_2,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_reserved_1,Reserved_1,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_pdm_clk_sel,pdm_clk_sel,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_clk_en_sel_reserved_0,Reserved_0,HI_BBP_INT_CLK_EN_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_CLK_EN_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_ahb2lbus_clk_sel_ahb2lbus_clk_sel,ahb2lbus_clk_sel,HI_BBP_INT_AHB2LBUS_CLK_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_AHB2LBUS_CLK_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_ahb2lbus_clk_sel_reserved,Reserved,HI_BBP_INT_AHB2LBUS_CLK_SEL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_AHB2LBUS_CLK_SEL_OFFSET)
HI_SET_GET(hi_bbp_int_rfin_srst_en_rfin_srst_en,rfin_srst_en,HI_BBP_INT_RFIN_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_RFIN_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_rfin_srst_en_reserved,Reserved,HI_BBP_INT_RFIN_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_RFIN_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_fpu_srst_en_fpu_srst_en,fpu_srst_en,HI_BBP_INT_FPU_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_FPU_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_fpu_srst_en_reserved,Reserved,HI_BBP_INT_FPU_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_FPU_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_ul_srst_en_ul_srst_en,ul_srst_en,HI_BBP_INT_UL_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_UL_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_ul_srst_en_reserved,Reserved,HI_BBP_INT_UL_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_UL_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_vdl_srst_en_vdl_srst_en,vdl_srst_en,HI_BBP_INT_VDL_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_VDL_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_vdl_srst_en_reserved,Reserved,HI_BBP_INT_VDL_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_VDL_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_pb_srst_en_pb_srst_en,pb_srst_en,HI_BBP_INT_PB_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_PB_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_pb_srst_en_reserved,Reserved,HI_BBP_INT_PB_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_PB_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_dbg_srst_en_dbg_srst_en,dbg_srst_en,HI_BBP_INT_DBG_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DBG_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_dbg_srst_en_reserved,Reserved,HI_BBP_INT_DBG_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_DBG_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_axim_srst_en_axim_srst_en,axim_srst_en,HI_BBP_INT_AXIM_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_AXIM_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_axim_srst_en_reserved,Reserved,HI_BBP_INT_AXIM_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_AXIM_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_axis_srst_en_axis_srst_en,axis_srst_en,HI_BBP_INT_AXIS_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_AXIS_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_axis_srst_en_reserved,Reserved,HI_BBP_INT_AXIS_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_AXIS_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_ahbs_srst_en_ahbs_srst_en,ahbs_srst_en,HI_BBP_INT_AHBS_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_AHBS_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_ahbs_srst_en_reserved,Reserved,HI_BBP_INT_AHBS_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_AHBS_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_int_srst_en_int_srst_en,int_srst_en,HI_BBP_INT_INT_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_int_srst_en_reserved,Reserved,HI_BBP_INT_INT_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_INT_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_stu_srst_en_stu_srst_en,stu_srst_en,HI_BBP_INT_STU_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_STU_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_stu_srst_en_reserved,Reserved,HI_BBP_INT_STU_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_STU_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_pdm_srst_en_pdm_srst_en,pdm_srst_en,HI_BBP_INT_PDM_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_PDM_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_pdm_srst_en_reserved,Reserved,HI_BBP_INT_PDM_SRST_EN_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_PDM_SRST_EN_OFFSET)
HI_SET_GET(hi_bbp_int_atpram_ctrl_atpram_ctrl,atpram_ctrl,HI_BBP_INT_ATPRAM_CTRL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_ATPRAM_CTRL_OFFSET)
HI_SET_GET(hi_bbp_int_atpram_ctrl_reserved,Reserved,HI_BBP_INT_ATPRAM_CTRL_T,HI_BBP_INT_BASE_ADDR, HI_BBP_INT_ATPRAM_CTRL_OFFSET)
#endif
#endif
