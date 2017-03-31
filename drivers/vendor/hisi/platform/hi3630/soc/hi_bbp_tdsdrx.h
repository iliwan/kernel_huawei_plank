#ifndef __HI_BBP_TDSDRX_H__
#define __HI_BBP_TDSDRX_H__ 
#ifndef HI_SET_GET
#define HI_SET_GET(a0,a1,a2,a3,a4) 
#endif
#define HI_BBP_TDSDRX_CLK_MSR_FRAC_OFFSET (0x10)
#define HI_BBP_TDSDRX_CLK_MSR_INTE_OFFSET (0x14)
#define HI_BBP_TDSDRX_SFRM_FRAML_OFFSET (0x18)
#define HI_BBP_TDSDRX_WAKEUP_32K_CNT_OFFSET (0x1C)
#define HI_BBP_TDSDRX_SWITCH_32K_CNT_OFFSET (0x20)
#define HI_BBP_TDSDRX_SLEEP_MODE_OFFSET (0x24)
#define HI_BBP_TDSDRX_SLEEP_START_OFFSET (0x28)
#define HI_BBP_TDSDRX_SWITCH_FORCE_START_OFFSET (0x2C)
#define HI_BBP_TDSDRX_ARM_SLEEP_INT_MSK_OFFSET (0x40)
#define HI_BBP_TDSDRX_ARM_SLEEP_INT_CLEAR_OFFSET (0x44)
#define HI_BBP_TDSDRX_ARM_SLEEP_INT_ALM_OFFSET (0x48)
#define HI_BBP_TDSDRX_DRX_CFG1_OFFSET (0x100)
#define HI_BBP_TDSDRX_DRX_CFG2_OFFSET (0x104)
#define HI_BBP_TDSDRX_DRX_CFG3_OFFSET (0x108)
#define HI_BBP_TDSDRX_DRX_CFG4_OFFSET (0x10C)
#define HI_BBP_TDSDRX_CLK_SWITCH_STATE_OFFSET (0x200)
#define HI_BBP_TDSDRX_AWAKE_TYPE_OFFSET (0x204)
#define HI_BBP_TDSDRX_DRX_SFN_ACC_OFFSET (0x208)
#define HI_BBP_TDSDRX_SLP_TIME_CUR_OFFSET (0x20C)
#define HI_BBP_TDSDRX_ARM_INT_STATE_OFFSET (0x220)
typedef union
{
    struct
    {
        unsigned int clk_msr_frac : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_CLK_MSR_FRAC_T;
typedef union
{
    struct
    {
        unsigned int clk_msr_inte : 12;
        unsigned int reserved : 20;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_CLK_MSR_INTE_T;
typedef union
{
    struct
    {
        unsigned int sfrm_framl : 20;
        unsigned int reserved : 12;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_SFRM_FRAML_T;
typedef union
{
    struct
    {
        unsigned int wakeup_32k_cnt : 27;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_WAKEUP_32K_CNT_T;
typedef union
{
    struct
    {
        unsigned int switch_32k_cnt : 12;
        unsigned int reserved : 20;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_SWITCH_32K_CNT_T;
typedef union
{
    struct
    {
        unsigned int sleep_mode : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_SLEEP_MODE_T;
typedef union
{
    struct
    {
        unsigned int sleep_start : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_SLEEP_START_T;
typedef union
{
    struct
    {
        unsigned int switch_force_start : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_SWITCH_FORCE_START_T;
typedef union
{
    struct
    {
        unsigned int switch_int_msk : 1;
        unsigned int wakeup_int_msk : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_ARM_SLEEP_INT_MSK_T;
typedef union
{
    struct
    {
        unsigned int switch_int_clear : 1;
        unsigned int wakeup_int_clear : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_ARM_SLEEP_INT_CLEAR_T;
typedef union
{
    struct
    {
        unsigned int switch_int_alm : 1;
        unsigned int wakeup_int_alm : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_ARM_SLEEP_INT_ALM_T;
typedef union
{
    struct
    {
        unsigned int drx_cfg1 : 32;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_DRX_CFG1_T;
typedef union
{
    struct
    {
        unsigned int drx_cfg2 : 32;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_DRX_CFG2_T;
typedef union
{
    struct
    {
        unsigned int drx_cfg3 : 32;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_DRX_CFG3_T;
typedef union
{
    struct
    {
        unsigned int drx_cfg4 : 32;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_DRX_CFG4_T;
typedef union
{
    struct
    {
        unsigned int clk_switch_state : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_CLK_SWITCH_STATE_T;
typedef union
{
    struct
    {
        unsigned int awake_type : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_AWAKE_TYPE_T;
typedef union
{
    struct
    {
        unsigned int drx_sfn_acc : 32;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_DRX_SFN_ACC_T;
typedef union
{
    struct
    {
        unsigned int slp_time_cur : 28;
        unsigned int reserved : 4;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_SLP_TIME_CUR_T;
typedef union
{
    struct
    {
        unsigned int switch_int_state : 1;
        unsigned int wakeup_int_state : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_TDSDRX_ARM_INT_STATE_T;
HI_SET_GET(hi_bbp_tdsdrx_clk_msr_frac_clk_msr_frac,clk_msr_frac,HI_BBP_TDSDRX_CLK_MSR_FRAC_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_CLK_MSR_FRAC_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_clk_msr_frac_reserved,reserved,HI_BBP_TDSDRX_CLK_MSR_FRAC_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_CLK_MSR_FRAC_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_clk_msr_inte_clk_msr_inte,clk_msr_inte,HI_BBP_TDSDRX_CLK_MSR_INTE_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_CLK_MSR_INTE_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_clk_msr_inte_reserved,reserved,HI_BBP_TDSDRX_CLK_MSR_INTE_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_CLK_MSR_INTE_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_sfrm_framl_sfrm_framl,sfrm_framl,HI_BBP_TDSDRX_SFRM_FRAML_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_SFRM_FRAML_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_sfrm_framl_reserved,reserved,HI_BBP_TDSDRX_SFRM_FRAML_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_SFRM_FRAML_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_wakeup_32k_cnt_wakeup_32k_cnt,wakeup_32k_cnt,HI_BBP_TDSDRX_WAKEUP_32K_CNT_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_WAKEUP_32K_CNT_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_wakeup_32k_cnt_reserved,reserved,HI_BBP_TDSDRX_WAKEUP_32K_CNT_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_WAKEUP_32K_CNT_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_switch_32k_cnt_switch_32k_cnt,switch_32k_cnt,HI_BBP_TDSDRX_SWITCH_32K_CNT_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_SWITCH_32K_CNT_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_switch_32k_cnt_reserved,reserved,HI_BBP_TDSDRX_SWITCH_32K_CNT_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_SWITCH_32K_CNT_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_sleep_mode_sleep_mode,sleep_mode,HI_BBP_TDSDRX_SLEEP_MODE_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_SLEEP_MODE_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_sleep_mode_reserved,reserved,HI_BBP_TDSDRX_SLEEP_MODE_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_SLEEP_MODE_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_sleep_start_sleep_start,sleep_start,HI_BBP_TDSDRX_SLEEP_START_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_SLEEP_START_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_sleep_start_reserved,reserved,HI_BBP_TDSDRX_SLEEP_START_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_SLEEP_START_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_switch_force_start_switch_force_start,switch_force_start,HI_BBP_TDSDRX_SWITCH_FORCE_START_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_SWITCH_FORCE_START_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_switch_force_start_reserved,reserved,HI_BBP_TDSDRX_SWITCH_FORCE_START_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_SWITCH_FORCE_START_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_arm_sleep_int_msk_switch_int_msk,switch_int_msk,HI_BBP_TDSDRX_ARM_SLEEP_INT_MSK_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_ARM_SLEEP_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_arm_sleep_int_msk_wakeup_int_msk,wakeup_int_msk,HI_BBP_TDSDRX_ARM_SLEEP_INT_MSK_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_ARM_SLEEP_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_arm_sleep_int_msk_reserved,reserved,HI_BBP_TDSDRX_ARM_SLEEP_INT_MSK_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_ARM_SLEEP_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_arm_sleep_int_clear_switch_int_clear,switch_int_clear,HI_BBP_TDSDRX_ARM_SLEEP_INT_CLEAR_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_ARM_SLEEP_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_arm_sleep_int_clear_wakeup_int_clear,wakeup_int_clear,HI_BBP_TDSDRX_ARM_SLEEP_INT_CLEAR_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_ARM_SLEEP_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_arm_sleep_int_clear_reserved,reserved,HI_BBP_TDSDRX_ARM_SLEEP_INT_CLEAR_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_ARM_SLEEP_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_arm_sleep_int_alm_switch_int_alm,switch_int_alm,HI_BBP_TDSDRX_ARM_SLEEP_INT_ALM_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_ARM_SLEEP_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_arm_sleep_int_alm_wakeup_int_alm,wakeup_int_alm,HI_BBP_TDSDRX_ARM_SLEEP_INT_ALM_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_ARM_SLEEP_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_arm_sleep_int_alm_reserved,reserved,HI_BBP_TDSDRX_ARM_SLEEP_INT_ALM_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_ARM_SLEEP_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_drx_cfg1_drx_cfg1,drx_cfg1,HI_BBP_TDSDRX_DRX_CFG1_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_DRX_CFG1_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_drx_cfg2_drx_cfg2,drx_cfg2,HI_BBP_TDSDRX_DRX_CFG2_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_DRX_CFG2_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_drx_cfg3_drx_cfg3,drx_cfg3,HI_BBP_TDSDRX_DRX_CFG3_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_DRX_CFG3_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_drx_cfg4_drx_cfg4,drx_cfg4,HI_BBP_TDSDRX_DRX_CFG4_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_DRX_CFG4_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_clk_switch_state_clk_switch_state,clk_switch_state,HI_BBP_TDSDRX_CLK_SWITCH_STATE_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_CLK_SWITCH_STATE_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_clk_switch_state_reserved,reserved,HI_BBP_TDSDRX_CLK_SWITCH_STATE_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_CLK_SWITCH_STATE_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_awake_type_awake_type,awake_type,HI_BBP_TDSDRX_AWAKE_TYPE_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_AWAKE_TYPE_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_awake_type_reserved,reserved,HI_BBP_TDSDRX_AWAKE_TYPE_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_AWAKE_TYPE_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_drx_sfn_acc_drx_sfn_acc,drx_sfn_acc,HI_BBP_TDSDRX_DRX_SFN_ACC_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_DRX_SFN_ACC_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_slp_time_cur_slp_time_cur,slp_time_cur,HI_BBP_TDSDRX_SLP_TIME_CUR_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_SLP_TIME_CUR_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_slp_time_cur_reserved,reserved,HI_BBP_TDSDRX_SLP_TIME_CUR_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_SLP_TIME_CUR_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_arm_int_state_switch_int_state,switch_int_state,HI_BBP_TDSDRX_ARM_INT_STATE_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_ARM_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_arm_int_state_wakeup_int_state,wakeup_int_state,HI_BBP_TDSDRX_ARM_INT_STATE_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_ARM_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_tdsdrx_arm_int_state_reserved,reserved,HI_BBP_TDSDRX_ARM_INT_STATE_T,HI_BBP_TDSDRX_BASE_ADDR, HI_BBP_TDSDRX_ARM_INT_STATE_OFFSET)
#endif
