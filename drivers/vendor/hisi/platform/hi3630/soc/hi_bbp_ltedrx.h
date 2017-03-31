#ifndef __HI_BBP_LTEDRX_H__
#define __HI_BBP_LTEDRX_H__ 
#ifndef HI_SET_GET
#define HI_SET_GET(a0,a1,a2,a3,a4) 
#endif
#define HI_BBP_LTEDRX_CLK_MSR_FRAC_OFFSET (0x10)
#define HI_BBP_LTEDRX_CLK_MSR_INTE_OFFSET (0x14)
#define HI_BBP_LTEDRX_SFRM_FRAML_OFFSET (0x18)
#define HI_BBP_LTEDRX_WAKEUP_32K_CNT_OFFSET (0x1C)
#define HI_BBP_LTEDRX_SWITCH_32K_CNT_OFFSET (0x20)
#define HI_BBP_LTEDRX_SLEEP_MODE_OFFSET (0x24)
#define HI_BBP_LTEDRX_SLEEP_START_OFFSET (0x28)
#define HI_BBP_LTEDRX_SWITCH_FORCE_START_OFFSET (0x2C)
#define HI_BBP_LTEDRX_ARM_SLEEP_INT_MSK_OFFSET (0x40)
#define HI_BBP_LTEDRX_ARM_SLEEP_INT_CLEAR_OFFSET (0x44)
#define HI_BBP_LTEDRX_ARM_SLEEP_INT_ALM_OFFSET (0x48)
#define HI_BBP_LTEDRX_LTE_SYS_TIMER_OFFSET (0x70)
#define HI_BBP_LTEDRX_LTE_3412_TIMER_OFFSET (0x74)
#define HI_BBP_LTEDRX_LTE_VPLMN_TIMER_OFFSET (0x78)
#define HI_BBP_LTEDRX_LTE_TSRHC_TIMER_OFFSET (0x7C)
#define HI_BBP_LTEDRX_LTE_TA_TIMER_OFFSET (0x80)
#define HI_BBP_LTEDRX_LTE_DEEPS_TIMER_OFFSET (0x84)
#define HI_BBP_LTEDRX_LTE_PS32K_TIMER_OFFSET (0x88)
#define HI_BBP_LTEDRX_LTE_PS32KBASE_TIMER_OFFSET (0x8C)
#define HI_BBP_LTEDRX_LTE_PS32K_BASE_MODE_OFFSET (0x90)
#define HI_BBP_LTEDRX_DRX_TIMER_EN_OFFSET (0x94)
#define HI_BBP_LTEDRX_DRX_TIMER_10MS_OFFSET (0x98)
#define HI_BBP_LTEDRX_DRX_TIMER_MIN_OFFSET (0x9C)
#define HI_BBP_LTEDRX_DRX_TIMER_HOUR_OFFSET (0xA0)
#define HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_OFFSET (0xB0)
#define HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_OFFSET (0xB4)
#define HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_OFFSET (0xB8)
#define HI_BBP_LTEDRX_CLK_SWITCH_STATE_OFFSET (0x200)
#define HI_BBP_LTEDRX_AWAKE_TYPE_OFFSET (0x204)
#define HI_BBP_LTEDRX_DRX_SFN_ACC_OFFSET (0x208)
#define HI_BBP_LTEDRX_SLP_TIME_CUR_OFFSET (0x20C)
#define HI_BBP_LTEDRX_ARM_INT_STATE_OFFSET (0x220)
#define HI_BBP_LTEDRX_LTE_SYS_CUR_TIMER_OFFSET (0x300)
#define HI_BBP_LTEDRX_LTE_3412_CUR_TIMER_OFFSET (0x304)
#define HI_BBP_LTEDRX_LTE_VPLMN_CUR_TIMER_OFFSET (0x308)
#define HI_BBP_LTEDRX_LTE_TSRHC_CUR_TIMER_OFFSET (0x30C)
#define HI_BBP_LTEDRX_LTE_TA_CUR_TIMER_OFFSET (0x310)
#define HI_BBP_LTEDRX_LTE_DEEPS_CUR_TIMER_OFFSET (0x314)
#define HI_BBP_LTEDRX_LTE_PS32K_CUR_TIMER_OFFSET (0x318)
#define HI_BBP_LTEDRX_LTE_PS32KBASE_CUR_TIMER_OFFSET (0x31C)
#define HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_OFFSET (0x340)
#ifndef __ASSEMBLY__
typedef union
{
    struct
    {
        unsigned int clk_msr_frac : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_CLK_MSR_FRAC_T;
typedef union
{
    struct
    {
        unsigned int clk_msr_inte : 12;
        unsigned int reserved : 20;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_CLK_MSR_INTE_T;
typedef union
{
    struct
    {
        unsigned int sfrm_framl : 20;
        unsigned int reserved : 12;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_SFRM_FRAML_T;
typedef union
{
    struct
    {
        unsigned int wakeup_32k_cnt : 27;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_WAKEUP_32K_CNT_T;
typedef union
{
    struct
    {
        unsigned int switch_32k_cnt : 12;
        unsigned int reserved : 20;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_SWITCH_32K_CNT_T;
typedef union
{
    struct
    {
        unsigned int sleep_mode : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_SLEEP_MODE_T;
typedef union
{
    struct
    {
        unsigned int sleep_start : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_SLEEP_START_T;
typedef union
{
    struct
    {
        unsigned int switch_force_start : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_SWITCH_FORCE_START_T;
typedef union
{
    struct
    {
        unsigned int switch_int_msk : 1;
        unsigned int wakeup_int_msk : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_ARM_SLEEP_INT_MSK_T;
typedef union
{
    struct
    {
        unsigned int switch_int_clear : 1;
        unsigned int wakeup_int_clear : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_ARM_SLEEP_INT_CLEAR_T;
typedef union
{
    struct
    {
        unsigned int switch_int_alm : 1;
        unsigned int wakeup_int_alm : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_ARM_SLEEP_INT_ALM_T;
typedef union
{
    struct
    {
        unsigned int lte_sys_timer : 3;
        unsigned int reserved : 29;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_SYS_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_3412_timer : 8;
        unsigned int reserved : 24;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_3412_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_vplmn_timer : 3;
        unsigned int reserved : 29;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_VPLMN_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_tsrhc_timer : 3;
        unsigned int reserved : 29;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_TSRHC_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_ta_timer : 11;
        unsigned int reserved : 21;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_TA_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_deeps_timer : 7;
        unsigned int reserved : 25;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_DEEPS_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_ps32k_timer : 32;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_PS32K_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_ps32kbase_timer : 32;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_PS32KBASE_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_ps32k_base_mode : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_PS32K_BASE_MODE_T;
typedef union
{
    struct
    {
        unsigned int lte_sys_timer_en : 1;
        unsigned int lte_3412_timer_en : 1;
        unsigned int lte_vplmn_timer_en : 1;
        unsigned int lte_tsrhc_timer_en : 1;
        unsigned int lte_ta_timer_en : 1;
        unsigned int lte_deeps_timer_en : 1;
        unsigned int lte_ps32k_timer_en : 1;
        unsigned int lte_ps32kbase_timer_en : 1;
        unsigned int reserved : 24;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_DRX_TIMER_EN_T;
typedef union
{
    struct
    {
        unsigned int drx_timer_10ms : 9;
        unsigned int reserved : 23;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_DRX_TIMER_10MS_T;
typedef union
{
    struct
    {
        unsigned int drx_timer_min : 21;
        unsigned int reserved : 11;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_DRX_TIMER_MIN_T;
typedef union
{
    struct
    {
        unsigned int drx_timer_hour : 6;
        unsigned int reserved : 26;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_DRX_TIMER_HOUR_T;
typedef union
{
    struct
    {
        unsigned int lte_sys_int_msk : 1;
        unsigned int lte_3412_int_msk : 1;
        unsigned int lte_vplmn_int_msk : 1;
        unsigned int lte_tsrhc_int_msk : 1;
        unsigned int lte_ta_int_msk : 1;
        unsigned int lte_deeps_int_msk : 1;
        unsigned int lte_ps32k_int_msk : 1;
        unsigned int lte_ps32kbase_int_msk : 1;
        unsigned int reserved : 24;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_T;
typedef union
{
    struct
    {
        unsigned int lte_sys_int_clear : 1;
        unsigned int lte_3412_int_clear : 1;
        unsigned int lte_vplmn_int_clear : 1;
        unsigned int lte_tsrhc_int_clear : 1;
        unsigned int lte_ta_int_clear : 1;
        unsigned int lte_deeps_int_clear : 1;
        unsigned int lte_ps32k_int_clear : 1;
        unsigned int lte_ps32kbase_int_clear : 1;
        unsigned int reserved : 24;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_T;
typedef union
{
    struct
    {
        unsigned int lte_sys_int_alm : 1;
        unsigned int lte_3412_int_alm : 1;
        unsigned int lte_vplmn_int_alm : 1;
        unsigned int lte_tsrhc_int_alm : 1;
        unsigned int lte_ta_int_alm : 1;
        unsigned int lte_deeps_int_alm : 1;
        unsigned int lte_ps32k_int_alm : 1;
        unsigned int lte_ps32kbase_int_alm : 1;
        unsigned int reserved : 24;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_T;
typedef union
{
    struct
    {
        unsigned int clk_switch_state : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_CLK_SWITCH_STATE_T;
typedef union
{
    struct
    {
        unsigned int awake_type : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_AWAKE_TYPE_T;
typedef union
{
    struct
    {
        unsigned int drx_sfn_acc : 32;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_DRX_SFN_ACC_T;
typedef union
{
    struct
    {
        unsigned int slp_time_cur : 28;
        unsigned int reserved : 4;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_SLP_TIME_CUR_T;
typedef union
{
    struct
    {
        unsigned int switch_int_state : 1;
        unsigned int wakeup_int_state : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_ARM_INT_STATE_T;
typedef union
{
    struct
    {
        unsigned int lte_sys_cur_timer : 3;
        unsigned int reserved : 29;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_SYS_CUR_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_3412_cur_timer : 8;
        unsigned int reserved : 24;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_3412_CUR_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_vplmn_cur_timer : 3;
        unsigned int reserved : 29;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_VPLMN_CUR_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_tsrhc_cur_timer : 3;
        unsigned int reserved : 29;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_TSRHC_CUR_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_ta_cur_timer : 11;
        unsigned int reserved : 21;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_TA_CUR_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_deeps_cur_timer : 7;
        unsigned int reserved : 25;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_DEEPS_CUR_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_ps32k_cur_timer : 32;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_PS32K_CUR_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_ps32kbase_cur_timer : 32;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_LTE_PS32KBASE_CUR_TIMER_T;
typedef union
{
    struct
    {
        unsigned int lte_sys_int_state : 1;
        unsigned int lte_3412_int_state : 1;
        unsigned int lte_vplmn_int_state : 1;
        unsigned int lte_tsrhc_int_state : 1;
        unsigned int lte_ta_int_state : 1;
        unsigned int lte_deeps_int_state : 1;
        unsigned int lte_ps32k_int_state : 1;
        unsigned int lte_ps32kbase_int_state : 1;
        unsigned int reserved : 24;
    } bits;
    unsigned int u32;
}HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_T;
HI_SET_GET(hi_bbp_ltedrx_clk_msr_frac_clk_msr_frac,clk_msr_frac,HI_BBP_LTEDRX_CLK_MSR_FRAC_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_CLK_MSR_FRAC_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_clk_msr_frac_reserved,reserved,HI_BBP_LTEDRX_CLK_MSR_FRAC_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_CLK_MSR_FRAC_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_clk_msr_inte_clk_msr_inte,clk_msr_inte,HI_BBP_LTEDRX_CLK_MSR_INTE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_CLK_MSR_INTE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_clk_msr_inte_reserved,reserved,HI_BBP_LTEDRX_CLK_MSR_INTE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_CLK_MSR_INTE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_sfrm_framl_sfrm_framl,sfrm_framl,HI_BBP_LTEDRX_SFRM_FRAML_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_SFRM_FRAML_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_sfrm_framl_reserved,reserved,HI_BBP_LTEDRX_SFRM_FRAML_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_SFRM_FRAML_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_wakeup_32k_cnt_wakeup_32k_cnt,wakeup_32k_cnt,HI_BBP_LTEDRX_WAKEUP_32K_CNT_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_WAKEUP_32K_CNT_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_wakeup_32k_cnt_reserved,reserved,HI_BBP_LTEDRX_WAKEUP_32K_CNT_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_WAKEUP_32K_CNT_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_switch_32k_cnt_switch_32k_cnt,switch_32k_cnt,HI_BBP_LTEDRX_SWITCH_32K_CNT_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_SWITCH_32K_CNT_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_switch_32k_cnt_reserved,reserved,HI_BBP_LTEDRX_SWITCH_32K_CNT_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_SWITCH_32K_CNT_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_sleep_mode_sleep_mode,sleep_mode,HI_BBP_LTEDRX_SLEEP_MODE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_SLEEP_MODE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_sleep_mode_reserved,reserved,HI_BBP_LTEDRX_SLEEP_MODE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_SLEEP_MODE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_sleep_start_sleep_start,sleep_start,HI_BBP_LTEDRX_SLEEP_START_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_SLEEP_START_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_sleep_start_reserved,reserved,HI_BBP_LTEDRX_SLEEP_START_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_SLEEP_START_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_switch_force_start_switch_force_start,switch_force_start,HI_BBP_LTEDRX_SWITCH_FORCE_START_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_SWITCH_FORCE_START_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_switch_force_start_reserved,reserved,HI_BBP_LTEDRX_SWITCH_FORCE_START_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_SWITCH_FORCE_START_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_sleep_int_msk_switch_int_msk,switch_int_msk,HI_BBP_LTEDRX_ARM_SLEEP_INT_MSK_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_SLEEP_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_sleep_int_msk_wakeup_int_msk,wakeup_int_msk,HI_BBP_LTEDRX_ARM_SLEEP_INT_MSK_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_SLEEP_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_sleep_int_msk_reserved,reserved,HI_BBP_LTEDRX_ARM_SLEEP_INT_MSK_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_SLEEP_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_sleep_int_clear_switch_int_clear,switch_int_clear,HI_BBP_LTEDRX_ARM_SLEEP_INT_CLEAR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_SLEEP_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_sleep_int_clear_wakeup_int_clear,wakeup_int_clear,HI_BBP_LTEDRX_ARM_SLEEP_INT_CLEAR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_SLEEP_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_sleep_int_clear_reserved,reserved,HI_BBP_LTEDRX_ARM_SLEEP_INT_CLEAR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_SLEEP_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_sleep_int_alm_switch_int_alm,switch_int_alm,HI_BBP_LTEDRX_ARM_SLEEP_INT_ALM_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_SLEEP_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_sleep_int_alm_wakeup_int_alm,wakeup_int_alm,HI_BBP_LTEDRX_ARM_SLEEP_INT_ALM_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_SLEEP_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_sleep_int_alm_reserved,reserved,HI_BBP_LTEDRX_ARM_SLEEP_INT_ALM_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_SLEEP_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_sys_timer_lte_sys_timer,lte_sys_timer,HI_BBP_LTEDRX_LTE_SYS_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_SYS_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_sys_timer_reserved,reserved,HI_BBP_LTEDRX_LTE_SYS_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_SYS_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_3412_timer_lte_3412_timer,lte_3412_timer,HI_BBP_LTEDRX_LTE_3412_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_3412_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_3412_timer_reserved,reserved,HI_BBP_LTEDRX_LTE_3412_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_3412_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_vplmn_timer_lte_vplmn_timer,lte_vplmn_timer,HI_BBP_LTEDRX_LTE_VPLMN_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_VPLMN_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_vplmn_timer_reserved,reserved,HI_BBP_LTEDRX_LTE_VPLMN_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_VPLMN_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_tsrhc_timer_lte_tsrhc_timer,lte_tsrhc_timer,HI_BBP_LTEDRX_LTE_TSRHC_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_TSRHC_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_tsrhc_timer_reserved,reserved,HI_BBP_LTEDRX_LTE_TSRHC_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_TSRHC_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_ta_timer_lte_ta_timer,lte_ta_timer,HI_BBP_LTEDRX_LTE_TA_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_TA_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_ta_timer_reserved,reserved,HI_BBP_LTEDRX_LTE_TA_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_TA_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_deeps_timer_lte_deeps_timer,lte_deeps_timer,HI_BBP_LTEDRX_LTE_DEEPS_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_DEEPS_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_deeps_timer_reserved,reserved,HI_BBP_LTEDRX_LTE_DEEPS_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_DEEPS_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_ps32k_timer_lte_ps32k_timer,lte_ps32k_timer,HI_BBP_LTEDRX_LTE_PS32K_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_PS32K_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_ps32kbase_timer_lte_ps32kbase_timer,lte_ps32kbase_timer,HI_BBP_LTEDRX_LTE_PS32KBASE_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_PS32KBASE_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_ps32k_base_mode_lte_ps32k_base_mode,lte_ps32k_base_mode,HI_BBP_LTEDRX_LTE_PS32K_BASE_MODE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_PS32K_BASE_MODE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_ps32k_base_mode_reserved,reserved,HI_BBP_LTEDRX_LTE_PS32K_BASE_MODE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_PS32K_BASE_MODE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_en_lte_sys_timer_en,lte_sys_timer_en,HI_BBP_LTEDRX_DRX_TIMER_EN_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_EN_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_en_lte_3412_timer_en,lte_3412_timer_en,HI_BBP_LTEDRX_DRX_TIMER_EN_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_EN_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_en_lte_vplmn_timer_en,lte_vplmn_timer_en,HI_BBP_LTEDRX_DRX_TIMER_EN_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_EN_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_en_lte_tsrhc_timer_en,lte_tsrhc_timer_en,HI_BBP_LTEDRX_DRX_TIMER_EN_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_EN_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_en_lte_ta_timer_en,lte_ta_timer_en,HI_BBP_LTEDRX_DRX_TIMER_EN_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_EN_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_en_lte_deeps_timer_en,lte_deeps_timer_en,HI_BBP_LTEDRX_DRX_TIMER_EN_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_EN_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_en_lte_ps32k_timer_en,lte_ps32k_timer_en,HI_BBP_LTEDRX_DRX_TIMER_EN_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_EN_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_en_lte_ps32kbase_timer_en,lte_ps32kbase_timer_en,HI_BBP_LTEDRX_DRX_TIMER_EN_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_EN_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_en_reserved,reserved,HI_BBP_LTEDRX_DRX_TIMER_EN_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_EN_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_10ms_drx_timer_10ms,drx_timer_10ms,HI_BBP_LTEDRX_DRX_TIMER_10MS_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_10MS_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_10ms_reserved,reserved,HI_BBP_LTEDRX_DRX_TIMER_10MS_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_10MS_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_min_drx_timer_min,drx_timer_min,HI_BBP_LTEDRX_DRX_TIMER_MIN_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_MIN_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_min_reserved,reserved,HI_BBP_LTEDRX_DRX_TIMER_MIN_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_MIN_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_hour_drx_timer_hour,drx_timer_hour,HI_BBP_LTEDRX_DRX_TIMER_HOUR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_HOUR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_timer_hour_reserved,reserved,HI_BBP_LTEDRX_DRX_TIMER_HOUR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_TIMER_HOUR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_msk_lte_sys_int_msk,lte_sys_int_msk,HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_msk_lte_3412_int_msk,lte_3412_int_msk,HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_msk_lte_vplmn_int_msk,lte_vplmn_int_msk,HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_msk_lte_tsrhc_int_msk,lte_tsrhc_int_msk,HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_msk_lte_ta_int_msk,lte_ta_int_msk,HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_msk_lte_deeps_int_msk,lte_deeps_int_msk,HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_msk_lte_ps32k_int_msk,lte_ps32k_int_msk,HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_msk_lte_ps32kbase_int_msk,lte_ps32kbase_int_msk,HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_msk_reserved,reserved,HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_MSK_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_clear_lte_sys_int_clear,lte_sys_int_clear,HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_clear_lte_3412_int_clear,lte_3412_int_clear,HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_clear_lte_vplmn_int_clear,lte_vplmn_int_clear,HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_clear_lte_tsrhc_int_clear,lte_tsrhc_int_clear,HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_clear_lte_ta_int_clear,lte_ta_int_clear,HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_clear_lte_deeps_int_clear,lte_deeps_int_clear,HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_clear_lte_ps32k_int_clear,lte_ps32k_int_clear,HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_clear_lte_ps32kbase_int_clear,lte_ps32kbase_int_clear,HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_clear_reserved,reserved,HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_CLEAR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_alm_lte_sys_int_alm,lte_sys_int_alm,HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_alm_lte_3412_int_alm,lte_3412_int_alm,HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_alm_lte_vplmn_int_alm,lte_vplmn_int_alm,HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_alm_lte_tsrhc_int_alm,lte_tsrhc_int_alm,HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_alm_lte_ta_int_alm,lte_ta_int_alm,HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_alm_lte_deeps_int_alm,lte_deeps_int_alm,HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_alm_lte_ps32k_int_alm,lte_ps32k_int_alm,HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_alm_lte_ps32kbase_int_alm,lte_ps32kbase_int_alm,HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_alm_reserved,reserved,HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_ALM_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_clk_switch_state_clk_switch_state,clk_switch_state,HI_BBP_LTEDRX_CLK_SWITCH_STATE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_CLK_SWITCH_STATE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_clk_switch_state_reserved,reserved,HI_BBP_LTEDRX_CLK_SWITCH_STATE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_CLK_SWITCH_STATE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_awake_type_awake_type,awake_type,HI_BBP_LTEDRX_AWAKE_TYPE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_AWAKE_TYPE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_awake_type_reserved,reserved,HI_BBP_LTEDRX_AWAKE_TYPE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_AWAKE_TYPE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_drx_sfn_acc_drx_sfn_acc,drx_sfn_acc,HI_BBP_LTEDRX_DRX_SFN_ACC_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_DRX_SFN_ACC_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_slp_time_cur_slp_time_cur,slp_time_cur,HI_BBP_LTEDRX_SLP_TIME_CUR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_SLP_TIME_CUR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_slp_time_cur_reserved,reserved,HI_BBP_LTEDRX_SLP_TIME_CUR_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_SLP_TIME_CUR_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_int_state_switch_int_state,switch_int_state,HI_BBP_LTEDRX_ARM_INT_STATE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_int_state_wakeup_int_state,wakeup_int_state,HI_BBP_LTEDRX_ARM_INT_STATE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_int_state_reserved,reserved,HI_BBP_LTEDRX_ARM_INT_STATE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_sys_cur_timer_lte_sys_cur_timer,lte_sys_cur_timer,HI_BBP_LTEDRX_LTE_SYS_CUR_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_SYS_CUR_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_sys_cur_timer_reserved,reserved,HI_BBP_LTEDRX_LTE_SYS_CUR_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_SYS_CUR_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_3412_cur_timer_lte_3412_cur_timer,lte_3412_cur_timer,HI_BBP_LTEDRX_LTE_3412_CUR_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_3412_CUR_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_3412_cur_timer_reserved,reserved,HI_BBP_LTEDRX_LTE_3412_CUR_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_3412_CUR_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_vplmn_cur_timer_lte_vplmn_cur_timer,lte_vplmn_cur_timer,HI_BBP_LTEDRX_LTE_VPLMN_CUR_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_VPLMN_CUR_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_vplmn_cur_timer_reserved,reserved,HI_BBP_LTEDRX_LTE_VPLMN_CUR_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_VPLMN_CUR_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_tsrhc_cur_timer_lte_tsrhc_cur_timer,lte_tsrhc_cur_timer,HI_BBP_LTEDRX_LTE_TSRHC_CUR_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_TSRHC_CUR_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_tsrhc_cur_timer_reserved,reserved,HI_BBP_LTEDRX_LTE_TSRHC_CUR_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_TSRHC_CUR_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_ta_cur_timer_lte_ta_cur_timer,lte_ta_cur_timer,HI_BBP_LTEDRX_LTE_TA_CUR_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_TA_CUR_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_ta_cur_timer_reserved,reserved,HI_BBP_LTEDRX_LTE_TA_CUR_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_TA_CUR_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_deeps_cur_timer_lte_deeps_cur_timer,lte_deeps_cur_timer,HI_BBP_LTEDRX_LTE_DEEPS_CUR_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_DEEPS_CUR_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_deeps_cur_timer_reserved,reserved,HI_BBP_LTEDRX_LTE_DEEPS_CUR_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_DEEPS_CUR_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_ps32k_cur_timer_lte_ps32k_cur_timer,lte_ps32k_cur_timer,HI_BBP_LTEDRX_LTE_PS32K_CUR_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_PS32K_CUR_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_lte_ps32kbase_cur_timer_lte_ps32kbase_cur_timer,lte_ps32kbase_cur_timer,HI_BBP_LTEDRX_LTE_PS32KBASE_CUR_TIMER_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_LTE_PS32KBASE_CUR_TIMER_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_state_lte_sys_int_state,lte_sys_int_state,HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_state_lte_3412_int_state,lte_3412_int_state,HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_state_lte_vplmn_int_state,lte_vplmn_int_state,HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_state_lte_tsrhc_int_state,lte_tsrhc_int_state,HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_state_lte_ta_int_state,lte_ta_int_state,HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_state_lte_deeps_int_state,lte_deeps_int_state,HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_state_lte_ps32k_int_state,lte_ps32k_int_state,HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_state_lte_ps32kbase_int_state,lte_ps32kbase_int_state,HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_OFFSET)
HI_SET_GET(hi_bbp_ltedrx_arm_timer_int_state_reserved,reserved,HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_T,HI_BBP_LTEDRX_BASE_ADDR, HI_BBP_LTEDRX_ARM_TIMER_INT_STATE_OFFSET)
#endif
#endif
