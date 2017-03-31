#ifndef __HI_BBP_STU_H__
#define __HI_BBP_STU_H__ 
#ifndef HI_SET_GET
#define HI_SET_GET(a0,a1,a2,a3,a4) 
#endif
#define HI_BBP_STU_CP_LENGTH_OFFSET (0x0)
#define HI_BBP_STU_TIM_SWITCH_OFFSET (0x4)
#define HI_BBP_STU_TIM_TRACK_OFFSET (0x8)
#define HI_BBP_STU_SYS_TIM_OFT_OFFSET (0xC)
#define HI_BBP_STU_SFN_INIT_OFFSET (0x10)
#define HI_BBP_STU_SFN_RPT_OFFSET (0x14)
#define HI_BBP_STU_SUBFRM_NUM_RPT_OFFSET (0x18)
#define HI_BBP_STU_ABS_TIM_RPT_OFFSET (0x1C)
#define HI_BBP_STU_BACKUP_TIM_VLD_OFFSET (0x20)
#define HI_BBP_STU_TIM_BACKUP_OFFSET (0x24)
#define HI_BBP_STU_BACKUP_TIM_OFT_OFFSET (0x28)
#define HI_BBP_STU_BACKUP_SFN_RPT_OFFSET (0x2C)
#define HI_BBP_STU_BBP_INT_RANGE_OFFSET (0x30)
#define HI_BBP_STU_SYS_TIM_RPT_OFFSET (0x34)
#define HI_BBP_STU_DSP_SYM_INT_POS_OFFSET (0x40)
#define HI_BBP_STU_DEM_SYM_POS_OFFSET (0x44)
#define HI_BBP_STU_ARM_SUBFRAME_INT_POS_OFFSET (0x50)
#define HI_BBP_STU_ARM_PUB_INT_POS_OFFSET (0x54)
#define HI_BBP_STU_BBP_VERSION_OFFSET (0x70)
#define HI_BBP_STU_BACKUP2_TIM_VLD_OFFSET (0x80)
#define HI_BBP_STU_TIM_BACKUP2_OFFSET (0x84)
#define HI_BBP_STU_BACKUP2_TIM_OFT_OFFSET (0x88)
#define HI_BBP_STU_BACKUP2_SFN_RPT_OFFSET (0x8C)
#define HI_BBP_STU_AFN_RPT_OFFSET (0x90)
#define HI_BBP_STU_TIM_LOCK_OFFSET (0x94)
#define HI_BBP_STU_ABS_INIT_OFFSET (0x98)
#define HI_BBP_STU_ABS_TIM_ADJ_EN_OFFSET (0xA0)
#define HI_BBP_STU_ABS_TIM_ADJ_OFT_OFFSET (0xA4)
#define HI_BBP_STU_WIRELESS_RELAY_CFG_OFFSET (0xA8)
#define HI_BBP_STU_HALF_FRAME_CFG_OFFSET (0xAC)
#define HI_BBP_STU_DEM_TIMER_FROM_FPU_OFFSET (0xB0)
#define HI_BBP_STU_COEX_LINE_OUT_CTRL_OFFSET (0xC0)
#define HI_BBP_STU_COEX_LINE_IN_CTRL_OFFSET (0xC4)
#define HI_BBP_STU_COEX_TIMER_AHEAD_RX_OFFSET (0xC8)
#define HI_BBP_STU_COEX_TIMER_DELAY_RX_OFFSET (0xCC)
#define HI_BBP_STU_COEX_FRAME_SYNC_PULSEWIDTH_OFFSET (0xD0)
#define HI_BBP_STU_COEX_LTE_RX_TX_ACTIVE_CMD_OFFSET (0xD4)
#define HI_BBP_STU_COEX_WLAN_BT_LD0_EN_CMD_OFFSET (0xD8)
#define HI_BBP_STU_COEX_LINE_IN_STATE_OFFSET (0xDC)
#define HI_BBP_STU_COEX_FRAME_SYNC_OFT_OFFSET (0xE0)
#define HI_BBP_STU_COEX_OUTPUT_IND_OFFSET (0xE4)
#define HI_BBP_STU_COEX_TIMER_AHEAD_TX_OFFSET (0xE8)
#define HI_BBP_STU_COEX_TIMER_DELAY_OFFSET (0xEC)
#ifndef __ASSEMBLY__
typedef union
{
    struct
    {
        unsigned int cp_length : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_STU_CP_LENGTH_T;
typedef union
{
    struct
    {
        unsigned int tim_switch : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_STU_TIM_SWITCH_T;
typedef union
{
    struct
    {
        unsigned int tim_track : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_STU_TIM_TRACK_T;
typedef union
{
    struct
    {
        unsigned int sys_cyc_oft : 3;
        unsigned int reserved_2 : 1;
        unsigned int sys_ts_oft : 15;
        unsigned int reserved_1 : 1;
        unsigned int sys_sub_oft : 4;
        unsigned int reserved_0 : 8;
    } bits;
    unsigned int u32;
}HI_BBP_STU_SYS_TIM_OFT_T;
typedef union
{
    struct
    {
        unsigned int sfn_init : 10;
        unsigned int reserved_1 : 6;
        unsigned int sfn_init_en : 1;
        unsigned int reserved_0 : 15;
    } bits;
    unsigned int u32;
}HI_BBP_STU_SFN_INIT_T;
typedef union
{
    struct
    {
        unsigned int sfn_rpt : 10;
        unsigned int reserved : 22;
    } bits;
    unsigned int u32;
}HI_BBP_STU_SFN_RPT_T;
typedef union
{
    struct
    {
        unsigned int subfrm_num_rpt : 4;
        unsigned int reserved : 28;
    } bits;
    unsigned int u32;
}HI_BBP_STU_SUBFRM_NUM_RPT_T;
typedef union
{
    struct
    {
        unsigned int abs_cyc_rpt : 3;
        unsigned int reserved_2 : 1;
        unsigned int abs_ts_rpt : 15;
        unsigned int reserved_1 : 1;
        unsigned int abs_sub_rpt : 4;
        unsigned int reserved_0 : 8;
    } bits;
    unsigned int u32;
}HI_BBP_STU_ABS_TIM_RPT_T;
typedef union
{
    struct
    {
        unsigned int backup_tim_vld : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_STU_BACKUP_TIM_VLD_T;
typedef union
{
    struct
    {
        unsigned int tim_backup : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_STU_TIM_BACKUP_T;
typedef union
{
    struct
    {
        unsigned int backup_cyc_oft : 3;
        unsigned int reserved_2 : 1;
        unsigned int backup_ts_oft : 15;
        unsigned int reserved_1 : 1;
        unsigned int backup_sub_oft : 4;
        unsigned int reserved_0 : 8;
    } bits;
    unsigned int u32;
}HI_BBP_STU_BACKUP_TIM_OFT_T;
typedef union
{
    struct
    {
        unsigned int backup_sfn_rpt : 10;
        unsigned int reserved : 22;
    } bits;
    unsigned int u32;
}HI_BBP_STU_BACKUP_SFN_RPT_T;
typedef union
{
    struct
    {
        unsigned int bbp_int_range : 8;
        unsigned int reserved : 24;
    } bits;
    unsigned int u32;
}HI_BBP_STU_BBP_INT_RANGE_T;
typedef union
{
    struct
    {
        unsigned int sys_cyc_rpt : 3;
        unsigned int reserved_2 : 1;
        unsigned int sys_ts_rpt : 15;
        unsigned int reserved_1 : 1;
        unsigned int sys_sub_rpt : 4;
        unsigned int reserved_0 : 8;
    } bits;
    unsigned int u32;
}HI_BBP_STU_SYS_TIM_RPT_T;
typedef union
{
    struct
    {
        unsigned int dsp_symint_ts_pos : 12;
        unsigned int reserved : 20;
    } bits;
    unsigned int u32;
}HI_BBP_STU_DSP_SYM_INT_POS_T;
typedef union
{
    struct
    {
        unsigned int dem_sym_pos : 12;
        unsigned int reserved : 20;
    } bits;
    unsigned int u32;
}HI_BBP_STU_DEM_SYM_POS_T;
typedef union
{
    struct
    {
        unsigned int arm_subf_int_pos : 15;
        unsigned int reserved : 17;
    } bits;
    unsigned int u32;
}HI_BBP_STU_ARM_SUBFRAME_INT_POS_T;
typedef union
{
    struct
    {
        unsigned int arm_pubint_pos : 15;
        unsigned int reserved : 17;
    } bits;
    unsigned int u32;
}HI_BBP_STU_ARM_PUB_INT_POS_T;
typedef union
{
    struct
    {
        unsigned int bbp_version : 32;
    } bits;
    unsigned int u32;
}HI_BBP_STU_BBP_VERSION_T;
typedef union
{
    struct
    {
        unsigned int backup2_tim_vld : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_STU_BACKUP2_TIM_VLD_T;
typedef union
{
    struct
    {
        unsigned int tim_backup2 : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_STU_TIM_BACKUP2_T;
typedef union
{
    struct
    {
        unsigned int backup2_cyc_oft : 3;
        unsigned int reserved_2 : 1;
        unsigned int backup2_ts_oft : 15;
        unsigned int reserved_1 : 1;
        unsigned int backup2_sub_oft : 4;
        unsigned int reserved_0 : 8;
    } bits;
    unsigned int u32;
}HI_BBP_STU_BACKUP2_TIM_OFT_T;
typedef union
{
    struct
    {
        unsigned int backup2_sfn_rpt : 10;
        unsigned int reserved : 22;
    } bits;
    unsigned int u32;
}HI_BBP_STU_BACKUP2_SFN_RPT_T;
typedef union
{
    struct
    {
        unsigned int afn_rpt : 32;
    } bits;
    unsigned int u32;
}HI_BBP_STU_AFN_RPT_T;
typedef union
{
    struct
    {
        unsigned int tim_lock : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_STU_TIM_LOCK_T;
typedef union
{
    struct
    {
        unsigned int abs_init_ts_pos : 15;
        unsigned int abs_init_ts_pos_en : 1;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_STU_ABS_INIT_T;
typedef union
{
    struct
    {
        unsigned int abs_tim_adj_en : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_STU_ABS_TIM_ADJ_EN_T;
typedef union
{
    struct
    {
        unsigned int abs_delta_ts : 15;
        unsigned int reserved_1 : 1;
        unsigned int abs_delta_subf : 4;
        unsigned int reserved_0 : 12;
    } bits;
    unsigned int u32;
}HI_BBP_STU_ABS_TIM_ADJ_OFT_T;
typedef union
{
    struct
    {
        unsigned int relay_multi_sync_mode : 1;
        unsigned int reserved_1 : 15;
        unsigned int relay_sync_interval : 2;
        unsigned int reserved_0 : 14;
    } bits;
    unsigned int u32;
}HI_BBP_STU_WIRELESS_RELAY_CFG_T;
typedef union
{
    struct
    {
        unsigned int cfg_subfrm_num0 : 4;
        unsigned int cfg_subfrm_num1 : 4;
        unsigned int reserved_1 : 7;
        unsigned int half_frame_mask : 1;
        unsigned int reserved_0 : 16;
    } bits;
    unsigned int u32;
}HI_BBP_STU_HALF_FRAME_CFG_T;
typedef union
{
    struct
    {
        unsigned int dem_timer_from_fpu : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_STU_DEM_TIMER_FROM_FPU_T;
typedef union
{
    struct
    {
        unsigned int lte_frame_sync_ctrl : 2;
        unsigned int reserved_3 : 2;
        unsigned int lte_rx_active_ctrl : 2;
        unsigned int reserved_2 : 2;
        unsigned int lte_tx_active_ctrl : 2;
        unsigned int reserved_1 : 2;
        unsigned int wlan_bt_ldo_en_ctrl : 2;
        unsigned int reserved_0 : 18;
    } bits;
    unsigned int u32;
}HI_BBP_STU_COEX_LINE_OUT_CTRL_T;
typedef union
{
    struct
    {
        unsigned int wlan_bt_priority_ctrl : 2;
        unsigned int reserved_1 : 2;
        unsigned int wlan_bt_tx_active_ctrl : 2;
        unsigned int reserved_0 : 26;
    } bits;
    unsigned int u32;
}HI_BBP_STU_COEX_LINE_IN_CTRL_T;
typedef union
{
    struct
    {
        unsigned int coex_t_ahead_rx : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_STU_COEX_TIMER_AHEAD_RX_T;
typedef union
{
    struct
    {
        unsigned int coex_t_delay_rx : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_STU_COEX_TIMER_DELAY_RX_T;
typedef union
{
    struct
    {
        unsigned int frame_sync_pulsewidth : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_STU_COEX_FRAME_SYNC_PULSEWIDTH_T;
typedef union
{
    struct
    {
        unsigned int coex_lte_rx_active_cmd : 1;
        unsigned int reserved_1 : 15;
        unsigned int coex_lte_tx_active_cmd : 1;
        unsigned int reserved_0 : 15;
    } bits;
    unsigned int u32;
}HI_BBP_STU_COEX_LTE_RX_TX_ACTIVE_CMD_T;
typedef union
{
    struct
    {
        unsigned int wlan_bt_ldo_en_cmd : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_BBP_STU_COEX_WLAN_BT_LD0_EN_CMD_T;
typedef union
{
    struct
    {
        unsigned int wlan_bt_priority_state : 1;
        unsigned int reserved_1 : 3;
        unsigned int wlan_bt_tx_active_state : 1;
        unsigned int reserved_0 : 27;
    } bits;
    unsigned int u32;
}HI_BBP_STU_COEX_LINE_IN_STATE_T;
typedef union
{
    struct
    {
        unsigned int coex_frame_sync_ts_oft : 15;
        unsigned int reserved_1 : 1;
        unsigned int coex_frame_sync_subfrm_oft : 4;
        unsigned int reserved_0 : 12;
    } bits;
    unsigned int u32;
}HI_BBP_STU_COEX_FRAME_SYNC_OFT_T;
typedef union
{
    struct
    {
        unsigned int wlan_bt_rx_active_ind : 1;
        unsigned int wlan_bt_lte_frame_sync_ind : 1;
        unsigned int reserved_1 : 14;
        unsigned int wlan_bt_tx_active_ind : 1;
        unsigned int reserved_0 : 15;
    } bits;
    unsigned int u32;
}HI_BBP_STU_COEX_OUTPUT_IND_T;
typedef union
{
    struct
    {
        unsigned int coex_t_ahead_tx : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_STU_COEX_TIMER_AHEAD_TX_T;
typedef union
{
    struct
    {
        unsigned int coex_t_delay_tx : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_BBP_STU_COEX_TIMER_DELAY_T;
HI_SET_GET(hi_bbp_stu_cp_length_cp_length,cp_length,HI_BBP_STU_CP_LENGTH_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_CP_LENGTH_OFFSET)
HI_SET_GET(hi_bbp_stu_cp_length_reserved,reserved,HI_BBP_STU_CP_LENGTH_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_CP_LENGTH_OFFSET)
HI_SET_GET(hi_bbp_stu_tim_switch_tim_switch,tim_switch,HI_BBP_STU_TIM_SWITCH_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_TIM_SWITCH_OFFSET)
HI_SET_GET(hi_bbp_stu_tim_switch_reserved,reserved,HI_BBP_STU_TIM_SWITCH_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_TIM_SWITCH_OFFSET)
HI_SET_GET(hi_bbp_stu_tim_track_tim_track,tim_track,HI_BBP_STU_TIM_TRACK_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_TIM_TRACK_OFFSET)
HI_SET_GET(hi_bbp_stu_tim_track_reserved,reserved,HI_BBP_STU_TIM_TRACK_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_TIM_TRACK_OFFSET)
HI_SET_GET(hi_bbp_stu_sys_tim_oft_sys_cyc_oft,sys_cyc_oft,HI_BBP_STU_SYS_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SYS_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_sys_tim_oft_reserved_2,reserved_2,HI_BBP_STU_SYS_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SYS_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_sys_tim_oft_sys_ts_oft,sys_ts_oft,HI_BBP_STU_SYS_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SYS_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_sys_tim_oft_reserved_1,reserved_1,HI_BBP_STU_SYS_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SYS_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_sys_tim_oft_sys_sub_oft,sys_sub_oft,HI_BBP_STU_SYS_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SYS_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_sys_tim_oft_reserved_0,reserved_0,HI_BBP_STU_SYS_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SYS_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_sfn_init_sfn_init,sfn_init,HI_BBP_STU_SFN_INIT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SFN_INIT_OFFSET)
HI_SET_GET(hi_bbp_stu_sfn_init_reserved_1,reserved_1,HI_BBP_STU_SFN_INIT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SFN_INIT_OFFSET)
HI_SET_GET(hi_bbp_stu_sfn_init_sfn_init_en,sfn_init_en,HI_BBP_STU_SFN_INIT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SFN_INIT_OFFSET)
HI_SET_GET(hi_bbp_stu_sfn_init_reserved_0,reserved_0,HI_BBP_STU_SFN_INIT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SFN_INIT_OFFSET)
HI_SET_GET(hi_bbp_stu_sfn_rpt_sfn_rpt,sfn_rpt,HI_BBP_STU_SFN_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SFN_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_sfn_rpt_reserved,reserved,HI_BBP_STU_SFN_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SFN_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_subfrm_num_rpt_subfrm_num_rpt,subfrm_num_rpt,HI_BBP_STU_SUBFRM_NUM_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SUBFRM_NUM_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_subfrm_num_rpt_reserved,reserved,HI_BBP_STU_SUBFRM_NUM_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SUBFRM_NUM_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_tim_rpt_abs_cyc_rpt,abs_cyc_rpt,HI_BBP_STU_ABS_TIM_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_TIM_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_tim_rpt_reserved_2,reserved_2,HI_BBP_STU_ABS_TIM_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_TIM_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_tim_rpt_abs_ts_rpt,abs_ts_rpt,HI_BBP_STU_ABS_TIM_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_TIM_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_tim_rpt_reserved_1,reserved_1,HI_BBP_STU_ABS_TIM_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_TIM_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_tim_rpt_abs_sub_rpt,abs_sub_rpt,HI_BBP_STU_ABS_TIM_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_TIM_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_tim_rpt_reserved_0,reserved_0,HI_BBP_STU_ABS_TIM_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_TIM_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup_tim_vld_backup_tim_vld,backup_tim_vld,HI_BBP_STU_BACKUP_TIM_VLD_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP_TIM_VLD_OFFSET)
HI_SET_GET(hi_bbp_stu_backup_tim_vld_reserved,reserved,HI_BBP_STU_BACKUP_TIM_VLD_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP_TIM_VLD_OFFSET)
HI_SET_GET(hi_bbp_stu_tim_backup_tim_backup,tim_backup,HI_BBP_STU_TIM_BACKUP_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_TIM_BACKUP_OFFSET)
HI_SET_GET(hi_bbp_stu_tim_backup_reserved,reserved,HI_BBP_STU_TIM_BACKUP_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_TIM_BACKUP_OFFSET)
HI_SET_GET(hi_bbp_stu_backup_tim_oft_backup_cyc_oft,backup_cyc_oft,HI_BBP_STU_BACKUP_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup_tim_oft_reserved_2,reserved_2,HI_BBP_STU_BACKUP_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup_tim_oft_backup_ts_oft,backup_ts_oft,HI_BBP_STU_BACKUP_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup_tim_oft_reserved_1,reserved_1,HI_BBP_STU_BACKUP_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup_tim_oft_backup_sub_oft,backup_sub_oft,HI_BBP_STU_BACKUP_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup_tim_oft_reserved_0,reserved_0,HI_BBP_STU_BACKUP_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup_sfn_rpt_backup_sfn_rpt,backup_sfn_rpt,HI_BBP_STU_BACKUP_SFN_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP_SFN_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup_sfn_rpt_reserved,reserved,HI_BBP_STU_BACKUP_SFN_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP_SFN_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_bbp_int_range_bbp_int_range,bbp_int_range,HI_BBP_STU_BBP_INT_RANGE_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BBP_INT_RANGE_OFFSET)
HI_SET_GET(hi_bbp_stu_bbp_int_range_reserved,reserved,HI_BBP_STU_BBP_INT_RANGE_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BBP_INT_RANGE_OFFSET)
HI_SET_GET(hi_bbp_stu_sys_tim_rpt_sys_cyc_rpt,sys_cyc_rpt,HI_BBP_STU_SYS_TIM_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SYS_TIM_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_sys_tim_rpt_reserved_2,reserved_2,HI_BBP_STU_SYS_TIM_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SYS_TIM_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_sys_tim_rpt_sys_ts_rpt,sys_ts_rpt,HI_BBP_STU_SYS_TIM_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SYS_TIM_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_sys_tim_rpt_reserved_1,reserved_1,HI_BBP_STU_SYS_TIM_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SYS_TIM_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_sys_tim_rpt_sys_sub_rpt,sys_sub_rpt,HI_BBP_STU_SYS_TIM_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SYS_TIM_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_sys_tim_rpt_reserved_0,reserved_0,HI_BBP_STU_SYS_TIM_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_SYS_TIM_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_dsp_sym_int_pos_dsp_symint_ts_pos,dsp_symint_ts_pos,HI_BBP_STU_DSP_SYM_INT_POS_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_DSP_SYM_INT_POS_OFFSET)
HI_SET_GET(hi_bbp_stu_dsp_sym_int_pos_reserved,reserved,HI_BBP_STU_DSP_SYM_INT_POS_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_DSP_SYM_INT_POS_OFFSET)
HI_SET_GET(hi_bbp_stu_dem_sym_pos_dem_sym_pos,dem_sym_pos,HI_BBP_STU_DEM_SYM_POS_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_DEM_SYM_POS_OFFSET)
HI_SET_GET(hi_bbp_stu_dem_sym_pos_reserved,reserved,HI_BBP_STU_DEM_SYM_POS_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_DEM_SYM_POS_OFFSET)
HI_SET_GET(hi_bbp_stu_arm_subframe_int_pos_arm_subf_int_pos,arm_subf_int_pos,HI_BBP_STU_ARM_SUBFRAME_INT_POS_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ARM_SUBFRAME_INT_POS_OFFSET)
HI_SET_GET(hi_bbp_stu_arm_subframe_int_pos_reserved,reserved,HI_BBP_STU_ARM_SUBFRAME_INT_POS_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ARM_SUBFRAME_INT_POS_OFFSET)
HI_SET_GET(hi_bbp_stu_arm_pub_int_pos_arm_pubint_pos,arm_pubint_pos,HI_BBP_STU_ARM_PUB_INT_POS_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ARM_PUB_INT_POS_OFFSET)
HI_SET_GET(hi_bbp_stu_arm_pub_int_pos_reserved,reserved,HI_BBP_STU_ARM_PUB_INT_POS_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ARM_PUB_INT_POS_OFFSET)
HI_SET_GET(hi_bbp_stu_bbp_version_bbp_version,bbp_version,HI_BBP_STU_BBP_VERSION_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BBP_VERSION_OFFSET)
HI_SET_GET(hi_bbp_stu_backup2_tim_vld_backup2_tim_vld,backup2_tim_vld,HI_BBP_STU_BACKUP2_TIM_VLD_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP2_TIM_VLD_OFFSET)
HI_SET_GET(hi_bbp_stu_backup2_tim_vld_reserved,reserved,HI_BBP_STU_BACKUP2_TIM_VLD_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP2_TIM_VLD_OFFSET)
HI_SET_GET(hi_bbp_stu_tim_backup2_tim_backup2,tim_backup2,HI_BBP_STU_TIM_BACKUP2_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_TIM_BACKUP2_OFFSET)
HI_SET_GET(hi_bbp_stu_tim_backup2_reserved,reserved,HI_BBP_STU_TIM_BACKUP2_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_TIM_BACKUP2_OFFSET)
HI_SET_GET(hi_bbp_stu_backup2_tim_oft_backup2_cyc_oft,backup2_cyc_oft,HI_BBP_STU_BACKUP2_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP2_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup2_tim_oft_reserved_2,reserved_2,HI_BBP_STU_BACKUP2_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP2_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup2_tim_oft_backup2_ts_oft,backup2_ts_oft,HI_BBP_STU_BACKUP2_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP2_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup2_tim_oft_reserved_1,reserved_1,HI_BBP_STU_BACKUP2_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP2_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup2_tim_oft_backup2_sub_oft,backup2_sub_oft,HI_BBP_STU_BACKUP2_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP2_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup2_tim_oft_reserved_0,reserved_0,HI_BBP_STU_BACKUP2_TIM_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP2_TIM_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup2_sfn_rpt_backup2_sfn_rpt,backup2_sfn_rpt,HI_BBP_STU_BACKUP2_SFN_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP2_SFN_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_backup2_sfn_rpt_reserved,reserved,HI_BBP_STU_BACKUP2_SFN_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_BACKUP2_SFN_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_afn_rpt_afn_rpt,afn_rpt,HI_BBP_STU_AFN_RPT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_AFN_RPT_OFFSET)
HI_SET_GET(hi_bbp_stu_tim_lock_tim_lock,tim_lock,HI_BBP_STU_TIM_LOCK_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_TIM_LOCK_OFFSET)
HI_SET_GET(hi_bbp_stu_tim_lock_reserved,reserved,HI_BBP_STU_TIM_LOCK_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_TIM_LOCK_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_init_abs_init_ts_pos,abs_init_ts_pos,HI_BBP_STU_ABS_INIT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_INIT_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_init_abs_init_ts_pos_en,abs_init_ts_pos_en,HI_BBP_STU_ABS_INIT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_INIT_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_init_reserved,reserved,HI_BBP_STU_ABS_INIT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_INIT_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_tim_adj_en_abs_tim_adj_en,abs_tim_adj_en,HI_BBP_STU_ABS_TIM_ADJ_EN_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_TIM_ADJ_EN_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_tim_adj_en_reserved,reserved,HI_BBP_STU_ABS_TIM_ADJ_EN_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_TIM_ADJ_EN_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_tim_adj_oft_abs_delta_ts,abs_delta_ts,HI_BBP_STU_ABS_TIM_ADJ_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_TIM_ADJ_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_tim_adj_oft_reserved_1,reserved_1,HI_BBP_STU_ABS_TIM_ADJ_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_TIM_ADJ_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_tim_adj_oft_abs_delta_subf,abs_delta_subf,HI_BBP_STU_ABS_TIM_ADJ_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_TIM_ADJ_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_abs_tim_adj_oft_reserved_0,reserved_0,HI_BBP_STU_ABS_TIM_ADJ_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_ABS_TIM_ADJ_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_wireless_relay_cfg_relay_multi_sync_mode,relay_multi_sync_mode,HI_BBP_STU_WIRELESS_RELAY_CFG_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_WIRELESS_RELAY_CFG_OFFSET)
HI_SET_GET(hi_bbp_stu_wireless_relay_cfg_reserved_1,reserved_1,HI_BBP_STU_WIRELESS_RELAY_CFG_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_WIRELESS_RELAY_CFG_OFFSET)
HI_SET_GET(hi_bbp_stu_wireless_relay_cfg_relay_sync_interval,relay_sync_interval,HI_BBP_STU_WIRELESS_RELAY_CFG_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_WIRELESS_RELAY_CFG_OFFSET)
HI_SET_GET(hi_bbp_stu_wireless_relay_cfg_reserved_0,reserved_0,HI_BBP_STU_WIRELESS_RELAY_CFG_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_WIRELESS_RELAY_CFG_OFFSET)
HI_SET_GET(hi_bbp_stu_half_frame_cfg_cfg_subfrm_num0,cfg_subfrm_num0,HI_BBP_STU_HALF_FRAME_CFG_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_HALF_FRAME_CFG_OFFSET)
HI_SET_GET(hi_bbp_stu_half_frame_cfg_cfg_subfrm_num1,cfg_subfrm_num1,HI_BBP_STU_HALF_FRAME_CFG_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_HALF_FRAME_CFG_OFFSET)
HI_SET_GET(hi_bbp_stu_half_frame_cfg_reserved_1,reserved_1,HI_BBP_STU_HALF_FRAME_CFG_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_HALF_FRAME_CFG_OFFSET)
HI_SET_GET(hi_bbp_stu_half_frame_cfg_half_frame_mask,half_frame_mask,HI_BBP_STU_HALF_FRAME_CFG_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_HALF_FRAME_CFG_OFFSET)
HI_SET_GET(hi_bbp_stu_half_frame_cfg_reserved_0,reserved_0,HI_BBP_STU_HALF_FRAME_CFG_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_HALF_FRAME_CFG_OFFSET)
HI_SET_GET(hi_bbp_stu_dem_timer_from_fpu_dem_timer_from_fpu,dem_timer_from_fpu,HI_BBP_STU_DEM_TIMER_FROM_FPU_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_DEM_TIMER_FROM_FPU_OFFSET)
HI_SET_GET(hi_bbp_stu_dem_timer_from_fpu_reserved,reserved,HI_BBP_STU_DEM_TIMER_FROM_FPU_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_DEM_TIMER_FROM_FPU_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_out_ctrl_lte_frame_sync_ctrl,lte_frame_sync_ctrl,HI_BBP_STU_COEX_LINE_OUT_CTRL_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_OUT_CTRL_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_out_ctrl_reserved_3,reserved_3,HI_BBP_STU_COEX_LINE_OUT_CTRL_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_OUT_CTRL_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_out_ctrl_lte_rx_active_ctrl,lte_rx_active_ctrl,HI_BBP_STU_COEX_LINE_OUT_CTRL_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_OUT_CTRL_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_out_ctrl_reserved_2,reserved_2,HI_BBP_STU_COEX_LINE_OUT_CTRL_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_OUT_CTRL_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_out_ctrl_lte_tx_active_ctrl,lte_tx_active_ctrl,HI_BBP_STU_COEX_LINE_OUT_CTRL_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_OUT_CTRL_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_out_ctrl_reserved_1,reserved_1,HI_BBP_STU_COEX_LINE_OUT_CTRL_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_OUT_CTRL_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_out_ctrl_wlan_bt_ldo_en_ctrl,wlan_bt_ldo_en_ctrl,HI_BBP_STU_COEX_LINE_OUT_CTRL_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_OUT_CTRL_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_out_ctrl_reserved_0,reserved_0,HI_BBP_STU_COEX_LINE_OUT_CTRL_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_OUT_CTRL_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_in_ctrl_wlan_bt_priority_ctrl,wlan_bt_priority_ctrl,HI_BBP_STU_COEX_LINE_IN_CTRL_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_IN_CTRL_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_in_ctrl_reserved_1,reserved_1,HI_BBP_STU_COEX_LINE_IN_CTRL_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_IN_CTRL_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_in_ctrl_wlan_bt_tx_active_ctrl,wlan_bt_tx_active_ctrl,HI_BBP_STU_COEX_LINE_IN_CTRL_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_IN_CTRL_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_in_ctrl_reserved_0,reserved_0,HI_BBP_STU_COEX_LINE_IN_CTRL_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_IN_CTRL_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_timer_ahead_rx_coex_t_ahead_rx,coex_t_ahead_rx,HI_BBP_STU_COEX_TIMER_AHEAD_RX_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_TIMER_AHEAD_RX_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_timer_ahead_rx_reserved,reserved,HI_BBP_STU_COEX_TIMER_AHEAD_RX_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_TIMER_AHEAD_RX_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_timer_delay_rx_coex_t_delay_rx,coex_t_delay_rx,HI_BBP_STU_COEX_TIMER_DELAY_RX_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_TIMER_DELAY_RX_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_timer_delay_rx_reserved,reserved,HI_BBP_STU_COEX_TIMER_DELAY_RX_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_TIMER_DELAY_RX_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_frame_sync_pulsewidth_frame_sync_pulsewidth,frame_sync_pulsewidth,HI_BBP_STU_COEX_FRAME_SYNC_PULSEWIDTH_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_FRAME_SYNC_PULSEWIDTH_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_frame_sync_pulsewidth_reserved,reserved,HI_BBP_STU_COEX_FRAME_SYNC_PULSEWIDTH_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_FRAME_SYNC_PULSEWIDTH_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_lte_rx_tx_active_cmd_coex_lte_rx_active_cmd,coex_lte_rx_active_cmd,HI_BBP_STU_COEX_LTE_RX_TX_ACTIVE_CMD_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LTE_RX_TX_ACTIVE_CMD_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_lte_rx_tx_active_cmd_reserved_1,reserved_1,HI_BBP_STU_COEX_LTE_RX_TX_ACTIVE_CMD_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LTE_RX_TX_ACTIVE_CMD_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_lte_rx_tx_active_cmd_coex_lte_tx_active_cmd,coex_lte_tx_active_cmd,HI_BBP_STU_COEX_LTE_RX_TX_ACTIVE_CMD_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LTE_RX_TX_ACTIVE_CMD_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_lte_rx_tx_active_cmd_reserved_0,reserved_0,HI_BBP_STU_COEX_LTE_RX_TX_ACTIVE_CMD_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LTE_RX_TX_ACTIVE_CMD_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_wlan_bt_ld0_en_cmd_wlan_bt_ldo_en_cmd,wlan_bt_ldo_en_cmd,HI_BBP_STU_COEX_WLAN_BT_LD0_EN_CMD_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_WLAN_BT_LD0_EN_CMD_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_wlan_bt_ld0_en_cmd_reserved,reserved,HI_BBP_STU_COEX_WLAN_BT_LD0_EN_CMD_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_WLAN_BT_LD0_EN_CMD_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_in_state_wlan_bt_priority_state,wlan_bt_priority_state,HI_BBP_STU_COEX_LINE_IN_STATE_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_IN_STATE_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_in_state_reserved_1,reserved_1,HI_BBP_STU_COEX_LINE_IN_STATE_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_IN_STATE_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_in_state_wlan_bt_tx_active_state,wlan_bt_tx_active_state,HI_BBP_STU_COEX_LINE_IN_STATE_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_IN_STATE_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_line_in_state_reserved_0,reserved_0,HI_BBP_STU_COEX_LINE_IN_STATE_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_LINE_IN_STATE_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_frame_sync_oft_coex_frame_sync_ts_oft,coex_frame_sync_ts_oft,HI_BBP_STU_COEX_FRAME_SYNC_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_FRAME_SYNC_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_frame_sync_oft_reserved_1,reserved_1,HI_BBP_STU_COEX_FRAME_SYNC_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_FRAME_SYNC_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_frame_sync_oft_coex_frame_sync_subfrm_oft,coex_frame_sync_subfrm_oft,HI_BBP_STU_COEX_FRAME_SYNC_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_FRAME_SYNC_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_frame_sync_oft_reserved_0,reserved_0,HI_BBP_STU_COEX_FRAME_SYNC_OFT_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_FRAME_SYNC_OFT_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_output_ind_wlan_bt_rx_active_ind,wlan_bt_rx_active_ind,HI_BBP_STU_COEX_OUTPUT_IND_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_OUTPUT_IND_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_output_ind_wlan_bt_lte_frame_sync_ind,wlan_bt_lte_frame_sync_ind,HI_BBP_STU_COEX_OUTPUT_IND_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_OUTPUT_IND_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_output_ind_reserved_1,reserved_1,HI_BBP_STU_COEX_OUTPUT_IND_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_OUTPUT_IND_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_output_ind_wlan_bt_tx_active_ind,wlan_bt_tx_active_ind,HI_BBP_STU_COEX_OUTPUT_IND_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_OUTPUT_IND_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_output_ind_reserved_0,reserved_0,HI_BBP_STU_COEX_OUTPUT_IND_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_OUTPUT_IND_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_timer_ahead_tx_coex_t_ahead_tx,coex_t_ahead_tx,HI_BBP_STU_COEX_TIMER_AHEAD_TX_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_TIMER_AHEAD_TX_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_timer_ahead_tx_reserved,reserved,HI_BBP_STU_COEX_TIMER_AHEAD_TX_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_TIMER_AHEAD_TX_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_timer_delay_coex_t_delay_tx,coex_t_delay_tx,HI_BBP_STU_COEX_TIMER_DELAY_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_TIMER_DELAY_OFFSET)
HI_SET_GET(hi_bbp_stu_coex_timer_delay_reserved,reserved,HI_BBP_STU_COEX_TIMER_DELAY_T,HI_BBP_STU_BASE_ADDR, HI_BBP_STU_COEX_TIMER_DELAY_OFFSET)
#endif
#endif
