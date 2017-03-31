#ifndef __HI_PMU_H__
#define __HI_PMU_H__ 
#ifndef HI_SET_GET
#define HI_SET_GET(a0,a1,a2,a3,a4) 
#endif
#define HI_PMU_VERSION_OFFSET (0x0)
#define HI_PMU_IRQ1_OFFSET (0x1)
#define HI_PMU_IRQ2_OFFSET (0x2)
#define HI_PMU_IRQ3_OFFSET (0x3)
#define HI_PMU_STATUS1_OFFSET (0x4)
#define HI_PMU_STATUS2_OFFSET (0x5)
#define HI_PMU_STATUS3_OFFSET (0x6)
#define HI_PMU_STATUS4_OFFSET (0x7)
#define HI_PMU_STATUS5_OFFSET (0x8)
#define HI_PMU_IRQM1_OFFSET (0x9)
#define HI_PMU_IRQM2_OFFSET (0xA)
#define HI_PMU_IRQM3_OFFSET (0xB)
#define HI_PMU_ONOFF1_OFFSET (0xC)
#define HI_PMU_ONOFF2_OFFSET (0xD)
#define HI_PMU_ONOFF3_OFFSET (0xE)
#define HI_PMU_ONOFF4_OFFSET (0xF)
#define HI_PMU_ONOFF5_OFFSET (0x10)
#define HI_PMU_ONOFF6_OFFSET (0x11)
#define HI_PMU_ONOFF7_OFFSET (0x12)
#define HI_PMU_ONOFF8_OFFSET (0x13)
#define HI_PMU_ONOFF9_OFFSET (0x14)
#define HI_PMU_LDO_SWICH1_OFFSET (0x15)
#define HI_PMU_LDO_SWITCH2_OFFSET (0x16)
#define HI_PMU_SET_BUCK1_OFFSET (0x17)
#define HI_PMU_SET_BUCK2_OFFSET (0x18)
#define HI_PMU_SET_BUCK3_OFFSET (0x19)
#define HI_PMU_SET_BUCK4_OFFSET (0x1A)
#define HI_PMU_SET_BUCK5_OFFSET (0x1B)
#define HI_PMU_SET_BUCK6_OFFSET (0x1C)
#define HI_PMU_BUCK1_ADJ1_OFFSET (0x1D)
#define HI_PMU_BUCK1_ADJ2_OFFSET (0x1E)
#define HI_PMU_BUCK2_ADJ1_OFFSET (0x1F)
#define HI_PMU_BUCK2_ADJ2_OFFSET (0x20)
#define HI_PMU_BUCK3_ADJ1_OFFSET (0x21)
#define HI_PMU_BUCK3_ADJ2_OFFSET (0x22)
#define HI_PMU_BUCK1_2_4_ADJ2_OFFSET (0x23)
#define HI_PMU_BUCK5_ADJ_OFFSET (0x24)
#define HI_PMU_BUCK6_ADJ1_OFFSET (0x25)
#define HI_PMU_BUCK6_ADJ2_OFFSET (0x26)
#define HI_PMU_BUCK4_5_FREQ_OFFSET (0x27)
#define HI_PMU_BUCK4_COMP_ADJ_OFFSET (0x28)
#define HI_PMU_BUCK5_COMP_ADJ_OFFSET (0x29)
#define HI_PMU_SET_LDO1_OFFSET (0x2A)
#define HI_PMU_SET_LDO2_OFFSET (0x2B)
#define HI_PMU_SET_LDO3_OFFSET (0x2C)
#define HI_PMU_SET_LDO4_OFFSET (0x2D)
#define HI_PMU_SET_LDO5_OFFSET (0x2E)
#define HI_PMU_SET_LDO6_OFFSET (0x2F)
#define HI_PMU_SET_LDO7_OFFSET (0x30)
#define HI_PMU_SET_LDO8_OFFSET (0x31)
#define HI_PMU_SET_LDO9_OFFSET (0x32)
#define HI_PMU_SET_LDO10_OFFSET (0x33)
#define HI_PMU_SET_LDO11_OFFSET (0x34)
#define HI_PMU_SET_LDO13_OFFSET (0x35)
#define HI_PMU_SET_LDO14_OFFSET (0x36)
#define HI_PMU_SET_LDO15_OFFSET (0x37)
#define HI_PMU_SET_LDO17_OFFSET (0x38)
#define HI_PMU_SET_OTP_OFFSET (0x39)
#define HI_PMU_DR1_MODE_OFFSET (0x3A)
#define HI_PMU_DR2_MODE_OFFSET (0x3B)
#define HI_PMU_DR3_MODE_OFFSET (0x3C)
#define HI_PMU_FLASH_PERIOD_OFFSET (0x3D)
#define HI_PMU_FLASH_ON_OFFSET (0x3E)
#define HI_PMU_PERIPH_CTRL1_OFFSET (0x3F)
#define HI_PMU_NO_PWR_IRQ1_OFFSET (0x40)
#define HI_PMU_NO_PWR_IRQ2_OFFSET (0x41)
#define HI_PMU_NO_PWR_IRQ3_OFFSET (0x42)
#define HI_PMU_NO_PWR_REG_RWC_OFFSET (0x43)
#define HI_PMU_NO_RWR_REG_RW_OFFSET (0x44)
#define HI_PMU_ANA_IN_OFFSET (0x46)
#define HI_PMU_RESERVED0_OFFSET (0x47)
#define HI_PMU_RESERVED1_OFFSET (0x48)
#define HI_PMU_RESERVED2_OFFSET (0x49)
#define HI_PMU_CLIM_ADJ_OFFSET (0x4A)
#define HI_PMU_LIT_CUR_SET_OFFSET (0x4B)
#define HI_PMU_OTP_CTRL_OFFSET (0x4C)
#define HI_PMU_OTP_PDIN_OFFSET (0x4D)
#define HI_PMU_OTP_PDOB0_OFFSET (0x4E)
#define HI_PMU_OTP_PDOB1_OFFSET (0x4F)
#define HI_PMU_OTP_PDOB2_OFFSET (0x50)
#define HI_PMU_OTP_PDOB3_OFFSET (0x51)
#define HI_PMU_BANDGAP_REG_OFFSET (0x52)
#define HI_PMU_DET_SD_LEVEL_CMD_OFFSET (0x53)
#define HI_PMU_DET_SD_LEVEL_STATUS_OFFSET (0x54)
#define HI_PMU_RTCDR0_OFFSET (0x55)
#define HI_PMU_RTCDR1_OFFSET (0x56)
#define HI_PMU_RTCDR2_OFFSET (0x57)
#define HI_PMU_RTCDR3_OFFSET (0x58)
#define HI_PMU_RTCLR0_OFFSET (0x59)
#define HI_PMU_RTCLR1_OFFSET (0x5A)
#define HI_PMU_RTCLR2_OFFSET (0x5B)
#define HI_PMU_RTCLR3_OFFSET (0x5C)
#define HI_PMU_RTCCTRL_OFFSET (0x5D)
#define HI_PMU_RTCMRA0_OFFSET (0x5E)
#define HI_PMU_RTCMRA1_OFFSET (0x5F)
#define HI_PMU_RTCMRA2_OFFSET (0x60)
#define HI_PMU_RTCMRA3_OFFSET (0x61)
#define HI_PMU_RTCMRB0_OFFSET (0x62)
#define HI_PMU_RTCMRB1_OFFSET (0x63)
#define HI_PMU_RTCMRB2_OFFSET (0x64)
#define HI_PMU_RTCMRB3_OFFSET (0x65)
#define HI_PMU_RTCMRC0_OFFSET (0x66)
#define HI_PMU_RTCMRC1_OFFSET (0x67)
#define HI_PMU_RTCMRC2_OFFSET (0x68)
#define HI_PMU_RTCMRC3_OFFSET (0x69)
#define HI_PMU_RTC_ADJ1_OFFSET (0x6A)
#define HI_PMU_RTC_ADJ2_OFFSET (0x6B)
#define HI_PMU_RESERVED3_OFFSET (0x6C)
#define HI_PMU_RESERVED4_OFFSET (0x6D)
#define HI_PMU_RESERVED5_OFFSET (0x6E)
#define HI_PMU_RESERVED6_OFFSET (0x6F)
#define HI_PMU_RESERVED7_OFFSET (0x70)
#define HI_PMU_RESERVED8_OFFSET (0x71)
#define HI_PMU_ONOFF10_OFFSET (0x72)
#define HI_PMU_DR1_BRE_CTRL_OFFSET (0x73)
#define HI_PMU_DR1_TIM_CONF1_OFFSET (0x74)
#define HI_PMU_DR1_TIM_CONF2_OFFSET (0x75)
#define HI_PMU_DR2_BRE_CTRL_OFFSET (0x76)
#define HI_PMU_DR2_TIM_CONF1_OFFSET (0x77)
#define HI_PMU_DR2_TIM_CONF2_OFFSET (0x78)
#define HI_PMU_DR3_BRE_CTRL_OFFSET (0x79)
#define HI_PMU_DR3_TIM_CONF1_OFFSET (0x7A)
#define HI_PMU_DR3_TIM_CONF2_OFFSET (0x7B)
#define HI_PMU_NO_PWR_RSVED1_OFFSET (0x7E)
#define HI_PMU_NO_PWR_RSVED2_OFFSET (0x7F)
typedef union
{
    struct
    {
        unsigned int version : 8;
    } bits;
    unsigned int u32;
}HI_PMU_VERSION_T;
typedef union
{
    struct
    {
        unsigned int otmp_d3r : 1;
        unsigned int hreset_n_f : 1;
        unsigned int pwr_ini_2p7_d3f : 1;
        unsigned int pwr_ini_6p0_d3r : 1;
        unsigned int pwr_ini_6p0_d100r : 1;
        unsigned int pwron_d1sr : 1;
        unsigned int pwron_d20f : 1;
        unsigned int pwron_d20r : 1;
    } bits;
    unsigned int u32;
}HI_PMU_IRQ1_T;
typedef union
{
    struct
    {
        unsigned int ocp_r : 1;
        unsigned int vin_ldo_l_2p5_d3r : 1;
        unsigned int usb_4p0_d3f : 1;
        unsigned int usb_4p0_d3r : 1;
        unsigned int usb_6p0_d3r : 1;
        unsigned int vbus_4p0_d3f : 1;
        unsigned int vbus_6p0_d3r : 1;
        unsigned int vbus_6p0_d100r : 1;
    } bits;
    unsigned int u32;
}HI_PMU_IRQ2_T;
typedef union
{
    struct
    {
        unsigned int alarm_on_expanda : 1;
        unsigned int alarm_on_expandb : 1;
        unsigned int alarm_on_expandc : 1;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_IRQ3_T;
typedef union
{
    struct
    {
        unsigned int ocp_ldo2 : 1;
        unsigned int ocp_ldo1 : 1;
        unsigned int ocp_buck6 : 1;
        unsigned int ocp_buck5 : 1;
        unsigned int ocp_buck4 : 1;
        unsigned int ocp_buck3 : 1;
        unsigned int ocp_buck2 : 1;
        unsigned int ocp_buck1 : 1;
    } bits;
    unsigned int u32;
}HI_PMU_STATUS1_T;
typedef union
{
    struct
    {
        unsigned int ocp_ldo10 : 1;
        unsigned int ocp_ldo9 : 1;
        unsigned int ocp_ldo8 : 1;
        unsigned int ocp_ldo7 : 1;
        unsigned int ocp_ldo6 : 1;
        unsigned int ocp_ldo5 : 1;
        unsigned int ocp_ldo4 : 1;
        unsigned int ocp_ldo3 : 1;
    } bits;
    unsigned int u32;
}HI_PMU_STATUS2_T;
typedef union
{
    struct
    {
        unsigned int ocp_ldo15 : 1;
        unsigned int ocp_ldo14 : 1;
        unsigned int ocp_ldo13 : 1;
        unsigned int ocp_ldo12 : 1;
        unsigned int ocp_ldo11 : 1;
        unsigned int reserved : 3;
    } bits;
    unsigned int u32;
}HI_PMU_STATUS3_T;
typedef union
{
    struct
    {
        unsigned int pwr_ini_2p7_d3f : 1;
        unsigned int pwr_ini_6p0_d3r : 1;
        unsigned int osc_state : 1;
        unsigned int otmp_d3r : 1;
        unsigned int pwron_d20rf : 1;
        unsigned int alarm_on_expenda : 1;
        unsigned int alarm_on_expendb : 1;
        unsigned int alarm_on_expendc : 1;
    } bits;
    unsigned int u32;
}HI_PMU_STATUS4_T;
typedef union
{
    struct
    {
        unsigned int usb_4p0_d3rf : 1;
        unsigned int usb_6p0_d3r : 1;
        unsigned int vbus_4p0_d3f : 1;
        unsigned int vbus_6p0_d3r : 1;
        unsigned int vin_ldo_l_2p5_d3r : 1;
        unsigned int reserved : 3;
    } bits;
    unsigned int u32;
}HI_PMU_STATUS5_T;
typedef union
{
    struct
    {
        unsigned int otmp_d3rm : 1;
        unsigned int hreset_n_fm : 1;
        unsigned int pwr_ini_2p7_d3fm : 1;
        unsigned int pwr_ini_6p0_d3rm : 1;
        unsigned int pwr_ini_6p0_d100rm : 1;
        unsigned int pwron_d1srm : 1;
        unsigned int pwron_d20fm : 1;
        unsigned int pwron_d20rm : 1;
    } bits;
    unsigned int u32;
}HI_PMU_IRQM1_T;
typedef union
{
    struct
    {
        unsigned int ocp_rm : 1;
        unsigned int vin_ldo_l_2p5_d3rm : 1;
        unsigned int usb_4p0_d3fm : 1;
        unsigned int usb_4p0_d3rm : 1;
        unsigned int usb_6p0_d3rm : 1;
        unsigned int vbus_4p0_d3fm : 1;
        unsigned int vbus_6p0_d3rm : 1;
        unsigned int vbus_6p0_d100rm : 1;
    } bits;
    unsigned int u32;
}HI_PMU_IRQM2_T;
typedef union
{
    struct
    {
        unsigned int alarm_on_expendam : 1;
        unsigned int alarm_on_expendbm : 1;
        unsigned int alarm_on_expendcm : 1;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_IRQM3_T;
typedef union
{
    struct
    {
        unsigned int en_eco_ldo4_int : 1;
        unsigned int en_ldo4_int : 1;
        unsigned int en_eco_ldo3_int : 1;
        unsigned int en_ldo3_int : 1;
        unsigned int en_eco_ldo2_int : 1;
        unsigned int en_ldo2_int : 1;
        unsigned int en_eco_ldo1_int : 1;
        unsigned int en_ldo1_int : 1;
    } bits;
    unsigned int u32;
}HI_PMU_ONOFF1_T;
typedef union
{
    struct
    {
        unsigned int en_eco_ldo8_int : 1;
        unsigned int en_ldo8_int : 1;
        unsigned int en_eco_ldo7_int : 1;
        unsigned int en_ldo7_int : 1;
        unsigned int en_eco_ldo6_int : 1;
        unsigned int en_ldo6_int : 1;
        unsigned int en_eco_ldo5_int : 1;
        unsigned int en_ldo5_int : 1;
    } bits;
    unsigned int u32;
}HI_PMU_ONOFF2_T;
typedef union
{
    struct
    {
        unsigned int en_eco_ldo12_int : 1;
        unsigned int en_ldo12_int : 1;
        unsigned int en_eco_ldo11_int : 1;
        unsigned int en_ldo11_int : 1;
        unsigned int en_eco_ldo10_int : 1;
        unsigned int en_ldo10_int : 1;
        unsigned int en_eco_ldo9_int : 1;
        unsigned int en_ldo9_int : 1;
    } bits;
    unsigned int u32;
}HI_PMU_ONOFF3_T;
typedef union
{
    struct
    {
        unsigned int en_eco_ldo15_int : 1;
        unsigned int en_ldo15_int : 1;
        unsigned int en_eco_ldo14_int : 1;
        unsigned int en_ldo14_int : 1;
        unsigned int en_eco_ldo13_int : 1;
        unsigned int en_ldo13_int : 1;
        unsigned int reserved : 2;
    } bits;
    unsigned int u32;
}HI_PMU_ONOFF4_T;
typedef union
{
    struct
    {
        unsigned int reserved_2 : 1;
        unsigned int en_buck4_int : 1;
        unsigned int reserved_1 : 1;
        unsigned int en_buck3_int : 1;
        unsigned int reserved_0 : 1;
        unsigned int en_buck2_int : 1;
        unsigned int en_buck1_int : 2;
    } bits;
    unsigned int u32;
}HI_PMU_ONOFF5_T;
typedef union
{
    struct
    {
        unsigned int reserved_1 : 2;
        unsigned int en_buck1_eno6_int : 1;
        unsigned int en_buck6_ldo_int : 1;
        unsigned int en_eno6_eco_int : 1;
        unsigned int en_buck6_int : 1;
        unsigned int reserved_0 : 1;
        unsigned int en_buck5_int : 1;
    } bits;
    unsigned int u32;
}HI_PMU_ONOFF6_T;
typedef union
{
    struct
    {
        unsigned int otmp_off_ctrl : 1;
        unsigned int en_32k2 : 1;
        unsigned int en_32k1 : 1;
        unsigned int set_tmp : 2;
        unsigned int en_tmp : 1;
        unsigned int reserved : 2;
    } bits;
    unsigned int u32;
}HI_PMU_ONOFF7_T;
typedef union
{
    struct
    {
        unsigned int vbus_4p0_ctrl : 1;
        unsigned int vbus_6p0_ctrl : 1;
        unsigned int pwr_ini_2p7_ctrl : 1;
        unsigned int pwr_ini_6p0_ctrl : 1;
        unsigned int reserved : 4;
    } bits;
    unsigned int u32;
}HI_PMU_ONOFF8_T;
typedef union
{
    struct
    {
        unsigned int en_vbus_4p0 : 1;
        unsigned int en_vbus_6p0 : 1;
        unsigned int en_pini_2p7 : 1;
        unsigned int en_pini_6p0 : 1;
        unsigned int en_vin_ldo_l_2p5 : 1;
        unsigned int reserved : 3;
    } bits;
    unsigned int u32;
}HI_PMU_ONOFF9_T;
typedef union
{
    struct
    {
        unsigned int en_ldo8_sw : 1;
        unsigned int en_ldo7_sw : 1;
        unsigned int en_ldo6_sw : 1;
        unsigned int en_ldo5_sw : 1;
        unsigned int en_ldo4_sw : 1;
        unsigned int en_ldo3_sw : 1;
        unsigned int en_ldo2_sw : 1;
        unsigned int en_ldo1_sw : 1;
    } bits;
    unsigned int u32;
}HI_PMU_LDO_SWICH1_T;
typedef union
{
    struct
    {
        unsigned int en_ldo15_sw : 1;
        unsigned int en_ldo14_sw : 1;
        unsigned int en_ldo13_sw : 1;
        unsigned int en_ldo12_sw : 1;
        unsigned int en_ldo11_sw : 1;
        unsigned int en_ldo10_sw : 1;
        unsigned int en_ldo9_sw : 1;
        unsigned int reserved : 1;
    } bits;
    unsigned int u32;
}HI_PMU_LDO_SWITCH2_T;
typedef union
{
    struct
    {
        unsigned int vset_buck1 : 4;
        unsigned int reserved : 4;
    } bits;
    unsigned int u32;
}HI_PMU_SET_BUCK1_T;
typedef union
{
    struct
    {
        unsigned int vset_buck2 : 4;
        unsigned int reserved : 4;
    } bits;
    unsigned int u32;
}HI_PMU_SET_BUCK2_T;
typedef union
{
    struct
    {
        unsigned int vset_buck3 : 4;
        unsigned int reserved : 4;
    } bits;
    unsigned int u32;
}HI_PMU_SET_BUCK3_T;
typedef union
{
    struct
    {
        unsigned int vset_buck4 : 3;
        unsigned int pdm_sel : 1;
        unsigned int buck4_mode_sel_int : 2;
        unsigned int reserved : 2;
    } bits;
    unsigned int u32;
}HI_PMU_SET_BUCK4_T;
typedef union
{
    struct
    {
        unsigned int vset_buck5 : 3;
        unsigned int buck5_mode_sel_int : 2;
        unsigned int reserved : 3;
    } bits;
    unsigned int u32;
}HI_PMU_SET_BUCK5_T;
typedef union
{
    struct
    {
        unsigned int vset_buck6 : 4;
        unsigned int reserved : 4;
    } bits;
    unsigned int u32;
}HI_PMU_SET_BUCK6_T;
typedef union
{
    struct
    {
        unsigned int ocp_d_buck1 : 1;
        unsigned int adj_clx_buck1 : 1;
        unsigned int adj_rlx_buck1 : 3;
        unsigned int icmp_buck1 : 2;
        unsigned int sleep_buck1_int : 1;
    } bits;
    unsigned int u32;
}HI_PMU_BUCK1_ADJ1_T;
typedef union
{
    struct
    {
        unsigned int reg_dr_buck1 : 2;
        unsigned int reg_r_buck1 : 2;
        unsigned int reg_c_buck1 : 1;
        unsigned int en_reg_buck1 : 1;
        unsigned int dt_sel_buck1 : 1;
        unsigned int reserved : 1;
    } bits;
    unsigned int u32;
}HI_PMU_BUCK1_ADJ2_T;
typedef union
{
    struct
    {
        unsigned int ocp_d_buck2 : 1;
        unsigned int adj_clx_buck2 : 1;
        unsigned int adj_rlx_buck2 : 3;
        unsigned int icmp_buck2 : 2;
        unsigned int sleep_buck2_int : 1;
    } bits;
    unsigned int u32;
}HI_PMU_BUCK2_ADJ1_T;
typedef union
{
    struct
    {
        unsigned int reg_dr_buck2 : 2;
        unsigned int reg_r_buck2 : 2;
        unsigned int reg_c_buck2 : 1;
        unsigned int en_reg_buck2 : 1;
        unsigned int dt_sel_buck2 : 1;
        unsigned int reserved : 1;
    } bits;
    unsigned int u32;
}HI_PMU_BUCK2_ADJ2_T;
typedef union
{
    struct
    {
        unsigned int ocp_d_buck3 : 1;
        unsigned int adj_clx_buck3 : 1;
        unsigned int adj_rlx_buck3 : 3;
        unsigned int icmp_buck3 : 2;
        unsigned int sleep_buck3_int : 1;
    } bits;
    unsigned int u32;
}HI_PMU_BUCK3_ADJ1_T;
typedef union
{
    struct
    {
        unsigned int reg_dr_buck3 : 2;
        unsigned int reg_r_buck3 : 2;
        unsigned int reg_c_buck3 : 1;
        unsigned int en_reg_buck3 : 1;
        unsigned int dt_sel_buck3 : 1;
        unsigned int reserved : 1;
    } bits;
    unsigned int u32;
}HI_PMU_BUCK3_ADJ2_T;
typedef union
{
    struct
    {
        unsigned int ocp_3a_p : 1;
        unsigned int reserved : 1;
        unsigned int ccm4_ctr : 1;
        unsigned int sleep_buck4_int : 1;
        unsigned int slope_ctrl_buck4 : 1;
        unsigned int offset_trim_start_int : 1;
        unsigned int offset_trim_reg : 1;
        unsigned int offset_cancel_en : 1;
    } bits;
    unsigned int u32;
}HI_PMU_BUCK1_2_4_ADJ2_T;
typedef union
{
    struct
    {
        unsigned int ccm5_ctr : 1;
        unsigned int sleep_buck5_int : 1;
        unsigned int slope_ctrl_buck5 : 1;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_BUCK5_ADJ_T;
typedef union
{
    struct
    {
        unsigned int ocp_d_buck6 : 1;
        unsigned int adj_clx_buck6 : 1;
        unsigned int adj_rlx_buck6 : 3;
        unsigned int icmp_buck6 : 2;
        unsigned int sleep_buck6_int : 1;
    } bits;
    unsigned int u32;
}HI_PMU_BUCK6_ADJ1_T;
typedef union
{
    struct
    {
        unsigned int reg_dr_buck6 : 2;
        unsigned int reg_r_buck6 : 2;
        unsigned int reg_c_buck6 : 1;
        unsigned int en_reg_buck6 : 1;
        unsigned int dt_sel_buck6 : 1;
        unsigned int reserved : 1;
    } bits;
    unsigned int u32;
}HI_PMU_BUCK6_ADJ2_T;
typedef union
{
    struct
    {
        unsigned int buck_frq_adj : 5;
        unsigned int ocp_shield_p : 1;
        unsigned int shortn : 1;
        unsigned int reserved : 1;
    } bits;
    unsigned int u32;
}HI_PMU_BUCK4_5_FREQ_T;
typedef union
{
    struct
    {
        unsigned int buck4_comp_adj : 8;
    } bits;
    unsigned int u32;
}HI_PMU_BUCK4_COMP_ADJ_T;
typedef union
{
    struct
    {
        unsigned int buck5_comp_adj : 8;
    } bits;
    unsigned int u32;
}HI_PMU_BUCK5_COMP_ADJ_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo1 : 3;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO1_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo2 : 3;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO2_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo3 : 3;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO3_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo4 : 3;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO4_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo5 : 3;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO5_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo6 : 3;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO6_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo7 : 3;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO7_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo8 : 3;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO8_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo9 : 3;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO9_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo10 : 3;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO10_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo11 : 3;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO11_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo13 : 3;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO13_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo14 : 3;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO14_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo15 : 3;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO15_T;
typedef union
{
    struct
    {
        unsigned int vset_ldo17 : 2;
        unsigned int reserved : 6;
    } bits;
    unsigned int u32;
}HI_PMU_SET_LDO17_T;
typedef union
{
    struct
    {
        unsigned int otp_por_pulse : 1;
        unsigned int otp_read_mask : 1;
        unsigned int otp_pwe_pulse : 1;
        unsigned int otp_write_mask : 1;
        unsigned int reserved : 4;
    } bits;
    unsigned int u32;
}HI_PMU_SET_OTP_T;
typedef union
{
    struct
    {
        unsigned int iset_dr1 : 3;
        unsigned int en_dr1_int : 1;
        unsigned int dr1_mode : 1;
        unsigned int reserved : 3;
    } bits;
    unsigned int u32;
}HI_PMU_DR1_MODE_T;
typedef union
{
    struct
    {
        unsigned int iset_dr2 : 3;
        unsigned int en_dr2_int : 1;
        unsigned int dr2_mode : 1;
        unsigned int reserved : 3;
    } bits;
    unsigned int u32;
}HI_PMU_DR2_MODE_T;
typedef union
{
    struct
    {
        unsigned int iset_dr3 : 3;
        unsigned int en_dr3_int : 1;
        unsigned int dr3_mode : 1;
        unsigned int reserved : 3;
    } bits;
    unsigned int u32;
}HI_PMU_DR3_MODE_T;
typedef union
{
    struct
    {
        unsigned int flash_period : 8;
    } bits;
    unsigned int u32;
}HI_PMU_FLASH_PERIOD_T;
typedef union
{
    struct
    {
        unsigned int flash_on : 8;
    } bits;
    unsigned int u32;
}HI_PMU_FLASH_ON_T;
typedef union
{
    struct
    {
        unsigned int ocp_auto_off : 1;
        unsigned int ocp_shut_down_ctrl : 1;
        unsigned int ocp_deb_sel : 2;
        unsigned int en_buck_ocp_debounce : 1;
        unsigned int en_ldo_ocp_debounce : 1;
        unsigned int lim_mode_int : 1;
        unsigned int reserved : 1;
    } bits;
    unsigned int u32;
}HI_PMU_PERIPH_CTRL1_T;
typedef union
{
    struct
    {
        unsigned int hrst_otmp_d3 : 1;
        unsigned int hrst_hreset_n_f : 1;
        unsigned int hrst_pwr_ini_2p7_d3f : 1;
        unsigned int hrst_pwr_ini_6p0_d3r : 1;
        unsigned int hrst_pwr_ini_6p0_d100r : 1;
        unsigned int hrst_pwron_d1sr : 1;
        unsigned int hrst_pwron_d20f : 1;
        unsigned int hrst_pwron_d20r : 1;
    } bits;
    unsigned int u32;
}HI_PMU_NO_PWR_IRQ1_T;
typedef union
{
    struct
    {
        unsigned int hrst_ocp_total : 1;
        unsigned int hrst_vin_ldo_l_2p5_d3r : 1;
        unsigned int hrst_usb_4p0_d3f : 1;
        unsigned int hrst_usb_4p0_d3r : 1;
        unsigned int hrst_usb_6p0_d3r : 1;
        unsigned int hrst_vbus_4p0_d3f : 1;
        unsigned int hrst_vbus_6p0_d3r : 1;
        unsigned int hrst_vbus_6p0_d100r : 1;
    } bits;
    unsigned int u32;
}HI_PMU_NO_PWR__IRQ2_T;
typedef union
{
    struct
    {
        unsigned int hrst_alarm_on_expenda : 1;
        unsigned int hrst_alarm_on_expendb : 1;
        unsigned int hrst_alarm_on_expendc : 1;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_NO_PWR_IRQ3_T;
typedef union
{
    struct
    {
        unsigned int otmp150_d3r : 1;
        unsigned int ilim_sht_pro_d3r : 1;
        unsigned int reserved : 6;
    } bits;
    unsigned int u32;
}HI_PMU_NO_PWR_REG_RWC_T;
typedef union
{
    struct
    {
        unsigned int leak_ctl : 1;
        unsigned int rc_off : 1;
        unsigned int dr_fla_bre_ctrl : 1;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_PMU_NO_RWR_REG_RW_T;
typedef union
{
    struct
    {
        unsigned int ana_in_2d : 8;
    } bits;
    unsigned int u32;
}HI_PMU_ANA_IN_T;
typedef union
{
    struct
    {
        unsigned int reserved0 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RESERVED0_T;
typedef union
{
    struct
    {
        unsigned int reserved1 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RESERVED1_T;
typedef union
{
    struct
    {
        unsigned int reserved2 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RESERVED2_T;
typedef union
{
    struct
    {
        unsigned int clim_ctl : 4;
        unsigned int clim_vth : 3;
        unsigned int clim_op_isel : 1;
    } bits;
    unsigned int u32;
}HI_PMU_CLIM_ADJ_T;
typedef union
{
    struct
    {
        unsigned int lit_cur_set : 2;
        unsigned int pro_mode : 1;
        unsigned int vs : 3;
        unsigned int reserved : 2;
    } bits;
    unsigned int u32;
}HI_PMU_LIT_CUR_SET_T;
typedef union
{
    struct
    {
        unsigned int otp_pwe_int : 1;
        unsigned int otp_por_int : 1;
        unsigned int otp_pa : 2;
        unsigned int otp_ptm : 2;
        unsigned int otp_pprog : 1;
        unsigned int reserved : 1;
    } bits;
    unsigned int u32;
}HI_PMU_OTP_CTRL_T;
typedef union
{
    struct
    {
        unsigned int otp_pdin : 8;
    } bits;
    unsigned int u32;
}HI_PMU_OTP_PDIN_T;
typedef union
{
    struct
    {
        unsigned int otp_pdob0 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_OTP_PDOB0_T;
typedef union
{
    struct
    {
        unsigned int otp_pdob1 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_OTP_PDOB1_T;
typedef union
{
    struct
    {
        unsigned int otp_pdob2 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_OTP_PDOB2_T;
typedef union
{
    struct
    {
        unsigned int otp_pdob3 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_OTP_PDOB3_T;
typedef union
{
    struct
    {
        unsigned int sleep_bandgap : 1;
        unsigned int v0p59_sel : 1;
        unsigned int sleep_ctrl1 : 1;
        unsigned int sleep_ctrl2 : 1;
        unsigned int reserved : 4;
    } bits;
    unsigned int u32;
}HI_PMU_BANDGAP_REG_T;
typedef union
{
    struct
    {
        unsigned int cmd_sd_2d : 1;
        unsigned int reserved : 7;
    } bits;
    unsigned int u32;
}HI_PMU_DET_SD_LEVEL_CMD_T;
typedef union
{
    struct
    {
        unsigned int state_sd_2d : 2;
        unsigned int reserved : 6;
    } bits;
    unsigned int u32;
}HI_PMU_DET_SD_LEVEL_STATUS_T;
typedef union
{
    struct
    {
        unsigned int rtcdr0 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCDR0_T;
typedef union
{
    struct
    {
        unsigned int rtcdr1 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCDR1_T;
typedef union
{
    struct
    {
        unsigned int rtcdr2 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCDR2_T;
typedef union
{
    struct
    {
        unsigned int rtcdr3 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCDR3_T;
typedef union
{
    struct
    {
        unsigned int rtcclr0 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCLR0_T;
typedef union
{
    struct
    {
        unsigned int rtcclr1 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCLR1_T;
typedef union
{
    struct
    {
        unsigned int rtcclr2 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCLR2_T;
typedef union
{
    struct
    {
        unsigned int rtcclr3 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCLR3_T;
typedef union
{
    struct
    {
        unsigned int rtccr : 1;
        unsigned int reserved : 7;
    } bits;
    unsigned int u32;
}HI_PMU_RTCCTRL_T;
typedef union
{
    struct
    {
        unsigned int rtcmra0 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCMRA0_T;
typedef union
{
    struct
    {
        unsigned int rtcmra1 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCMRA1_T;
typedef union
{
    struct
    {
        unsigned int rtcmra2 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCMRA2_T;
typedef union
{
    struct
    {
        unsigned int rtcmra3 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCMRA3_T;
typedef union
{
    struct
    {
        unsigned int rtcmrb0 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCMRB0_T;
typedef union
{
    struct
    {
        unsigned int rtcmrb1 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCMRB1_T;
typedef union
{
    struct
    {
        unsigned int rtcmrb2 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCMRB2_T;
typedef union
{
    struct
    {
        unsigned int rtcmrb3 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCMRB3_T;
typedef union
{
    struct
    {
        unsigned int rtcmrc0 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCMRC0_T;
typedef union
{
    struct
    {
        unsigned int rtcmrc1 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCMRC1_T;
typedef union
{
    struct
    {
        unsigned int rtcmrc2 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCMRC2_T;
typedef union
{
    struct
    {
        unsigned int rtcmrc3 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTCMRC3_T;
typedef union
{
    struct
    {
        unsigned int rtc_clk_setp_adj1 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTC_ADJ1_T;
typedef union
{
    struct
    {
        unsigned int rtc_clk_setp_adj2 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RTC_ADJ2_T;
typedef union
{
    struct
    {
        unsigned int reserved3 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RESERVED3_T;
typedef union
{
    struct
    {
        unsigned int reserved4 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RESERVED4_T;
typedef union
{
    struct
    {
        unsigned int reserved5 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RESERVED5_T;
typedef union
{
    struct
    {
        unsigned int reserved6 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RESERVED6_T;
typedef union
{
    struct
    {
        unsigned int reserved7 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RESERVED7_T;
typedef union
{
    struct
    {
        unsigned int reserved8 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_RESERVED8_T;
typedef union
{
    struct
    {
        unsigned int sht_pro_off_ctrl : 1;
        unsigned int reserved : 7;
    } bits;
    unsigned int u32;
}HI_PMU_ONOFF10_T;
typedef union
{
    struct
    {
        unsigned int dr1_en_bre : 1;
        unsigned int dr1_flash_en : 1;
        unsigned int reserved : 6;
    } bits;
    unsigned int u32;
}HI_PMU_DR1_BRE_CTRL_T;
typedef union
{
    struct
    {
        unsigned int dr1_t_off : 3;
        unsigned int reserved_1 : 1;
        unsigned int dr1_t_on : 3;
        unsigned int reserved_0 : 1;
    } bits;
    unsigned int u32;
}HI_PMU_DR1_TIM_CONF1_T;
typedef union
{
    struct
    {
        unsigned int dr1_t_rise : 3;
        unsigned int reserved_1 : 1;
        unsigned int dr1_t_fall : 3;
        unsigned int reserved_0 : 1;
    } bits;
    unsigned int u32;
}HI_PMU_DR1_TIM_CONF2_T;
typedef union
{
    struct
    {
        unsigned int dr2_en_bre : 1;
        unsigned int dr2_flash_en : 1;
        unsigned int reserved : 6;
    } bits;
    unsigned int u32;
}HI_PMU_DR2_BRE_CTRL_T;
typedef union
{
    struct
    {
        unsigned int dr2_t_off : 3;
        unsigned int reserved_1 : 1;
        unsigned int dr2_t_on : 3;
        unsigned int reserved_0 : 1;
    } bits;
    unsigned int u32;
}HI_PMU_DR2_TIM_CONF1_T;
typedef union
{
    struct
    {
        unsigned int dr2_t_rise : 3;
        unsigned int reserved_1 : 1;
        unsigned int dr2_t_fall : 3;
        unsigned int reserved_0 : 1;
    } bits;
    unsigned int u32;
}HI_PMU_DR2_TIM_CONF2_T;
typedef union
{
    struct
    {
        unsigned int d3_en : 1;
        unsigned int dr3_flash_en : 1;
        unsigned int reserved : 6;
    } bits;
    unsigned int u32;
}HI_PMU_DR3_BRE_CTRL_T;
typedef union
{
    struct
    {
        unsigned int dr3_t_off : 3;
        unsigned int reserved_1 : 1;
        unsigned int dr3_t_on : 3;
        unsigned int reserved_0 : 1;
    } bits;
    unsigned int u32;
}HI_PMU_DR3_TIM_CONF1_T;
typedef union
{
    struct
    {
        unsigned int dr3_t_rise : 3;
        unsigned int reserved_1 : 1;
        unsigned int dr3_t_fall : 3;
        unsigned int reserved_0 : 1;
    } bits;
    unsigned int u32;
}HI_PMU_DR3_TIM_CONF2_T;
typedef union
{
    struct
    {
        unsigned int no_pwr_resved1 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_NO_PWR_RSVED1_T;
typedef union
{
    struct
    {
        unsigned int no_pwr_resved2 : 8;
    } bits;
    unsigned int u32;
}HI_PMU_NO_PWR_RSVED2_T;
HI_SET_GET(hi_pmu_version_version,version,HI_PMU_VERSION_T,HI_PMU_BASE_ADDR, HI_PMU_VERSION_OFFSET)
HI_SET_GET(hi_pmu_irq1_otmp_d3r,otmp_d3r,HI_PMU_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_irq1_hreset_n_f,hreset_n_f,HI_PMU_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_irq1_pwr_ini_2p7_d3f,pwr_ini_2p7_d3f,HI_PMU_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_irq1_pwr_ini_6p0_d3r,pwr_ini_6p0_d3r,HI_PMU_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_irq1_pwr_ini_6p0_d100r,pwr_ini_6p0_d100r,HI_PMU_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_irq1_pwron_d1sr,pwron_d1sr,HI_PMU_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_irq1_pwron_d20f,pwron_d20f,HI_PMU_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_irq1_pwron_d20r,pwron_d20r,HI_PMU_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_irq2_ocp_r,ocp_r,HI_PMU_IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ2_OFFSET)
HI_SET_GET(hi_pmu_irq2_vin_ldo_l_2p5_d3r,vin_ldo_l_2p5_d3r,HI_PMU_IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ2_OFFSET)
HI_SET_GET(hi_pmu_irq2_usb_4p0_d3f,usb_4p0_d3f,HI_PMU_IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ2_OFFSET)
HI_SET_GET(hi_pmu_irq2_usb_4p0_d3r,usb_4p0_d3r,HI_PMU_IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ2_OFFSET)
HI_SET_GET(hi_pmu_irq2_usb_6p0_d3r,usb_6p0_d3r,HI_PMU_IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ2_OFFSET)
HI_SET_GET(hi_pmu_irq2_vbus_4p0_d3f,vbus_4p0_d3f,HI_PMU_IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ2_OFFSET)
HI_SET_GET(hi_pmu_irq2_vbus_6p0_d3r,vbus_6p0_d3r,HI_PMU_IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ2_OFFSET)
HI_SET_GET(hi_pmu_irq2_vbus_6p0_d100r,vbus_6p0_d100r,HI_PMU_IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ2_OFFSET)
HI_SET_GET(hi_pmu_irq3_alarm_on_expanda,alarm_on_expanda,HI_PMU_IRQ3_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ3_OFFSET)
HI_SET_GET(hi_pmu_irq3_alarm_on_expandb,alarm_on_expandb,HI_PMU_IRQ3_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ3_OFFSET)
HI_SET_GET(hi_pmu_irq3_alarm_on_expandc,alarm_on_expandc,HI_PMU_IRQ3_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ3_OFFSET)
HI_SET_GET(hi_pmu_irq3_reserved,reserved,HI_PMU_IRQ3_T,HI_PMU_BASE_ADDR, HI_PMU_IRQ3_OFFSET)
HI_SET_GET(hi_pmu_status1_ocp_ldo2,ocp_ldo2,HI_PMU_STATUS1_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS1_OFFSET)
HI_SET_GET(hi_pmu_status1_ocp_ldo1,ocp_ldo1,HI_PMU_STATUS1_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS1_OFFSET)
HI_SET_GET(hi_pmu_status1_ocp_buck6,ocp_buck6,HI_PMU_STATUS1_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS1_OFFSET)
HI_SET_GET(hi_pmu_status1_ocp_buck5,ocp_buck5,HI_PMU_STATUS1_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS1_OFFSET)
HI_SET_GET(hi_pmu_status1_ocp_buck4,ocp_buck4,HI_PMU_STATUS1_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS1_OFFSET)
HI_SET_GET(hi_pmu_status1_ocp_buck3,ocp_buck3,HI_PMU_STATUS1_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS1_OFFSET)
HI_SET_GET(hi_pmu_status1_ocp_buck2,ocp_buck2,HI_PMU_STATUS1_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS1_OFFSET)
HI_SET_GET(hi_pmu_status1_ocp_buck1,ocp_buck1,HI_PMU_STATUS1_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS1_OFFSET)
HI_SET_GET(hi_pmu_status2_ocp_ldo10,ocp_ldo10,HI_PMU_STATUS2_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS2_OFFSET)
HI_SET_GET(hi_pmu_status2_ocp_ldo9,ocp_ldo9,HI_PMU_STATUS2_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS2_OFFSET)
HI_SET_GET(hi_pmu_status2_ocp_ldo8,ocp_ldo8,HI_PMU_STATUS2_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS2_OFFSET)
HI_SET_GET(hi_pmu_status2_ocp_ldo7,ocp_ldo7,HI_PMU_STATUS2_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS2_OFFSET)
HI_SET_GET(hi_pmu_status2_ocp_ldo6,ocp_ldo6,HI_PMU_STATUS2_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS2_OFFSET)
HI_SET_GET(hi_pmu_status2_ocp_ldo5,ocp_ldo5,HI_PMU_STATUS2_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS2_OFFSET)
HI_SET_GET(hi_pmu_status2_ocp_ldo4,ocp_ldo4,HI_PMU_STATUS2_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS2_OFFSET)
HI_SET_GET(hi_pmu_status2_ocp_ldo3,ocp_ldo3,HI_PMU_STATUS2_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS2_OFFSET)
HI_SET_GET(hi_pmu_status3_ocp_ldo15,ocp_ldo15,HI_PMU_STATUS3_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS3_OFFSET)
HI_SET_GET(hi_pmu_status3_ocp_ldo14,ocp_ldo14,HI_PMU_STATUS3_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS3_OFFSET)
HI_SET_GET(hi_pmu_status3_ocp_ldo13,ocp_ldo13,HI_PMU_STATUS3_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS3_OFFSET)
HI_SET_GET(hi_pmu_status3_ocp_ldo12,ocp_ldo12,HI_PMU_STATUS3_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS3_OFFSET)
HI_SET_GET(hi_pmu_status3_ocp_ldo11,ocp_ldo11,HI_PMU_STATUS3_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS3_OFFSET)
HI_SET_GET(hi_pmu_status3_reserved,reserved,HI_PMU_STATUS3_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS3_OFFSET)
HI_SET_GET(hi_pmu_status4_pwr_ini_2p7_d3f,pwr_ini_2p7_d3f,HI_PMU_STATUS4_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS4_OFFSET)
HI_SET_GET(hi_pmu_status4_pwr_ini_6p0_d3r,pwr_ini_6p0_d3r,HI_PMU_STATUS4_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS4_OFFSET)
HI_SET_GET(hi_pmu_status4_osc_state,osc_state,HI_PMU_STATUS4_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS4_OFFSET)
HI_SET_GET(hi_pmu_status4_otmp_d3r,otmp_d3r,HI_PMU_STATUS4_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS4_OFFSET)
HI_SET_GET(hi_pmu_status4_pwron_d20rf,pwron_d20rf,HI_PMU_STATUS4_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS4_OFFSET)
HI_SET_GET(hi_pmu_status4_alarm_on_expenda,alarm_on_expenda,HI_PMU_STATUS4_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS4_OFFSET)
HI_SET_GET(hi_pmu_status4_alarm_on_expendb,alarm_on_expendb,HI_PMU_STATUS4_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS4_OFFSET)
HI_SET_GET(hi_pmu_status4_alarm_on_expendc,alarm_on_expendc,HI_PMU_STATUS4_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS4_OFFSET)
HI_SET_GET(hi_pmu_status5_usb_4p0_d3rf,usb_4p0_d3rf,HI_PMU_STATUS5_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS5_OFFSET)
HI_SET_GET(hi_pmu_status5_usb_6p0_d3r,usb_6p0_d3r,HI_PMU_STATUS5_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS5_OFFSET)
HI_SET_GET(hi_pmu_status5_vbus_4p0_d3f,vbus_4p0_d3f,HI_PMU_STATUS5_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS5_OFFSET)
HI_SET_GET(hi_pmu_status5_vbus_6p0_d3r,vbus_6p0_d3r,HI_PMU_STATUS5_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS5_OFFSET)
HI_SET_GET(hi_pmu_status5_vin_ldo_l_2p5_d3r,vin_ldo_l_2p5_d3r,HI_PMU_STATUS5_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS5_OFFSET)
HI_SET_GET(hi_pmu_status5_reserved,reserved,HI_PMU_STATUS5_T,HI_PMU_BASE_ADDR, HI_PMU_STATUS5_OFFSET)
HI_SET_GET(hi_pmu_irqm1_otmp_d3rm,otmp_d3rm,HI_PMU_IRQM1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM1_OFFSET)
HI_SET_GET(hi_pmu_irqm1_hreset_n_fm,hreset_n_fm,HI_PMU_IRQM1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM1_OFFSET)
HI_SET_GET(hi_pmu_irqm1_pwr_ini_2p7_d3fm,pwr_ini_2p7_d3fm,HI_PMU_IRQM1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM1_OFFSET)
HI_SET_GET(hi_pmu_irqm1_pwr_ini_6p0_d3rm,pwr_ini_6p0_d3rm,HI_PMU_IRQM1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM1_OFFSET)
HI_SET_GET(hi_pmu_irqm1_pwr_ini_6p0_d100rm,pwr_ini_6p0_d100rm,HI_PMU_IRQM1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM1_OFFSET)
HI_SET_GET(hi_pmu_irqm1_pwron_d1srm,pwron_d1srm,HI_PMU_IRQM1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM1_OFFSET)
HI_SET_GET(hi_pmu_irqm1_pwron_d20fm,pwron_d20fm,HI_PMU_IRQM1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM1_OFFSET)
HI_SET_GET(hi_pmu_irqm1_pwron_d20rm,pwron_d20rm,HI_PMU_IRQM1_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM1_OFFSET)
HI_SET_GET(hi_pmu_irqm2_ocp_rm,ocp_rm,HI_PMU_IRQM2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM2_OFFSET)
HI_SET_GET(hi_pmu_irqm2_vin_ldo_l_2p5_d3rm,vin_ldo_l_2p5_d3rm,HI_PMU_IRQM2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM2_OFFSET)
HI_SET_GET(hi_pmu_irqm2_usb_4p0_d3fm,usb_4p0_d3fm,HI_PMU_IRQM2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM2_OFFSET)
HI_SET_GET(hi_pmu_irqm2_usb_4p0_d3rm,usb_4p0_d3rm,HI_PMU_IRQM2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM2_OFFSET)
HI_SET_GET(hi_pmu_irqm2_usb_6p0_d3rm,usb_6p0_d3rm,HI_PMU_IRQM2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM2_OFFSET)
HI_SET_GET(hi_pmu_irqm2_vbus_4p0_d3fm,vbus_4p0_d3fm,HI_PMU_IRQM2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM2_OFFSET)
HI_SET_GET(hi_pmu_irqm2_vbus_6p0_d3rm,vbus_6p0_d3rm,HI_PMU_IRQM2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM2_OFFSET)
HI_SET_GET(hi_pmu_irqm2_vbus_6p0_d100rm,vbus_6p0_d100rm,HI_PMU_IRQM2_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM2_OFFSET)
HI_SET_GET(hi_pmu_irqm3_alarm_on_expendam,alarm_on_expendam,HI_PMU_IRQM3_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM3_OFFSET)
HI_SET_GET(hi_pmu_irqm3_alarm_on_expendbm,alarm_on_expendbm,HI_PMU_IRQM3_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM3_OFFSET)
HI_SET_GET(hi_pmu_irqm3_alarm_on_expendcm,alarm_on_expendcm,HI_PMU_IRQM3_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM3_OFFSET)
HI_SET_GET(hi_pmu_irqm3_reserved,reserved,HI_PMU_IRQM3_T,HI_PMU_BASE_ADDR, HI_PMU_IRQM3_OFFSET)
HI_SET_GET(hi_pmu_onoff1_en_eco_ldo4_int,en_eco_ldo4_int,HI_PMU_ONOFF1_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF1_OFFSET)
HI_SET_GET(hi_pmu_onoff1_en_ldo4_int,en_ldo4_int,HI_PMU_ONOFF1_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF1_OFFSET)
HI_SET_GET(hi_pmu_onoff1_en_eco_ldo3_int,en_eco_ldo3_int,HI_PMU_ONOFF1_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF1_OFFSET)
HI_SET_GET(hi_pmu_onoff1_en_ldo3_int,en_ldo3_int,HI_PMU_ONOFF1_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF1_OFFSET)
HI_SET_GET(hi_pmu_onoff1_en_eco_ldo2_int,en_eco_ldo2_int,HI_PMU_ONOFF1_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF1_OFFSET)
HI_SET_GET(hi_pmu_onoff1_en_ldo2_int,en_ldo2_int,HI_PMU_ONOFF1_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF1_OFFSET)
HI_SET_GET(hi_pmu_onoff1_en_eco_ldo1_int,en_eco_ldo1_int,HI_PMU_ONOFF1_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF1_OFFSET)
HI_SET_GET(hi_pmu_onoff1_en_ldo1_int,en_ldo1_int,HI_PMU_ONOFF1_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF1_OFFSET)
HI_SET_GET(hi_pmu_onoff2_en_eco_ldo8_int,en_eco_ldo8_int,HI_PMU_ONOFF2_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF2_OFFSET)
HI_SET_GET(hi_pmu_onoff2_en_ldo8_int,en_ldo8_int,HI_PMU_ONOFF2_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF2_OFFSET)
HI_SET_GET(hi_pmu_onoff2_en_eco_ldo7_int,en_eco_ldo7_int,HI_PMU_ONOFF2_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF2_OFFSET)
HI_SET_GET(hi_pmu_onoff2_en_ldo7_int,en_ldo7_int,HI_PMU_ONOFF2_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF2_OFFSET)
HI_SET_GET(hi_pmu_onoff2_en_eco_ldo6_int,en_eco_ldo6_int,HI_PMU_ONOFF2_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF2_OFFSET)
HI_SET_GET(hi_pmu_onoff2_en_ldo6_int,en_ldo6_int,HI_PMU_ONOFF2_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF2_OFFSET)
HI_SET_GET(hi_pmu_onoff2_en_eco_ldo5_int,en_eco_ldo5_int,HI_PMU_ONOFF2_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF2_OFFSET)
HI_SET_GET(hi_pmu_onoff2_en_ldo5_int,en_ldo5_int,HI_PMU_ONOFF2_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF2_OFFSET)
HI_SET_GET(hi_pmu_onoff3_en_eco_ldo12_int,en_eco_ldo12_int,HI_PMU_ONOFF3_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF3_OFFSET)
HI_SET_GET(hi_pmu_onoff3_en_ldo12_int,en_ldo12_int,HI_PMU_ONOFF3_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF3_OFFSET)
HI_SET_GET(hi_pmu_onoff3_en_eco_ldo11_int,en_eco_ldo11_int,HI_PMU_ONOFF3_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF3_OFFSET)
HI_SET_GET(hi_pmu_onoff3_en_ldo11_int,en_ldo11_int,HI_PMU_ONOFF3_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF3_OFFSET)
HI_SET_GET(hi_pmu_onoff3_en_eco_ldo10_int,en_eco_ldo10_int,HI_PMU_ONOFF3_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF3_OFFSET)
HI_SET_GET(hi_pmu_onoff3_en_ldo10_int,en_ldo10_int,HI_PMU_ONOFF3_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF3_OFFSET)
HI_SET_GET(hi_pmu_onoff3_en_eco_ldo9_int,en_eco_ldo9_int,HI_PMU_ONOFF3_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF3_OFFSET)
HI_SET_GET(hi_pmu_onoff3_en_ldo9_int,en_ldo9_int,HI_PMU_ONOFF3_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF3_OFFSET)
HI_SET_GET(hi_pmu_onoff4_en_eco_ldo15_int,en_eco_ldo15_int,HI_PMU_ONOFF4_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF4_OFFSET)
HI_SET_GET(hi_pmu_onoff4_en_ldo15_int,en_ldo15_int,HI_PMU_ONOFF4_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF4_OFFSET)
HI_SET_GET(hi_pmu_onoff4_en_eco_ldo14_int,en_eco_ldo14_int,HI_PMU_ONOFF4_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF4_OFFSET)
HI_SET_GET(hi_pmu_onoff4_en_ldo14_int,en_ldo14_int,HI_PMU_ONOFF4_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF4_OFFSET)
HI_SET_GET(hi_pmu_onoff4_en_eco_ldo13_int,en_eco_ldo13_int,HI_PMU_ONOFF4_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF4_OFFSET)
HI_SET_GET(hi_pmu_onoff4_en_ldo13_int,en_ldo13_int,HI_PMU_ONOFF4_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF4_OFFSET)
HI_SET_GET(hi_pmu_onoff4_reserved,reserved,HI_PMU_ONOFF4_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF4_OFFSET)
HI_SET_GET(hi_pmu_onoff5_reserved_2,reserved_2,HI_PMU_ONOFF5_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF5_OFFSET)
HI_SET_GET(hi_pmu_onoff5_en_buck4_int,en_buck4_int,HI_PMU_ONOFF5_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF5_OFFSET)
HI_SET_GET(hi_pmu_onoff5_reserved_1,reserved_1,HI_PMU_ONOFF5_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF5_OFFSET)
HI_SET_GET(hi_pmu_onoff5_en_buck3_int,en_buck3_int,HI_PMU_ONOFF5_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF5_OFFSET)
HI_SET_GET(hi_pmu_onoff5_reserved_0,reserved_0,HI_PMU_ONOFF5_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF5_OFFSET)
HI_SET_GET(hi_pmu_onoff5_en_buck2_int,en_buck2_int,HI_PMU_ONOFF5_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF5_OFFSET)
HI_SET_GET(hi_pmu_onoff5_en_buck1_int,en_buck1_int,HI_PMU_ONOFF5_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF5_OFFSET)
HI_SET_GET(hi_pmu_onoff6_reserved_1,reserved_1,HI_PMU_ONOFF6_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF6_OFFSET)
HI_SET_GET(hi_pmu_onoff6_en_buck1_eno6_int,en_buck1_eno6_int,HI_PMU_ONOFF6_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF6_OFFSET)
HI_SET_GET(hi_pmu_onoff6_en_buck6_ldo_int,en_buck6_ldo_int,HI_PMU_ONOFF6_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF6_OFFSET)
HI_SET_GET(hi_pmu_onoff6_en_eno6_eco_int,en_eno6_eco_int,HI_PMU_ONOFF6_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF6_OFFSET)
HI_SET_GET(hi_pmu_onoff6_en_buck6_int,en_buck6_int,HI_PMU_ONOFF6_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF6_OFFSET)
HI_SET_GET(hi_pmu_onoff6_reserved_0,reserved_0,HI_PMU_ONOFF6_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF6_OFFSET)
HI_SET_GET(hi_pmu_onoff6_en_buck5_int,en_buck5_int,HI_PMU_ONOFF6_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF6_OFFSET)
HI_SET_GET(hi_pmu_onoff7_otmp_off_ctrl,otmp_off_ctrl,HI_PMU_ONOFF7_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF7_OFFSET)
HI_SET_GET(hi_pmu_onoff7_en_32k2,en_32k2,HI_PMU_ONOFF7_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF7_OFFSET)
HI_SET_GET(hi_pmu_onoff7_en_32k1,en_32k1,HI_PMU_ONOFF7_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF7_OFFSET)
HI_SET_GET(hi_pmu_onoff7_set_tmp,set_tmp,HI_PMU_ONOFF7_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF7_OFFSET)
HI_SET_GET(hi_pmu_onoff7_en_tmp,en_tmp,HI_PMU_ONOFF7_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF7_OFFSET)
HI_SET_GET(hi_pmu_onoff7_reserved,reserved,HI_PMU_ONOFF7_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF7_OFFSET)
HI_SET_GET(hi_pmu_onoff8_vbus_4p0_ctrl,vbus_4p0_ctrl,HI_PMU_ONOFF8_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF8_OFFSET)
HI_SET_GET(hi_pmu_onoff8_vbus_6p0_ctrl,vbus_6p0_ctrl,HI_PMU_ONOFF8_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF8_OFFSET)
HI_SET_GET(hi_pmu_onoff8_pwr_ini_2p7_ctrl,pwr_ini_2p7_ctrl,HI_PMU_ONOFF8_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF8_OFFSET)
HI_SET_GET(hi_pmu_onoff8_pwr_ini_6p0_ctrl,pwr_ini_6p0_ctrl,HI_PMU_ONOFF8_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF8_OFFSET)
HI_SET_GET(hi_pmu_onoff8_reserved,reserved,HI_PMU_ONOFF8_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF8_OFFSET)
HI_SET_GET(hi_pmu_onoff9_en_vbus_4p0,en_vbus_4p0,HI_PMU_ONOFF9_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF9_OFFSET)
HI_SET_GET(hi_pmu_onoff9_en_vbus_6p0,en_vbus_6p0,HI_PMU_ONOFF9_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF9_OFFSET)
HI_SET_GET(hi_pmu_onoff9_en_pini_2p7,en_pini_2p7,HI_PMU_ONOFF9_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF9_OFFSET)
HI_SET_GET(hi_pmu_onoff9_en_pini_6p0,en_pini_6p0,HI_PMU_ONOFF9_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF9_OFFSET)
HI_SET_GET(hi_pmu_onoff9_en_vin_ldo_l_2p5,en_vin_ldo_l_2p5,HI_PMU_ONOFF9_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF9_OFFSET)
HI_SET_GET(hi_pmu_onoff9_reserved,reserved,HI_PMU_ONOFF9_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF9_OFFSET)
HI_SET_GET(hi_pmu_ldo_swich1_en_ldo8_sw,en_ldo8_sw,HI_PMU_LDO_SWICH1_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWICH1_OFFSET)
HI_SET_GET(hi_pmu_ldo_swich1_en_ldo7_sw,en_ldo7_sw,HI_PMU_LDO_SWICH1_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWICH1_OFFSET)
HI_SET_GET(hi_pmu_ldo_swich1_en_ldo6_sw,en_ldo6_sw,HI_PMU_LDO_SWICH1_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWICH1_OFFSET)
HI_SET_GET(hi_pmu_ldo_swich1_en_ldo5_sw,en_ldo5_sw,HI_PMU_LDO_SWICH1_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWICH1_OFFSET)
HI_SET_GET(hi_pmu_ldo_swich1_en_ldo4_sw,en_ldo4_sw,HI_PMU_LDO_SWICH1_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWICH1_OFFSET)
HI_SET_GET(hi_pmu_ldo_swich1_en_ldo3_sw,en_ldo3_sw,HI_PMU_LDO_SWICH1_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWICH1_OFFSET)
HI_SET_GET(hi_pmu_ldo_swich1_en_ldo2_sw,en_ldo2_sw,HI_PMU_LDO_SWICH1_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWICH1_OFFSET)
HI_SET_GET(hi_pmu_ldo_swich1_en_ldo1_sw,en_ldo1_sw,HI_PMU_LDO_SWICH1_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWICH1_OFFSET)
HI_SET_GET(hi_pmu_ldo_switch2_en_ldo15_sw,en_ldo15_sw,HI_PMU_LDO_SWITCH2_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWITCH2_OFFSET)
HI_SET_GET(hi_pmu_ldo_switch2_en_ldo14_sw,en_ldo14_sw,HI_PMU_LDO_SWITCH2_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWITCH2_OFFSET)
HI_SET_GET(hi_pmu_ldo_switch2_en_ldo13_sw,en_ldo13_sw,HI_PMU_LDO_SWITCH2_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWITCH2_OFFSET)
HI_SET_GET(hi_pmu_ldo_switch2_en_ldo12_sw,en_ldo12_sw,HI_PMU_LDO_SWITCH2_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWITCH2_OFFSET)
HI_SET_GET(hi_pmu_ldo_switch2_en_ldo11_sw,en_ldo11_sw,HI_PMU_LDO_SWITCH2_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWITCH2_OFFSET)
HI_SET_GET(hi_pmu_ldo_switch2_en_ldo10_sw,en_ldo10_sw,HI_PMU_LDO_SWITCH2_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWITCH2_OFFSET)
HI_SET_GET(hi_pmu_ldo_switch2_en_ldo9_sw,en_ldo9_sw,HI_PMU_LDO_SWITCH2_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWITCH2_OFFSET)
HI_SET_GET(hi_pmu_ldo_switch2_reserved,reserved,HI_PMU_LDO_SWITCH2_T,HI_PMU_BASE_ADDR, HI_PMU_LDO_SWITCH2_OFFSET)
HI_SET_GET(hi_pmu_set_buck1_vset_buck1,vset_buck1,HI_PMU_SET_BUCK1_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK1_OFFSET)
HI_SET_GET(hi_pmu_set_buck1_reserved,reserved,HI_PMU_SET_BUCK1_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK1_OFFSET)
HI_SET_GET(hi_pmu_set_buck2_vset_buck2,vset_buck2,HI_PMU_SET_BUCK2_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK2_OFFSET)
HI_SET_GET(hi_pmu_set_buck2_reserved,reserved,HI_PMU_SET_BUCK2_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK2_OFFSET)
HI_SET_GET(hi_pmu_set_buck3_vset_buck3,vset_buck3,HI_PMU_SET_BUCK3_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK3_OFFSET)
HI_SET_GET(hi_pmu_set_buck3_reserved,reserved,HI_PMU_SET_BUCK3_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK3_OFFSET)
HI_SET_GET(hi_pmu_set_buck4_vset_buck4,vset_buck4,HI_PMU_SET_BUCK4_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK4_OFFSET)
HI_SET_GET(hi_pmu_set_buck4_pdm_sel,pdm_sel,HI_PMU_SET_BUCK4_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK4_OFFSET)
HI_SET_GET(hi_pmu_set_buck4_buck4_mode_sel_int,buck4_mode_sel_int,HI_PMU_SET_BUCK4_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK4_OFFSET)
HI_SET_GET(hi_pmu_set_buck4_reserved,reserved,HI_PMU_SET_BUCK4_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK4_OFFSET)
HI_SET_GET(hi_pmu_set_buck5_vset_buck5,vset_buck5,HI_PMU_SET_BUCK5_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK5_OFFSET)
HI_SET_GET(hi_pmu_set_buck5_buck5_mode_sel_int,buck5_mode_sel_int,HI_PMU_SET_BUCK5_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK5_OFFSET)
HI_SET_GET(hi_pmu_set_buck5_reserved,reserved,HI_PMU_SET_BUCK5_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK5_OFFSET)
HI_SET_GET(hi_pmu_set_buck6_vset_buck6,vset_buck6,HI_PMU_SET_BUCK6_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK6_OFFSET)
HI_SET_GET(hi_pmu_set_buck6_reserved,reserved,HI_PMU_SET_BUCK6_T,HI_PMU_BASE_ADDR, HI_PMU_SET_BUCK6_OFFSET)
HI_SET_GET(hi_pmu_buck1_adj1_ocp_d_buck1,ocp_d_buck1,HI_PMU_BUCK1_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck1_adj1_adj_clx_buck1,adj_clx_buck1,HI_PMU_BUCK1_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck1_adj1_adj_rlx_buck1,adj_rlx_buck1,HI_PMU_BUCK1_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck1_adj1_icmp_buck1,icmp_buck1,HI_PMU_BUCK1_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck1_adj1_sleep_buck1_int,sleep_buck1_int,HI_PMU_BUCK1_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck1_adj2_reg_dr_buck1,reg_dr_buck1,HI_PMU_BUCK1_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck1_adj2_reg_r_buck1,reg_r_buck1,HI_PMU_BUCK1_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck1_adj2_reg_c_buck1,reg_c_buck1,HI_PMU_BUCK1_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck1_adj2_en_reg_buck1,en_reg_buck1,HI_PMU_BUCK1_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck1_adj2_dt_sel_buck1,dt_sel_buck1,HI_PMU_BUCK1_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck1_adj2_reserved,reserved,HI_PMU_BUCK1_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck2_adj1_ocp_d_buck2,ocp_d_buck2,HI_PMU_BUCK2_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK2_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck2_adj1_adj_clx_buck2,adj_clx_buck2,HI_PMU_BUCK2_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK2_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck2_adj1_adj_rlx_buck2,adj_rlx_buck2,HI_PMU_BUCK2_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK2_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck2_adj1_icmp_buck2,icmp_buck2,HI_PMU_BUCK2_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK2_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck2_adj1_sleep_buck2_int,sleep_buck2_int,HI_PMU_BUCK2_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK2_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck2_adj2_reg_dr_buck2,reg_dr_buck2,HI_PMU_BUCK2_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK2_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck2_adj2_reg_r_buck2,reg_r_buck2,HI_PMU_BUCK2_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK2_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck2_adj2_reg_c_buck2,reg_c_buck2,HI_PMU_BUCK2_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK2_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck2_adj2_en_reg_buck2,en_reg_buck2,HI_PMU_BUCK2_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK2_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck2_adj2_dt_sel_buck2,dt_sel_buck2,HI_PMU_BUCK2_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK2_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck2_adj2_reserved,reserved,HI_PMU_BUCK2_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK2_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck3_adj1_ocp_d_buck3,ocp_d_buck3,HI_PMU_BUCK3_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK3_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck3_adj1_adj_clx_buck3,adj_clx_buck3,HI_PMU_BUCK3_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK3_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck3_adj1_adj_rlx_buck3,adj_rlx_buck3,HI_PMU_BUCK3_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK3_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck3_adj1_icmp_buck3,icmp_buck3,HI_PMU_BUCK3_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK3_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck3_adj1_sleep_buck3_int,sleep_buck3_int,HI_PMU_BUCK3_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK3_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck3_adj2_reg_dr_buck3,reg_dr_buck3,HI_PMU_BUCK3_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK3_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck3_adj2_reg_r_buck3,reg_r_buck3,HI_PMU_BUCK3_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK3_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck3_adj2_reg_c_buck3,reg_c_buck3,HI_PMU_BUCK3_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK3_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck3_adj2_en_reg_buck3,en_reg_buck3,HI_PMU_BUCK3_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK3_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck3_adj2_dt_sel_buck3,dt_sel_buck3,HI_PMU_BUCK3_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK3_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck3_adj2_reserved,reserved,HI_PMU_BUCK3_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK3_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck1_2_4_adj2_ocp_3a_p,ocp_3a_p,HI_PMU_BUCK1_2_4_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_2_4_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck1_2_4_adj2_reserved,reserved,HI_PMU_BUCK1_2_4_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_2_4_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck1_2_4_adj2_ccm4_ctr,ccm4_ctr,HI_PMU_BUCK1_2_4_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_2_4_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck1_2_4_adj2_sleep_buck4_int,sleep_buck4_int,HI_PMU_BUCK1_2_4_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_2_4_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck1_2_4_adj2_slope_ctrl_buck4,slope_ctrl_buck4,HI_PMU_BUCK1_2_4_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_2_4_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck1_2_4_adj2_offset_trim_start_int,offset_trim_start_int,HI_PMU_BUCK1_2_4_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_2_4_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck1_2_4_adj2_offset_trim_reg,offset_trim_reg,HI_PMU_BUCK1_2_4_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_2_4_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck1_2_4_adj2_offset_cancel_en,offset_cancel_en,HI_PMU_BUCK1_2_4_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK1_2_4_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck5_adj_ccm5_ctr,ccm5_ctr,HI_PMU_BUCK5_ADJ_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK5_ADJ_OFFSET)
HI_SET_GET(hi_pmu_buck5_adj_sleep_buck5_int,sleep_buck5_int,HI_PMU_BUCK5_ADJ_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK5_ADJ_OFFSET)
HI_SET_GET(hi_pmu_buck5_adj_slope_ctrl_buck5,slope_ctrl_buck5,HI_PMU_BUCK5_ADJ_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK5_ADJ_OFFSET)
HI_SET_GET(hi_pmu_buck5_adj_reserved,reserved,HI_PMU_BUCK5_ADJ_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK5_ADJ_OFFSET)
HI_SET_GET(hi_pmu_buck6_adj1_ocp_d_buck6,ocp_d_buck6,HI_PMU_BUCK6_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK6_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck6_adj1_adj_clx_buck6,adj_clx_buck6,HI_PMU_BUCK6_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK6_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck6_adj1_adj_rlx_buck6,adj_rlx_buck6,HI_PMU_BUCK6_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK6_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck6_adj1_icmp_buck6,icmp_buck6,HI_PMU_BUCK6_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK6_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck6_adj1_sleep_buck6_int,sleep_buck6_int,HI_PMU_BUCK6_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK6_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_buck6_adj2_reg_dr_buck6,reg_dr_buck6,HI_PMU_BUCK6_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK6_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck6_adj2_reg_r_buck6,reg_r_buck6,HI_PMU_BUCK6_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK6_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck6_adj2_reg_c_buck6,reg_c_buck6,HI_PMU_BUCK6_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK6_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck6_adj2_en_reg_buck6,en_reg_buck6,HI_PMU_BUCK6_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK6_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck6_adj2_dt_sel_buck6,dt_sel_buck6,HI_PMU_BUCK6_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK6_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck6_adj2_reserved,reserved,HI_PMU_BUCK6_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK6_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_buck4_5_freq_buck_frq_adj,buck_frq_adj,HI_PMU_BUCK4_5_FREQ_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK4_5_FREQ_OFFSET)
HI_SET_GET(hi_pmu_buck4_5_freq_ocp_shield_p,ocp_shield_p,HI_PMU_BUCK4_5_FREQ_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK4_5_FREQ_OFFSET)
HI_SET_GET(hi_pmu_buck4_5_freq_shortn,shortn,HI_PMU_BUCK4_5_FREQ_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK4_5_FREQ_OFFSET)
HI_SET_GET(hi_pmu_buck4_5_freq_reserved,reserved,HI_PMU_BUCK4_5_FREQ_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK4_5_FREQ_OFFSET)
HI_SET_GET(hi_pmu_buck4_comp_adj_buck4_comp_adj,buck4_comp_adj,HI_PMU_BUCK4_COMP_ADJ_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK4_COMP_ADJ_OFFSET)
HI_SET_GET(hi_pmu_buck5_comp_adj_buck5_comp_adj,buck5_comp_adj,HI_PMU_BUCK5_COMP_ADJ_T,HI_PMU_BASE_ADDR, HI_PMU_BUCK5_COMP_ADJ_OFFSET)
HI_SET_GET(hi_pmu_set_ldo1_vset_ldo1,vset_ldo1,HI_PMU_SET_LDO1_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO1_OFFSET)
HI_SET_GET(hi_pmu_set_ldo1_reserved,reserved,HI_PMU_SET_LDO1_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO1_OFFSET)
HI_SET_GET(hi_pmu_set_ldo2_vset_ldo2,vset_ldo2,HI_PMU_SET_LDO2_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO2_OFFSET)
HI_SET_GET(hi_pmu_set_ldo2_reserved,reserved,HI_PMU_SET_LDO2_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO2_OFFSET)
HI_SET_GET(hi_pmu_set_ldo3_vset_ldo3,vset_ldo3,HI_PMU_SET_LDO3_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO3_OFFSET)
HI_SET_GET(hi_pmu_set_ldo3_reserved,reserved,HI_PMU_SET_LDO3_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO3_OFFSET)
HI_SET_GET(hi_pmu_set_ldo4_vset_ldo4,vset_ldo4,HI_PMU_SET_LDO4_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO4_OFFSET)
HI_SET_GET(hi_pmu_set_ldo4_reserved,reserved,HI_PMU_SET_LDO4_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO4_OFFSET)
HI_SET_GET(hi_pmu_set_ldo5_vset_ldo5,vset_ldo5,HI_PMU_SET_LDO5_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO5_OFFSET)
HI_SET_GET(hi_pmu_set_ldo5_reserved,reserved,HI_PMU_SET_LDO5_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO5_OFFSET)
HI_SET_GET(hi_pmu_set_ldo6_vset_ldo6,vset_ldo6,HI_PMU_SET_LDO6_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO6_OFFSET)
HI_SET_GET(hi_pmu_set_ldo6_reserved,reserved,HI_PMU_SET_LDO6_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO6_OFFSET)
HI_SET_GET(hi_pmu_set_ldo7_vset_ldo7,vset_ldo7,HI_PMU_SET_LDO7_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO7_OFFSET)
HI_SET_GET(hi_pmu_set_ldo7_reserved,reserved,HI_PMU_SET_LDO7_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO7_OFFSET)
HI_SET_GET(hi_pmu_set_ldo8_vset_ldo8,vset_ldo8,HI_PMU_SET_LDO8_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO8_OFFSET)
HI_SET_GET(hi_pmu_set_ldo8_reserved,reserved,HI_PMU_SET_LDO8_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO8_OFFSET)
HI_SET_GET(hi_pmu_set_ldo9_vset_ldo9,vset_ldo9,HI_PMU_SET_LDO9_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO9_OFFSET)
HI_SET_GET(hi_pmu_set_ldo9_reserved,reserved,HI_PMU_SET_LDO9_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO9_OFFSET)
HI_SET_GET(hi_pmu_set_ldo10_vset_ldo10,vset_ldo10,HI_PMU_SET_LDO10_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO10_OFFSET)
HI_SET_GET(hi_pmu_set_ldo10_reserved,reserved,HI_PMU_SET_LDO10_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO10_OFFSET)
HI_SET_GET(hi_pmu_set_ldo11_vset_ldo11,vset_ldo11,HI_PMU_SET_LDO11_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO11_OFFSET)
HI_SET_GET(hi_pmu_set_ldo11_reserved,reserved,HI_PMU_SET_LDO11_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO11_OFFSET)
HI_SET_GET(hi_pmu_set_ldo13_vset_ldo13,vset_ldo13,HI_PMU_SET_LDO13_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO13_OFFSET)
HI_SET_GET(hi_pmu_set_ldo13_reserved,reserved,HI_PMU_SET_LDO13_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO13_OFFSET)
HI_SET_GET(hi_pmu_set_ldo14_vset_ldo14,vset_ldo14,HI_PMU_SET_LDO14_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO14_OFFSET)
HI_SET_GET(hi_pmu_set_ldo14_reserved,reserved,HI_PMU_SET_LDO14_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO14_OFFSET)
HI_SET_GET(hi_pmu_set_ldo15_vset_ldo15,vset_ldo15,HI_PMU_SET_LDO15_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO15_OFFSET)
HI_SET_GET(hi_pmu_set_ldo15_reserved,reserved,HI_PMU_SET_LDO15_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO15_OFFSET)
HI_SET_GET(hi_pmu_set_ldo17_vset_ldo17,vset_ldo17,HI_PMU_SET_LDO17_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO17_OFFSET)
HI_SET_GET(hi_pmu_set_ldo17_reserved,reserved,HI_PMU_SET_LDO17_T,HI_PMU_BASE_ADDR, HI_PMU_SET_LDO17_OFFSET)
HI_SET_GET(hi_pmu_set_otp_otp_por_pulse,otp_por_pulse,HI_PMU_SET_OTP_T,HI_PMU_BASE_ADDR, HI_PMU_SET_OTP_OFFSET)
HI_SET_GET(hi_pmu_set_otp_otp_read_mask,otp_read_mask,HI_PMU_SET_OTP_T,HI_PMU_BASE_ADDR, HI_PMU_SET_OTP_OFFSET)
HI_SET_GET(hi_pmu_set_otp_otp_pwe_pulse,otp_pwe_pulse,HI_PMU_SET_OTP_T,HI_PMU_BASE_ADDR, HI_PMU_SET_OTP_OFFSET)
HI_SET_GET(hi_pmu_set_otp_otp_write_mask,otp_write_mask,HI_PMU_SET_OTP_T,HI_PMU_BASE_ADDR, HI_PMU_SET_OTP_OFFSET)
HI_SET_GET(hi_pmu_set_otp_reserved,reserved,HI_PMU_SET_OTP_T,HI_PMU_BASE_ADDR, HI_PMU_SET_OTP_OFFSET)
HI_SET_GET(hi_pmu_dr1_mode_iset_dr1,iset_dr1,HI_PMU_DR1_MODE_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_MODE_OFFSET)
HI_SET_GET(hi_pmu_dr1_mode_en_dr1_int,en_dr1_int,HI_PMU_DR1_MODE_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_MODE_OFFSET)
HI_SET_GET(hi_pmu_dr1_mode_dr1_mode,dr1_mode,HI_PMU_DR1_MODE_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_MODE_OFFSET)
HI_SET_GET(hi_pmu_dr1_mode_reserved,reserved,HI_PMU_DR1_MODE_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_MODE_OFFSET)
HI_SET_GET(hi_pmu_dr2_mode_iset_dr2,iset_dr2,HI_PMU_DR2_MODE_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_MODE_OFFSET)
HI_SET_GET(hi_pmu_dr2_mode_en_dr2_int,en_dr2_int,HI_PMU_DR2_MODE_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_MODE_OFFSET)
HI_SET_GET(hi_pmu_dr2_mode_dr2_mode,dr2_mode,HI_PMU_DR2_MODE_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_MODE_OFFSET)
HI_SET_GET(hi_pmu_dr2_mode_reserved,reserved,HI_PMU_DR2_MODE_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_MODE_OFFSET)
HI_SET_GET(hi_pmu_dr3_mode_iset_dr3,iset_dr3,HI_PMU_DR3_MODE_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_MODE_OFFSET)
HI_SET_GET(hi_pmu_dr3_mode_en_dr3_int,en_dr3_int,HI_PMU_DR3_MODE_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_MODE_OFFSET)
HI_SET_GET(hi_pmu_dr3_mode_dr3_mode,dr3_mode,HI_PMU_DR3_MODE_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_MODE_OFFSET)
HI_SET_GET(hi_pmu_dr3_mode_reserved,reserved,HI_PMU_DR3_MODE_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_MODE_OFFSET)
HI_SET_GET(hi_pmu_flash_period_flash_period,flash_period,HI_PMU_FLASH_PERIOD_T,HI_PMU_BASE_ADDR, HI_PMU_FLASH_PERIOD_OFFSET)
HI_SET_GET(hi_pmu_flash_on_flash_on,flash_on,HI_PMU_FLASH_ON_T,HI_PMU_BASE_ADDR, HI_PMU_FLASH_ON_OFFSET)
HI_SET_GET(hi_pmu_periph_ctrl1_ocp_auto_off,ocp_auto_off,HI_PMU_PERIPH_CTRL1_T,HI_PMU_BASE_ADDR, HI_PMU_PERIPH_CTRL1_OFFSET)
HI_SET_GET(hi_pmu_periph_ctrl1_ocp_shut_down_ctrl,ocp_shut_down_ctrl,HI_PMU_PERIPH_CTRL1_T,HI_PMU_BASE_ADDR, HI_PMU_PERIPH_CTRL1_OFFSET)
HI_SET_GET(hi_pmu_periph_ctrl1_ocp_deb_sel,ocp_deb_sel,HI_PMU_PERIPH_CTRL1_T,HI_PMU_BASE_ADDR, HI_PMU_PERIPH_CTRL1_OFFSET)
HI_SET_GET(hi_pmu_periph_ctrl1_en_buck_ocp_debounce,en_buck_ocp_debounce,HI_PMU_PERIPH_CTRL1_T,HI_PMU_BASE_ADDR, HI_PMU_PERIPH_CTRL1_OFFSET)
HI_SET_GET(hi_pmu_periph_ctrl1_en_ldo_ocp_debounce,en_ldo_ocp_debounce,HI_PMU_PERIPH_CTRL1_T,HI_PMU_BASE_ADDR, HI_PMU_PERIPH_CTRL1_OFFSET)
HI_SET_GET(hi_pmu_periph_ctrl1_lim_mode_int,lim_mode_int,HI_PMU_PERIPH_CTRL1_T,HI_PMU_BASE_ADDR, HI_PMU_PERIPH_CTRL1_OFFSET)
HI_SET_GET(hi_pmu_periph_ctrl1_reserved,reserved,HI_PMU_PERIPH_CTRL1_T,HI_PMU_BASE_ADDR, HI_PMU_PERIPH_CTRL1_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_irq1_hrst_otmp_d3,hrst_otmp_d3,HI_PMU_NO_PWR_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_irq1_hrst_hreset_n_f,hrst_hreset_n_f,HI_PMU_NO_PWR_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_irq1_hrst_pwr_ini_2p7_d3f,hrst_pwr_ini_2p7_d3f,HI_PMU_NO_PWR_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_irq1_hrst_pwr_ini_6p0_d3r,hrst_pwr_ini_6p0_d3r,HI_PMU_NO_PWR_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_irq1_hrst_pwr_ini_6p0_d100r,hrst_pwr_ini_6p0_d100r,HI_PMU_NO_PWR_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_irq1_hrst_pwron_d1sr,hrst_pwron_d1sr,HI_PMU_NO_PWR_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_irq1_hrst_pwron_d20f,hrst_pwron_d20f,HI_PMU_NO_PWR_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_irq1_hrst_pwron_d20r,hrst_pwron_d20r,HI_PMU_NO_PWR_IRQ1_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_IRQ1_OFFSET)
HI_SET_GET(hi_pmu_no_pwr__irq2_hrst_ocp_total,hrst_ocp_total,HI_PMU_NO_PWR__IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR__IRQ2_OFFSET)
HI_SET_GET(hi_pmu_no_pwr__irq2_hrst_vin_ldo_l_2p5_d3r,hrst_vin_ldo_l_2p5_d3r,HI_PMU_NO_PWR__IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR__IRQ2_OFFSET)
HI_SET_GET(hi_pmu_no_pwr__irq2_hrst_usb_4p0_d3f,hrst_usb_4p0_d3f,HI_PMU_NO_PWR__IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR__IRQ2_OFFSET)
HI_SET_GET(hi_pmu_no_pwr__irq2_hrst_usb_4p0_d3r,hrst_usb_4p0_d3r,HI_PMU_NO_PWR__IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR__IRQ2_OFFSET)
HI_SET_GET(hi_pmu_no_pwr__irq2_hrst_usb_6p0_d3r,hrst_usb_6p0_d3r,HI_PMU_NO_PWR__IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR__IRQ2_OFFSET)
HI_SET_GET(hi_pmu_no_pwr__irq2_hrst_vbus_4p0_d3f,hrst_vbus_4p0_d3f,HI_PMU_NO_PWR__IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR__IRQ2_OFFSET)
HI_SET_GET(hi_pmu_no_pwr__irq2_hrst_vbus_6p0_d3r,hrst_vbus_6p0_d3r,HI_PMU_NO_PWR__IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR__IRQ2_OFFSET)
HI_SET_GET(hi_pmu_no_pwr__irq2_hrst_vbus_6p0_d100r,hrst_vbus_6p0_d100r,HI_PMU_NO_PWR__IRQ2_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR__IRQ2_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_irq3_hrst_alarm_on_expenda,hrst_alarm_on_expenda,HI_PMU_NO_PWR_IRQ3_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_IRQ3_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_irq3_hrst_alarm_on_expendb,hrst_alarm_on_expendb,HI_PMU_NO_PWR_IRQ3_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_IRQ3_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_irq3_hrst_alarm_on_expendc,hrst_alarm_on_expendc,HI_PMU_NO_PWR_IRQ3_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_IRQ3_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_irq3_reserved,reserved,HI_PMU_NO_PWR_IRQ3_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_IRQ3_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_reg_rwc_otmp150_d3r,otmp150_d3r,HI_PMU_NO_PWR_REG_RWC_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_REG_RWC_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_reg_rwc_ilim_sht_pro_d3r,ilim_sht_pro_d3r,HI_PMU_NO_PWR_REG_RWC_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_REG_RWC_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_reg_rwc_reserved,reserved,HI_PMU_NO_PWR_REG_RWC_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_REG_RWC_OFFSET)
HI_SET_GET(hi_pmu_no_rwr_reg_rw_leak_ctl,leak_ctl,HI_PMU_NO_RWR_REG_RW_T,HI_PMU_BASE_ADDR, HI_PMU_NO_RWR_REG_RW_OFFSET)
HI_SET_GET(hi_pmu_no_rwr_reg_rw_rc_off,rc_off,HI_PMU_NO_RWR_REG_RW_T,HI_PMU_BASE_ADDR, HI_PMU_NO_RWR_REG_RW_OFFSET)
HI_SET_GET(hi_pmu_no_rwr_reg_rw_dr_fla_bre_ctrl,dr_fla_bre_ctrl,HI_PMU_NO_RWR_REG_RW_T,HI_PMU_BASE_ADDR, HI_PMU_NO_RWR_REG_RW_OFFSET)
HI_SET_GET(hi_pmu_no_rwr_reg_rw_reserved,reserved,HI_PMU_NO_RWR_REG_RW_T,HI_PMU_BASE_ADDR, HI_PMU_NO_RWR_REG_RW_OFFSET)
HI_SET_GET(hi_pmu_ana_in_ana_in_2d,ana_in_2d,HI_PMU_ANA_IN_T,HI_PMU_BASE_ADDR, HI_PMU_ANA_IN_OFFSET)
HI_SET_GET(hi_pmu_reserved0_reserved0,reserved0,HI_PMU_RESERVED0_T,HI_PMU_BASE_ADDR, HI_PMU_RESERVED0_OFFSET)
HI_SET_GET(hi_pmu_reserved1_reserved1,reserved1,HI_PMU_RESERVED1_T,HI_PMU_BASE_ADDR, HI_PMU_RESERVED1_OFFSET)
HI_SET_GET(hi_pmu_reserved2_reserved2,reserved2,HI_PMU_RESERVED2_T,HI_PMU_BASE_ADDR, HI_PMU_RESERVED2_OFFSET)
HI_SET_GET(hi_pmu_clim_adj_clim_ctl,clim_ctl,HI_PMU_CLIM_ADJ_T,HI_PMU_BASE_ADDR, HI_PMU_CLIM_ADJ_OFFSET)
HI_SET_GET(hi_pmu_clim_adj_clim_vth,clim_vth,HI_PMU_CLIM_ADJ_T,HI_PMU_BASE_ADDR, HI_PMU_CLIM_ADJ_OFFSET)
HI_SET_GET(hi_pmu_clim_adj_clim_op_isel,clim_op_isel,HI_PMU_CLIM_ADJ_T,HI_PMU_BASE_ADDR, HI_PMU_CLIM_ADJ_OFFSET)
HI_SET_GET(hi_pmu_lit_cur_set_lit_cur_set,lit_cur_set,HI_PMU_LIT_CUR_SET_T,HI_PMU_BASE_ADDR, HI_PMU_LIT_CUR_SET_OFFSET)
HI_SET_GET(hi_pmu_lit_cur_set_pro_mode,pro_mode,HI_PMU_LIT_CUR_SET_T,HI_PMU_BASE_ADDR, HI_PMU_LIT_CUR_SET_OFFSET)
HI_SET_GET(hi_pmu_lit_cur_set_vs,vs,HI_PMU_LIT_CUR_SET_T,HI_PMU_BASE_ADDR, HI_PMU_LIT_CUR_SET_OFFSET)
HI_SET_GET(hi_pmu_lit_cur_set_reserved,reserved,HI_PMU_LIT_CUR_SET_T,HI_PMU_BASE_ADDR, HI_PMU_LIT_CUR_SET_OFFSET)
HI_SET_GET(hi_pmu_otp_ctrl_otp_pwe_int,otp_pwe_int,HI_PMU_OTP_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_OTP_CTRL_OFFSET)
HI_SET_GET(hi_pmu_otp_ctrl_otp_por_int,otp_por_int,HI_PMU_OTP_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_OTP_CTRL_OFFSET)
HI_SET_GET(hi_pmu_otp_ctrl_otp_pa,otp_pa,HI_PMU_OTP_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_OTP_CTRL_OFFSET)
HI_SET_GET(hi_pmu_otp_ctrl_otp_ptm,otp_ptm,HI_PMU_OTP_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_OTP_CTRL_OFFSET)
HI_SET_GET(hi_pmu_otp_ctrl_otp_pprog,otp_pprog,HI_PMU_OTP_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_OTP_CTRL_OFFSET)
HI_SET_GET(hi_pmu_otp_ctrl_reserved,reserved,HI_PMU_OTP_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_OTP_CTRL_OFFSET)
HI_SET_GET(hi_pmu_otp_pdin_otp_pdin,otp_pdin,HI_PMU_OTP_PDIN_T,HI_PMU_BASE_ADDR, HI_PMU_OTP_PDIN_OFFSET)
HI_SET_GET(hi_pmu_otp_pdob0_otp_pdob0,otp_pdob0,HI_PMU_OTP_PDOB0_T,HI_PMU_BASE_ADDR, HI_PMU_OTP_PDOB0_OFFSET)
HI_SET_GET(hi_pmu_otp_pdob1_otp_pdob1,otp_pdob1,HI_PMU_OTP_PDOB1_T,HI_PMU_BASE_ADDR, HI_PMU_OTP_PDOB1_OFFSET)
HI_SET_GET(hi_pmu_otp_pdob2_otp_pdob2,otp_pdob2,HI_PMU_OTP_PDOB2_T,HI_PMU_BASE_ADDR, HI_PMU_OTP_PDOB2_OFFSET)
HI_SET_GET(hi_pmu_otp_pdob3_otp_pdob3,otp_pdob3,HI_PMU_OTP_PDOB3_T,HI_PMU_BASE_ADDR, HI_PMU_OTP_PDOB3_OFFSET)
HI_SET_GET(hi_pmu_bandgap_reg_sleep_bandgap,sleep_bandgap,HI_PMU_BANDGAP_REG_T,HI_PMU_BASE_ADDR, HI_PMU_BANDGAP_REG_OFFSET)
HI_SET_GET(hi_pmu_bandgap_reg_v0p59_sel,v0p59_sel,HI_PMU_BANDGAP_REG_T,HI_PMU_BASE_ADDR, HI_PMU_BANDGAP_REG_OFFSET)
HI_SET_GET(hi_pmu_bandgap_reg_sleep_ctrl1,sleep_ctrl1,HI_PMU_BANDGAP_REG_T,HI_PMU_BASE_ADDR, HI_PMU_BANDGAP_REG_OFFSET)
HI_SET_GET(hi_pmu_bandgap_reg_sleep_ctrl2,sleep_ctrl2,HI_PMU_BANDGAP_REG_T,HI_PMU_BASE_ADDR, HI_PMU_BANDGAP_REG_OFFSET)
HI_SET_GET(hi_pmu_bandgap_reg_reserved,reserved,HI_PMU_BANDGAP_REG_T,HI_PMU_BASE_ADDR, HI_PMU_BANDGAP_REG_OFFSET)
HI_SET_GET(hi_pmu_det_sd_level_cmd_cmd_sd_2d,cmd_sd_2d,HI_PMU_DET_SD_LEVEL_CMD_T,HI_PMU_BASE_ADDR, HI_PMU_DET_SD_LEVEL_CMD_OFFSET)
HI_SET_GET(hi_pmu_det_sd_level_cmd_reserved,reserved,HI_PMU_DET_SD_LEVEL_CMD_T,HI_PMU_BASE_ADDR, HI_PMU_DET_SD_LEVEL_CMD_OFFSET)
HI_SET_GET(hi_pmu_det_sd_level_status_state_sd_2d,state_sd_2d,HI_PMU_DET_SD_LEVEL_STATUS_T,HI_PMU_BASE_ADDR, HI_PMU_DET_SD_LEVEL_STATUS_OFFSET)
HI_SET_GET(hi_pmu_det_sd_level_status_reserved,reserved,HI_PMU_DET_SD_LEVEL_STATUS_T,HI_PMU_BASE_ADDR, HI_PMU_DET_SD_LEVEL_STATUS_OFFSET)
HI_SET_GET(hi_pmu_rtcdr0_rtcdr0,rtcdr0,HI_PMU_RTCDR0_T,HI_PMU_BASE_ADDR, HI_PMU_RTCDR0_OFFSET)
HI_SET_GET(hi_pmu_rtcdr1_rtcdr1,rtcdr1,HI_PMU_RTCDR1_T,HI_PMU_BASE_ADDR, HI_PMU_RTCDR1_OFFSET)
HI_SET_GET(hi_pmu_rtcdr2_rtcdr2,rtcdr2,HI_PMU_RTCDR2_T,HI_PMU_BASE_ADDR, HI_PMU_RTCDR2_OFFSET)
HI_SET_GET(hi_pmu_rtcdr3_rtcdr3,rtcdr3,HI_PMU_RTCDR3_T,HI_PMU_BASE_ADDR, HI_PMU_RTCDR3_OFFSET)
HI_SET_GET(hi_pmu_rtclr0_rtcclr0,rtcclr0,HI_PMU_RTCLR0_T,HI_PMU_BASE_ADDR, HI_PMU_RTCLR0_OFFSET)
HI_SET_GET(hi_pmu_rtclr1_rtcclr1,rtcclr1,HI_PMU_RTCLR1_T,HI_PMU_BASE_ADDR, HI_PMU_RTCLR1_OFFSET)
HI_SET_GET(hi_pmu_rtclr2_rtcclr2,rtcclr2,HI_PMU_RTCLR2_T,HI_PMU_BASE_ADDR, HI_PMU_RTCLR2_OFFSET)
HI_SET_GET(hi_pmu_rtclr3_rtcclr3,rtcclr3,HI_PMU_RTCLR3_T,HI_PMU_BASE_ADDR, HI_PMU_RTCLR3_OFFSET)
HI_SET_GET(hi_pmu_rtcctrl_rtccr,rtccr,HI_PMU_RTCCTRL_T,HI_PMU_BASE_ADDR, HI_PMU_RTCCTRL_OFFSET)
HI_SET_GET(hi_pmu_rtcctrl_reserved,reserved,HI_PMU_RTCCTRL_T,HI_PMU_BASE_ADDR, HI_PMU_RTCCTRL_OFFSET)
HI_SET_GET(hi_pmu_rtcmra0_rtcmra0,rtcmra0,HI_PMU_RTCMRA0_T,HI_PMU_BASE_ADDR, HI_PMU_RTCMRA0_OFFSET)
HI_SET_GET(hi_pmu_rtcmra1_rtcmra1,rtcmra1,HI_PMU_RTCMRA1_T,HI_PMU_BASE_ADDR, HI_PMU_RTCMRA1_OFFSET)
HI_SET_GET(hi_pmu_rtcmra2_rtcmra2,rtcmra2,HI_PMU_RTCMRA2_T,HI_PMU_BASE_ADDR, HI_PMU_RTCMRA2_OFFSET)
HI_SET_GET(hi_pmu_rtcmra3_rtcmra3,rtcmra3,HI_PMU_RTCMRA3_T,HI_PMU_BASE_ADDR, HI_PMU_RTCMRA3_OFFSET)
HI_SET_GET(hi_pmu_rtcmrb0_rtcmrb0,rtcmrb0,HI_PMU_RTCMRB0_T,HI_PMU_BASE_ADDR, HI_PMU_RTCMRB0_OFFSET)
HI_SET_GET(hi_pmu_rtcmrb1_rtcmrb1,rtcmrb1,HI_PMU_RTCMRB1_T,HI_PMU_BASE_ADDR, HI_PMU_RTCMRB1_OFFSET)
HI_SET_GET(hi_pmu_rtcmrb2_rtcmrb2,rtcmrb2,HI_PMU_RTCMRB2_T,HI_PMU_BASE_ADDR, HI_PMU_RTCMRB2_OFFSET)
HI_SET_GET(hi_pmu_rtcmrb3_rtcmrb3,rtcmrb3,HI_PMU_RTCMRB3_T,HI_PMU_BASE_ADDR, HI_PMU_RTCMRB3_OFFSET)
HI_SET_GET(hi_pmu_rtcmrc0_rtcmrc0,rtcmrc0,HI_PMU_RTCMRC0_T,HI_PMU_BASE_ADDR, HI_PMU_RTCMRC0_OFFSET)
HI_SET_GET(hi_pmu_rtcmrc1_rtcmrc1,rtcmrc1,HI_PMU_RTCMRC1_T,HI_PMU_BASE_ADDR, HI_PMU_RTCMRC1_OFFSET)
HI_SET_GET(hi_pmu_rtcmrc2_rtcmrc2,rtcmrc2,HI_PMU_RTCMRC2_T,HI_PMU_BASE_ADDR, HI_PMU_RTCMRC2_OFFSET)
HI_SET_GET(hi_pmu_rtcmrc3_rtcmrc3,rtcmrc3,HI_PMU_RTCMRC3_T,HI_PMU_BASE_ADDR, HI_PMU_RTCMRC3_OFFSET)
HI_SET_GET(hi_pmu_rtc_adj1_rtc_clk_setp_adj1,rtc_clk_setp_adj1,HI_PMU_RTC_ADJ1_T,HI_PMU_BASE_ADDR, HI_PMU_RTC_ADJ1_OFFSET)
HI_SET_GET(hi_pmu_rtc_adj2_rtc_clk_setp_adj2,rtc_clk_setp_adj2,HI_PMU_RTC_ADJ2_T,HI_PMU_BASE_ADDR, HI_PMU_RTC_ADJ2_OFFSET)
HI_SET_GET(hi_pmu_reserved3_reserved3,reserved3,HI_PMU_RESERVED3_T,HI_PMU_BASE_ADDR, HI_PMU_RESERVED3_OFFSET)
HI_SET_GET(hi_pmu_reserved4_reserved4,reserved4,HI_PMU_RESERVED4_T,HI_PMU_BASE_ADDR, HI_PMU_RESERVED4_OFFSET)
HI_SET_GET(hi_pmu_reserved5_reserved5,reserved5,HI_PMU_RESERVED5_T,HI_PMU_BASE_ADDR, HI_PMU_RESERVED5_OFFSET)
HI_SET_GET(hi_pmu_reserved6_reserved6,reserved6,HI_PMU_RESERVED6_T,HI_PMU_BASE_ADDR, HI_PMU_RESERVED6_OFFSET)
HI_SET_GET(hi_pmu_reserved7_reserved7,reserved7,HI_PMU_RESERVED7_T,HI_PMU_BASE_ADDR, HI_PMU_RESERVED7_OFFSET)
HI_SET_GET(hi_pmu_reserved8_reserved8,reserved8,HI_PMU_RESERVED8_T,HI_PMU_BASE_ADDR, HI_PMU_RESERVED8_OFFSET)
HI_SET_GET(hi_pmu_onoff10_sht_pro_off_ctrl,sht_pro_off_ctrl,HI_PMU_ONOFF10_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF10_OFFSET)
HI_SET_GET(hi_pmu_onoff10_reserved,reserved,HI_PMU_ONOFF10_T,HI_PMU_BASE_ADDR, HI_PMU_ONOFF10_OFFSET)
HI_SET_GET(hi_pmu_dr1_bre_ctrl_dr1_en_bre,dr1_en_bre,HI_PMU_DR1_BRE_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_BRE_CTRL_OFFSET)
HI_SET_GET(hi_pmu_dr1_bre_ctrl_dr1_flash_en,dr1_flash_en,HI_PMU_DR1_BRE_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_BRE_CTRL_OFFSET)
HI_SET_GET(hi_pmu_dr1_bre_ctrl_reserved,reserved,HI_PMU_DR1_BRE_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_BRE_CTRL_OFFSET)
HI_SET_GET(hi_pmu_dr1_tim_conf1_dr1_t_off,dr1_t_off,HI_PMU_DR1_TIM_CONF1_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_TIM_CONF1_OFFSET)
HI_SET_GET(hi_pmu_dr1_tim_conf1_reserved_1,reserved_1,HI_PMU_DR1_TIM_CONF1_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_TIM_CONF1_OFFSET)
HI_SET_GET(hi_pmu_dr1_tim_conf1_dr1_t_on,dr1_t_on,HI_PMU_DR1_TIM_CONF1_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_TIM_CONF1_OFFSET)
HI_SET_GET(hi_pmu_dr1_tim_conf1_reserved_0,reserved_0,HI_PMU_DR1_TIM_CONF1_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_TIM_CONF1_OFFSET)
HI_SET_GET(hi_pmu_dr1_tim_conf2_dr1_t_rise,dr1_t_rise,HI_PMU_DR1_TIM_CONF2_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_TIM_CONF2_OFFSET)
HI_SET_GET(hi_pmu_dr1_tim_conf2_reserved_1,reserved_1,HI_PMU_DR1_TIM_CONF2_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_TIM_CONF2_OFFSET)
HI_SET_GET(hi_pmu_dr1_tim_conf2_dr1_t_fall,dr1_t_fall,HI_PMU_DR1_TIM_CONF2_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_TIM_CONF2_OFFSET)
HI_SET_GET(hi_pmu_dr1_tim_conf2_reserved_0,reserved_0,HI_PMU_DR1_TIM_CONF2_T,HI_PMU_BASE_ADDR, HI_PMU_DR1_TIM_CONF2_OFFSET)
HI_SET_GET(hi_pmu_dr2_bre_ctrl_dr2_en_bre,dr2_en_bre,HI_PMU_DR2_BRE_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_BRE_CTRL_OFFSET)
HI_SET_GET(hi_pmu_dr2_bre_ctrl_dr2_flash_en,dr2_flash_en,HI_PMU_DR2_BRE_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_BRE_CTRL_OFFSET)
HI_SET_GET(hi_pmu_dr2_bre_ctrl_reserved,reserved,HI_PMU_DR2_BRE_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_BRE_CTRL_OFFSET)
HI_SET_GET(hi_pmu_dr2_tim_conf1_dr2_t_off,dr2_t_off,HI_PMU_DR2_TIM_CONF1_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_TIM_CONF1_OFFSET)
HI_SET_GET(hi_pmu_dr2_tim_conf1_reserved_1,reserved_1,HI_PMU_DR2_TIM_CONF1_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_TIM_CONF1_OFFSET)
HI_SET_GET(hi_pmu_dr2_tim_conf1_dr2_t_on,dr2_t_on,HI_PMU_DR2_TIM_CONF1_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_TIM_CONF1_OFFSET)
HI_SET_GET(hi_pmu_dr2_tim_conf1_reserved_0,reserved_0,HI_PMU_DR2_TIM_CONF1_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_TIM_CONF1_OFFSET)
HI_SET_GET(hi_pmu_dr2_tim_conf2_dr2_t_rise,dr2_t_rise,HI_PMU_DR2_TIM_CONF2_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_TIM_CONF2_OFFSET)
HI_SET_GET(hi_pmu_dr2_tim_conf2_reserved_1,reserved_1,HI_PMU_DR2_TIM_CONF2_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_TIM_CONF2_OFFSET)
HI_SET_GET(hi_pmu_dr2_tim_conf2_dr2_t_fall,dr2_t_fall,HI_PMU_DR2_TIM_CONF2_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_TIM_CONF2_OFFSET)
HI_SET_GET(hi_pmu_dr2_tim_conf2_reserved_0,reserved_0,HI_PMU_DR2_TIM_CONF2_T,HI_PMU_BASE_ADDR, HI_PMU_DR2_TIM_CONF2_OFFSET)
HI_SET_GET(hi_pmu_dr3_bre_ctrl_d3_en,d3_en,HI_PMU_DR3_BRE_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_BRE_CTRL_OFFSET)
HI_SET_GET(hi_pmu_dr3_bre_ctrl_dr3_flash_en,dr3_flash_en,HI_PMU_DR3_BRE_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_BRE_CTRL_OFFSET)
HI_SET_GET(hi_pmu_dr3_bre_ctrl_reserved,reserved,HI_PMU_DR3_BRE_CTRL_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_BRE_CTRL_OFFSET)
HI_SET_GET(hi_pmu_dr3_tim_conf1_dr3_t_off,dr3_t_off,HI_PMU_DR3_TIM_CONF1_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_TIM_CONF1_OFFSET)
HI_SET_GET(hi_pmu_dr3_tim_conf1_reserved_1,reserved_1,HI_PMU_DR3_TIM_CONF1_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_TIM_CONF1_OFFSET)
HI_SET_GET(hi_pmu_dr3_tim_conf1_dr3_t_on,dr3_t_on,HI_PMU_DR3_TIM_CONF1_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_TIM_CONF1_OFFSET)
HI_SET_GET(hi_pmu_dr3_tim_conf1_reserved_0,reserved_0,HI_PMU_DR3_TIM_CONF1_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_TIM_CONF1_OFFSET)
HI_SET_GET(hi_pmu_dr3_tim_conf2_dr3_t_rise,dr3_t_rise,HI_PMU_DR3_TIM_CONF2_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_TIM_CONF2_OFFSET)
HI_SET_GET(hi_pmu_dr3_tim_conf2_reserved_1,reserved_1,HI_PMU_DR3_TIM_CONF2_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_TIM_CONF2_OFFSET)
HI_SET_GET(hi_pmu_dr3_tim_conf2_dr3_t_fall,dr3_t_fall,HI_PMU_DR3_TIM_CONF2_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_TIM_CONF2_OFFSET)
HI_SET_GET(hi_pmu_dr3_tim_conf2_reserved_0,reserved_0,HI_PMU_DR3_TIM_CONF2_T,HI_PMU_BASE_ADDR, HI_PMU_DR3_TIM_CONF2_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_rsved1_no_pwr_resved1,no_pwr_resved1,HI_PMU_NO_PWR_RSVED1_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_RSVED1_OFFSET)
HI_SET_GET(hi_pmu_no_pwr_rsved2_no_pwr_resved2,no_pwr_resved2,HI_PMU_NO_PWR_RSVED2_T,HI_PMU_BASE_ADDR, HI_PMU_NO_PWR_RSVED2_OFFSET)
#endif
