#ifndef __HI_SYSSC_H__
#define __HI_SYSSC_H__ 
#ifndef HI_SET_GET
#define HI_SET_GET(a0,a1,a2,a3,a4) 
#endif
#define HI_CRG_CLKEN3_OFFSET (0x18)
#define HI_CRG_CLKDIS3_OFFSET (0x1C)
#define HI_CRG_CLKSTAT3_OFFSET (0x20)
#define HI_CRG_CLKEN4_OFFSET (0x24)
#define HI_CRG_CLKDIS4_OFFSET (0x28)
#define HI_CRG_CLKSTAT4_OFFSET (0x2C)
#define HI_CRG_CLKEN5_OFFSET (0x30)
#define HI_CRG_CLKDIS5_OFFSET (0x34)
#define HI_CRG_CLKSTAT5_OFFSET (0x38)
#define HI_CRG_SRSTEN1_OFFSET (0x60)
#define HI_CRG_SRSTDIS1_OFFSET (0x64)
#define HI_CRG_SRSTSTAT1_OFFSET (0x68)
#define HI_CRG_SRSTEN3_OFFSET (0x78)
#define HI_CRG_SRSTDIS3_OFFSET (0x7C)
#define HI_CRG_SRSTSTAT3_OFFSET (0x80)
#define HI_CRG_CLKDIV2_OFFSET (0x104)
#define HI_CRG_CLKDIV5_OFFSET (0x110)
#define HI_CRG_CLK_SEL2_OFFSET (0x144)
#define HI_CRG_CLK_SEL3_OFFSET (0x148)
#define HI_CRG_A9PLL_CFG0_OFFSET (0x200)
#define HI_CRG_A9PLL_CFG1_OFFSET (0x204)
#define HI_CRG_A9PLL_CFG2_OFFSET (0x208)
#define HI_CRG_DSPPLL_CFG0_OFFSET (0x20C)
#define HI_CRG_DSPPLL_CFG1_OFFSET (0x210)
#define HI_CRG_DSPPLL_CFG2_OFFSET (0x214)
#define HI_CRG_BBPPLL_CFG0_OFFSET (0x224)
#define HI_CRG_BBPPLL_CFG1_OFFSET (0x228)
#define HI_CRG_BBPPLL_CFG2_OFFSET (0x22C)
#define HI_SC_CTRL0_OFFSET (0x400)
#define HI_SC_CTRL2_OFFSET (0x408)
#define HI_SC_CTRL3_OFFSET (0x40C)
#define HI_SC_CTRL4_OFFSET (0x410)
#define HI_SC_CTRL5_OFFSET (0x414)
#define HI_SC_CTRL6_OFFSET (0x418)
#define HI_SC_CTRL9_OFFSET (0x424)
#define HI_SC_CTRL10_OFFSET (0x428)
#define HI_SC_CTRL11_OFFSET (0x42C)
#define HI_SC_CTRL12_OFFSET (0x430)
#define HI_SC_CTRL13_OFFSET (0x434)
#define HI_SC_CTRL17_OFFSET (0x444)
#define HI_SC_CTRL20_OFFSET (0x450)
#define HI_SC_CTRL21_OFFSET (0x454)
#define HI_SC_CTRL22_OFFSET (0x458)
#define HI_SC_CTRL23_OFFSET (0x45C)
#define HI_SC_CTRL24_OFFSET (0x460)
#define HI_SC_CTRL25_OFFSET (0x464)
#define HI_SC_CTRL26_OFFSET (0x468)
#define HI_SC_CTRL28_OFFSET (0x470)
#define HI_SC_CTRL29_OFFSET (0x474)
#define HI_SC_CTRL30_OFFSET (0x478)
#define HI_SC_CTRL45_OFFSET (0x4B4)
#define HI_SC_CTRL52_OFFSET (0x4D0)
#define HI_SC_CTRL55_OFFSET (0x4DC)
#define HI_SC_CTRL56_OFFSET (0x4E0)
#define HI_SC_CTRL57_OFFSET (0x4E4)
#define HI_SC_CTRL68_OFFSET (0x510)
#define HI_SC_CTRL69_OFFSET (0x514)
#define HI_SC_CTRL70_OFFSET (0x518)
#define HI_SC_CTRL71_OFFSET (0x51C)
#define HI_SC_CTRL72_OFFSET (0x520)
#define HI_SC_CTRL73_OFFSET (0x524)
#define HI_SC_CTRL74_OFFSET (0x528)
#define HI_SC_CTRL75_OFFSET (0x52C)
#define HI_SC_CTRL76_OFFSET (0x530)
#define HI_SC_CTRL77_OFFSET (0x534)
#define HI_SC_CTRL78_OFFSET (0x538)
#define HI_SC_CTRL79_OFFSET (0x53C)
#define HI_SC_CTRL80_OFFSET (0x540)
#define HI_SC_CTRL103_OFFSET (0x59C)
#define HI_SC_CTRL104_OFFSET (0x5A0)
#define HI_SC_CTRL105_OFFSET (0x5A4)
#define HI_SC_STAT1_OFFSET (0x604)
#define HI_SC_STAT2_OFFSET (0x608)
#define HI_SC_STAT3_OFFSET (0x60C)
#define HI_SC_STAT5_OFFSET (0x614)
#define HI_SC_STAT6_OFFSET (0x618)
#define HI_SC_STAT9_OFFSET (0x624)
#define HI_SC_STAT10_OFFSET (0x628)
#define HI_SC_STAT15_OFFSET (0x63C)
#define HI_SC_STAT22_OFFSET (0x658)
#define HI_SC_STAT26_OFFSET (0x668)
#define HI_SC_STAT27_OFFSET (0x66C)
#define HI_SC_STAT29_OFFSET (0x674)
#define HI_SC_STAT32_OFFSET (0x680)
#define HI_SC_STAT35_OFFSET (0x68C)
#define HI_SC_STAT36_OFFSET (0x690)
#define HI_SC_STAT37_OFFSET (0x694)
#define HI_SC_STAT38_OFFSET (0x698)
#define HI_SC_STAT41_OFFSET (0x6A4)
#define HI_SC_STAT42_OFFSET (0x6A8)
#define HI_SC_STAT43_OFFSET (0x6AC)
#define HI_SC_STAT44_OFFSET (0x6B0)
#define HI_SC_STAT46_OFFSET (0x6B8)
#define HI_SC_STAT47_OFFSET (0x6BC)
#define HI_SC_STAT48_OFFSET (0x6C0)
#define HI_SC_STAT49_OFFSET (0x6C4)
#define HI_SC_STAT50_OFFSET (0x6C8)
#define HI_SC_STAT51_OFFSET (0x6CC)
#define HI_SC_STAT52_OFFSET (0x6D0)
#define HI_SC_STAT53_OFFSET (0x6D4)
#define HI_SC_STAT54_OFFSET (0x6D8)
#define HI_SC_STAT55_OFFSET (0x6DC)
#define HI_SC_STAT56_OFFSET (0x6E0)
#define HI_SC_STAT57_OFFSET (0x6E4)
#define HI_SC_STAT62_OFFSET (0x6F8)
#define HI_SC_STAT63_OFFSET (0x6FC)
#define HI_SC_STAT64_OFFSET (0x700)
#define HI_SC_STAT65_OFFSET (0x704)
#define HI_SC_STAT66_OFFSET (0x708)
#define HI_SC_STAT67_OFFSET (0x70C)
#define HI_SC_STAT68_OFFSET (0x710)
#define HI_SC_STAT69_OFFSET (0x714)
#define HI_PWR_CTRL2_OFFSET (0xC08)
#define HI_PWR_CTRL4_OFFSET (0xC10)
#define HI_PWR_CTRL5_OFFSET (0xC14)
#define HI_PWR_CTRL6_OFFSET (0xC18)
#define HI_PWR_CTRL7_OFFSET (0xC1C)
#define HI_PWR_STAT1_OFFSET (0xE04)
#define HI_PWR_STAT3_OFFSET (0xE0C)
#define HI_PWR_STAT4_OFFSET (0xE10)
#define HI_SEC_CTRL0_OFFSET (0xF04)
#define HI_SEC_CTRL1_OFFSET (0xF08)
#define HI_SEC_CTRL2_OFFSET (0xF0C)
#define HI_SEC_CTRL3_OFFSET (0xF10)
#define HI_SEC_CTRL4_OFFSET (0xF14)
#define HI_SEC_CTRL5_OFFSET (0xF18)
#ifndef __ASSEMBLY__
typedef union
{
    struct
    {
        unsigned int reserved_1 : 24;
        unsigned int bbe_refclk_en : 1;
        unsigned int a9_refclk_en : 1;
        unsigned int hpm_clk_en : 1;
        unsigned int reserved_0 : 5;
    } bits;
    unsigned int u32;
}HI_CRG_CLKEN3_T;
typedef union
{
    struct
    {
        unsigned int reserved_1 : 24;
        unsigned int bbe_refclk_dis : 1;
        unsigned int a9_refclk_dis : 1;
        unsigned int hpm_clk_dis : 1;
        unsigned int reserved_0 : 5;
    } bits;
    unsigned int u32;
}HI_CRG_CLKDIS3_T;
typedef union
{
    struct
    {
        unsigned int reserved_1 : 24;
        unsigned int bbe_refclk_status : 1;
        unsigned int a9_refclk_status : 1;
        unsigned int hpm_clk_status : 1;
        unsigned int reserved_0 : 5;
    } bits;
    unsigned int u32;
}HI_CRG_CLKSTAT3_T;
typedef union
{
    struct
    {
        unsigned int bbe_pd_clk_en : 1;
        unsigned int bbe_core_clk_en : 1;
        unsigned int reserved_2 : 1;
        unsigned int mcpu_pd_clk_en : 1;
        unsigned int l2c_clk_en : 1;
        unsigned int reserved_1 : 1;
        unsigned int mcpu_mbist_clk_en : 1;
        unsigned int reserved_0 : 1;
        unsigned int cicom0_clk_en : 1;
        unsigned int cicom1_clk_en : 1;
        unsigned int ipf_clk_en : 1;
        unsigned int upacc_clk_en : 1;
        unsigned int sci0_clk_en : 1;
        unsigned int sci1_clk_en : 1;
        unsigned int uicc_clk_en : 1;
        unsigned int uart_clk_en : 1;
        unsigned int bbe_vic_clk_en : 1;
        unsigned int cipher_clk_en : 1;
        unsigned int edmac_clk_en : 1;
        unsigned int ipcm_clk_en : 1;
        unsigned int hsuart_clk_en : 1;
        unsigned int aximem_clk_en : 1;
        unsigned int aximon_clk_en : 1;
        unsigned int timer_clk_en : 8;
        unsigned int wdog_clk_en : 1;
    } bits;
    unsigned int u32;
}HI_CRG_CLKEN4_T;
typedef union
{
    struct
    {
        unsigned int dsp0_pd_clk_dis : 1;
        unsigned int dsp0_core_clk_dis : 1;
        unsigned int dsp0_dbg_clk_dis : 1;
        unsigned int mcpu_pd_clk_dis : 1;
        unsigned int l2c_clk_dis : 1;
        unsigned int mcpu_dbg_clk_dis : 1;
        unsigned int mcpu_mbist_clk_dis : 1;
        unsigned int reserved : 1;
        unsigned int cicom0_clk_dis : 1;
        unsigned int cicom1_clk_dis : 1;
        unsigned int ipf_clk_dis : 1;
        unsigned int upacc_clk_dis : 1;
        unsigned int sci0_clk_dis : 1;
        unsigned int sci1_clk_dis : 1;
        unsigned int uicc_clk_dis : 1;
        unsigned int uart_clk_dis : 1;
        unsigned int bbe_vic_clk_dis : 1;
        unsigned int cipher_clk_dis : 1;
        unsigned int edmac_clk_dis : 1;
        unsigned int ipcm_clk_dis : 1;
        unsigned int hsuart_clk_dis : 1;
        unsigned int aximem_clk_dis : 1;
        unsigned int aximon_clk_dis : 1;
        unsigned int timer_clk_dis : 8;
        unsigned int wdog_clk_dis : 1;
    } bits;
    unsigned int u32;
}HI_CRG_CLKDIS4_T;
typedef union
{
    struct
    {
        unsigned int bbe_pd_clk_status : 1;
        unsigned int bbe_core_clk_status : 1;
        unsigned int bbe_dbg_clk_status : 1;
        unsigned int mcpu_pd_clk_status : 1;
        unsigned int l2c_clk_status : 1;
        unsigned int mcpu_dbg_clk_status : 1;
        unsigned int mcpu_mbist_clk_status : 1;
        unsigned int reserved : 1;
        unsigned int cicom0_clk_status : 1;
        unsigned int cicom1_clk_status : 1;
        unsigned int ipf_clk_status : 1;
        unsigned int upacc_clk_status : 1;
        unsigned int sci0_clk_status : 1;
        unsigned int sci1_clk_status : 1;
        unsigned int uicc_clk_status : 1;
        unsigned int uart_clk_status : 1;
        unsigned int bbe_vic_clk_status : 1;
        unsigned int cipher_clk_status : 1;
        unsigned int edmac_clk_status : 1;
        unsigned int ipcm_clk_status : 1;
        unsigned int hsuart_clk_status : 1;
        unsigned int aximem_clk_status : 1;
        unsigned int aximon_clk_status : 1;
        unsigned int timer_clk_status : 8;
        unsigned int wdog_clk_status : 1;
    } bits;
    unsigned int u32;
}HI_CRG_CLKSTAT4_T;
typedef union
{
    struct
    {
        unsigned int bbp_ao_clk_en : 1;
        unsigned int bbpcommon_2a_clk_en : 1;
        unsigned int ltebbp_pd_clk_en : 1;
        unsigned int g1bbp_pd_clk_en : 1;
        unsigned int g2bbp_pd_clk_en : 1;
        unsigned int twbbp_pd_clk_en : 1;
        unsigned int wbbp_pd_clk_en : 1;
        unsigned int irm_pd_clk_en : 1;
        unsigned int lbbp_axi_clk_en : 1;
        unsigned int lbbp_pdt_clk_en : 1;
        unsigned int lbbp_pdf_clk_en : 1;
        unsigned int lbbp_tdl_clk_en : 1;
        unsigned int lbbp_vdl_clk_en : 1;
        unsigned int lbbp_tds_clk_en : 1;
        unsigned int reserved_1 : 2;
        unsigned int irm_turbo_clk_en : 1;
        unsigned int irm_bbc_245m_clk_en : 1;
        unsigned int irm_wbbp_122m_clk_en : 1;
        unsigned int twbbp_wbbp_122m_clk_en : 1;
        unsigned int twbbp_wbbp_61m_clk_en : 1;
        unsigned int twbbp_tbbp_122m_clk_en : 1;
        unsigned int twbbp_tbbp_245m_clk_en : 1;
        unsigned int wbbp_61m_clk_en : 1;
        unsigned int wbbp_122m_clk_en : 1;
        unsigned int wbbp_245m_clk_en : 1;
        unsigned int wbbp_axi_clk_en : 1;
        unsigned int reserved_0 : 5;
    } bits;
    unsigned int u32;
}HI_CRG_CLKEN5_T;
typedef union
{
    struct
    {
        unsigned int bbp_ao_clk_dis : 1;
        unsigned int bbpcommon_2a_clk_dis : 1;
        unsigned int lbbp_pd_clk_dis : 1;
        unsigned int g1bbp_pd_clk_dis : 1;
        unsigned int g2bbp_pd_clk_dis : 1;
        unsigned int twbbp_pd_clk_dis : 1;
        unsigned int wbbp_pd_clk_dis : 1;
        unsigned int irmbbp_pd_clk_dis : 1;
        unsigned int lbbp_axi_clk_dis : 1;
        unsigned int lbbp_pdt_clk_dis : 1;
        unsigned int lbbp_pdf_clk_dis : 1;
        unsigned int lbbp_tdl_clk_dis : 1;
        unsigned int lbbp_vdl_clk_dis : 1;
        unsigned int lbbp_tds_clk_dis : 1;
        unsigned int reserved_1 : 2;
        unsigned int irm_turbo_clk_dis : 1;
        unsigned int irm_bbc_245m_clk_dis : 1;
        unsigned int irm_wbbp_clk_dis : 1;
        unsigned int twbbp_wbbp_122m_clk_dis : 1;
        unsigned int twbbp_wbbp_61m_clk_dis : 1;
        unsigned int twbbp_tbbp_122m_clk_dis : 1;
        unsigned int twbbp_tbbp_245m_clk_dis : 1;
        unsigned int wbbp_61m_clk_dis : 1;
        unsigned int wbbp_122m_clk_dis : 1;
        unsigned int wbbp_245m_clk_dis : 1;
        unsigned int wbbp_axi_clk_dis : 1;
        unsigned int reserved_0 : 5;
    } bits;
    unsigned int u32;
}HI_CRG_CLKDIS5_T;
typedef union
{
    struct
    {
        unsigned int bbp_ao_clk_stat : 1;
        unsigned int bbpcom_clk_stat : 1;
        unsigned int lbbp_pd_clk_stat : 1;
        unsigned int g1bbp_pd_clk_stat : 1;
        unsigned int g2bbp_pd_clk_stat : 1;
        unsigned int twbbp_pd_clk_stat : 1;
        unsigned int wbbp_pd_clk_stat : 1;
        unsigned int irmbbp_pd_clk_stat : 1;
        unsigned int lbbp_axi_clk_stat : 1;
        unsigned int lbbp_pdt_clk_stat : 1;
        unsigned int lbbp_pdf_clk_stat : 1;
        unsigned int lbbp_tdl_clk_stat : 1;
        unsigned int lbbp_vdl_clk_stat : 1;
        unsigned int lbbp_tds_clk_stat : 1;
        unsigned int reserved_1 : 2;
        unsigned int irm_turbo_clk_stat : 1;
        unsigned int irm_bbc_245m_clk_stat : 1;
        unsigned int irm_wbbp_clk_stat : 1;
        unsigned int twbbp_wbbp_122m_clk_stat : 1;
        unsigned int twbbp_wbbp_61m_clk_stat : 1;
        unsigned int twbbp_tbbp_122m_clk_stat : 1;
        unsigned int twbbp_tbbp_245m_clk_stat : 1;
        unsigned int wbbp_61m_clk_stat : 1;
        unsigned int wbbp_122m_clk_stat : 1;
        unsigned int wbbp_245m_clk_stat : 1;
        unsigned int wbbp_axi_clk_stat : 1;
        unsigned int reserved_0 : 5;
    } bits;
    unsigned int u32;
}HI_CRG_CLKSTAT5_T;
typedef union
{
    struct
    {
        unsigned int bbe_pd_srst_en : 1;
        unsigned int bbe_core_srst_en : 1;
        unsigned int bbe_dbg_srst_en : 1;
        unsigned int reserved_4 : 3;
        unsigned int moda9_cpu_srst_en : 1;
        unsigned int moda9_dbg_srst_en : 1;
        unsigned int moda9_peri_srst_en : 1;
        unsigned int moda9_scu_srst_en : 1;
        unsigned int moda9_ptm_srst_en : 1;
        unsigned int moda9_wd_srst_en : 1;
        unsigned int reserved_3 : 3;
        unsigned int mdma9_pd_srst_en : 1;
        unsigned int reserved_2 : 10;
        unsigned int uicc_srst_en : 1;
        unsigned int reserved_1 : 2;
        unsigned int amon_soc_srst_en : 1;
        unsigned int reserved_0 : 1;
        unsigned int hpm_srst_en : 1;
    } bits;
    unsigned int u32;
}HI_CRG_SRSTEN1_T;
typedef union
{
    struct
    {
        unsigned int bbe_pd_srst_dis : 1;
        unsigned int bbe_core_srst_dis : 1;
        unsigned int bbe_dbg_srst_dis : 1;
        unsigned int reserved_4 : 3;
        unsigned int moda9_core_srst_dis : 1;
        unsigned int moda9_dbg_srst_dis : 1;
        unsigned int moda9_peri_srst_dis : 1;
        unsigned int moda9_scu_srst_dis : 1;
        unsigned int moda9_ptm_srst_dis : 1;
        unsigned int moda9_wd_srst_dis : 1;
        unsigned int reserved_3 : 3;
        unsigned int mdma9_pd_srst_dis : 1;
        unsigned int reserved_2 : 10;
        unsigned int uicc_srst_dis : 1;
        unsigned int reserved_1 : 2;
        unsigned int amon_soc_srst_dis : 1;
        unsigned int reserved_0 : 1;
        unsigned int hpm_srst_dis : 1;
    } bits;
    unsigned int u32;
}HI_CRG_SRSTDIS1_T;
typedef union
{
    struct
    {
        unsigned int bbe_pd_srst_status : 1;
        unsigned int bbe_core_srst_status : 1;
        unsigned int bbe_dbg_srst_status : 1;
        unsigned int reserved_4 : 3;
        unsigned int moda9_core_srst_status : 1;
        unsigned int moda9_dbg_srst_status : 1;
        unsigned int moda9_peri_srst_status : 1;
        unsigned int moda9_scu_srst_status : 1;
        unsigned int moda9_ptm_srst_status : 1;
        unsigned int moda9_wd_srst_status : 1;
        unsigned int reserved_3 : 3;
        unsigned int mdma9_pd_srst_status : 1;
        unsigned int reserved_2 : 10;
        unsigned int uicc_srst_status : 1;
        unsigned int reserved_1 : 2;
        unsigned int amon_soc_srst_status : 1;
        unsigned int reserved_0 : 1;
        unsigned int hpm_srst_status : 1;
    } bits;
    unsigned int u32;
}HI_CRG_SRSTSTAT1_T;
typedef union
{
    struct
    {
        unsigned int bbp_crg_srst_en : 1;
        unsigned int bbpcommon_2a_srst_en : 1;
        unsigned int lbbp_pd_srst_en : 1;
        unsigned int g1bbp_pd_srst_en : 1;
        unsigned int g2bbp_pd_srst_en : 1;
        unsigned int twbbp_pd_srst_en : 1;
        unsigned int wbbp_pd_srst_en : 1;
        unsigned int irm_pd_srst_en : 1;
        unsigned int bbc_lbbp_pdt_srst_en : 1;
        unsigned int bbc_lbbp_pdf_srst_en : 1;
        unsigned int bbc_lbbp_tdl_srst_en : 1;
        unsigned int bbc_tbbp_245m_srst_en : 1;
        unsigned int bbc_twbbp_122m_srst_en : 1;
        unsigned int bbc_g1bbp_104m_srst_en : 1;
        unsigned int bbc_g2bbp_104m_srst_en : 1;
        unsigned int reserved : 16;
        unsigned int abb_srst_en : 1;
    } bits;
    unsigned int u32;
}HI_CRG_SRSTEN3_T;
typedef union
{
    struct
    {
        unsigned int bbp_crg_srst_dis : 1;
        unsigned int bbpcommon_2a_pd_srst_dis : 1;
        unsigned int lbbp_pd_srst_dis : 1;
        unsigned int g1bbp_pd_srst_dis : 1;
        unsigned int g2bbp_pd_srst_dis : 1;
        unsigned int twbbp_pd_srst_dis : 1;
        unsigned int wbbp_pd_srst_dis : 1;
        unsigned int irm_pd_srst_dis : 1;
        unsigned int bbc_lbbp_pdt_srst_dis : 1;
        unsigned int bbc_lbbp_pdf_srst_dis : 1;
        unsigned int bbc_lbbp_tdl_srst_dis : 1;
        unsigned int bbc_tbbp_245m_srst_dis : 1;
        unsigned int bbc_twbbp_122m_srst_dis : 1;
        unsigned int bbc_g1bbp_104m_srst_dis : 1;
        unsigned int bbc_g2bbp_104m_srst_dis : 1;
        unsigned int reserved : 16;
        unsigned int abb_srst_dis : 1;
    } bits;
    unsigned int u32;
}HI_CRG_SRSTDIS3_T;
typedef union
{
    struct
    {
        unsigned int bbp_crg_srst_stat : 1;
        unsigned int bbpcommon_2a_srst_stat : 1;
        unsigned int lbbp_pd_srst_stat : 1;
        unsigned int g1bbp_pd_srst_stat : 1;
        unsigned int g2bbp_pd_srst_stat : 1;
        unsigned int twbbp_pd_srst_stat : 1;
        unsigned int wbbp_pd_srst_stat : 1;
        unsigned int irm_pd_srst_stat : 1;
        unsigned int bbc_lbbp_pdt_srstctrl_stat : 1;
        unsigned int bbc_lbbp_pdf_srstctrl_stat : 1;
        unsigned int bbc_lbbp_tdl_srstctrl_stat : 1;
        unsigned int bbc_tbbp_245m_srstctrl_stat : 1;
        unsigned int bbc_twbbp_122m_srstctrl_stat : 1;
        unsigned int bbc_g1bbp_104m_srstctrl_stat : 1;
        unsigned int bbc_g2bbp_104m_srstctrl_stat : 1;
        unsigned int reserved : 16;
        unsigned int abb_srst_status : 1;
    } bits;
    unsigned int u32;
}HI_CRG_SRSTSTAT3_T;
typedef union
{
    struct
    {
        unsigned int reserved_4 : 4;
        unsigned int mdma9_clk_div : 4;
        unsigned int a92slow_freqmode : 3;
        unsigned int reserved_3 : 1;
        unsigned int a92fast_freqmode : 3;
        unsigned int reserved_2 : 1;
        unsigned int a9_clksw_req : 3;
        unsigned int reserved_1 : 11;
        unsigned int apb_freqmode : 1;
        unsigned int reserved_0 : 1;
    } bits;
    unsigned int u32;
}HI_CRG_CLKDIV2_T;
typedef union
{
    struct
    {
        unsigned int bbe_clk_div_num : 2;
        unsigned int reserved_2 : 2;
        unsigned int bbe_freqmode : 2;
        unsigned int reserved_1 : 22;
        unsigned int cipher_clk_div : 3;
        unsigned int reserved_0 : 1;
    } bits;
    unsigned int u32;
}HI_CRG_CLKDIV5_T;
typedef union
{
    struct
    {
        unsigned int timer_clk_sel : 8;
        unsigned int gps_tcxo_clk_sel : 1;
        unsigned int hpm_refclk_sel : 1;
        unsigned int reserved_1 : 10;
        unsigned int sc_a9wdt_rst_en : 1;
        unsigned int reserved_0 : 11;
    } bits;
    unsigned int u32;
}HI_CRG_CLK_SEL2_T;
typedef union
{
    struct
    {
        unsigned int abb_tcxo_clk_sel : 1;
        unsigned int bbppll_refclk_sel : 1;
        unsigned int bbp_tcxo_clk_sel : 1;
        unsigned int ch0_tcxo_clk_sel : 1;
        unsigned int ch1_tcxo_clk_sel : 1;
        unsigned int g1bbp_104m_clk_sel : 1;
        unsigned int g2bbp_104m_clk_sel : 1;
        unsigned int tdl_clk_sel : 1;
        unsigned int lbbp_vdl_clk_sel : 1;
        unsigned int lbbp_pdf_clk_sel : 1;
        unsigned int reserved : 22;
    } bits;
    unsigned int u32;
}HI_CRG_CLK_SEL3_T;
typedef union
{
    struct
    {
        unsigned int pll_en : 1;
        unsigned int pll_bp : 1;
        unsigned int pll_refdiv : 6;
        unsigned int pll_intprog : 12;
        unsigned int pll_postdiv1 : 3;
        unsigned int pll_postdiv2 : 3;
        unsigned int pll_lock : 1;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_CRG_A9PLL_CFG0_T;
typedef union
{
    struct
    {
        unsigned int pll_fracdiv : 24;
        unsigned int pll_int_mod : 1;
        unsigned int pll_cfg_vld : 1;
        unsigned int pll_clk_gt : 1;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_CRG_A9PLL_CFG1_T;
typedef union
{
    struct
    {
        unsigned int pll_ssc_reset : 1;
        unsigned int pll_ssc_disable : 1;
        unsigned int pll_ssc_downspread : 1;
        unsigned int pll_ssc_spread : 3;
        unsigned int pll_ssc_divval : 4;
        unsigned int reserved : 22;
    } bits;
    unsigned int u32;
}HI_CRG_A9PLL_CFG2_T;
typedef union
{
    struct
    {
        unsigned int pll_en : 1;
        unsigned int pll_bp : 1;
        unsigned int pll_refdiv : 6;
        unsigned int pll_intprog : 12;
        unsigned int pll_postdiv1 : 3;
        unsigned int pll_postdiv2 : 3;
        unsigned int pll_lock : 1;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_CRG_DSPPLL_CFG0_T;
typedef union
{
    struct
    {
        unsigned int pll_fracdiv : 24;
        unsigned int pll_int_mod : 1;
        unsigned int pll_cfg_vld : 1;
        unsigned int pll_clk_gt : 1;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_CRG_DSPPLL_CFG1_T;
typedef union
{
    struct
    {
        unsigned int pll_ssc_reset : 1;
        unsigned int pll_ssc_disable : 1;
        unsigned int pll_ssc_downspread : 1;
        unsigned int pll_ssc_spread : 3;
        unsigned int pll_ssc_divval : 4;
        unsigned int reserved : 22;
    } bits;
    unsigned int u32;
}HI_CRG_DSPPLL_CFG2_T;
typedef union
{
    struct
    {
        unsigned int pll_en : 1;
        unsigned int pll_bp : 1;
        unsigned int pll_refdiv : 6;
        unsigned int pll_intprog : 12;
        unsigned int pll_postdiv1 : 3;
        unsigned int pll_postdiv2 : 3;
        unsigned int pll_lock : 1;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_CRG_BBPPLL_CFG0_T;
typedef union
{
    struct
    {
        unsigned int pll_fracdiv : 24;
        unsigned int pll_int_mod : 1;
        unsigned int pll_cfg_vld : 1;
        unsigned int pll_clk_gt : 1;
        unsigned int reserved : 5;
    } bits;
    unsigned int u32;
}HI_CRG_BBPPLL_CFG1_T;
typedef union
{
    struct
    {
        unsigned int pll_ssc_reset : 1;
        unsigned int pll_ssc_disable : 1;
        unsigned int pll_ssc_downspread : 1;
        unsigned int pll_ssc_spread : 3;
        unsigned int pll_ssc_divval : 4;
        unsigned int reserved : 22;
    } bits;
    unsigned int u32;
}HI_CRG_BBPPLL_CFG2_T;
typedef union
{
    struct
    {
        unsigned int mcpu_boot_remap_clear : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_SC_CTRL0_T;
typedef union
{
    struct
    {
        unsigned int wdt_clk_en : 1;
        unsigned int reserved_1 : 2;
        unsigned int wdt_en_ov : 1;
        unsigned int reserved_0 : 12;
        unsigned int wdt_en_ctrl : 16;
    } bits;
    unsigned int u32;
}HI_SC_CTRL2_T;
typedef union
{
    struct
    {
        unsigned int reserved_3 : 10;
        unsigned int amon_monitor_start : 1;
        unsigned int reserved_2 : 4;
        unsigned int dsp0_uart_en : 2;
        unsigned int reserved_1 : 14;
        unsigned int reserved_0 : 1;
    } bits;
    unsigned int u32;
}HI_SC_CTRL3_T;
typedef union
{
    struct
    {
        unsigned int cicom0_sel_mod : 1;
        unsigned int cicom1_sel_mod : 1;
        unsigned int reserved : 30;
    } bits;
    unsigned int u32;
}HI_SC_CTRL4_T;
typedef union
{
    struct
    {
        unsigned int reserved : 32;
    } bits;
    unsigned int u32;
}HI_SC_CTRL5_T;
typedef union
{
    struct
    {
        unsigned int reserved : 32;
    } bits;
    unsigned int u32;
}HI_SC_CTRL6_T;
typedef union
{
    struct
    {
        unsigned int reserved : 16;
        unsigned int sw_dsp0_boot_addr : 16;
    } bits;
    unsigned int u32;
}HI_SC_CTRL9_T;
typedef union
{
    struct
    {
        unsigned int reserved : 32;
    } bits;
    unsigned int u32;
}HI_SC_CTRL10_T;
typedef union
{
    struct
    {
        unsigned int reserved_2 : 1;
        unsigned int moda9_cfgnmfi : 1;
        unsigned int moda9_cfgsdisable : 1;
        unsigned int moda9_cp15sdisable : 1;
        unsigned int moda9_pwrctli0 : 2;
        unsigned int reserved_1 : 10;
        unsigned int moda9_l2_waysize : 3;
        unsigned int reserved_0 : 1;
        unsigned int moda9_l2_regfilebase : 12;
    } bits;
    unsigned int u32;
}HI_SC_CTRL11_T;
typedef union
{
    struct
    {
        unsigned int reserved : 32;
    } bits;
    unsigned int u32;
}HI_SC_CTRL12_T;
typedef union
{
    struct
    {
        unsigned int reserved_1 : 16;
        unsigned int ocdhaltonreset : 1;
        unsigned int runstall : 1;
        unsigned int statvectorsel : 1;
        unsigned int breaksync_en : 3;
        unsigned int crosstrig_en : 3;
        unsigned int reserved_0 : 7;
    } bits;
    unsigned int u32;
}HI_SC_CTRL13_T;
typedef union
{
    struct
    {
        unsigned int hpm_clk_div : 6;
        unsigned int reserved_1 : 1;
        unsigned int hpm_en : 1;
        unsigned int hpmx_en : 1;
        unsigned int reserved_0 : 23;
    } bits;
    unsigned int u32;
}HI_SC_CTRL17_T;
typedef union
{
    struct
    {
        unsigned int axi_mem_gatedclock_en : 1;
        unsigned int cicom0_auto_clk_gate_en : 1;
        unsigned int cicom0_soft_gate_clk_en : 1;
        unsigned int cicom1_auto_clk_gate_en : 1;
        unsigned int cicom1_soft_gate_clk_en : 1;
        unsigned int hs_uart_gatedclock_en : 1;
        unsigned int uart_gatedclock_en : 1;
        unsigned int reserved_2 : 12;
        unsigned int uicc_gatedclock_en : 1;
        unsigned int uicc_ss_scaledown_mode : 2;
        unsigned int upacc_auto_clk_gate_en : 1;
        unsigned int upacc_soft_gate_clk_en : 1;
        unsigned int bbe16_cg_en : 1;
        unsigned int reserved_1 : 3;
        unsigned int ipcm_auto_clk_gate_en : 1;
        unsigned int ipcm_soft_gate_clk_en : 1;
        unsigned int reserved_0 : 1;
        unsigned int sysreg_auto_gate_en : 1;
    } bits;
    unsigned int u32;
}HI_SC_CTRL20_T;
typedef union
{
    struct
    {
        unsigned int reserved_6 : 4;
        unsigned int timer_gatedclock_en : 1;
        unsigned int reserved_5 : 5;
        unsigned int dw_axi_glb_cg_en : 1;
        unsigned int dw_axi_mst_cg_en : 1;
        unsigned int reserved_4 : 1;
        unsigned int dw_axi_bbphy_cg_en : 1;
        unsigned int reserved_3 : 1;
        unsigned int dw_x2x_async_cg_en : 1;
        unsigned int reserved_2 : 1;
        unsigned int dw_x2h_qsync_cg_en : 1;
        unsigned int dw_hmx_cg_en : 1;
        unsigned int dw_x2p_cg_en : 1;
        unsigned int dw_gs_cg_en : 1;
        unsigned int ashb_gatedclock_en : 1;
        unsigned int dw_ahb_mst_gatedclock_en : 1;
        unsigned int reserved_1 : 1;
        unsigned int edmac_autogated_clk_en : 1;
        unsigned int reserved_0 : 7;
    } bits;
    unsigned int u32;
}HI_SC_CTRL21_T;
typedef union
{
    struct
    {
        unsigned int reserved_1 : 16;
        unsigned int bbe16_ema : 3;
        unsigned int bbe16_emaw : 2;
        unsigned int bbe16_emas : 1;
        unsigned int reserved_0 : 10;
    } bits;
    unsigned int u32;
}HI_SC_CTRL22_T;
typedef union
{
    struct
    {
        unsigned int axi_mem_ema : 3;
        unsigned int axi_mem_emaw : 2;
        unsigned int axi_mem_emas : 1;
        unsigned int reserved_1 : 2;
        unsigned int soc_mem_ema : 3;
        unsigned int soc_mem_spram_emaw : 2;
        unsigned int soc_mem_spram_emas : 1;
        unsigned int soc_mem_tpram_emab : 3;
        unsigned int soc_mem_tpram_emasa : 1;
        unsigned int soc_mem_dpram_emaw : 2;
        unsigned int soc_mem_dpram_emas : 1;
        unsigned int reserved_0 : 11;
    } bits;
    unsigned int u32;
}HI_SC_CTRL23_T;
typedef union
{
    struct
    {
        unsigned int reserved_1 : 10;
        unsigned int moda9_hs_mem_adjust : 10;
        unsigned int reserved_0 : 6;
        unsigned int moda9_l2_ema : 3;
        unsigned int moda9_l2_emaw : 2;
        unsigned int moda9_l2_emas : 1;
    } bits;
    unsigned int u32;
}HI_SC_CTRL24_T;
typedef union
{
    struct
    {
        unsigned int reserved : 32;
    } bits;
    unsigned int u32;
}HI_SC_CTRL25_T;
typedef union
{
    struct
    {
        unsigned int reserved : 32;
    } bits;
    unsigned int u32;
}HI_SC_CTRL26_T;
typedef union
{
    struct
    {
        unsigned int acp_filter_start : 32;
    } bits;
    unsigned int u32;
}HI_SC_CTRL28_T;
typedef union
{
    struct
    {
        unsigned int acp_filter_end : 32;
    } bits;
    unsigned int u32;
}HI_SC_CTRL29_T;
typedef union
{
    struct
    {
        unsigned int reserved : 32;
    } bits;
    unsigned int u32;
}HI_SC_CTRL30_T;
typedef union
{
    struct
    {
        unsigned int uicc_ic_usb_vbusvalid : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_SC_CTRL45_T;
typedef union
{
    struct
    {
        unsigned int dsp0_nmi : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_SC_CTRL52_T;
typedef union
{
    struct
    {
        unsigned int reserved_7 : 5;
        unsigned int uicc_ret1n : 1;
        unsigned int reserved_6 : 3;
        unsigned int amon_soc_ret1n : 1;
        unsigned int reserved_5 : 3;
        unsigned int edmac_colldisn : 1;
        unsigned int reserved_4 : 3;
        unsigned int amon_soc_colldisn : 1;
        unsigned int reserved_3 : 1;
        unsigned int ipf_ret1n : 1;
        unsigned int ipf_colldisn : 1;
        unsigned int cipher_ret1n : 1;
        unsigned int cipher_colldisn : 1;
        unsigned int reserved_2 : 2;
        unsigned int hs_uart_ret1n : 1;
        unsigned int reserved_1 : 3;
        unsigned int edmac_ret1n : 1;
        unsigned int reserved_0 : 2;
    } bits;
    unsigned int u32;
}HI_SC_CTRL55_T;
typedef union
{
    struct
    {
        unsigned int prior_level : 2;
        unsigned int gatedclock_en : 1;
        unsigned int dw_axi_rs_gatedclock_en : 1;
        unsigned int dw_axi_gs_gatedclock_en : 1;
        unsigned int overf_prot : 2;
        unsigned int reserved : 9;
        unsigned int atpram_ctrl : 16;
    } bits;
    unsigned int u32;
}HI_SC_CTRL56_T;
typedef union
{
    struct
    {
        unsigned int soc2lte_tbd : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_SC_CTRL57_T;
typedef union
{
    struct
    {
        unsigned int moda9_l2_ret1n : 1;
        unsigned int moda9_l2_ret2n : 1;
        unsigned int moda9_l2_pgen : 1;
        unsigned int reserved_2 : 5;
        unsigned int dsp0_ret1n : 1;
        unsigned int dsp0_ret2n : 1;
        unsigned int dsp0_pgen : 1;
        unsigned int reserved_1 : 5;
        unsigned int pd_axi_mem_ret1n : 1;
        unsigned int pd_axi_mem_ret2n : 1;
        unsigned int pd_axi_mem_pgen : 1;
        unsigned int reserved_0 : 13;
    } bits;
    unsigned int u32;
}HI_SC_CTRL68_T;
typedef union
{
    struct
    {
        unsigned int axi_bbphy_xdcdr_sel : 1;
        unsigned int reserved_2 : 2;
        unsigned int axi_glb_xdcdr_sel : 1;
        unsigned int reserved_1 : 1;
        unsigned int socapb_pslverr_sel : 1;
        unsigned int x2h_hslverr_sel : 1;
        unsigned int mst_err_srst_req : 1;
        unsigned int reserved_0 : 24;
    } bits;
    unsigned int u32;
}HI_SC_CTRL69_T;
typedef union
{
    struct
    {
        unsigned int axi_bbphy_priority_m1 : 2;
        unsigned int axi_bbphy_priority_m2 : 2;
        unsigned int axi_bbphy_priority_m3 : 2;
        unsigned int axi_bbphy_priority_m4 : 2;
        unsigned int reserved_1 : 8;
        unsigned int axi_mst_priority_m9 : 4;
        unsigned int axi_mst_priority_m10 : 4;
        unsigned int reserved_0 : 8;
    } bits;
    unsigned int u32;
}HI_SC_CTRL70_T;
typedef union
{
    struct
    {
        unsigned int reserved : 4;
        unsigned int axi_glb_priority_m1 : 3;
        unsigned int axi_glb_priority_m2 : 3;
        unsigned int axi_glb_priority_m3 : 3;
        unsigned int axi_glb_priority_m4 : 3;
        unsigned int axi_glb_priority_m5 : 3;
        unsigned int axi_glb_priority_m6 : 3;
        unsigned int axi_mst_cache_cfg_en : 1;
        unsigned int axi_mst_sideband : 5;
        unsigned int axi_mst_cache : 4;
    } bits;
    unsigned int u32;
}HI_SC_CTRL71_T;
typedef union
{
    struct
    {
        unsigned int axi_mst_priority_m1 : 4;
        unsigned int axi_mst_priority_m2 : 4;
        unsigned int axi_mst_priority_m3 : 4;
        unsigned int axi_mst_priority_m4 : 4;
        unsigned int axi_mst_priority_m5 : 4;
        unsigned int axi_mst_priority_m6 : 4;
        unsigned int axi_mst_priority_m7 : 4;
        unsigned int axi_mst_priority_m8 : 4;
    } bits;
    unsigned int u32;
}HI_SC_CTRL72_T;
typedef union
{
    struct
    {
        unsigned int peri_mst_region1_ctrl : 8;
        unsigned int peri_mst_secctrl_bypass : 1;
        unsigned int reserved : 1;
        unsigned int peri_mst_region1_staddr : 22;
    } bits;
    unsigned int u32;
}HI_SC_CTRL73_T;
typedef union
{
    struct
    {
        unsigned int reserved : 10;
        unsigned int peri_mst_region1_endaddr : 22;
    } bits;
    unsigned int u32;
}HI_SC_CTRL74_T;
typedef union
{
    struct
    {
        unsigned int peri_mst_region2_ctrl : 8;
        unsigned int reserved : 2;
        unsigned int peri_mst_region2_staddr : 22;
    } bits;
    unsigned int u32;
}HI_SC_CTRL75_T;
typedef union
{
    struct
    {
        unsigned int reserved : 10;
        unsigned int peri_mst_region2_endaddr : 22;
    } bits;
    unsigned int u32;
}HI_SC_CTRL76_T;
typedef union
{
    struct
    {
        unsigned int peri_mst_region3_ctrl : 8;
        unsigned int reserved : 2;
        unsigned int peri_mst_region3_staddr : 22;
    } bits;
    unsigned int u32;
}HI_SC_CTRL77_T;
typedef union
{
    struct
    {
        unsigned int reserved : 10;
        unsigned int peri_mst_region3_endaddr : 22;
    } bits;
    unsigned int u32;
}HI_SC_CTRL78_T;
typedef union
{
    struct
    {
        unsigned int peri_mst_region4_ctrl : 8;
        unsigned int reserved : 2;
        unsigned int peri_mst_region4_staddr : 22;
    } bits;
    unsigned int u32;
}HI_SC_CTRL79_T;
typedef union
{
    struct
    {
        unsigned int reserved : 10;
        unsigned int peri_mst_region4_endaddr : 22;
    } bits;
    unsigned int u32;
}HI_SC_CTRL80_T;
typedef union
{
    struct
    {
        unsigned int reserved_8 : 1;
        unsigned int bbphy_dsp0_axislv_active_mask : 1;
        unsigned int bbphy_bbp_axislv_active_mask : 1;
        unsigned int reserved_7 : 1;
        unsigned int reserved_6 : 4;
        unsigned int mdmacp_axislv_active_mask : 1;
        unsigned int reserved_5 : 2;
        unsigned int axi_mem_axislv_active_mask : 1;
        unsigned int reserved_4 : 1;
        unsigned int bbphy_axislv_active_mask : 1;
        unsigned int reserved_3 : 1;
        unsigned int wbbp_axislv_active_mask : 1;
        unsigned int amon_axislv_active_mask : 1;
        unsigned int reserved_2 : 2;
        unsigned int wdog_apbslv_active_mask : 1;
        unsigned int timer0_7_apbslv_active_mask : 1;
        unsigned int reserved_1 : 4;
        unsigned int uart0_apbslv_active_mask : 1;
        unsigned int edmac_slv_active_mask : 1;
        unsigned int reserved_0 : 5;
    } bits;
    unsigned int u32;
}HI_SC_CTRL103_T;
typedef union
{
    struct
    {
        unsigned int reserved : 32;
    } bits;
    unsigned int u32;
}HI_SC_CTRL104_T;
typedef union
{
    struct
    {
        unsigned int uicc : 1;
        unsigned int reserved_6 : 5;
        unsigned int ipcm : 1;
        unsigned int reserved_5 : 1;
        unsigned int hs_uart : 1;
        unsigned int reserved_4 : 2;
        unsigned int cipher : 1;
        unsigned int ipf : 1;
        unsigned int reserved_3 : 6;
        unsigned int cicom0 : 1;
        unsigned int cicom1 : 1;
        unsigned int reserved_2 : 4;
        unsigned int vic1 : 1;
        unsigned int reserved_1 : 3;
        unsigned int upacc : 1;
        unsigned int reserved_0 : 2;
    } bits;
    unsigned int u32;
}HI_SC_CTRL105_T;
typedef union
{
    struct
    {
        unsigned int reserved_1 : 14;
        unsigned int moda9_standbywfi : 1;
        unsigned int moda9_standbywfe : 1;
        unsigned int moda9_pmupriv : 1;
        unsigned int moda9_pmusecure : 1;
        unsigned int moda9_smpnamp : 1;
        unsigned int moda9_scuevabort : 1;
        unsigned int moda9_pwrctlo0 : 2;
        unsigned int moda9_l2_tagclkouten : 1;
        unsigned int moda9_l2_dataclkouten : 4;
        unsigned int moda9_l2_idle : 1;
        unsigned int moda9_l2_clkstopped : 1;
        unsigned int reserved_0 : 3;
    } bits;
    unsigned int u32;
}HI_SC_STAT1_T;
typedef union
{
    struct
    {
        unsigned int reserved_1 : 16;
        unsigned int dsp0_pwaitmode : 1;
        unsigned int dsp0_xocdmode : 1;
        unsigned int reserved_0 : 14;
    } bits;
    unsigned int u32;
}HI_SC_STAT2_T;
typedef union
{
    struct
    {
        unsigned int hpmx_opc : 10;
        unsigned int hpmx_opc_vld : 1;
        unsigned int reserved_1 : 1;
        unsigned int hpm_opc : 10;
        unsigned int hpm_opc_vld : 1;
        unsigned int reserved_0 : 9;
    } bits;
    unsigned int u32;
}HI_SC_STAT3_T;
typedef union
{
    struct
    {
        unsigned int dsp0_nmi : 1;
        unsigned int intr_ipc_ns : 1;
        unsigned int intr_ipc_ns_mbx : 1;
        unsigned int dsp_uart_int : 1;
        unsigned int edmac_int1 : 1;
        unsigned int lte_dsp_aagc_int : 1;
        unsigned int lte_dsp_cell_int : 1;
        unsigned int lte_dsp_vdl_int : 1;
        unsigned int lte_dsp_cmu_int : 1;
        unsigned int lte_dsp_pwrm_int : 1;
        unsigned int lte_dsp_cfi_int : 1;
        unsigned int lte_dsp_tdl_int : 1;
        unsigned int lte_dsp_bbp_dma_int : 1;
        unsigned int lte_dsp_pub_int : 1;
        unsigned int lte_dsp_synb_int : 1;
        unsigned int tds_stu_sfrm_int : 1;
        unsigned int tds_hsupa_int : 1;
        unsigned int tds_harq_int : 1;
        unsigned int tds_turbo_int : 1;
        unsigned int tds_viterbi_int : 1;
        unsigned int tds_rfc_int : 1;
        unsigned int tds_fpu_int : 1;
        unsigned int tds_stu_dsp_int : 1;
        unsigned int ctu_int_lte : 1;
        unsigned int ctu_int_tds : 1;
        unsigned int dsp_vic_int : 1;
        unsigned int reserved : 6;
    } bits;
    unsigned int u32;
}HI_SC_STAT5_T;
typedef union
{
    struct
    {
        unsigned int reserved_1 : 12;
        unsigned int moda9_parityfail0 : 8;
        unsigned int moda9_parityfailscu : 1;
        unsigned int reserved_0 : 11;
    } bits;
    unsigned int u32;
}HI_SC_STAT6_T;
typedef union
{
    struct
    {
        unsigned int dw_axi_mst_dlock_wr : 1;
        unsigned int dw_axi_mst_dlock_slv : 1;
        unsigned int reserved_2 : 2;
        unsigned int dw_axi_mst_dlock_mst : 4;
        unsigned int reserved_1 : 12;
        unsigned int dw_axi_glb_dlock_wr : 1;
        unsigned int dw_axi_glb_dlock_slv : 4;
        unsigned int dw_axi_glb_dlock_mst : 3;
        unsigned int reserved_0 : 4;
    } bits;
    unsigned int u32;
}HI_SC_STAT9_T;
typedef union
{
    struct
    {
        unsigned int dw_axi_glb_dlock_id : 8;
        unsigned int reserved : 20;
        unsigned int dw_axi_mst_dlock_id : 4;
    } bits;
    unsigned int u32;
}HI_SC_STAT10_T;
typedef union
{
    struct
    {
        unsigned int apb_pslv_active0 : 9;
        unsigned int reserved : 23;
    } bits;
    unsigned int u32;
}HI_SC_STAT15_T;
typedef union
{
    struct
    {
        unsigned int dw_axi_bbphy_dlock_mst : 2;
        unsigned int dw_axi_bbphy_dlock_slv : 3;
        unsigned int dw_axi_bbphy_dlock_wr : 1;
        unsigned int reserved_1 : 2;
        unsigned int dw_axi_bbphy_dlock_id : 12;
        unsigned int reserved_0 : 12;
    } bits;
    unsigned int u32;
}HI_SC_STAT22_T;
typedef union
{
    struct
    {
        unsigned int reserved_1 : 1;
        unsigned int ipf_idle : 1;
        unsigned int cicom0_clk_state : 1;
        unsigned int cicom1_clk_state : 1;
        unsigned int reserved_0 : 28;
    } bits;
    unsigned int u32;
}HI_SC_STAT26_T;
typedef union
{
    struct
    {
        unsigned int bbphy_slv_active : 4;
        unsigned int reserved_1 : 4;
        unsigned int glb_slv_active : 9;
        unsigned int reserved_0 : 15;
    } bits;
    unsigned int u32;
}HI_SC_STAT27_T;
typedef union
{
    struct
    {
        unsigned int x2h_peri_slv_active : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT29_T;
typedef union
{
    struct
    {
        unsigned int lte2soc_tbd : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_SC_STAT32_T;
typedef union
{
    struct
    {
        unsigned int ap2mdm_key0 : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT35_T;
typedef union
{
    struct
    {
        unsigned int ap2mdm_key0 : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT36_T;
typedef union
{
    struct
    {
        unsigned int ap2mdm_key2 : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT37_T;
typedef union
{
    struct
    {
        unsigned int ap2mdm_key3 : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT38_T;
typedef union
{
    struct
    {
        unsigned int bbphy_mst_err : 8;
        unsigned int reserved : 12;
        unsigned int glb_mst_err : 12;
    } bits;
    unsigned int u32;
}HI_SC_STAT41_T;
typedef union
{
    struct
    {
        unsigned int reserved_1 : 1;
        unsigned int socapb_psel_err : 1;
        unsigned int ahb_peri_mst_err : 1;
        unsigned int reserved_0 : 29;
    } bits;
    unsigned int u32;
}HI_SC_STAT42_T;
typedef union
{
    struct
    {
        unsigned int x2h_peri_addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT43_T;
typedef union
{
    struct
    {
        unsigned int reserved : 12;
        unsigned int addr_err : 20;
    } bits;
    unsigned int u32;
}HI_SC_STAT44_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT46_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT47_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT48_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT49_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT50_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT51_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT52_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT53_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT54_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT55_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT56_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT57_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT62_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT63_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT64_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT65_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT66_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT67_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT68_T;
typedef union
{
    struct
    {
        unsigned int addr_err : 32;
    } bits;
    unsigned int u32;
}HI_SC_STAT69_T;
typedef union
{
    struct
    {
        unsigned int reserved_1 : 20;
        unsigned int sc_tcxo0_en_ctrl : 1;
        unsigned int sc_tcxo1_en_ctrl : 1;
        unsigned int reserved_0 : 9;
        unsigned int sc_tcxo_en_ctrl : 1;
    } bits;
    unsigned int u32;
}HI_PWR_CTRL2_T;
typedef union
{
    struct
    {
        unsigned int reserved_3 : 1;
        unsigned int ccpu_iso_ctrl_en : 1;
        unsigned int reserved_2 : 2;
        unsigned int bbe16_iso_ctrl_en : 1;
        unsigned int reserved_1 : 1;
        unsigned int ltebbp_iso_ctrl_en : 1;
        unsigned int twbbp_iso_ctrl_en : 1;
        unsigned int wbbp_iso_ctrl_en : 1;
        unsigned int g1bbp_iso_ctrl_en : 1;
        unsigned int g2bbp_iso_ctrl_en : 1;
        unsigned int irmbbp_iso_ctrl_en : 1;
        unsigned int reserved_0 : 20;
    } bits;
    unsigned int u32;
}HI_PWR_CTRL4_T;
typedef union
{
    struct
    {
        unsigned int reserved_3 : 1;
        unsigned int ccpu_iso_ctrl_dis : 1;
        unsigned int reserved_2 : 2;
        unsigned int bbe16_iso_ctrl_dis : 1;
        unsigned int reserved_1 : 1;
        unsigned int ltebbp_iso_ctrl_dis : 1;
        unsigned int twbbp_iso_ctrl_dis : 1;
        unsigned int wbbp_iso_ctrl_dis : 1;
        unsigned int g1bbp_iso_ctrl_dis : 1;
        unsigned int g2bbp_iso_ctrl_dis : 1;
        unsigned int irmbbp_iso_ctrl_dis : 1;
        unsigned int reserved_0 : 20;
    } bits;
    unsigned int u32;
}HI_PWR_CTRL5_T;
typedef union
{
    struct
    {
        unsigned int reserved_3 : 1;
        unsigned int ccpu_mtcmos_ctrl_en : 1;
        unsigned int reserved_2 : 2;
        unsigned int bbe16_mtcmos_ctrl_en : 1;
        unsigned int reserved_1 : 1;
        unsigned int ltebbp_mtcmos_ctrl_en : 1;
        unsigned int twbbp_mtcmos_ctrl_en : 1;
        unsigned int wbbp_mtcmos_ctrl_en : 1;
        unsigned int g1bbp_mtcmos_ctrl_en : 1;
        unsigned int g2bbp_mtcmos_ctrl_en : 1;
        unsigned int irmbbp_mtcmos_ctrl_en : 1;
        unsigned int reserved_0 : 20;
    } bits;
    unsigned int u32;
}HI_PWR_CTRL6_T;
typedef union
{
    struct
    {
        unsigned int reserved_3 : 1;
        unsigned int ccpu_mtcmos_ctrl_dis : 1;
        unsigned int reserved_2 : 2;
        unsigned int bbe16_mtcmos_ctrl_dis : 1;
        unsigned int reserved_1 : 1;
        unsigned int ltebbp_mtcmos_ctrl_dis : 1;
        unsigned int twbbp_mtcmos_ctrl_dis : 1;
        unsigned int wbbp_mtcmos_ctrl_dis : 1;
        unsigned int g1bbp_mtcmos_ctrl_dis : 1;
        unsigned int g2bbp_mtcmos_ctrl_dis : 1;
        unsigned int irmbbp_mtcmos_ctrl_dis : 1;
        unsigned int reserved_0 : 20;
    } bits;
    unsigned int u32;
}HI_PWR_CTRL7_T;
typedef union
{
    struct
    {
        unsigned int reserved_4 : 1;
        unsigned int ccpu_mtcmos_rdy_stat : 1;
        unsigned int reserved_3 : 2;
        unsigned int bbe16_mtcmos_rdy_stat : 1;
        unsigned int reserved_2 : 1;
        unsigned int ltebbp_mtcmos_rdy_stat : 1;
        unsigned int twbbp_mtcmos_rdy_stat : 1;
        unsigned int wbbp_mtcmos_rdy_stat : 1;
        unsigned int g1bbp_mtcmos_rdy_stat : 1;
        unsigned int g2bbp_mtcmos_rdy_stat : 1;
        unsigned int irmbbp_mtcmos_rdy_stat : 1;
        unsigned int reserved_1 : 2;
        unsigned int ltebbp0_mtcmos_rdy_stat : 1;
        unsigned int reserved_0 : 17;
    } bits;
    unsigned int u32;
}HI_PWR_STAT1_T;
typedef union
{
    struct
    {
        unsigned int reserved_3 : 1;
        unsigned int ccpu_iso_ctrl_stat : 1;
        unsigned int reserved_2 : 2;
        unsigned int bbe16_iso_ctrl_stat : 1;
        unsigned int reserved_1 : 1;
        unsigned int ltebbp_iso_ctrl_stat : 1;
        unsigned int twbbp_iso_ctrl_stat : 1;
        unsigned int wbbp_iso_ctrl_stat : 1;
        unsigned int g1bbp_iso_ctrl_stat : 1;
        unsigned int g2bbp_iso_ctrl_stat : 1;
        unsigned int irmbbp_iso_ctrl_stat : 1;
        unsigned int reserved_0 : 20;
    } bits;
    unsigned int u32;
}HI_PWR_STAT3_T;
typedef union
{
    struct
    {
        unsigned int reserved_3 : 1;
        unsigned int ccpu_mtcmos_ctrl_stat : 1;
        unsigned int reserved_2 : 2;
        unsigned int bbe16_mtcmos_ctrl_stat : 1;
        unsigned int reserved_1 : 1;
        unsigned int ltebbp_mtcmos_ctrl_stat : 1;
        unsigned int twbbp_mtcmos_ctrl_stat : 1;
        unsigned int wbbp_mtcmos_ctrl_stat : 1;
        unsigned int g1bbp_mtcmos_ctrl_stat : 1;
        unsigned int g2bbp_mtcmos_ctrl_stat : 1;
        unsigned int irmbbp_mtcmos_ctrl_stat : 1;
        unsigned int reserved_0 : 20;
    } bits;
    unsigned int u32;
}HI_PWR_STAT4_T;
typedef union
{
    struct
    {
        unsigned int ipf_sec_w_ctrl : 1;
        unsigned int ipf_sec_r_ctrl : 1;
        unsigned int region1_sec_w_ctrl : 1;
        unsigned int region1_sec_r_ctrl : 1;
        unsigned int ipcm_sec_w_ctrl : 1;
        unsigned int ipcm_sec_r_ctrl : 1;
        unsigned int aximon_sec_w_ctrl : 1;
        unsigned int aximon_sec_r_ctrl : 1;
        unsigned int others_sec_w_ctrl : 1;
        unsigned int others_sec_r_ctrl : 1;
        unsigned int region2_sec_r_ctrl : 2;
        unsigned int uicc_sec_w_ctrl : 1;
        unsigned int uicc_sec_r_ctrl : 1;
        unsigned int reserved : 18;
    } bits;
    unsigned int u32;
}HI_SEC_CTRL0_T;
typedef union
{
    struct
    {
        unsigned int noddr_bypass : 1;
        unsigned int reserved : 15;
        unsigned int sci0_sec_w_ctrl : 1;
        unsigned int sci0_sec_r_ctrl : 1;
        unsigned int sci1_sec_w_ctrl : 1;
        unsigned int sci1_sec_r_ctrl : 1;
        unsigned int ipcm_s_sec_w_ctrl : 1;
        unsigned int ipcm_s_sec_r_ctrl : 1;
        unsigned int ipcm_ns_sec_w_ctrl : 1;
        unsigned int ipcm_ns_sec_r_ctrl : 1;
        unsigned int secram_sec_w_ctrl : 1;
        unsigned int secram_sec_r_ctrl : 1;
        unsigned int socp_sec_w_ctrl : 1;
        unsigned int socp_sec_r_ctrl : 1;
        unsigned int others_sec_w_ctrl : 1;
        unsigned int others_sec_r_ctrl : 1;
        unsigned int ap_sec_ctrl : 2;
    } bits;
    unsigned int u32;
}HI_SEC_CTRL1_T;
typedef union
{
    struct
    {
        unsigned int region1_filter_st_addr : 32;
    } bits;
    unsigned int u32;
}HI_SEC_CTRL2_T;
typedef union
{
    struct
    {
        unsigned int region1_filter_end_addr : 32;
    } bits;
    unsigned int u32;
}HI_SEC_CTRL3_T;
typedef union
{
    struct
    {
        unsigned int secram_filter_st_addr : 32;
    } bits;
    unsigned int u32;
}HI_SEC_CTRL4_T;
typedef union
{
    struct
    {
        unsigned int secram_filter_end_addr : 32;
    } bits;
    unsigned int u32;
}HI_SEC_CTRL5_T;
#ifndef __KERNEL__
HI_SET_GET(hi_crg_clken3_reserved_1,reserved_1,HI_CRG_CLKEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN3_OFFSET)
HI_SET_GET(hi_crg_clken3_bbe_refclk_en,bbe_refclk_en,HI_CRG_CLKEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN3_OFFSET)
HI_SET_GET(hi_crg_clken3_a9_refclk_en,a9_refclk_en,HI_CRG_CLKEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN3_OFFSET)
HI_SET_GET(hi_crg_clken3_hpm_clk_en,hpm_clk_en,HI_CRG_CLKEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN3_OFFSET)
HI_SET_GET(hi_crg_clken3_reserved_0,reserved_0,HI_CRG_CLKEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN3_OFFSET)
HI_SET_GET(hi_crg_clkdis3_reserved_1,reserved_1,HI_CRG_CLKDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS3_OFFSET)
HI_SET_GET(hi_crg_clkdis3_bbe_refclk_dis,bbe_refclk_dis,HI_CRG_CLKDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS3_OFFSET)
HI_SET_GET(hi_crg_clkdis3_a9_refclk_dis,a9_refclk_dis,HI_CRG_CLKDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS3_OFFSET)
HI_SET_GET(hi_crg_clkdis3_hpm_clk_dis,hpm_clk_dis,HI_CRG_CLKDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS3_OFFSET)
HI_SET_GET(hi_crg_clkdis3_reserved_0,reserved_0,HI_CRG_CLKDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS3_OFFSET)
HI_SET_GET(hi_crg_clkstat3_reserved_1,reserved_1,HI_CRG_CLKSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT3_OFFSET)
HI_SET_GET(hi_crg_clkstat3_bbe_refclk_status,bbe_refclk_status,HI_CRG_CLKSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT3_OFFSET)
HI_SET_GET(hi_crg_clkstat3_a9_refclk_status,a9_refclk_status,HI_CRG_CLKSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT3_OFFSET)
HI_SET_GET(hi_crg_clkstat3_hpm_clk_status,hpm_clk_status,HI_CRG_CLKSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT3_OFFSET)
HI_SET_GET(hi_crg_clkstat3_reserved_0,reserved_0,HI_CRG_CLKSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT3_OFFSET)
HI_SET_GET(hi_crg_clken4_bbe_pd_clk_en,bbe_pd_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_bbe_core_clk_en,bbe_core_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_reserved_2,reserved_2,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_mcpu_pd_clk_en,mcpu_pd_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_l2c_clk_en,l2c_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_reserved_1,reserved_1,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_mcpu_mbist_clk_en,mcpu_mbist_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_reserved_0,reserved_0,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_cicom0_clk_en,cicom0_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_cicom1_clk_en,cicom1_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_ipf_clk_en,ipf_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_upacc_clk_en,upacc_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_sci0_clk_en,sci0_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_sci1_clk_en,sci1_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_uicc_clk_en,uicc_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_uart_clk_en,uart_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_bbe_vic_clk_en,bbe_vic_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_cipher_clk_en,cipher_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_edmac_clk_en,edmac_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_ipcm_clk_en,ipcm_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_hsuart_clk_en,hsuart_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_aximem_clk_en,aximem_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_aximon_clk_en,aximon_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_timer_clk_en,timer_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clken4_wdog_clk_en,wdog_clk_en,HI_CRG_CLKEN4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_dsp0_pd_clk_dis,dsp0_pd_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_dsp0_core_clk_dis,dsp0_core_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_dsp0_dbg_clk_dis,dsp0_dbg_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_mcpu_pd_clk_dis,mcpu_pd_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_l2c_clk_dis,l2c_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_mcpu_dbg_clk_dis,mcpu_dbg_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_mcpu_mbist_clk_dis,mcpu_mbist_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_reserved,reserved,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_cicom0_clk_dis,cicom0_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_cicom1_clk_dis,cicom1_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_ipf_clk_dis,ipf_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_upacc_clk_dis,upacc_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_sci0_clk_dis,sci0_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_sci1_clk_dis,sci1_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_uicc_clk_dis,uicc_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_uart_clk_dis,uart_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_bbe_vic_clk_dis,bbe_vic_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_cipher_clk_dis,cipher_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_edmac_clk_dis,edmac_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_ipcm_clk_dis,ipcm_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_hsuart_clk_dis,hsuart_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_aximem_clk_dis,aximem_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_aximon_clk_dis,aximon_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_timer_clk_dis,timer_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkdis4_wdog_clk_dis,wdog_clk_dis,HI_CRG_CLKDIS4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_bbe_pd_clk_status,bbe_pd_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_bbe_core_clk_status,bbe_core_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_bbe_dbg_clk_status,bbe_dbg_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_mcpu_pd_clk_status,mcpu_pd_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_l2c_clk_status,l2c_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_mcpu_dbg_clk_status,mcpu_dbg_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_mcpu_mbist_clk_status,mcpu_mbist_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_reserved,reserved,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_cicom0_clk_status,cicom0_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_cicom1_clk_status,cicom1_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_ipf_clk_status,ipf_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_upacc_clk_status,upacc_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_sci0_clk_status,sci0_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_sci1_clk_status,sci1_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_uicc_clk_status,uicc_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_uart_clk_status,uart_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_bbe_vic_clk_status,bbe_vic_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_cipher_clk_status,cipher_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_edmac_clk_status,edmac_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_ipcm_clk_status,ipcm_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_hsuart_clk_status,hsuart_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_aximem_clk_status,aximem_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_aximon_clk_status,aximon_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_timer_clk_status,timer_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clkstat4_wdog_clk_status,wdog_clk_status,HI_CRG_CLKSTAT4_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT4_OFFSET)
HI_SET_GET(hi_crg_clken5_bbp_ao_clk_en,bbp_ao_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_bbpcommon_2a_clk_en,bbpcommon_2a_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_ltebbp_pd_clk_en,ltebbp_pd_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_g1bbp_pd_clk_en,g1bbp_pd_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_g2bbp_pd_clk_en,g2bbp_pd_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_twbbp_pd_clk_en,twbbp_pd_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_wbbp_pd_clk_en,wbbp_pd_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_irm_pd_clk_en,irm_pd_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_lbbp_axi_clk_en,lbbp_axi_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_lbbp_pdt_clk_en,lbbp_pdt_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_lbbp_pdf_clk_en,lbbp_pdf_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_lbbp_tdl_clk_en,lbbp_tdl_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_lbbp_vdl_clk_en,lbbp_vdl_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_lbbp_tds_clk_en,lbbp_tds_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_reserved_1,reserved_1,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_irm_turbo_clk_en,irm_turbo_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_irm_bbc_245m_clk_en,irm_bbc_245m_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_irm_wbbp_122m_clk_en,irm_wbbp_122m_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_twbbp_wbbp_122m_clk_en,twbbp_wbbp_122m_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_twbbp_wbbp_61m_clk_en,twbbp_wbbp_61m_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_twbbp_tbbp_122m_clk_en,twbbp_tbbp_122m_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_twbbp_tbbp_245m_clk_en,twbbp_tbbp_245m_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_wbbp_61m_clk_en,wbbp_61m_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_wbbp_122m_clk_en,wbbp_122m_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_wbbp_245m_clk_en,wbbp_245m_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_wbbp_axi_clk_en,wbbp_axi_clk_en,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clken5_reserved_0,reserved_0,HI_CRG_CLKEN5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKEN5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_bbp_ao_clk_dis,bbp_ao_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_bbpcommon_2a_clk_dis,bbpcommon_2a_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_lbbp_pd_clk_dis,lbbp_pd_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_g1bbp_pd_clk_dis,g1bbp_pd_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_g2bbp_pd_clk_dis,g2bbp_pd_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_twbbp_pd_clk_dis,twbbp_pd_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_wbbp_pd_clk_dis,wbbp_pd_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_irmbbp_pd_clk_dis,irmbbp_pd_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_lbbp_axi_clk_dis,lbbp_axi_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_lbbp_pdt_clk_dis,lbbp_pdt_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_lbbp_pdf_clk_dis,lbbp_pdf_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_lbbp_tdl_clk_dis,lbbp_tdl_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_lbbp_vdl_clk_dis,lbbp_vdl_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_lbbp_tds_clk_dis,lbbp_tds_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_reserved_1,reserved_1,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_irm_turbo_clk_dis,irm_turbo_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_irm_bbc_245m_clk_dis,irm_bbc_245m_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_irm_wbbp_clk_dis,irm_wbbp_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_twbbp_wbbp_122m_clk_dis,twbbp_wbbp_122m_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_twbbp_wbbp_61m_clk_dis,twbbp_wbbp_61m_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_twbbp_tbbp_122m_clk_dis,twbbp_tbbp_122m_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_twbbp_tbbp_245m_clk_dis,twbbp_tbbp_245m_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_wbbp_61m_clk_dis,wbbp_61m_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_wbbp_122m_clk_dis,wbbp_122m_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_wbbp_245m_clk_dis,wbbp_245m_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_wbbp_axi_clk_dis,wbbp_axi_clk_dis,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkdis5_reserved_0,reserved_0,HI_CRG_CLKDIS5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIS5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_bbp_ao_clk_stat,bbp_ao_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_bbpcom_clk_stat,bbpcom_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_lbbp_pd_clk_stat,lbbp_pd_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_g1bbp_pd_clk_stat,g1bbp_pd_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_g2bbp_pd_clk_stat,g2bbp_pd_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_twbbp_pd_clk_stat,twbbp_pd_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_wbbp_pd_clk_stat,wbbp_pd_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_irmbbp_pd_clk_stat,irmbbp_pd_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_lbbp_axi_clk_stat,lbbp_axi_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_lbbp_pdt_clk_stat,lbbp_pdt_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_lbbp_pdf_clk_stat,lbbp_pdf_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_lbbp_tdl_clk_stat,lbbp_tdl_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_lbbp_vdl_clk_stat,lbbp_vdl_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_lbbp_tds_clk_stat,lbbp_tds_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_reserved_1,reserved_1,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_irm_turbo_clk_stat,irm_turbo_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_irm_bbc_245m_clk_stat,irm_bbc_245m_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_irm_wbbp_clk_stat,irm_wbbp_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_twbbp_wbbp_122m_clk_stat,twbbp_wbbp_122m_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_twbbp_wbbp_61m_clk_stat,twbbp_wbbp_61m_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_twbbp_tbbp_122m_clk_stat,twbbp_tbbp_122m_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_twbbp_tbbp_245m_clk_stat,twbbp_tbbp_245m_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_wbbp_61m_clk_stat,wbbp_61m_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_wbbp_122m_clk_stat,wbbp_122m_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_wbbp_245m_clk_stat,wbbp_245m_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_wbbp_axi_clk_stat,wbbp_axi_clk_stat,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_clkstat5_reserved_0,reserved_0,HI_CRG_CLKSTAT5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKSTAT5_OFFSET)
HI_SET_GET(hi_crg_srsten1_bbe_pd_srst_en,bbe_pd_srst_en,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_bbe_core_srst_en,bbe_core_srst_en,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_bbe_dbg_srst_en,bbe_dbg_srst_en,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_reserved_4,reserved_4,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_moda9_cpu_srst_en,moda9_cpu_srst_en,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_moda9_dbg_srst_en,moda9_dbg_srst_en,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_moda9_peri_srst_en,moda9_peri_srst_en,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_moda9_scu_srst_en,moda9_scu_srst_en,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_moda9_ptm_srst_en,moda9_ptm_srst_en,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_moda9_wd_srst_en,moda9_wd_srst_en,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_reserved_3,reserved_3,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_mdma9_pd_srst_en,mdma9_pd_srst_en,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_reserved_2,reserved_2,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_uicc_srst_en,uicc_srst_en,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_reserved_1,reserved_1,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_amon_soc_srst_en,amon_soc_srst_en,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_reserved_0,reserved_0,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srsten1_hpm_srst_en,hpm_srst_en,HI_CRG_SRSTEN1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_bbe_pd_srst_dis,bbe_pd_srst_dis,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_bbe_core_srst_dis,bbe_core_srst_dis,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_bbe_dbg_srst_dis,bbe_dbg_srst_dis,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_reserved_4,reserved_4,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_moda9_core_srst_dis,moda9_core_srst_dis,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_moda9_dbg_srst_dis,moda9_dbg_srst_dis,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_moda9_peri_srst_dis,moda9_peri_srst_dis,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_moda9_scu_srst_dis,moda9_scu_srst_dis,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_moda9_ptm_srst_dis,moda9_ptm_srst_dis,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_moda9_wd_srst_dis,moda9_wd_srst_dis,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_reserved_3,reserved_3,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_mdma9_pd_srst_dis,mdma9_pd_srst_dis,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_reserved_2,reserved_2,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_uicc_srst_dis,uicc_srst_dis,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_reserved_1,reserved_1,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_amon_soc_srst_dis,amon_soc_srst_dis,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_reserved_0,reserved_0,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srstdis1_hpm_srst_dis,hpm_srst_dis,HI_CRG_SRSTDIS1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS1_OFFSET)
HI_SET_GET(hi_crg_srststat1_bbe_pd_srst_status,bbe_pd_srst_status,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_bbe_core_srst_status,bbe_core_srst_status,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_bbe_dbg_srst_status,bbe_dbg_srst_status,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_reserved_4,reserved_4,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_moda9_core_srst_status,moda9_core_srst_status,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_moda9_dbg_srst_status,moda9_dbg_srst_status,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_moda9_peri_srst_status,moda9_peri_srst_status,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_moda9_scu_srst_status,moda9_scu_srst_status,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_moda9_ptm_srst_status,moda9_ptm_srst_status,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_moda9_wd_srst_status,moda9_wd_srst_status,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_reserved_3,reserved_3,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_mdma9_pd_srst_status,mdma9_pd_srst_status,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_reserved_2,reserved_2,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_uicc_srst_status,uicc_srst_status,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_reserved_1,reserved_1,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_amon_soc_srst_status,amon_soc_srst_status,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_reserved_0,reserved_0,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srststat1_hpm_srst_status,hpm_srst_status,HI_CRG_SRSTSTAT1_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT1_OFFSET)
HI_SET_GET(hi_crg_srsten3_bbp_crg_srst_en,bbp_crg_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_bbpcommon_2a_srst_en,bbpcommon_2a_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_lbbp_pd_srst_en,lbbp_pd_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_g1bbp_pd_srst_en,g1bbp_pd_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_g2bbp_pd_srst_en,g2bbp_pd_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_twbbp_pd_srst_en,twbbp_pd_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_wbbp_pd_srst_en,wbbp_pd_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_irm_pd_srst_en,irm_pd_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_bbc_lbbp_pdt_srst_en,bbc_lbbp_pdt_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_bbc_lbbp_pdf_srst_en,bbc_lbbp_pdf_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_bbc_lbbp_tdl_srst_en,bbc_lbbp_tdl_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_bbc_tbbp_245m_srst_en,bbc_tbbp_245m_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_bbc_twbbp_122m_srst_en,bbc_twbbp_122m_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_bbc_g1bbp_104m_srst_en,bbc_g1bbp_104m_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_bbc_g2bbp_104m_srst_en,bbc_g2bbp_104m_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_reserved,reserved,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srsten3_abb_srst_en,abb_srst_en,HI_CRG_SRSTEN3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTEN3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_bbp_crg_srst_dis,bbp_crg_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_bbpcommon_2a_pd_srst_dis,bbpcommon_2a_pd_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_lbbp_pd_srst_dis,lbbp_pd_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_g1bbp_pd_srst_dis,g1bbp_pd_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_g2bbp_pd_srst_dis,g2bbp_pd_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_twbbp_pd_srst_dis,twbbp_pd_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_wbbp_pd_srst_dis,wbbp_pd_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_irm_pd_srst_dis,irm_pd_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_bbc_lbbp_pdt_srst_dis,bbc_lbbp_pdt_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_bbc_lbbp_pdf_srst_dis,bbc_lbbp_pdf_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_bbc_lbbp_tdl_srst_dis,bbc_lbbp_tdl_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_bbc_tbbp_245m_srst_dis,bbc_tbbp_245m_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_bbc_twbbp_122m_srst_dis,bbc_twbbp_122m_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_bbc_g1bbp_104m_srst_dis,bbc_g1bbp_104m_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_bbc_g2bbp_104m_srst_dis,bbc_g2bbp_104m_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_reserved,reserved,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srstdis3_abb_srst_dis,abb_srst_dis,HI_CRG_SRSTDIS3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTDIS3_OFFSET)
HI_SET_GET(hi_crg_srststat3_bbp_crg_srst_stat,bbp_crg_srst_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_bbpcommon_2a_srst_stat,bbpcommon_2a_srst_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_lbbp_pd_srst_stat,lbbp_pd_srst_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_g1bbp_pd_srst_stat,g1bbp_pd_srst_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_g2bbp_pd_srst_stat,g2bbp_pd_srst_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_twbbp_pd_srst_stat,twbbp_pd_srst_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_wbbp_pd_srst_stat,wbbp_pd_srst_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_irm_pd_srst_stat,irm_pd_srst_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_bbc_lbbp_pdt_srstctrl_stat,bbc_lbbp_pdt_srstctrl_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_bbc_lbbp_pdf_srstctrl_stat,bbc_lbbp_pdf_srstctrl_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_bbc_lbbp_tdl_srstctrl_stat,bbc_lbbp_tdl_srstctrl_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_bbc_tbbp_245m_srstctrl_stat,bbc_tbbp_245m_srstctrl_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_bbc_twbbp_122m_srstctrl_stat,bbc_twbbp_122m_srstctrl_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_bbc_g1bbp_104m_srstctrl_stat,bbc_g1bbp_104m_srstctrl_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_bbc_g2bbp_104m_srstctrl_stat,bbc_g2bbp_104m_srstctrl_stat,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_reserved,reserved,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_srststat3_abb_srst_status,abb_srst_status,HI_CRG_SRSTSTAT3_T,HI_SYSSC_BASE_ADDR, HI_CRG_SRSTSTAT3_OFFSET)
HI_SET_GET(hi_crg_clkdiv2_reserved_4,reserved_4,HI_CRG_CLKDIV2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV2_OFFSET)
HI_SET_GET(hi_crg_clkdiv2_mdma9_clk_div,mdma9_clk_div,HI_CRG_CLKDIV2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV2_OFFSET)
HI_SET_GET(hi_crg_clkdiv2_a92slow_freqmode,a92slow_freqmode,HI_CRG_CLKDIV2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV2_OFFSET)
HI_SET_GET(hi_crg_clkdiv2_reserved_3,reserved_3,HI_CRG_CLKDIV2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV2_OFFSET)
HI_SET_GET(hi_crg_clkdiv2_a92fast_freqmode,a92fast_freqmode,HI_CRG_CLKDIV2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV2_OFFSET)
HI_SET_GET(hi_crg_clkdiv2_reserved_2,reserved_2,HI_CRG_CLKDIV2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV2_OFFSET)
HI_SET_GET(hi_crg_clkdiv2_a9_clksw_req,a9_clksw_req,HI_CRG_CLKDIV2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV2_OFFSET)
HI_SET_GET(hi_crg_clkdiv2_reserved_1,reserved_1,HI_CRG_CLKDIV2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV2_OFFSET)
HI_SET_GET(hi_crg_clkdiv2_apb_freqmode,apb_freqmode,HI_CRG_CLKDIV2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV2_OFFSET)
HI_SET_GET(hi_crg_clkdiv2_reserved_0,reserved_0,HI_CRG_CLKDIV2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV2_OFFSET)
HI_SET_GET(hi_crg_clkdiv5_bbe_clk_div_num,bbe_clk_div_num,HI_CRG_CLKDIV5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV5_OFFSET)
HI_SET_GET(hi_crg_clkdiv5_reserved_2,reserved_2,HI_CRG_CLKDIV5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV5_OFFSET)
HI_SET_GET(hi_crg_clkdiv5_bbe_freqmode,bbe_freqmode,HI_CRG_CLKDIV5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV5_OFFSET)
HI_SET_GET(hi_crg_clkdiv5_reserved_1,reserved_1,HI_CRG_CLKDIV5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV5_OFFSET)
HI_SET_GET(hi_crg_clkdiv5_cipher_clk_div,cipher_clk_div,HI_CRG_CLKDIV5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV5_OFFSET)
HI_SET_GET(hi_crg_clkdiv5_reserved_0,reserved_0,HI_CRG_CLKDIV5_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLKDIV5_OFFSET)
HI_SET_GET(hi_crg_clk_sel2_timer_clk_sel,timer_clk_sel,HI_CRG_CLK_SEL2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL2_OFFSET)
HI_SET_GET(hi_crg_clk_sel2_gps_tcxo_clk_sel,gps_tcxo_clk_sel,HI_CRG_CLK_SEL2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL2_OFFSET)
HI_SET_GET(hi_crg_clk_sel2_hpm_refclk_sel,hpm_refclk_sel,HI_CRG_CLK_SEL2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL2_OFFSET)
HI_SET_GET(hi_crg_clk_sel2_reserved_1,reserved_1,HI_CRG_CLK_SEL2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL2_OFFSET)
HI_SET_GET(hi_crg_clk_sel2_sc_a9wdt_rst_en,sc_a9wdt_rst_en,HI_CRG_CLK_SEL2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL2_OFFSET)
HI_SET_GET(hi_crg_clk_sel2_reserved_0,reserved_0,HI_CRG_CLK_SEL2_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL2_OFFSET)
HI_SET_GET(hi_crg_clk_sel3_abb_tcxo_clk_sel,abb_tcxo_clk_sel,HI_CRG_CLK_SEL3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL3_OFFSET)
HI_SET_GET(hi_crg_clk_sel3_bbppll_refclk_sel,bbppll_refclk_sel,HI_CRG_CLK_SEL3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL3_OFFSET)
HI_SET_GET(hi_crg_clk_sel3_bbp_tcxo_clk_sel,bbp_tcxo_clk_sel,HI_CRG_CLK_SEL3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL3_OFFSET)
HI_SET_GET(hi_crg_clk_sel3_ch0_tcxo_clk_sel,ch0_tcxo_clk_sel,HI_CRG_CLK_SEL3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL3_OFFSET)
HI_SET_GET(hi_crg_clk_sel3_ch1_tcxo_clk_sel,ch1_tcxo_clk_sel,HI_CRG_CLK_SEL3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL3_OFFSET)
HI_SET_GET(hi_crg_clk_sel3_g1bbp_104m_clk_sel,g1bbp_104m_clk_sel,HI_CRG_CLK_SEL3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL3_OFFSET)
HI_SET_GET(hi_crg_clk_sel3_g2bbp_104m_clk_sel,g2bbp_104m_clk_sel,HI_CRG_CLK_SEL3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL3_OFFSET)
HI_SET_GET(hi_crg_clk_sel3_tdl_clk_sel,tdl_clk_sel,HI_CRG_CLK_SEL3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL3_OFFSET)
HI_SET_GET(hi_crg_clk_sel3_lbbp_vdl_clk_sel,lbbp_vdl_clk_sel,HI_CRG_CLK_SEL3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL3_OFFSET)
HI_SET_GET(hi_crg_clk_sel3_lbbp_pdf_clk_sel,lbbp_pdf_clk_sel,HI_CRG_CLK_SEL3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL3_OFFSET)
HI_SET_GET(hi_crg_clk_sel3_reserved,reserved,HI_CRG_CLK_SEL3_T,HI_SYSSC_BASE_ADDR, HI_CRG_CLK_SEL3_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg0_pll_en,pll_en,HI_CRG_A9PLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg0_pll_bp,pll_bp,HI_CRG_A9PLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg0_pll_refdiv,pll_refdiv,HI_CRG_A9PLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg0_pll_intprog,pll_intprog,HI_CRG_A9PLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg0_pll_postdiv1,pll_postdiv1,HI_CRG_A9PLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg0_pll_postdiv2,pll_postdiv2,HI_CRG_A9PLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg0_pll_lock,pll_lock,HI_CRG_A9PLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg0_reserved,reserved,HI_CRG_A9PLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg1_pll_fracdiv,pll_fracdiv,HI_CRG_A9PLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg1_pll_int_mod,pll_int_mod,HI_CRG_A9PLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg1_pll_cfg_vld,pll_cfg_vld,HI_CRG_A9PLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg1_pll_clk_gt,pll_clk_gt,HI_CRG_A9PLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg1_reserved,reserved,HI_CRG_A9PLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg2_pll_ssc_reset,pll_ssc_reset,HI_CRG_A9PLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg2_pll_ssc_disable,pll_ssc_disable,HI_CRG_A9PLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg2_pll_ssc_downspread,pll_ssc_downspread,HI_CRG_A9PLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg2_pll_ssc_spread,pll_ssc_spread,HI_CRG_A9PLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg2_pll_ssc_divval,pll_ssc_divval,HI_CRG_A9PLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_a9pll_cfg2_reserved,reserved,HI_CRG_A9PLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_A9PLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg0_pll_en,pll_en,HI_CRG_DSPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg0_pll_bp,pll_bp,HI_CRG_DSPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg0_pll_refdiv,pll_refdiv,HI_CRG_DSPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg0_pll_intprog,pll_intprog,HI_CRG_DSPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg0_pll_postdiv1,pll_postdiv1,HI_CRG_DSPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg0_pll_postdiv2,pll_postdiv2,HI_CRG_DSPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg0_pll_lock,pll_lock,HI_CRG_DSPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg0_reserved,reserved,HI_CRG_DSPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg1_pll_fracdiv,pll_fracdiv,HI_CRG_DSPPLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg1_pll_int_mod,pll_int_mod,HI_CRG_DSPPLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg1_pll_cfg_vld,pll_cfg_vld,HI_CRG_DSPPLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg1_pll_clk_gt,pll_clk_gt,HI_CRG_DSPPLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg1_reserved,reserved,HI_CRG_DSPPLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg2_pll_ssc_reset,pll_ssc_reset,HI_CRG_DSPPLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg2_pll_ssc_disable,pll_ssc_disable,HI_CRG_DSPPLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg2_pll_ssc_downspread,pll_ssc_downspread,HI_CRG_DSPPLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg2_pll_ssc_spread,pll_ssc_spread,HI_CRG_DSPPLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg2_pll_ssc_divval,pll_ssc_divval,HI_CRG_DSPPLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_dsppll_cfg2_reserved,reserved,HI_CRG_DSPPLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_DSPPLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg0_pll_en,pll_en,HI_CRG_BBPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg0_pll_bp,pll_bp,HI_CRG_BBPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg0_pll_refdiv,pll_refdiv,HI_CRG_BBPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg0_pll_intprog,pll_intprog,HI_CRG_BBPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg0_pll_postdiv1,pll_postdiv1,HI_CRG_BBPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg0_pll_postdiv2,pll_postdiv2,HI_CRG_BBPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg0_pll_lock,pll_lock,HI_CRG_BBPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg0_reserved,reserved,HI_CRG_BBPPLL_CFG0_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG0_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg1_pll_fracdiv,pll_fracdiv,HI_CRG_BBPPLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg1_pll_int_mod,pll_int_mod,HI_CRG_BBPPLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg1_pll_cfg_vld,pll_cfg_vld,HI_CRG_BBPPLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg1_pll_clk_gt,pll_clk_gt,HI_CRG_BBPPLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg1_reserved,reserved,HI_CRG_BBPPLL_CFG1_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG1_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg2_pll_ssc_reset,pll_ssc_reset,HI_CRG_BBPPLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg2_pll_ssc_disable,pll_ssc_disable,HI_CRG_BBPPLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg2_pll_ssc_downspread,pll_ssc_downspread,HI_CRG_BBPPLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg2_pll_ssc_spread,pll_ssc_spread,HI_CRG_BBPPLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg2_pll_ssc_divval,pll_ssc_divval,HI_CRG_BBPPLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG2_OFFSET)
HI_SET_GET(hi_crg_bbppll_cfg2_reserved,reserved,HI_CRG_BBPPLL_CFG2_T,HI_SYSSC_BASE_ADDR, HI_CRG_BBPPLL_CFG2_OFFSET)
HI_SET_GET(hi_sc_ctrl0_mcpu_boot_remap_clear,mcpu_boot_remap_clear,HI_SC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL0_OFFSET)
HI_SET_GET(hi_sc_ctrl0_reserved,reserved,HI_SC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL0_OFFSET)
HI_SET_GET(hi_sc_ctrl2_wdt_clk_en,wdt_clk_en,HI_SC_CTRL2_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL2_OFFSET)
HI_SET_GET(hi_sc_ctrl2_reserved_1,reserved_1,HI_SC_CTRL2_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL2_OFFSET)
HI_SET_GET(hi_sc_ctrl2_wdt_en_ov,wdt_en_ov,HI_SC_CTRL2_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL2_OFFSET)
HI_SET_GET(hi_sc_ctrl2_reserved_0,reserved_0,HI_SC_CTRL2_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL2_OFFSET)
HI_SET_GET(hi_sc_ctrl2_wdt_en_ctrl,wdt_en_ctrl,HI_SC_CTRL2_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL2_OFFSET)
HI_SET_GET(hi_sc_ctrl3_reserved_3,reserved_3,HI_SC_CTRL3_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL3_OFFSET)
HI_SET_GET(hi_sc_ctrl3_amon_monitor_start,amon_monitor_start,HI_SC_CTRL3_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL3_OFFSET)
HI_SET_GET(hi_sc_ctrl3_reserved_2,reserved_2,HI_SC_CTRL3_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL3_OFFSET)
HI_SET_GET(hi_sc_ctrl3_dsp0_uart_en,dsp0_uart_en,HI_SC_CTRL3_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL3_OFFSET)
HI_SET_GET(hi_sc_ctrl3_reserved_1,reserved_1,HI_SC_CTRL3_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL3_OFFSET)
HI_SET_GET(hi_sc_ctrl3_reserved_0,reserved_0,HI_SC_CTRL3_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL3_OFFSET)
HI_SET_GET(hi_sc_ctrl4_cicom0_sel_mod,cicom0_sel_mod,HI_SC_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL4_OFFSET)
HI_SET_GET(hi_sc_ctrl4_cicom1_sel_mod,cicom1_sel_mod,HI_SC_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL4_OFFSET)
HI_SET_GET(hi_sc_ctrl4_reserved,reserved,HI_SC_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL4_OFFSET)
HI_SET_GET(hi_sc_ctrl5_reserved,reserved,HI_SC_CTRL5_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL5_OFFSET)
HI_SET_GET(hi_sc_ctrl6_reserved,reserved,HI_SC_CTRL6_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL6_OFFSET)
HI_SET_GET(hi_sc_ctrl9_reserved,reserved,HI_SC_CTRL9_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL9_OFFSET)
HI_SET_GET(hi_sc_ctrl9_sw_dsp0_boot_addr,sw_dsp0_boot_addr,HI_SC_CTRL9_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL9_OFFSET)
HI_SET_GET(hi_sc_ctrl10_reserved,reserved,HI_SC_CTRL10_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL10_OFFSET)
HI_SET_GET(hi_sc_ctrl11_reserved_2,reserved_2,HI_SC_CTRL11_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL11_OFFSET)
HI_SET_GET(hi_sc_ctrl11_moda9_cfgnmfi,moda9_cfgnmfi,HI_SC_CTRL11_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL11_OFFSET)
HI_SET_GET(hi_sc_ctrl11_moda9_cfgsdisable,moda9_cfgsdisable,HI_SC_CTRL11_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL11_OFFSET)
HI_SET_GET(hi_sc_ctrl11_moda9_cp15sdisable,moda9_cp15sdisable,HI_SC_CTRL11_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL11_OFFSET)
HI_SET_GET(hi_sc_ctrl11_moda9_pwrctli0,moda9_pwrctli0,HI_SC_CTRL11_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL11_OFFSET)
HI_SET_GET(hi_sc_ctrl11_reserved_1,reserved_1,HI_SC_CTRL11_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL11_OFFSET)
HI_SET_GET(hi_sc_ctrl11_moda9_l2_waysize,moda9_l2_waysize,HI_SC_CTRL11_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL11_OFFSET)
HI_SET_GET(hi_sc_ctrl11_reserved_0,reserved_0,HI_SC_CTRL11_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL11_OFFSET)
HI_SET_GET(hi_sc_ctrl11_moda9_l2_regfilebase,moda9_l2_regfilebase,HI_SC_CTRL11_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL11_OFFSET)
HI_SET_GET(hi_sc_ctrl12_reserved,reserved,HI_SC_CTRL12_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL12_OFFSET)
HI_SET_GET(hi_sc_ctrl13_reserved_1,reserved_1,HI_SC_CTRL13_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL13_OFFSET)
HI_SET_GET(hi_sc_ctrl13_ocdhaltonreset,ocdhaltonreset,HI_SC_CTRL13_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL13_OFFSET)
HI_SET_GET(hi_sc_ctrl13_runstall,runstall,HI_SC_CTRL13_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL13_OFFSET)
HI_SET_GET(hi_sc_ctrl13_statvectorsel,statvectorsel,HI_SC_CTRL13_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL13_OFFSET)
HI_SET_GET(hi_sc_ctrl13_breaksync_en,breaksync_en,HI_SC_CTRL13_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL13_OFFSET)
HI_SET_GET(hi_sc_ctrl13_crosstrig_en,crosstrig_en,HI_SC_CTRL13_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL13_OFFSET)
HI_SET_GET(hi_sc_ctrl13_reserved_0,reserved_0,HI_SC_CTRL13_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL13_OFFSET)
HI_SET_GET(hi_sc_ctrl17_hpm_clk_div,hpm_clk_div,HI_SC_CTRL17_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL17_OFFSET)
HI_SET_GET(hi_sc_ctrl17_reserved_1,reserved_1,HI_SC_CTRL17_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL17_OFFSET)
HI_SET_GET(hi_sc_ctrl17_hpm_en,hpm_en,HI_SC_CTRL17_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL17_OFFSET)
HI_SET_GET(hi_sc_ctrl17_hpmx_en,hpmx_en,HI_SC_CTRL17_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL17_OFFSET)
HI_SET_GET(hi_sc_ctrl17_reserved_0,reserved_0,HI_SC_CTRL17_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL17_OFFSET)
HI_SET_GET(hi_sc_ctrl20_axi_mem_gatedclock_en,axi_mem_gatedclock_en,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_cicom0_auto_clk_gate_en,cicom0_auto_clk_gate_en,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_cicom0_soft_gate_clk_en,cicom0_soft_gate_clk_en,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_cicom1_auto_clk_gate_en,cicom1_auto_clk_gate_en,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_cicom1_soft_gate_clk_en,cicom1_soft_gate_clk_en,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_hs_uart_gatedclock_en,hs_uart_gatedclock_en,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_uart_gatedclock_en,uart_gatedclock_en,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_reserved_2,reserved_2,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_uicc_gatedclock_en,uicc_gatedclock_en,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_uicc_ss_scaledown_mode,uicc_ss_scaledown_mode,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_upacc_auto_clk_gate_en,upacc_auto_clk_gate_en,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_upacc_soft_gate_clk_en,upacc_soft_gate_clk_en,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_bbe16_cg_en,bbe16_cg_en,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_reserved_1,reserved_1,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_ipcm_auto_clk_gate_en,ipcm_auto_clk_gate_en,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_ipcm_soft_gate_clk_en,ipcm_soft_gate_clk_en,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_reserved_0,reserved_0,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl20_sysreg_auto_gate_en,sysreg_auto_gate_en,HI_SC_CTRL20_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL20_OFFSET)
HI_SET_GET(hi_sc_ctrl21_reserved_6,reserved_6,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_timer_gatedclock_en,timer_gatedclock_en,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_reserved_5,reserved_5,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_dw_axi_glb_cg_en,dw_axi_glb_cg_en,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_dw_axi_mst_cg_en,dw_axi_mst_cg_en,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_reserved_4,reserved_4,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_dw_axi_bbphy_cg_en,dw_axi_bbphy_cg_en,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_reserved_3,reserved_3,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_dw_x2x_async_cg_en,dw_x2x_async_cg_en,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_reserved_2,reserved_2,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_dw_x2h_qsync_cg_en,dw_x2h_qsync_cg_en,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_dw_hmx_cg_en,dw_hmx_cg_en,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_dw_x2p_cg_en,dw_x2p_cg_en,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_dw_gs_cg_en,dw_gs_cg_en,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_ashb_gatedclock_en,ashb_gatedclock_en,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_dw_ahb_mst_gatedclock_en,dw_ahb_mst_gatedclock_en,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_reserved_1,reserved_1,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_edmac_autogated_clk_en,edmac_autogated_clk_en,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl21_reserved_0,reserved_0,HI_SC_CTRL21_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL21_OFFSET)
HI_SET_GET(hi_sc_ctrl22_reserved_1,reserved_1,HI_SC_CTRL22_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL22_OFFSET)
HI_SET_GET(hi_sc_ctrl22_bbe16_ema,bbe16_ema,HI_SC_CTRL22_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL22_OFFSET)
HI_SET_GET(hi_sc_ctrl22_bbe16_emaw,bbe16_emaw,HI_SC_CTRL22_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL22_OFFSET)
HI_SET_GET(hi_sc_ctrl22_bbe16_emas,bbe16_emas,HI_SC_CTRL22_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL22_OFFSET)
HI_SET_GET(hi_sc_ctrl22_reserved_0,reserved_0,HI_SC_CTRL22_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL22_OFFSET)
HI_SET_GET(hi_sc_ctrl23_axi_mem_ema,axi_mem_ema,HI_SC_CTRL23_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL23_OFFSET)
HI_SET_GET(hi_sc_ctrl23_axi_mem_emaw,axi_mem_emaw,HI_SC_CTRL23_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL23_OFFSET)
HI_SET_GET(hi_sc_ctrl23_axi_mem_emas,axi_mem_emas,HI_SC_CTRL23_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL23_OFFSET)
HI_SET_GET(hi_sc_ctrl23_reserved_1,reserved_1,HI_SC_CTRL23_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL23_OFFSET)
HI_SET_GET(hi_sc_ctrl23_soc_mem_ema,soc_mem_ema,HI_SC_CTRL23_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL23_OFFSET)
HI_SET_GET(hi_sc_ctrl23_soc_mem_spram_emaw,soc_mem_spram_emaw,HI_SC_CTRL23_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL23_OFFSET)
HI_SET_GET(hi_sc_ctrl23_soc_mem_spram_emas,soc_mem_spram_emas,HI_SC_CTRL23_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL23_OFFSET)
HI_SET_GET(hi_sc_ctrl23_soc_mem_tpram_emab,soc_mem_tpram_emab,HI_SC_CTRL23_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL23_OFFSET)
HI_SET_GET(hi_sc_ctrl23_soc_mem_tpram_emasa,soc_mem_tpram_emasa,HI_SC_CTRL23_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL23_OFFSET)
HI_SET_GET(hi_sc_ctrl23_soc_mem_dpram_emaw,soc_mem_dpram_emaw,HI_SC_CTRL23_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL23_OFFSET)
HI_SET_GET(hi_sc_ctrl23_soc_mem_dpram_emas,soc_mem_dpram_emas,HI_SC_CTRL23_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL23_OFFSET)
HI_SET_GET(hi_sc_ctrl23_reserved_0,reserved_0,HI_SC_CTRL23_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL23_OFFSET)
HI_SET_GET(hi_sc_ctrl24_reserved_1,reserved_1,HI_SC_CTRL24_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL24_OFFSET)
HI_SET_GET(hi_sc_ctrl24_moda9_hs_mem_adjust,moda9_hs_mem_adjust,HI_SC_CTRL24_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL24_OFFSET)
HI_SET_GET(hi_sc_ctrl24_reserved_0,reserved_0,HI_SC_CTRL24_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL24_OFFSET)
HI_SET_GET(hi_sc_ctrl24_moda9_l2_ema,moda9_l2_ema,HI_SC_CTRL24_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL24_OFFSET)
HI_SET_GET(hi_sc_ctrl24_moda9_l2_emaw,moda9_l2_emaw,HI_SC_CTRL24_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL24_OFFSET)
HI_SET_GET(hi_sc_ctrl24_moda9_l2_emas,moda9_l2_emas,HI_SC_CTRL24_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL24_OFFSET)
HI_SET_GET(hi_sc_ctrl25_reserved,reserved,HI_SC_CTRL25_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL25_OFFSET)
HI_SET_GET(hi_sc_ctrl26_reserved,reserved,HI_SC_CTRL26_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL26_OFFSET)
HI_SET_GET(hi_sc_ctrl28_acp_filter_start,acp_filter_start,HI_SC_CTRL28_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL28_OFFSET)
HI_SET_GET(hi_sc_ctrl29_acp_filter_end,acp_filter_end,HI_SC_CTRL29_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL29_OFFSET)
HI_SET_GET(hi_sc_ctrl30_reserved,reserved,HI_SC_CTRL30_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL30_OFFSET)
HI_SET_GET(hi_sc_ctrl45_uicc_ic_usb_vbusvalid,uicc_ic_usb_vbusvalid,HI_SC_CTRL45_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL45_OFFSET)
HI_SET_GET(hi_sc_ctrl45_reserved,reserved,HI_SC_CTRL45_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL45_OFFSET)
HI_SET_GET(hi_sc_ctrl52_dsp0_nmi,dsp0_nmi,HI_SC_CTRL52_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL52_OFFSET)
HI_SET_GET(hi_sc_ctrl52_reserved,reserved,HI_SC_CTRL52_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL52_OFFSET)
HI_SET_GET(hi_sc_ctrl55_reserved_7,reserved_7,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_uicc_ret1n,uicc_ret1n,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_reserved_6,reserved_6,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_amon_soc_ret1n,amon_soc_ret1n,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_reserved_5,reserved_5,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_edmac_colldisn,edmac_colldisn,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_reserved_4,reserved_4,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_amon_soc_colldisn,amon_soc_colldisn,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_reserved_3,reserved_3,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_ipf_ret1n,ipf_ret1n,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_ipf_colldisn,ipf_colldisn,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_cipher_ret1n,cipher_ret1n,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_cipher_colldisn,cipher_colldisn,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_reserved_2,reserved_2,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_hs_uart_ret1n,hs_uart_ret1n,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_reserved_1,reserved_1,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_edmac_ret1n,edmac_ret1n,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl55_reserved_0,reserved_0,HI_SC_CTRL55_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL55_OFFSET)
HI_SET_GET(hi_sc_ctrl56_prior_level,prior_level,HI_SC_CTRL56_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL56_OFFSET)
HI_SET_GET(hi_sc_ctrl56_gatedclock_en,gatedclock_en,HI_SC_CTRL56_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL56_OFFSET)
HI_SET_GET(hi_sc_ctrl56_dw_axi_rs_gatedclock_en,dw_axi_rs_gatedclock_en,HI_SC_CTRL56_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL56_OFFSET)
HI_SET_GET(hi_sc_ctrl56_dw_axi_gs_gatedclock_en,dw_axi_gs_gatedclock_en,HI_SC_CTRL56_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL56_OFFSET)
HI_SET_GET(hi_sc_ctrl56_overf_prot,overf_prot,HI_SC_CTRL56_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL56_OFFSET)
HI_SET_GET(hi_sc_ctrl56_reserved,reserved,HI_SC_CTRL56_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL56_OFFSET)
HI_SET_GET(hi_sc_ctrl56_atpram_ctrl,atpram_ctrl,HI_SC_CTRL56_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL56_OFFSET)
HI_SET_GET(hi_sc_ctrl57_soc2lte_tbd,soc2lte_tbd,HI_SC_CTRL57_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL57_OFFSET)
HI_SET_GET(hi_sc_ctrl57_reserved,reserved,HI_SC_CTRL57_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL57_OFFSET)
HI_SET_GET(hi_sc_ctrl68_moda9_l2_ret1n,moda9_l2_ret1n,HI_SC_CTRL68_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL68_OFFSET)
HI_SET_GET(hi_sc_ctrl68_moda9_l2_ret2n,moda9_l2_ret2n,HI_SC_CTRL68_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL68_OFFSET)
HI_SET_GET(hi_sc_ctrl68_moda9_l2_pgen,moda9_l2_pgen,HI_SC_CTRL68_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL68_OFFSET)
HI_SET_GET(hi_sc_ctrl68_reserved_2,reserved_2,HI_SC_CTRL68_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL68_OFFSET)
HI_SET_GET(hi_sc_ctrl68_dsp0_ret1n,dsp0_ret1n,HI_SC_CTRL68_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL68_OFFSET)
HI_SET_GET(hi_sc_ctrl68_dsp0_ret2n,dsp0_ret2n,HI_SC_CTRL68_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL68_OFFSET)
HI_SET_GET(hi_sc_ctrl68_dsp0_pgen,dsp0_pgen,HI_SC_CTRL68_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL68_OFFSET)
HI_SET_GET(hi_sc_ctrl68_reserved_1,reserved_1,HI_SC_CTRL68_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL68_OFFSET)
HI_SET_GET(hi_sc_ctrl68_pd_axi_mem_ret1n,pd_axi_mem_ret1n,HI_SC_CTRL68_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL68_OFFSET)
HI_SET_GET(hi_sc_ctrl68_pd_axi_mem_ret2n,pd_axi_mem_ret2n,HI_SC_CTRL68_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL68_OFFSET)
HI_SET_GET(hi_sc_ctrl68_pd_axi_mem_pgen,pd_axi_mem_pgen,HI_SC_CTRL68_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL68_OFFSET)
HI_SET_GET(hi_sc_ctrl68_reserved_0,reserved_0,HI_SC_CTRL68_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL68_OFFSET)
HI_SET_GET(hi_sc_ctrl69_axi_bbphy_xdcdr_sel,axi_bbphy_xdcdr_sel,HI_SC_CTRL69_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL69_OFFSET)
HI_SET_GET(hi_sc_ctrl69_reserved_2,reserved_2,HI_SC_CTRL69_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL69_OFFSET)
HI_SET_GET(hi_sc_ctrl69_axi_glb_xdcdr_sel,axi_glb_xdcdr_sel,HI_SC_CTRL69_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL69_OFFSET)
HI_SET_GET(hi_sc_ctrl69_reserved_1,reserved_1,HI_SC_CTRL69_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL69_OFFSET)
HI_SET_GET(hi_sc_ctrl69_socapb_pslverr_sel,socapb_pslverr_sel,HI_SC_CTRL69_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL69_OFFSET)
HI_SET_GET(hi_sc_ctrl69_x2h_hslverr_sel,x2h_hslverr_sel,HI_SC_CTRL69_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL69_OFFSET)
HI_SET_GET(hi_sc_ctrl69_mst_err_srst_req,mst_err_srst_req,HI_SC_CTRL69_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL69_OFFSET)
HI_SET_GET(hi_sc_ctrl69_reserved_0,reserved_0,HI_SC_CTRL69_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL69_OFFSET)
HI_SET_GET(hi_sc_ctrl70_axi_bbphy_priority_m1,axi_bbphy_priority_m1,HI_SC_CTRL70_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL70_OFFSET)
HI_SET_GET(hi_sc_ctrl70_axi_bbphy_priority_m2,axi_bbphy_priority_m2,HI_SC_CTRL70_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL70_OFFSET)
HI_SET_GET(hi_sc_ctrl70_axi_bbphy_priority_m3,axi_bbphy_priority_m3,HI_SC_CTRL70_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL70_OFFSET)
HI_SET_GET(hi_sc_ctrl70_axi_bbphy_priority_m4,axi_bbphy_priority_m4,HI_SC_CTRL70_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL70_OFFSET)
HI_SET_GET(hi_sc_ctrl70_reserved_1,reserved_1,HI_SC_CTRL70_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL70_OFFSET)
HI_SET_GET(hi_sc_ctrl70_axi_mst_priority_m9,axi_mst_priority_m9,HI_SC_CTRL70_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL70_OFFSET)
HI_SET_GET(hi_sc_ctrl70_axi_mst_priority_m10,axi_mst_priority_m10,HI_SC_CTRL70_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL70_OFFSET)
HI_SET_GET(hi_sc_ctrl70_reserved_0,reserved_0,HI_SC_CTRL70_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL70_OFFSET)
HI_SET_GET(hi_sc_ctrl71_reserved,reserved,HI_SC_CTRL71_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL71_OFFSET)
HI_SET_GET(hi_sc_ctrl71_axi_glb_priority_m1,axi_glb_priority_m1,HI_SC_CTRL71_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL71_OFFSET)
HI_SET_GET(hi_sc_ctrl71_axi_glb_priority_m2,axi_glb_priority_m2,HI_SC_CTRL71_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL71_OFFSET)
HI_SET_GET(hi_sc_ctrl71_axi_glb_priority_m3,axi_glb_priority_m3,HI_SC_CTRL71_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL71_OFFSET)
HI_SET_GET(hi_sc_ctrl71_axi_glb_priority_m4,axi_glb_priority_m4,HI_SC_CTRL71_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL71_OFFSET)
HI_SET_GET(hi_sc_ctrl71_axi_glb_priority_m5,axi_glb_priority_m5,HI_SC_CTRL71_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL71_OFFSET)
HI_SET_GET(hi_sc_ctrl71_axi_glb_priority_m6,axi_glb_priority_m6,HI_SC_CTRL71_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL71_OFFSET)
HI_SET_GET(hi_sc_ctrl71_axi_mst_cache_cfg_en,axi_mst_cache_cfg_en,HI_SC_CTRL71_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL71_OFFSET)
HI_SET_GET(hi_sc_ctrl71_axi_mst_sideband,axi_mst_sideband,HI_SC_CTRL71_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL71_OFFSET)
HI_SET_GET(hi_sc_ctrl71_axi_mst_cache,axi_mst_cache,HI_SC_CTRL71_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL71_OFFSET)
HI_SET_GET(hi_sc_ctrl72_axi_mst_priority_m1,axi_mst_priority_m1,HI_SC_CTRL72_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL72_OFFSET)
HI_SET_GET(hi_sc_ctrl72_axi_mst_priority_m2,axi_mst_priority_m2,HI_SC_CTRL72_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL72_OFFSET)
HI_SET_GET(hi_sc_ctrl72_axi_mst_priority_m3,axi_mst_priority_m3,HI_SC_CTRL72_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL72_OFFSET)
HI_SET_GET(hi_sc_ctrl72_axi_mst_priority_m4,axi_mst_priority_m4,HI_SC_CTRL72_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL72_OFFSET)
HI_SET_GET(hi_sc_ctrl72_axi_mst_priority_m5,axi_mst_priority_m5,HI_SC_CTRL72_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL72_OFFSET)
HI_SET_GET(hi_sc_ctrl72_axi_mst_priority_m6,axi_mst_priority_m6,HI_SC_CTRL72_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL72_OFFSET)
HI_SET_GET(hi_sc_ctrl72_axi_mst_priority_m7,axi_mst_priority_m7,HI_SC_CTRL72_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL72_OFFSET)
HI_SET_GET(hi_sc_ctrl72_axi_mst_priority_m8,axi_mst_priority_m8,HI_SC_CTRL72_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL72_OFFSET)
HI_SET_GET(hi_sc_ctrl73_peri_mst_region1_ctrl,peri_mst_region1_ctrl,HI_SC_CTRL73_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL73_OFFSET)
HI_SET_GET(hi_sc_ctrl73_peri_mst_secctrl_bypass,peri_mst_secctrl_bypass,HI_SC_CTRL73_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL73_OFFSET)
HI_SET_GET(hi_sc_ctrl73_reserved,reserved,HI_SC_CTRL73_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL73_OFFSET)
HI_SET_GET(hi_sc_ctrl73_peri_mst_region1_staddr,peri_mst_region1_staddr,HI_SC_CTRL73_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL73_OFFSET)
HI_SET_GET(hi_sc_ctrl74_reserved,reserved,HI_SC_CTRL74_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL74_OFFSET)
HI_SET_GET(hi_sc_ctrl74_peri_mst_region1_endaddr,peri_mst_region1_endaddr,HI_SC_CTRL74_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL74_OFFSET)
HI_SET_GET(hi_sc_ctrl75_peri_mst_region2_ctrl,peri_mst_region2_ctrl,HI_SC_CTRL75_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL75_OFFSET)
HI_SET_GET(hi_sc_ctrl75_reserved,reserved,HI_SC_CTRL75_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL75_OFFSET)
HI_SET_GET(hi_sc_ctrl75_peri_mst_region2_staddr,peri_mst_region2_staddr,HI_SC_CTRL75_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL75_OFFSET)
HI_SET_GET(hi_sc_ctrl76_reserved,reserved,HI_SC_CTRL76_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL76_OFFSET)
HI_SET_GET(hi_sc_ctrl76_peri_mst_region2_endaddr,peri_mst_region2_endaddr,HI_SC_CTRL76_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL76_OFFSET)
HI_SET_GET(hi_sc_ctrl77_peri_mst_region3_ctrl,peri_mst_region3_ctrl,HI_SC_CTRL77_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL77_OFFSET)
HI_SET_GET(hi_sc_ctrl77_reserved,reserved,HI_SC_CTRL77_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL77_OFFSET)
HI_SET_GET(hi_sc_ctrl77_peri_mst_region3_staddr,peri_mst_region3_staddr,HI_SC_CTRL77_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL77_OFFSET)
HI_SET_GET(hi_sc_ctrl78_reserved,reserved,HI_SC_CTRL78_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL78_OFFSET)
HI_SET_GET(hi_sc_ctrl78_peri_mst_region3_endaddr,peri_mst_region3_endaddr,HI_SC_CTRL78_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL78_OFFSET)
HI_SET_GET(hi_sc_ctrl79_peri_mst_region4_ctrl,peri_mst_region4_ctrl,HI_SC_CTRL79_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL79_OFFSET)
HI_SET_GET(hi_sc_ctrl79_reserved,reserved,HI_SC_CTRL79_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL79_OFFSET)
HI_SET_GET(hi_sc_ctrl79_peri_mst_region4_staddr,peri_mst_region4_staddr,HI_SC_CTRL79_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL79_OFFSET)
HI_SET_GET(hi_sc_ctrl80_reserved,reserved,HI_SC_CTRL80_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL80_OFFSET)
HI_SET_GET(hi_sc_ctrl80_peri_mst_region4_endaddr,peri_mst_region4_endaddr,HI_SC_CTRL80_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL80_OFFSET)
HI_SET_GET(hi_sc_ctrl103_reserved_8,reserved_8,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_bbphy_dsp0_axislv_active_mask,bbphy_dsp0_axislv_active_mask,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_bbphy_bbp_axislv_active_mask,bbphy_bbp_axislv_active_mask,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_reserved_7,reserved_7,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_reserved_6,reserved_6,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_mdmacp_axislv_active_mask,mdmacp_axislv_active_mask,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_reserved_5,reserved_5,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_axi_mem_axislv_active_mask,axi_mem_axislv_active_mask,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_reserved_4,reserved_4,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_bbphy_axislv_active_mask,bbphy_axislv_active_mask,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_reserved_3,reserved_3,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_wbbp_axislv_active_mask,wbbp_axislv_active_mask,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_amon_axislv_active_mask,amon_axislv_active_mask,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_reserved_2,reserved_2,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_wdog_apbslv_active_mask,wdog_apbslv_active_mask,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_timer0_7_apbslv_active_mask,timer0_7_apbslv_active_mask,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_reserved_1,reserved_1,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_uart0_apbslv_active_mask,uart0_apbslv_active_mask,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_edmac_slv_active_mask,edmac_slv_active_mask,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl103_reserved_0,reserved_0,HI_SC_CTRL103_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL103_OFFSET)
HI_SET_GET(hi_sc_ctrl104_reserved,reserved,HI_SC_CTRL104_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL104_OFFSET)
HI_SET_GET(hi_sc_ctrl105_uicc,uicc,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_reserved_6,reserved_6,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_ipcm,ipcm,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_reserved_5,reserved_5,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_hs_uart,hs_uart,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_reserved_4,reserved_4,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_cipher,cipher,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_ipf,ipf,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_reserved_3,reserved_3,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_cicom0,cicom0,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_cicom1,cicom1,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_reserved_2,reserved_2,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_vic1,vic1,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_reserved_1,reserved_1,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_upacc,upacc,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_ctrl105_reserved_0,reserved_0,HI_SC_CTRL105_T,HI_SYSSC_BASE_ADDR, HI_SC_CTRL105_OFFSET)
HI_SET_GET(hi_sc_stat1_reserved_1,reserved_1,HI_SC_STAT1_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT1_OFFSET)
HI_SET_GET(hi_sc_stat1_moda9_standbywfi,moda9_standbywfi,HI_SC_STAT1_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT1_OFFSET)
HI_SET_GET(hi_sc_stat1_moda9_standbywfe,moda9_standbywfe,HI_SC_STAT1_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT1_OFFSET)
HI_SET_GET(hi_sc_stat1_moda9_pmupriv,moda9_pmupriv,HI_SC_STAT1_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT1_OFFSET)
HI_SET_GET(hi_sc_stat1_moda9_pmusecure,moda9_pmusecure,HI_SC_STAT1_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT1_OFFSET)
HI_SET_GET(hi_sc_stat1_moda9_smpnamp,moda9_smpnamp,HI_SC_STAT1_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT1_OFFSET)
HI_SET_GET(hi_sc_stat1_moda9_scuevabort,moda9_scuevabort,HI_SC_STAT1_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT1_OFFSET)
HI_SET_GET(hi_sc_stat1_moda9_pwrctlo0,moda9_pwrctlo0,HI_SC_STAT1_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT1_OFFSET)
HI_SET_GET(hi_sc_stat1_moda9_l2_tagclkouten,moda9_l2_tagclkouten,HI_SC_STAT1_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT1_OFFSET)
HI_SET_GET(hi_sc_stat1_moda9_l2_dataclkouten,moda9_l2_dataclkouten,HI_SC_STAT1_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT1_OFFSET)
HI_SET_GET(hi_sc_stat1_moda9_l2_idle,moda9_l2_idle,HI_SC_STAT1_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT1_OFFSET)
HI_SET_GET(hi_sc_stat1_moda9_l2_clkstopped,moda9_l2_clkstopped,HI_SC_STAT1_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT1_OFFSET)
HI_SET_GET(hi_sc_stat1_reserved_0,reserved_0,HI_SC_STAT1_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT1_OFFSET)
HI_SET_GET(hi_sc_stat2_reserved_1,reserved_1,HI_SC_STAT2_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT2_OFFSET)
HI_SET_GET(hi_sc_stat2_dsp0_pwaitmode,dsp0_pwaitmode,HI_SC_STAT2_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT2_OFFSET)
HI_SET_GET(hi_sc_stat2_dsp0_xocdmode,dsp0_xocdmode,HI_SC_STAT2_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT2_OFFSET)
HI_SET_GET(hi_sc_stat2_reserved_0,reserved_0,HI_SC_STAT2_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT2_OFFSET)
HI_SET_GET(hi_sc_stat3_hpmx_opc,hpmx_opc,HI_SC_STAT3_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT3_OFFSET)
HI_SET_GET(hi_sc_stat3_hpmx_opc_vld,hpmx_opc_vld,HI_SC_STAT3_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT3_OFFSET)
HI_SET_GET(hi_sc_stat3_reserved_1,reserved_1,HI_SC_STAT3_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT3_OFFSET)
HI_SET_GET(hi_sc_stat3_hpm_opc,hpm_opc,HI_SC_STAT3_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT3_OFFSET)
HI_SET_GET(hi_sc_stat3_hpm_opc_vld,hpm_opc_vld,HI_SC_STAT3_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT3_OFFSET)
HI_SET_GET(hi_sc_stat3_reserved_0,reserved_0,HI_SC_STAT3_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT3_OFFSET)
HI_SET_GET(hi_sc_stat5_dsp0_nmi,dsp0_nmi,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_intr_ipc_ns,intr_ipc_ns,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_intr_ipc_ns_mbx,intr_ipc_ns_mbx,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_dsp_uart_int,dsp_uart_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_edmac_int1,edmac_int1,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_lte_dsp_aagc_int,lte_dsp_aagc_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_lte_dsp_cell_int,lte_dsp_cell_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_lte_dsp_vdl_int,lte_dsp_vdl_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_lte_dsp_cmu_int,lte_dsp_cmu_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_lte_dsp_pwrm_int,lte_dsp_pwrm_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_lte_dsp_cfi_int,lte_dsp_cfi_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_lte_dsp_tdl_int,lte_dsp_tdl_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_lte_dsp_bbp_dma_int,lte_dsp_bbp_dma_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_lte_dsp_pub_int,lte_dsp_pub_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_lte_dsp_synb_int,lte_dsp_synb_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_tds_stu_sfrm_int,tds_stu_sfrm_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_tds_hsupa_int,tds_hsupa_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_tds_harq_int,tds_harq_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_tds_turbo_int,tds_turbo_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_tds_viterbi_int,tds_viterbi_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_tds_rfc_int,tds_rfc_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_tds_fpu_int,tds_fpu_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_tds_stu_dsp_int,tds_stu_dsp_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_ctu_int_lte,ctu_int_lte,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_ctu_int_tds,ctu_int_tds,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_dsp_vic_int,dsp_vic_int,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat5_reserved,reserved,HI_SC_STAT5_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT5_OFFSET)
HI_SET_GET(hi_sc_stat6_reserved_1,reserved_1,HI_SC_STAT6_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT6_OFFSET)
HI_SET_GET(hi_sc_stat6_moda9_parityfail0,moda9_parityfail0,HI_SC_STAT6_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT6_OFFSET)
HI_SET_GET(hi_sc_stat6_moda9_parityfailscu,moda9_parityfailscu,HI_SC_STAT6_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT6_OFFSET)
HI_SET_GET(hi_sc_stat6_reserved_0,reserved_0,HI_SC_STAT6_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT6_OFFSET)
HI_SET_GET(hi_sc_stat9_dw_axi_mst_dlock_wr,dw_axi_mst_dlock_wr,HI_SC_STAT9_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT9_OFFSET)
HI_SET_GET(hi_sc_stat9_dw_axi_mst_dlock_slv,dw_axi_mst_dlock_slv,HI_SC_STAT9_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT9_OFFSET)
HI_SET_GET(hi_sc_stat9_reserved_2,reserved_2,HI_SC_STAT9_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT9_OFFSET)
HI_SET_GET(hi_sc_stat9_dw_axi_mst_dlock_mst,dw_axi_mst_dlock_mst,HI_SC_STAT9_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT9_OFFSET)
HI_SET_GET(hi_sc_stat9_reserved_1,reserved_1,HI_SC_STAT9_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT9_OFFSET)
HI_SET_GET(hi_sc_stat9_dw_axi_glb_dlock_wr,dw_axi_glb_dlock_wr,HI_SC_STAT9_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT9_OFFSET)
HI_SET_GET(hi_sc_stat9_dw_axi_glb_dlock_slv,dw_axi_glb_dlock_slv,HI_SC_STAT9_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT9_OFFSET)
HI_SET_GET(hi_sc_stat9_dw_axi_glb_dlock_mst,dw_axi_glb_dlock_mst,HI_SC_STAT9_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT9_OFFSET)
HI_SET_GET(hi_sc_stat9_reserved_0,reserved_0,HI_SC_STAT9_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT9_OFFSET)
HI_SET_GET(hi_sc_stat10_dw_axi_glb_dlock_id,dw_axi_glb_dlock_id,HI_SC_STAT10_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT10_OFFSET)
HI_SET_GET(hi_sc_stat10_reserved,reserved,HI_SC_STAT10_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT10_OFFSET)
HI_SET_GET(hi_sc_stat10_dw_axi_mst_dlock_id,dw_axi_mst_dlock_id,HI_SC_STAT10_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT10_OFFSET)
HI_SET_GET(hi_sc_stat15_apb_pslv_active0,apb_pslv_active0,HI_SC_STAT15_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT15_OFFSET)
HI_SET_GET(hi_sc_stat15_reserved,reserved,HI_SC_STAT15_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT15_OFFSET)
HI_SET_GET(hi_sc_stat22_dw_axi_bbphy_dlock_mst,dw_axi_bbphy_dlock_mst,HI_SC_STAT22_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT22_OFFSET)
HI_SET_GET(hi_sc_stat22_dw_axi_bbphy_dlock_slv,dw_axi_bbphy_dlock_slv,HI_SC_STAT22_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT22_OFFSET)
HI_SET_GET(hi_sc_stat22_dw_axi_bbphy_dlock_wr,dw_axi_bbphy_dlock_wr,HI_SC_STAT22_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT22_OFFSET)
HI_SET_GET(hi_sc_stat22_reserved_1,reserved_1,HI_SC_STAT22_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT22_OFFSET)
HI_SET_GET(hi_sc_stat22_dw_axi_bbphy_dlock_id,dw_axi_bbphy_dlock_id,HI_SC_STAT22_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT22_OFFSET)
HI_SET_GET(hi_sc_stat22_reserved_0,reserved_0,HI_SC_STAT22_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT22_OFFSET)
HI_SET_GET(hi_sc_stat26_reserved_1,reserved_1,HI_SC_STAT26_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT26_OFFSET)
HI_SET_GET(hi_sc_stat26_ipf_idle,ipf_idle,HI_SC_STAT26_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT26_OFFSET)
HI_SET_GET(hi_sc_stat26_cicom0_clk_state,cicom0_clk_state,HI_SC_STAT26_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT26_OFFSET)
HI_SET_GET(hi_sc_stat26_cicom1_clk_state,cicom1_clk_state,HI_SC_STAT26_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT26_OFFSET)
HI_SET_GET(hi_sc_stat26_reserved_0,reserved_0,HI_SC_STAT26_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT26_OFFSET)
HI_SET_GET(hi_sc_stat27_bbphy_slv_active,bbphy_slv_active,HI_SC_STAT27_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT27_OFFSET)
HI_SET_GET(hi_sc_stat27_reserved_1,reserved_1,HI_SC_STAT27_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT27_OFFSET)
HI_SET_GET(hi_sc_stat27_glb_slv_active,glb_slv_active,HI_SC_STAT27_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT27_OFFSET)
HI_SET_GET(hi_sc_stat27_reserved_0,reserved_0,HI_SC_STAT27_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT27_OFFSET)
HI_SET_GET(hi_sc_stat29_x2h_peri_slv_active,x2h_peri_slv_active,HI_SC_STAT29_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT29_OFFSET)
HI_SET_GET(hi_sc_stat32_lte2soc_tbd,lte2soc_tbd,HI_SC_STAT32_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT32_OFFSET)
HI_SET_GET(hi_sc_stat32_reserved,reserved,HI_SC_STAT32_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT32_OFFSET)
HI_SET_GET(hi_sc_stat35_ap2mdm_key0,ap2mdm_key0,HI_SC_STAT35_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT35_OFFSET)
HI_SET_GET(hi_sc_stat36_ap2mdm_key0,ap2mdm_key0,HI_SC_STAT36_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT36_OFFSET)
HI_SET_GET(hi_sc_stat37_ap2mdm_key2,ap2mdm_key2,HI_SC_STAT37_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT37_OFFSET)
HI_SET_GET(hi_sc_stat38_ap2mdm_key3,ap2mdm_key3,HI_SC_STAT38_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT38_OFFSET)
HI_SET_GET(hi_sc_stat41_bbphy_mst_err,bbphy_mst_err,HI_SC_STAT41_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT41_OFFSET)
HI_SET_GET(hi_sc_stat41_reserved,reserved,HI_SC_STAT41_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT41_OFFSET)
HI_SET_GET(hi_sc_stat41_glb_mst_err,glb_mst_err,HI_SC_STAT41_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT41_OFFSET)
HI_SET_GET(hi_sc_stat42_reserved_1,reserved_1,HI_SC_STAT42_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT42_OFFSET)
HI_SET_GET(hi_sc_stat42_socapb_psel_err,socapb_psel_err,HI_SC_STAT42_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT42_OFFSET)
HI_SET_GET(hi_sc_stat42_ahb_peri_mst_err,ahb_peri_mst_err,HI_SC_STAT42_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT42_OFFSET)
HI_SET_GET(hi_sc_stat42_reserved_0,reserved_0,HI_SC_STAT42_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT42_OFFSET)
HI_SET_GET(hi_sc_stat43_x2h_peri_addr_err,x2h_peri_addr_err,HI_SC_STAT43_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT43_OFFSET)
HI_SET_GET(hi_sc_stat44_reserved,reserved,HI_SC_STAT44_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT44_OFFSET)
HI_SET_GET(hi_sc_stat44_addr_err,addr_err,HI_SC_STAT44_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT44_OFFSET)
HI_SET_GET(hi_sc_stat46_addr_err,addr_err,HI_SC_STAT46_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT46_OFFSET)
HI_SET_GET(hi_sc_stat47_addr_err,addr_err,HI_SC_STAT47_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT47_OFFSET)
HI_SET_GET(hi_sc_stat48_addr_err,addr_err,HI_SC_STAT48_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT48_OFFSET)
HI_SET_GET(hi_sc_stat49_addr_err,addr_err,HI_SC_STAT49_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT49_OFFSET)
HI_SET_GET(hi_sc_stat50_addr_err,addr_err,HI_SC_STAT50_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT50_OFFSET)
HI_SET_GET(hi_sc_stat51_addr_err,addr_err,HI_SC_STAT51_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT51_OFFSET)
HI_SET_GET(hi_sc_stat52_addr_err,addr_err,HI_SC_STAT52_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT52_OFFSET)
HI_SET_GET(hi_sc_stat53_addr_err,addr_err,HI_SC_STAT53_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT53_OFFSET)
HI_SET_GET(hi_sc_stat54_addr_err,addr_err,HI_SC_STAT54_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT54_OFFSET)
HI_SET_GET(hi_sc_stat55_addr_err,addr_err,HI_SC_STAT55_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT55_OFFSET)
HI_SET_GET(hi_sc_stat56_addr_err,addr_err,HI_SC_STAT56_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT56_OFFSET)
HI_SET_GET(hi_sc_stat57_addr_err,addr_err,HI_SC_STAT57_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT57_OFFSET)
HI_SET_GET(hi_sc_stat62_addr_err,addr_err,HI_SC_STAT62_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT62_OFFSET)
HI_SET_GET(hi_sc_stat63_addr_err,addr_err,HI_SC_STAT63_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT63_OFFSET)
HI_SET_GET(hi_sc_stat64_addr_err,addr_err,HI_SC_STAT64_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT64_OFFSET)
HI_SET_GET(hi_sc_stat65_addr_err,addr_err,HI_SC_STAT65_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT65_OFFSET)
HI_SET_GET(hi_sc_stat66_addr_err,addr_err,HI_SC_STAT66_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT66_OFFSET)
HI_SET_GET(hi_sc_stat67_addr_err,addr_err,HI_SC_STAT67_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT67_OFFSET)
HI_SET_GET(hi_sc_stat68_addr_err,addr_err,HI_SC_STAT68_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT68_OFFSET)
HI_SET_GET(hi_sc_stat69_addr_err,addr_err,HI_SC_STAT69_T,HI_SYSSC_BASE_ADDR, HI_SC_STAT69_OFFSET)
HI_SET_GET(hi_pwr_ctrl2_reserved_1,reserved_1,HI_PWR_CTRL2_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL2_OFFSET)
HI_SET_GET(hi_pwr_ctrl2_sc_tcxo0_en_ctrl,sc_tcxo0_en_ctrl,HI_PWR_CTRL2_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL2_OFFSET)
HI_SET_GET(hi_pwr_ctrl2_sc_tcxo1_en_ctrl,sc_tcxo1_en_ctrl,HI_PWR_CTRL2_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL2_OFFSET)
HI_SET_GET(hi_pwr_ctrl2_reserved_0,reserved_0,HI_PWR_CTRL2_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL2_OFFSET)
HI_SET_GET(hi_pwr_ctrl2_sc_tcxo_en_ctrl,sc_tcxo_en_ctrl,HI_PWR_CTRL2_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL2_OFFSET)
HI_SET_GET(hi_pwr_ctrl4_reserved_3,reserved_3,HI_PWR_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL4_OFFSET)
HI_SET_GET(hi_pwr_ctrl4_ccpu_iso_ctrl_en,ccpu_iso_ctrl_en,HI_PWR_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL4_OFFSET)
HI_SET_GET(hi_pwr_ctrl4_reserved_2,reserved_2,HI_PWR_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL4_OFFSET)
HI_SET_GET(hi_pwr_ctrl4_bbe16_iso_ctrl_en,bbe16_iso_ctrl_en,HI_PWR_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL4_OFFSET)
HI_SET_GET(hi_pwr_ctrl4_reserved_1,reserved_1,HI_PWR_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL4_OFFSET)
HI_SET_GET(hi_pwr_ctrl4_ltebbp_iso_ctrl_en,ltebbp_iso_ctrl_en,HI_PWR_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL4_OFFSET)
HI_SET_GET(hi_pwr_ctrl4_twbbp_iso_ctrl_en,twbbp_iso_ctrl_en,HI_PWR_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL4_OFFSET)
HI_SET_GET(hi_pwr_ctrl4_wbbp_iso_ctrl_en,wbbp_iso_ctrl_en,HI_PWR_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL4_OFFSET)
HI_SET_GET(hi_pwr_ctrl4_g1bbp_iso_ctrl_en,g1bbp_iso_ctrl_en,HI_PWR_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL4_OFFSET)
HI_SET_GET(hi_pwr_ctrl4_g2bbp_iso_ctrl_en,g2bbp_iso_ctrl_en,HI_PWR_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL4_OFFSET)
HI_SET_GET(hi_pwr_ctrl4_irmbbp_iso_ctrl_en,irmbbp_iso_ctrl_en,HI_PWR_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL4_OFFSET)
HI_SET_GET(hi_pwr_ctrl4_reserved_0,reserved_0,HI_PWR_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL4_OFFSET)
HI_SET_GET(hi_pwr_ctrl5_reserved_3,reserved_3,HI_PWR_CTRL5_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL5_OFFSET)
HI_SET_GET(hi_pwr_ctrl5_ccpu_iso_ctrl_dis,ccpu_iso_ctrl_dis,HI_PWR_CTRL5_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL5_OFFSET)
HI_SET_GET(hi_pwr_ctrl5_reserved_2,reserved_2,HI_PWR_CTRL5_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL5_OFFSET)
HI_SET_GET(hi_pwr_ctrl5_bbe16_iso_ctrl_dis,bbe16_iso_ctrl_dis,HI_PWR_CTRL5_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL5_OFFSET)
HI_SET_GET(hi_pwr_ctrl5_reserved_1,reserved_1,HI_PWR_CTRL5_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL5_OFFSET)
HI_SET_GET(hi_pwr_ctrl5_ltebbp_iso_ctrl_dis,ltebbp_iso_ctrl_dis,HI_PWR_CTRL5_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL5_OFFSET)
HI_SET_GET(hi_pwr_ctrl5_twbbp_iso_ctrl_dis,twbbp_iso_ctrl_dis,HI_PWR_CTRL5_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL5_OFFSET)
HI_SET_GET(hi_pwr_ctrl5_wbbp_iso_ctrl_dis,wbbp_iso_ctrl_dis,HI_PWR_CTRL5_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL5_OFFSET)
HI_SET_GET(hi_pwr_ctrl5_g1bbp_iso_ctrl_dis,g1bbp_iso_ctrl_dis,HI_PWR_CTRL5_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL5_OFFSET)
HI_SET_GET(hi_pwr_ctrl5_g2bbp_iso_ctrl_dis,g2bbp_iso_ctrl_dis,HI_PWR_CTRL5_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL5_OFFSET)
HI_SET_GET(hi_pwr_ctrl5_irmbbp_iso_ctrl_dis,irmbbp_iso_ctrl_dis,HI_PWR_CTRL5_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL5_OFFSET)
HI_SET_GET(hi_pwr_ctrl5_reserved_0,reserved_0,HI_PWR_CTRL5_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL5_OFFSET)
HI_SET_GET(hi_pwr_ctrl6_reserved_3,reserved_3,HI_PWR_CTRL6_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL6_OFFSET)
HI_SET_GET(hi_pwr_ctrl6_ccpu_mtcmos_ctrl_en,ccpu_mtcmos_ctrl_en,HI_PWR_CTRL6_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL6_OFFSET)
HI_SET_GET(hi_pwr_ctrl6_reserved_2,reserved_2,HI_PWR_CTRL6_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL6_OFFSET)
HI_SET_GET(hi_pwr_ctrl6_bbe16_mtcmos_ctrl_en,bbe16_mtcmos_ctrl_en,HI_PWR_CTRL6_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL6_OFFSET)
HI_SET_GET(hi_pwr_ctrl6_reserved_1,reserved_1,HI_PWR_CTRL6_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL6_OFFSET)
HI_SET_GET(hi_pwr_ctrl6_ltebbp_mtcmos_ctrl_en,ltebbp_mtcmos_ctrl_en,HI_PWR_CTRL6_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL6_OFFSET)
HI_SET_GET(hi_pwr_ctrl6_twbbp_mtcmos_ctrl_en,twbbp_mtcmos_ctrl_en,HI_PWR_CTRL6_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL6_OFFSET)
HI_SET_GET(hi_pwr_ctrl6_wbbp_mtcmos_ctrl_en,wbbp_mtcmos_ctrl_en,HI_PWR_CTRL6_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL6_OFFSET)
HI_SET_GET(hi_pwr_ctrl6_g1bbp_mtcmos_ctrl_en,g1bbp_mtcmos_ctrl_en,HI_PWR_CTRL6_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL6_OFFSET)
HI_SET_GET(hi_pwr_ctrl6_g2bbp_mtcmos_ctrl_en,g2bbp_mtcmos_ctrl_en,HI_PWR_CTRL6_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL6_OFFSET)
HI_SET_GET(hi_pwr_ctrl6_irmbbp_mtcmos_ctrl_en,irmbbp_mtcmos_ctrl_en,HI_PWR_CTRL6_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL6_OFFSET)
HI_SET_GET(hi_pwr_ctrl6_reserved_0,reserved_0,HI_PWR_CTRL6_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL6_OFFSET)
HI_SET_GET(hi_pwr_ctrl7_reserved_3,reserved_3,HI_PWR_CTRL7_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL7_OFFSET)
HI_SET_GET(hi_pwr_ctrl7_ccpu_mtcmos_ctrl_dis,ccpu_mtcmos_ctrl_dis,HI_PWR_CTRL7_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL7_OFFSET)
HI_SET_GET(hi_pwr_ctrl7_reserved_2,reserved_2,HI_PWR_CTRL7_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL7_OFFSET)
HI_SET_GET(hi_pwr_ctrl7_bbe16_mtcmos_ctrl_dis,bbe16_mtcmos_ctrl_dis,HI_PWR_CTRL7_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL7_OFFSET)
HI_SET_GET(hi_pwr_ctrl7_reserved_1,reserved_1,HI_PWR_CTRL7_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL7_OFFSET)
HI_SET_GET(hi_pwr_ctrl7_ltebbp_mtcmos_ctrl_dis,ltebbp_mtcmos_ctrl_dis,HI_PWR_CTRL7_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL7_OFFSET)
HI_SET_GET(hi_pwr_ctrl7_twbbp_mtcmos_ctrl_dis,twbbp_mtcmos_ctrl_dis,HI_PWR_CTRL7_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL7_OFFSET)
HI_SET_GET(hi_pwr_ctrl7_wbbp_mtcmos_ctrl_dis,wbbp_mtcmos_ctrl_dis,HI_PWR_CTRL7_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL7_OFFSET)
HI_SET_GET(hi_pwr_ctrl7_g1bbp_mtcmos_ctrl_dis,g1bbp_mtcmos_ctrl_dis,HI_PWR_CTRL7_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL7_OFFSET)
HI_SET_GET(hi_pwr_ctrl7_g2bbp_mtcmos_ctrl_dis,g2bbp_mtcmos_ctrl_dis,HI_PWR_CTRL7_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL7_OFFSET)
HI_SET_GET(hi_pwr_ctrl7_irmbbp_mtcmos_ctrl_dis,irmbbp_mtcmos_ctrl_dis,HI_PWR_CTRL7_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL7_OFFSET)
HI_SET_GET(hi_pwr_ctrl7_reserved_0,reserved_0,HI_PWR_CTRL7_T,HI_SYSSC_BASE_ADDR, HI_PWR_CTRL7_OFFSET)
HI_SET_GET(hi_pwr_stat1_reserved_4,reserved_4,HI_PWR_STAT1_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT1_OFFSET)
HI_SET_GET(hi_pwr_stat1_ccpu_mtcmos_rdy_stat,ccpu_mtcmos_rdy_stat,HI_PWR_STAT1_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT1_OFFSET)
HI_SET_GET(hi_pwr_stat1_reserved_3,reserved_3,HI_PWR_STAT1_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT1_OFFSET)
HI_SET_GET(hi_pwr_stat1_bbe16_mtcmos_rdy_stat,bbe16_mtcmos_rdy_stat,HI_PWR_STAT1_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT1_OFFSET)
HI_SET_GET(hi_pwr_stat1_reserved_2,reserved_2,HI_PWR_STAT1_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT1_OFFSET)
HI_SET_GET(hi_pwr_stat1_ltebbp_mtcmos_rdy_stat,ltebbp_mtcmos_rdy_stat,HI_PWR_STAT1_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT1_OFFSET)
HI_SET_GET(hi_pwr_stat1_twbbp_mtcmos_rdy_stat,twbbp_mtcmos_rdy_stat,HI_PWR_STAT1_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT1_OFFSET)
HI_SET_GET(hi_pwr_stat1_wbbp_mtcmos_rdy_stat,wbbp_mtcmos_rdy_stat,HI_PWR_STAT1_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT1_OFFSET)
HI_SET_GET(hi_pwr_stat1_g1bbp_mtcmos_rdy_stat,g1bbp_mtcmos_rdy_stat,HI_PWR_STAT1_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT1_OFFSET)
HI_SET_GET(hi_pwr_stat1_g2bbp_mtcmos_rdy_stat,g2bbp_mtcmos_rdy_stat,HI_PWR_STAT1_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT1_OFFSET)
HI_SET_GET(hi_pwr_stat1_irmbbp_mtcmos_rdy_stat,irmbbp_mtcmos_rdy_stat,HI_PWR_STAT1_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT1_OFFSET)
HI_SET_GET(hi_pwr_stat1_reserved_1,reserved_1,HI_PWR_STAT1_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT1_OFFSET)
HI_SET_GET(hi_pwr_stat1_ltebbp0_mtcmos_rdy_stat,ltebbp0_mtcmos_rdy_stat,HI_PWR_STAT1_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT1_OFFSET)
HI_SET_GET(hi_pwr_stat1_reserved_0,reserved_0,HI_PWR_STAT1_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT1_OFFSET)
HI_SET_GET(hi_pwr_stat3_reserved_3,reserved_3,HI_PWR_STAT3_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT3_OFFSET)
HI_SET_GET(hi_pwr_stat3_ccpu_iso_ctrl_stat,ccpu_iso_ctrl_stat,HI_PWR_STAT3_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT3_OFFSET)
HI_SET_GET(hi_pwr_stat3_reserved_2,reserved_2,HI_PWR_STAT3_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT3_OFFSET)
HI_SET_GET(hi_pwr_stat3_bbe16_iso_ctrl_stat,bbe16_iso_ctrl_stat,HI_PWR_STAT3_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT3_OFFSET)
HI_SET_GET(hi_pwr_stat3_reserved_1,reserved_1,HI_PWR_STAT3_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT3_OFFSET)
HI_SET_GET(hi_pwr_stat3_ltebbp_iso_ctrl_stat,ltebbp_iso_ctrl_stat,HI_PWR_STAT3_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT3_OFFSET)
HI_SET_GET(hi_pwr_stat3_twbbp_iso_ctrl_stat,twbbp_iso_ctrl_stat,HI_PWR_STAT3_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT3_OFFSET)
HI_SET_GET(hi_pwr_stat3_wbbp_iso_ctrl_stat,wbbp_iso_ctrl_stat,HI_PWR_STAT3_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT3_OFFSET)
HI_SET_GET(hi_pwr_stat3_g1bbp_iso_ctrl_stat,g1bbp_iso_ctrl_stat,HI_PWR_STAT3_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT3_OFFSET)
HI_SET_GET(hi_pwr_stat3_g2bbp_iso_ctrl_stat,g2bbp_iso_ctrl_stat,HI_PWR_STAT3_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT3_OFFSET)
HI_SET_GET(hi_pwr_stat3_irmbbp_iso_ctrl_stat,irmbbp_iso_ctrl_stat,HI_PWR_STAT3_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT3_OFFSET)
HI_SET_GET(hi_pwr_stat3_reserved_0,reserved_0,HI_PWR_STAT3_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT3_OFFSET)
HI_SET_GET(hi_pwr_stat4_reserved_3,reserved_3,HI_PWR_STAT4_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT4_OFFSET)
HI_SET_GET(hi_pwr_stat4_ccpu_mtcmos_ctrl_stat,ccpu_mtcmos_ctrl_stat,HI_PWR_STAT4_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT4_OFFSET)
HI_SET_GET(hi_pwr_stat4_reserved_2,reserved_2,HI_PWR_STAT4_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT4_OFFSET)
HI_SET_GET(hi_pwr_stat4_bbe16_mtcmos_ctrl_stat,bbe16_mtcmos_ctrl_stat,HI_PWR_STAT4_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT4_OFFSET)
HI_SET_GET(hi_pwr_stat4_reserved_1,reserved_1,HI_PWR_STAT4_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT4_OFFSET)
HI_SET_GET(hi_pwr_stat4_ltebbp_mtcmos_ctrl_stat,ltebbp_mtcmos_ctrl_stat,HI_PWR_STAT4_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT4_OFFSET)
HI_SET_GET(hi_pwr_stat4_twbbp_mtcmos_ctrl_stat,twbbp_mtcmos_ctrl_stat,HI_PWR_STAT4_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT4_OFFSET)
HI_SET_GET(hi_pwr_stat4_wbbp_mtcmos_ctrl_stat,wbbp_mtcmos_ctrl_stat,HI_PWR_STAT4_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT4_OFFSET)
HI_SET_GET(hi_pwr_stat4_g1bbp_mtcmos_ctrl_stat,g1bbp_mtcmos_ctrl_stat,HI_PWR_STAT4_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT4_OFFSET)
HI_SET_GET(hi_pwr_stat4_g2bbp_mtcmos_ctrl_stat,g2bbp_mtcmos_ctrl_stat,HI_PWR_STAT4_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT4_OFFSET)
HI_SET_GET(hi_pwr_stat4_irmbbp_mtcmos_ctrl_stat,irmbbp_mtcmos_ctrl_stat,HI_PWR_STAT4_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT4_OFFSET)
HI_SET_GET(hi_pwr_stat4_reserved_0,reserved_0,HI_PWR_STAT4_T,HI_SYSSC_BASE_ADDR, HI_PWR_STAT4_OFFSET)
HI_SET_GET(hi_sec_ctrl0_ipf_sec_w_ctrl,ipf_sec_w_ctrl,HI_SEC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL0_OFFSET)
HI_SET_GET(hi_sec_ctrl0_ipf_sec_r_ctrl,ipf_sec_r_ctrl,HI_SEC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL0_OFFSET)
HI_SET_GET(hi_sec_ctrl0_region1_sec_w_ctrl,region1_sec_w_ctrl,HI_SEC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL0_OFFSET)
HI_SET_GET(hi_sec_ctrl0_region1_sec_r_ctrl,region1_sec_r_ctrl,HI_SEC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL0_OFFSET)
HI_SET_GET(hi_sec_ctrl0_ipcm_sec_w_ctrl,ipcm_sec_w_ctrl,HI_SEC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL0_OFFSET)
HI_SET_GET(hi_sec_ctrl0_ipcm_sec_r_ctrl,ipcm_sec_r_ctrl,HI_SEC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL0_OFFSET)
HI_SET_GET(hi_sec_ctrl0_aximon_sec_w_ctrl,aximon_sec_w_ctrl,HI_SEC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL0_OFFSET)
HI_SET_GET(hi_sec_ctrl0_aximon_sec_r_ctrl,aximon_sec_r_ctrl,HI_SEC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL0_OFFSET)
HI_SET_GET(hi_sec_ctrl0_others_sec_w_ctrl,others_sec_w_ctrl,HI_SEC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL0_OFFSET)
HI_SET_GET(hi_sec_ctrl0_others_sec_r_ctrl,others_sec_r_ctrl,HI_SEC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL0_OFFSET)
HI_SET_GET(hi_sec_ctrl0_region2_sec_r_ctrl,region2_sec_r_ctrl,HI_SEC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL0_OFFSET)
HI_SET_GET(hi_sec_ctrl0_uicc_sec_w_ctrl,uicc_sec_w_ctrl,HI_SEC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL0_OFFSET)
HI_SET_GET(hi_sec_ctrl0_uicc_sec_r_ctrl,uicc_sec_r_ctrl,HI_SEC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL0_OFFSET)
HI_SET_GET(hi_sec_ctrl0_reserved,reserved,HI_SEC_CTRL0_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL0_OFFSET)
HI_SET_GET(hi_sec_ctrl1_noddr_bypass,noddr_bypass,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_reserved,reserved,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_sci0_sec_w_ctrl,sci0_sec_w_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_sci0_sec_r_ctrl,sci0_sec_r_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_sci1_sec_w_ctrl,sci1_sec_w_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_sci1_sec_r_ctrl,sci1_sec_r_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_ipcm_s_sec_w_ctrl,ipcm_s_sec_w_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_ipcm_s_sec_r_ctrl,ipcm_s_sec_r_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_ipcm_ns_sec_w_ctrl,ipcm_ns_sec_w_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_ipcm_ns_sec_r_ctrl,ipcm_ns_sec_r_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_secram_sec_w_ctrl,secram_sec_w_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_secram_sec_r_ctrl,secram_sec_r_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_socp_sec_w_ctrl,socp_sec_w_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_socp_sec_r_ctrl,socp_sec_r_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_others_sec_w_ctrl,others_sec_w_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_others_sec_r_ctrl,others_sec_r_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl1_ap_sec_ctrl,ap_sec_ctrl,HI_SEC_CTRL1_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL1_OFFSET)
HI_SET_GET(hi_sec_ctrl2_region1_filter_st_addr,region1_filter_st_addr,HI_SEC_CTRL2_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL2_OFFSET)
HI_SET_GET(hi_sec_ctrl3_region1_filter_end_addr,region1_filter_end_addr,HI_SEC_CTRL3_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL3_OFFSET)
HI_SET_GET(hi_sec_ctrl4_secram_filter_st_addr,secram_filter_st_addr,HI_SEC_CTRL4_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL4_OFFSET)
HI_SET_GET(hi_sec_ctrl5_secram_filter_end_addr,secram_filter_end_addr,HI_SEC_CTRL5_T,HI_SYSSC_BASE_ADDR, HI_SEC_CTRL5_OFFSET)
#endif
#endif
#endif
