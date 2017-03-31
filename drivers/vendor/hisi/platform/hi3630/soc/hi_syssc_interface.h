#ifndef __HI_SYSSC_INTER_H__
#define __HI_SYSSC_INTER_H__ 
#include "hi_base.h"
#include "hi_syssc.h"
#define HI_SYSSC_SOCID_OFFSET 0xe00
static __inline__ void hi_syssc_wdt_reboot(void)
{
}
#define CONFIG_HI3630_CCORE_WDT 
#ifndef __KERNEL__
static __inline__ void hi_syssc_wdt_enble(void)
{
 set_hi_sc_ctrl2_wdt_en_ctrl(0x6920);
 set_hi_sc_ctrl2_wdt_clk_en(1);
}
static __inline__ void hi_syscrg_amon_cpufast_clk_enable(void)
{
    return;
}
static __inline__ void hi_syscrg_amon_soc_clk_enable(void)
{
    set_hi_crg_clken4_aximon_clk_en(1);
}
static __inline__ void hi_syscrg_amon_cpufast_clk_disable(void)
{
    return;
}
static __inline__ void hi_syscrg_amon_soc_clk_disable(void)
{
    set_hi_crg_clkdis4_aximon_clk_dis(1);
}
static __inline__ unsigned int hi_syscrg_amon_cpufast_get_clk_status(void)
{
    return 0;
}
static __inline__ unsigned int hi_syscrg_amon_soc_get_clk_status(void)
{
    return get_hi_crg_clkstat4_aximon_clk_status();
}
static __inline__ void hi_syscrg_amon_cpufast_soft_reset(void)
{
    return;
}
static __inline__ void hi_syscrg_amon_soc_soft_reset(void)
{
    set_hi_crg_srsten1_amon_soc_srst_en(1);
}
static __inline__ void hi_syscrg_amon_cpufast_rls_reset(void)
{
    return;
}
static __inline__ void hi_syscrg_amon_soc_rls_reset(void)
{
    set_hi_crg_srstdis1_amon_soc_srst_dis(1);
}
static __inline__ void hi_syssc_amon_cpufast_start(void)
{
    return;
}
static __inline__ void hi_syssc_amon_soc_start(void)
{
    if(get_hi_sc_ctrl3_amon_monitor_start())
    {
        set_hi_sc_ctrl3_amon_monitor_start(0);
    }
    set_hi_sc_ctrl3_amon_monitor_start(1);
}
static __inline__ void hi_syssc_amon_cpufast_stop(void)
{
    return;
}
static __inline__ void hi_syssc_amon_soc_stop(void)
{
    set_hi_sc_ctrl3_amon_monitor_start(0);
}
#define MDM_BOOT_ADDR_PERI_CTRL11 (0xE8A09000 + 0xC18)
static __inline__ void hi_syssc_set_mdma9_boot_addr(unsigned int boot_addr)
{
    (*(volatile unsigned *) (MDM_BOOT_ADDR_PERI_CTRL11)) = (boot_addr >> 16);
}
static __inline__ void edma_ch4_set_axi_mst_min(void)
{
    return;
}
#define edma_dw_ssi0_dma_sel(edma_id) 
#define edma_dw_ssi1_dma_sel(edma_id) 
#define edma_sio_dma_sel(edma_id) 
#define edma_hs_uart_dma_sel(edma_id) 
#define edma_uart0_dma_sel(edma_id) 
#define edma_uart1_dma_sel(edma_id) 
#define edma_uart2_dma_sel(edma_id) 
#define edma_sci0_dma_sel(edma_id) 
#define edma_sci1_dma_sel(edma_id) 
#define edma_bbp_dbg_dma_sel(edma_id) 
#define edma_bbp_grif_dma_sel(edma_id) 
#define edma_amon_soc_dma_sel(edma_id) 
#define edma_amon_fast_dma_sel(edma_id) 
#define HI_SC_GUBBP_WAKEUP_STAT_OFFSET 0x530
#define GUBBP_WAKEUP_STAT_MASK 0x7
static __inline__ unsigned int hi_get_gubbp_wakeup_status(void)
{
 unsigned int temp = 0;
    temp = (*(volatile unsigned *) (HI_AP_SYSCTRL_BASE_ADDR_VIRT + HI_SC_GUBBP_WAKEUP_STAT_OFFSET));
 return (temp & GUBBP_WAKEUP_STAT_MASK);
}
#endif
static __inline__ unsigned int get_hi_version_id_version_id(void)
{
#if defined(__KERNEL__)
 return readl((const volatile void *)(HI_SYSSC_BASE_ADDR_VIRT+HI_SYSSC_SOCID_OFFSET));
#else
 return readl((HI_SYSSC_BASE_ADDR_VIRT+HI_SYSSC_SOCID_OFFSET));
#endif
}
#endif
