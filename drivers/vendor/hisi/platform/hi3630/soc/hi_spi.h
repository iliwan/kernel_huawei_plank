#ifndef __HI_SPI_H__
#define __HI_SPI_H__ 
#ifndef HI_SET_GET
#define HI_SET_GET(a0,a1,a2,a3,a4) 
#endif
#define HI_SPI_CTRLR0_OFFSET (0x0)
#define HI_SPI_CTRLR1_OFFSET (0x4)
#define HI_SPI_SSIENR_OFFSET (0x8)
#define HI_SPI_MWCR_OFFSET (0xC)
#define HI_SPI_SER_OFFSET (0x10)
#define HI_SPI_BAUDR_OFFSET (0x14)
#define HI_SPI_TXFTLR_OFFSET (0x18)
#define HI_SPI_RXFTLR_OFFSET (0x1C)
#define HI_SPI_TXFLR_OFFSET (0x20)
#define HI_SPI_RXFLR_OFFSET (0x24)
#define HI_SPI_SR_OFFSET (0x28)
#define HI_SPI_IMR_OFFSET (0x2C)
#define HI_SPI_ISR_OFFSET (0x30)
#define HI_SPI_RISR_OFFSET (0x34)
#define HI_SPI_TXOICR_OFFSET (0x38)
#define HI_SPI_RXOICR_OFFSET (0x3C)
#define HI_SPI_RXUICR_OFFSET (0x40)
#define HI_SPI_MSTICR_OFFSET (0x44)
#define HI_SPI_ICR_OFFSET (0x48)
#define HI_SPI_DMACR_OFFSET (0x4C)
#define HI_SPI_DMATDLR_OFFSET (0x50)
#define HI_SPI_DMARDLR_OFFSET (0x54)
#define HI_SPI_IDR_OFFSET (0x58)
#define HI_SPI_SSI_COMP_VERSION_OFFSET (0x5C)
#define HI_SPI_DR_OFFSET (0x60)
#define HI_SPI_RX_SAMPLE_DLY_OFFSET (0xF0)
typedef union
{
    struct
    {
        unsigned int DFS : 4;
        unsigned int FRF : 2;
        unsigned int SCPH : 1;
        unsigned int SCPOL : 1;
        unsigned int TMOD : 2;
        unsigned int SLV_OE : 1;
        unsigned int SRL : 1;
        unsigned int CFS : 4;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_SPI_CTRLR0_T;
typedef union
{
    struct
    {
        unsigned int NDF : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_SPI_CTRLR1_T;
typedef union
{
    struct
    {
        unsigned int SSI_EN : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_SPI_SSIENR_T;
typedef union
{
    struct
    {
        unsigned int MWMOD : 1;
        unsigned int MDD : 1;
        unsigned int MHS : 1;
        unsigned int reserved_1 : 1;
        unsigned int mw_toggle_cyc : 4;
        unsigned int reserved_0 : 24;
    } bits;
    unsigned int u32;
}HI_SPI_MWCR_T;
typedef union
{
    struct
    {
        unsigned int SER : 4;
        unsigned int reserved : 28;
    } bits;
    unsigned int u32;
}HI_SPI_SER_T;
typedef union
{
    struct
    {
        unsigned int SCKDV : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_SPI_BAUDR_T;
typedef union
{
    struct
    {
        unsigned int TFT : 8;
        unsigned int reserved : 24;
    } bits;
    unsigned int u32;
}HI_SPI_TXFTLR_T;
typedef union
{
    struct
    {
        unsigned int RFT : 3;
        unsigned int reserved_1 : 5;
        unsigned int reserved_0 : 24;
    } bits;
    unsigned int u32;
}HI_SPI_RXFTLR_T;
typedef union
{
    struct
    {
        unsigned int TXTFL : 9;
        unsigned int reserved : 23;
    } bits;
    unsigned int u32;
}HI_SPI_TXFLR_T;
typedef union
{
    struct
    {
        unsigned int RXTFL : 4;
        unsigned int reserved : 28;
    } bits;
    unsigned int u32;
}HI_SPI_RXFLR_T;
typedef union
{
    struct
    {
        unsigned int BUSY : 1;
        unsigned int TFNF : 1;
        unsigned int TFE : 1;
        unsigned int RFNE : 1;
        unsigned int RFF : 1;
        unsigned int TXE : 1;
        unsigned int DCOL : 1;
        unsigned int reserved : 25;
    } bits;
    unsigned int u32;
}HI_SPI_SR_T;
typedef union
{
    struct
    {
        unsigned int TXEIM : 1;
        unsigned int TXOIM : 1;
        unsigned int RXUIM : 1;
        unsigned int RXOIM : 1;
        unsigned int RXFIM : 1;
        unsigned int MSTIM : 1;
        unsigned int reserved : 26;
    } bits;
    unsigned int u32;
}HI_SPI_IMR_T;
typedef union
{
    struct
    {
        unsigned int TXEIS : 1;
        unsigned int TXOIS : 1;
        unsigned int RXUIS : 1;
        unsigned int RXOIS : 1;
        unsigned int RXFIS : 1;
        unsigned int MSTIS : 1;
        unsigned int reserved : 26;
    } bits;
    unsigned int u32;
}HI_SPI_ISR_T;
typedef union
{
    struct
    {
        unsigned int TXEIR : 1;
        unsigned int TXOIR : 1;
        unsigned int RXUIR : 1;
        unsigned int RXOIR : 1;
        unsigned int RXFIR : 1;
        unsigned int MSTIR : 1;
        unsigned int reserved : 26;
    } bits;
    unsigned int u32;
}HI_SPI_RISR_T;
typedef union
{
    struct
    {
        unsigned int TXOICR : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_SPI_TXOICR_T;
typedef union
{
    struct
    {
        unsigned int RXOICR : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_SPI_RXOICR_T;
typedef union
{
    struct
    {
        unsigned int RXUICR : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_SPI_RXUICR_T;
typedef union
{
    struct
    {
        unsigned int MSTICR : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_SPI_MSTICR_T;
typedef union
{
    struct
    {
        unsigned int ICR : 1;
        unsigned int reserved : 31;
    } bits;
    unsigned int u32;
}HI_SPI_ICR_T;
typedef union
{
    struct
    {
        unsigned int RDMAE : 1;
        unsigned int TDMAE : 1;
        unsigned int PMI0_IND : 30;
    } bits;
    unsigned int u32;
}HI_SPI_DMACR_T;
typedef union
{
    struct
    {
        unsigned int DMATDL : 3;
        unsigned int reserved_1 : 5;
        unsigned int reserved_0 : 24;
    } bits;
    unsigned int u32;
}HI_SPI_DMATDLR_T;
typedef union
{
    struct
    {
        unsigned int DMARDL : 3;
        unsigned int reserved_1 : 5;
        unsigned int reserved_0 : 24;
    } bits;
    unsigned int u32;
}HI_SPI_DMARDLR_T;
typedef union
{
    struct
    {
        unsigned int IDCODE : 32;
    } bits;
    unsigned int u32;
}HI_SPI_IDR_T;
typedef union
{
    struct
    {
        unsigned int SSI_COMP_VERSION : 32;
    } bits;
    unsigned int u32;
}HI_SPI_SSI_COMP_VERSION_T;
typedef union
{
    struct
    {
        unsigned int DR : 16;
        unsigned int reserved : 16;
    } bits;
    unsigned int u32;
}HI_SPI_DR_T;
typedef union
{
    struct
    {
        unsigned int RSD : 8;
        unsigned int reserved : 24;
    } bits;
    unsigned int u32;
}HI_SPI_RX_SAMPLE_DLY_T;
HI_SET_GET(hi_spi_ctrlr0_dfs,dfs,HI_SPI_CTRLR0_T,HI_SPI_BASE_ADDR, HI_SPI_CTRLR0_OFFSET)
HI_SET_GET(hi_spi_ctrlr0_frf,frf,HI_SPI_CTRLR0_T,HI_SPI_BASE_ADDR, HI_SPI_CTRLR0_OFFSET)
HI_SET_GET(hi_spi_ctrlr0_scph,scph,HI_SPI_CTRLR0_T,HI_SPI_BASE_ADDR, HI_SPI_CTRLR0_OFFSET)
HI_SET_GET(hi_spi_ctrlr0_scpol,scpol,HI_SPI_CTRLR0_T,HI_SPI_BASE_ADDR, HI_SPI_CTRLR0_OFFSET)
HI_SET_GET(hi_spi_ctrlr0_tmod,tmod,HI_SPI_CTRLR0_T,HI_SPI_BASE_ADDR, HI_SPI_CTRLR0_OFFSET)
HI_SET_GET(hi_spi_ctrlr0_slv_oe,slv_oe,HI_SPI_CTRLR0_T,HI_SPI_BASE_ADDR, HI_SPI_CTRLR0_OFFSET)
HI_SET_GET(hi_spi_ctrlr0_srl,srl,HI_SPI_CTRLR0_T,HI_SPI_BASE_ADDR, HI_SPI_CTRLR0_OFFSET)
HI_SET_GET(hi_spi_ctrlr0_cfs,cfs,HI_SPI_CTRLR0_T,HI_SPI_BASE_ADDR, HI_SPI_CTRLR0_OFFSET)
HI_SET_GET(hi_spi_ctrlr0_reserved,reserved,HI_SPI_CTRLR0_T,HI_SPI_BASE_ADDR, HI_SPI_CTRLR0_OFFSET)
HI_SET_GET(hi_spi_ctrlr1_ndf,ndf,HI_SPI_CTRLR1_T,HI_SPI_BASE_ADDR, HI_SPI_CTRLR1_OFFSET)
HI_SET_GET(hi_spi_ctrlr1_reserved,reserved,HI_SPI_CTRLR1_T,HI_SPI_BASE_ADDR, HI_SPI_CTRLR1_OFFSET)
HI_SET_GET(hi_spi_ssienr_ssi_en,ssi_en,HI_SPI_SSIENR_T,HI_SPI_BASE_ADDR, HI_SPI_SSIENR_OFFSET)
HI_SET_GET(hi_spi_ssienr_reserved,reserved,HI_SPI_SSIENR_T,HI_SPI_BASE_ADDR, HI_SPI_SSIENR_OFFSET)
HI_SET_GET(hi_spi_mwcr_mwmod,mwmod,HI_SPI_MWCR_T,HI_SPI_BASE_ADDR, HI_SPI_MWCR_OFFSET)
HI_SET_GET(hi_spi_mwcr_mdd,mdd,HI_SPI_MWCR_T,HI_SPI_BASE_ADDR, HI_SPI_MWCR_OFFSET)
HI_SET_GET(hi_spi_mwcr_mhs,mhs,HI_SPI_MWCR_T,HI_SPI_BASE_ADDR, HI_SPI_MWCR_OFFSET)
HI_SET_GET(hi_spi_mwcr_reserved_1,reserved_1,HI_SPI_MWCR_T,HI_SPI_BASE_ADDR, HI_SPI_MWCR_OFFSET)
HI_SET_GET(hi_spi_mwcr_mw_toggle_cyc,mw_toggle_cyc,HI_SPI_MWCR_T,HI_SPI_BASE_ADDR, HI_SPI_MWCR_OFFSET)
HI_SET_GET(hi_spi_mwcr_reserved_0,reserved_0,HI_SPI_MWCR_T,HI_SPI_BASE_ADDR, HI_SPI_MWCR_OFFSET)
HI_SET_GET(hi_spi_ser_ser,ser,HI_SPI_SER_T,HI_SPI_BASE_ADDR, HI_SPI_SER_OFFSET)
HI_SET_GET(hi_spi_ser_reserved,reserved,HI_SPI_SER_T,HI_SPI_BASE_ADDR, HI_SPI_SER_OFFSET)
HI_SET_GET(hi_spi_baudr_sckdv,sckdv,HI_SPI_BAUDR_T,HI_SPI_BASE_ADDR, HI_SPI_BAUDR_OFFSET)
HI_SET_GET(hi_spi_baudr_reserved,reserved,HI_SPI_BAUDR_T,HI_SPI_BASE_ADDR, HI_SPI_BAUDR_OFFSET)
HI_SET_GET(hi_spi_txftlr_tft,tft,HI_SPI_TXFTLR_T,HI_SPI_BASE_ADDR, HI_SPI_TXFTLR_OFFSET)
HI_SET_GET(hi_spi_txftlr_reserved,reserved,HI_SPI_TXFTLR_T,HI_SPI_BASE_ADDR, HI_SPI_TXFTLR_OFFSET)
HI_SET_GET(hi_spi_rxftlr_rft,rft,HI_SPI_RXFTLR_T,HI_SPI_BASE_ADDR, HI_SPI_RXFTLR_OFFSET)
HI_SET_GET(hi_spi_rxftlr_reserved_1,reserved_1,HI_SPI_RXFTLR_T,HI_SPI_BASE_ADDR, HI_SPI_RXFTLR_OFFSET)
HI_SET_GET(hi_spi_rxftlr_reserved_0,reserved_0,HI_SPI_RXFTLR_T,HI_SPI_BASE_ADDR, HI_SPI_RXFTLR_OFFSET)
HI_SET_GET(hi_spi_txflr_txtfl,txtfl,HI_SPI_TXFLR_T,HI_SPI_BASE_ADDR, HI_SPI_TXFLR_OFFSET)
HI_SET_GET(hi_spi_txflr_reserved,reserved,HI_SPI_TXFLR_T,HI_SPI_BASE_ADDR, HI_SPI_TXFLR_OFFSET)
HI_SET_GET(hi_spi_rxflr_rxtfl,rxtfl,HI_SPI_RXFLR_T,HI_SPI_BASE_ADDR, HI_SPI_RXFLR_OFFSET)
HI_SET_GET(hi_spi_rxflr_reserved,reserved,HI_SPI_RXFLR_T,HI_SPI_BASE_ADDR, HI_SPI_RXFLR_OFFSET)
HI_SET_GET(hi_spi_sr_busy,busy,HI_SPI_SR_T,HI_SPI_BASE_ADDR, HI_SPI_SR_OFFSET)
HI_SET_GET(hi_spi_sr_tfnf,tfnf,HI_SPI_SR_T,HI_SPI_BASE_ADDR, HI_SPI_SR_OFFSET)
HI_SET_GET(hi_spi_sr_tfe,tfe,HI_SPI_SR_T,HI_SPI_BASE_ADDR, HI_SPI_SR_OFFSET)
HI_SET_GET(hi_spi_sr_rfne,rfne,HI_SPI_SR_T,HI_SPI_BASE_ADDR, HI_SPI_SR_OFFSET)
HI_SET_GET(hi_spi_sr_rff,rff,HI_SPI_SR_T,HI_SPI_BASE_ADDR, HI_SPI_SR_OFFSET)
HI_SET_GET(hi_spi_sr_txe,txe,HI_SPI_SR_T,HI_SPI_BASE_ADDR, HI_SPI_SR_OFFSET)
HI_SET_GET(hi_spi_sr_dcol,dcol,HI_SPI_SR_T,HI_SPI_BASE_ADDR, HI_SPI_SR_OFFSET)
HI_SET_GET(hi_spi_sr_reserved,reserved,HI_SPI_SR_T,HI_SPI_BASE_ADDR, HI_SPI_SR_OFFSET)
HI_SET_GET(hi_spi_imr_txeim,txeim,HI_SPI_IMR_T,HI_SPI_BASE_ADDR, HI_SPI_IMR_OFFSET)
HI_SET_GET(hi_spi_imr_txoim,txoim,HI_SPI_IMR_T,HI_SPI_BASE_ADDR, HI_SPI_IMR_OFFSET)
HI_SET_GET(hi_spi_imr_rxuim,rxuim,HI_SPI_IMR_T,HI_SPI_BASE_ADDR, HI_SPI_IMR_OFFSET)
HI_SET_GET(hi_spi_imr_rxoim,rxoim,HI_SPI_IMR_T,HI_SPI_BASE_ADDR, HI_SPI_IMR_OFFSET)
HI_SET_GET(hi_spi_imr_rxfim,rxfim,HI_SPI_IMR_T,HI_SPI_BASE_ADDR, HI_SPI_IMR_OFFSET)
HI_SET_GET(hi_spi_imr_mstim,mstim,HI_SPI_IMR_T,HI_SPI_BASE_ADDR, HI_SPI_IMR_OFFSET)
HI_SET_GET(hi_spi_imr_reserved,reserved,HI_SPI_IMR_T,HI_SPI_BASE_ADDR, HI_SPI_IMR_OFFSET)
HI_SET_GET(hi_spi_isr_txeis,txeis,HI_SPI_ISR_T,HI_SPI_BASE_ADDR, HI_SPI_ISR_OFFSET)
HI_SET_GET(hi_spi_isr_txois,txois,HI_SPI_ISR_T,HI_SPI_BASE_ADDR, HI_SPI_ISR_OFFSET)
HI_SET_GET(hi_spi_isr_rxuis,rxuis,HI_SPI_ISR_T,HI_SPI_BASE_ADDR, HI_SPI_ISR_OFFSET)
HI_SET_GET(hi_spi_isr_rxois,rxois,HI_SPI_ISR_T,HI_SPI_BASE_ADDR, HI_SPI_ISR_OFFSET)
HI_SET_GET(hi_spi_isr_rxfis,rxfis,HI_SPI_ISR_T,HI_SPI_BASE_ADDR, HI_SPI_ISR_OFFSET)
HI_SET_GET(hi_spi_isr_mstis,mstis,HI_SPI_ISR_T,HI_SPI_BASE_ADDR, HI_SPI_ISR_OFFSET)
HI_SET_GET(hi_spi_isr_reserved,reserved,HI_SPI_ISR_T,HI_SPI_BASE_ADDR, HI_SPI_ISR_OFFSET)
HI_SET_GET(hi_spi_risr_txeir,txeir,HI_SPI_RISR_T,HI_SPI_BASE_ADDR, HI_SPI_RISR_OFFSET)
HI_SET_GET(hi_spi_risr_txoir,txoir,HI_SPI_RISR_T,HI_SPI_BASE_ADDR, HI_SPI_RISR_OFFSET)
HI_SET_GET(hi_spi_risr_rxuir,rxuir,HI_SPI_RISR_T,HI_SPI_BASE_ADDR, HI_SPI_RISR_OFFSET)
HI_SET_GET(hi_spi_risr_rxoir,rxoir,HI_SPI_RISR_T,HI_SPI_BASE_ADDR, HI_SPI_RISR_OFFSET)
HI_SET_GET(hi_spi_risr_rxfir,rxfir,HI_SPI_RISR_T,HI_SPI_BASE_ADDR, HI_SPI_RISR_OFFSET)
HI_SET_GET(hi_spi_risr_mstir,mstir,HI_SPI_RISR_T,HI_SPI_BASE_ADDR, HI_SPI_RISR_OFFSET)
HI_SET_GET(hi_spi_risr_reserved,reserved,HI_SPI_RISR_T,HI_SPI_BASE_ADDR, HI_SPI_RISR_OFFSET)
HI_SET_GET(hi_spi_txoicr_txoicr,txoicr,HI_SPI_TXOICR_T,HI_SPI_BASE_ADDR, HI_SPI_TXOICR_OFFSET)
HI_SET_GET(hi_spi_txoicr_reserved,reserved,HI_SPI_TXOICR_T,HI_SPI_BASE_ADDR, HI_SPI_TXOICR_OFFSET)
HI_SET_GET(hi_spi_rxoicr_rxoicr,rxoicr,HI_SPI_RXOICR_T,HI_SPI_BASE_ADDR, HI_SPI_RXOICR_OFFSET)
HI_SET_GET(hi_spi_rxoicr_reserved,reserved,HI_SPI_RXOICR_T,HI_SPI_BASE_ADDR, HI_SPI_RXOICR_OFFSET)
HI_SET_GET(hi_spi_rxuicr_rxuicr,rxuicr,HI_SPI_RXUICR_T,HI_SPI_BASE_ADDR, HI_SPI_RXUICR_OFFSET)
HI_SET_GET(hi_spi_rxuicr_reserved,reserved,HI_SPI_RXUICR_T,HI_SPI_BASE_ADDR, HI_SPI_RXUICR_OFFSET)
HI_SET_GET(hi_spi_msticr_msticr,msticr,HI_SPI_MSTICR_T,HI_SPI_BASE_ADDR, HI_SPI_MSTICR_OFFSET)
HI_SET_GET(hi_spi_msticr_reserved,reserved,HI_SPI_MSTICR_T,HI_SPI_BASE_ADDR, HI_SPI_MSTICR_OFFSET)
HI_SET_GET(hi_spi_icr_icr,icr,HI_SPI_ICR_T,HI_SPI_BASE_ADDR, HI_SPI_ICR_OFFSET)
HI_SET_GET(hi_spi_icr_reserved,reserved,HI_SPI_ICR_T,HI_SPI_BASE_ADDR, HI_SPI_ICR_OFFSET)
HI_SET_GET(hi_spi_dmacr_rdmae,rdmae,HI_SPI_DMACR_T,HI_SPI_BASE_ADDR, HI_SPI_DMACR_OFFSET)
HI_SET_GET(hi_spi_dmacr_tdmae,tdmae,HI_SPI_DMACR_T,HI_SPI_BASE_ADDR, HI_SPI_DMACR_OFFSET)
HI_SET_GET(hi_spi_dmacr_pmi0_ind,pmi0_ind,HI_SPI_DMACR_T,HI_SPI_BASE_ADDR, HI_SPI_DMACR_OFFSET)
HI_SET_GET(hi_spi_dmatdlr_dmatdl,dmatdl,HI_SPI_DMATDLR_T,HI_SPI_BASE_ADDR, HI_SPI_DMATDLR_OFFSET)
HI_SET_GET(hi_spi_dmatdlr_reserved_1,reserved_1,HI_SPI_DMATDLR_T,HI_SPI_BASE_ADDR, HI_SPI_DMATDLR_OFFSET)
HI_SET_GET(hi_spi_dmatdlr_reserved_0,reserved_0,HI_SPI_DMATDLR_T,HI_SPI_BASE_ADDR, HI_SPI_DMATDLR_OFFSET)
HI_SET_GET(hi_spi_dmardlr_dmardl,dmardl,HI_SPI_DMARDLR_T,HI_SPI_BASE_ADDR, HI_SPI_DMARDLR_OFFSET)
HI_SET_GET(hi_spi_dmardlr_reserved_1,reserved_1,HI_SPI_DMARDLR_T,HI_SPI_BASE_ADDR, HI_SPI_DMARDLR_OFFSET)
HI_SET_GET(hi_spi_dmardlr_reserved_0,reserved_0,HI_SPI_DMARDLR_T,HI_SPI_BASE_ADDR, HI_SPI_DMARDLR_OFFSET)
HI_SET_GET(hi_spi_idr_idcode,idcode,HI_SPI_IDR_T,HI_SPI_BASE_ADDR, HI_SPI_IDR_OFFSET)
HI_SET_GET(hi_spi_ssi_comp_version_ssi_comp_version,ssi_comp_version,HI_SPI_SSI_COMP_VERSION_T,HI_SPI_BASE_ADDR, HI_SPI_SSI_COMP_VERSION_OFFSET)
HI_SET_GET(hi_spi_dr_dr,dr,HI_SPI_DR_T,HI_SPI_BASE_ADDR, HI_SPI_DR_OFFSET)
HI_SET_GET(hi_spi_dr_reserved,reserved,HI_SPI_DR_T,HI_SPI_BASE_ADDR, HI_SPI_DR_OFFSET)
HI_SET_GET(hi_spi_rx_sample_dly_rsd,rsd,HI_SPI_RX_SAMPLE_DLY_T,HI_SPI_BASE_ADDR, HI_SPI_RX_SAMPLE_DLY_OFFSET)
HI_SET_GET(hi_spi_rx_sample_dly_reserved,reserved,HI_SPI_RX_SAMPLE_DLY_T,HI_SPI_BASE_ADDR, HI_SPI_RX_SAMPLE_DLY_OFFSET)
#endif
