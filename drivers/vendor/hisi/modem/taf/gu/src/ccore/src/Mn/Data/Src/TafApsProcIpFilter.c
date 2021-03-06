


/*****************************************************************************
  1 头文件包含
*****************************************************************************/
/* #include  "TafApsApi.h" */
#include "Taf_Aps.h"
#include "TafApsCtx.h"
#include "MnApsComm.h"
#include "TafLog.h"

#include "TafApsProcIpFilter.h"
#include "CdsInterface.h"
#include "stdlib.h"


#ifdef __cplusplus
#if __cplusplus
    extern "C" {
#endif
#endif

/*****************************************************************************
    协议栈打印打点方式下的.C文件宏定义
*****************************************************************************/
#define    THIS_FILE_ID        PS_FILE_ID_TAF_APS_PROCFILTER_C

/******************************************************************************
   2 外部函数变量声明
******************************************************************************/

/******************************************************************************
   3 私有定义
******************************************************************************/


/******************************************************************************
   4 全局变量定义
*****************************************************************************/
/* RABM IPF的Filter队列, 保存目前使用的所有Filter */
TAF_APS_IPF_FILTER_ARRAY  g_stTafApsIpfFilterArray        = {0};

TAF_APS_UL_NDIS_FILTER_FLAG_ENUM_UINT32 g_enTafApsUlNdisFilterValidFlag = TAF_APS_UL_NDIS_FILTER_INVALID;

TAF_APS_IPF_UL_NDIS_FILTER_INFO g_astTafApsUlNdisFilter[TAF_APS_IPF_MAX_UL_NDIS_FILTER];

/* 上行NDIS Filter ID与Filter对应BID的绑定关系 */
STATIC VOS_UINT32 g_aulTafApsUlNdisFilterTypeTable[][2] =
{
    {TAF_APS_IPF_UL_NDIS_FILTER_DHCP4,    CDS_UL_IPF_BEARER_ID_DHCPV4},
    {TAF_APS_IPF_UL_NDIS_FILTER_DHCP6,    CDS_UL_IPF_BEARER_ID_DHCPV6},
    {TAF_APS_IPF_UL_NDIS_FILTER_RS,       CDS_UL_IPF_BEARER_ID_ICMPV6},
    {TAF_APS_IPF_UL_NDIS_FILTER_RA,       CDS_UL_IPF_BEARER_ID_ICMPV6},
    {TAF_APS_IPF_UL_NDIS_FILTER_NS,       CDS_UL_IPF_BEARER_ID_ICMPV6},
    {TAF_APS_IPF_UL_NDIS_FILTER_NA,       CDS_UL_IPF_BEARER_ID_ICMPV6},
    {TAF_APS_IPF_UL_NDIS_FILTER_REDIRECT, CDS_UL_IPF_BEARER_ID_ICMPV6},
    {TAF_APS_IPF_UL_NDIS_FILTER_LOC_PING6,CDS_UL_IPF_BEARER_ID_ICMPV6},
    {TAF_APS_IPF_UL_NDIS_FILTER_LOC_FE80, CDS_UL_IPF_BEARER_ID_LL_FE80},
    {TAF_APS_IPF_UL_NDIS_FILTER_LOC_FF,   CDS_UL_IPF_BEARER_ID_LL_FF}
};

/* 保存配置的过滤规则 */
VOS_UINT32                              g_ulDebugPrintIpfFilterFlg = VOS_FALSE;
VOS_UINT32                              g_ulDebugIpfFilterNum;
IPF_FILTER_CONFIG_S                     g_astDebugIpfFilterConfig[20];
IPF_FILTER_CONFIG_S                     g_astDebugFilterConfig[11];

VOS_VOID TAF_APS_SetDebugPrintIpfFilterFlg(VOS_UINT32 ulFlg)
{
    g_ulDebugPrintIpfFilterFlg = ulFlg;
}

#if (FEATURE_OFF == FEATURE_SKB_EXP)    
VOS_UINT32 TAF_APS_IpfConfigUlFilterDebug(
    IPF_FILTER_CHAIN_TYPE_E             eFilterChainhead,
    VOS_UINT8                           ucFilterNum
)
{
    PS_MEM_SET(g_astDebugFilterConfig, 0, sizeof(g_astDebugFilterConfig));

    vos_printf("TAF_APS_IpfConfigUlFilterDebug: eFilterChainhead is %d,\r\n", eFilterChainhead);
    
    if (PS_SUCC != BSP_IPF_SetFilter(eFilterChainhead, g_astDebugFilterConfig, ucFilterNum))
    {
        vos_printf("TAF_APS_IpfConfigUlFilterDebug: BSP Config All Filters Fail.\r\n");
        return PS_FAIL;
    }
    
    return PS_SUCC;
}
#endif
/******************************************************************************
   5 函数实现
******************************************************************************/


VOS_VOID TAF_APS_IpfUlNdisFilterInit( VOS_VOID )
{
    TAF_APS_IPF_UL_NDIS_FILTER_INFO *pstFilter;

    /*打印进入该函数*/
    TAF_INFO_LOG(WUEPS_PID_TAF, "TAF_APS_IpfUlNdisFilterInit is entered.");

    /* 下行规格支持12个Filter， 目前使用了10个，如有添加超过12个，需要修改
      对应宏定义，注意不要溢出 */

    /* 定义上行NDIS DHCPv4 类型Filter */
    TAF_APS_IPF_DEF_UL_NDIS_DHCPV4_FILTER();

    /* 定义上行NDIS DHCPv6类型的下行Filter */
    TAF_APS_IPF_DEF_UL_NDIS_DHCPV6_FILTER();

    /* 定义上行NDIS ICMP Router Solicitation Filter */
    TAF_APS_IPF_DEF_UL_NDIS_ICMP_RS_FILTER();

    /* 定义上行NDIS ICMP Router Advertisement Filter */
    TAF_APS_IPF_DEF_UL_NDIS_ICMP_RA_FILTER();

    /* 定义上行NDIS ICMP Neighbor Solicitation Filter */
    TAF_APS_IPF_DEF_UL_NDIS_ICMP_NS_FILTER();

    /* 定义上行NDIS ICMP Neighbor Advertisement Filter */
    TAF_APS_IPF_DEF_UL_NDIS_ICMP_NA_FILTER();

    /* 定义上行NDIS ICMP Redirect Filter */
    TAF_APS_IPF_DEF_UL_NDIS_ICMP_REDIRECT_FILTER();

    /* 定义上行NDIS ICMP ECHO REQUEST Filter */
    TAF_APS_IPF_DEF_UL_NDIS_LOC_PING6_FILTER();

    /* 定义上行NDIS 目的地址FE80打头定义 Filter */
    TAF_APS_IPF_DEF_UL_NDIS_LOC_FE80_FILTER();

    /* 定义上行NDIS 目的地址FF打头定义 Filter */
    TAF_APS_IPF_DEF_UL_NDIS_LOC_FF_FILTER();
}


IPF_FILTER_CONFIG_S * TAF_APS_IpfGetFreeFilter(
    TAF_APS_IPF_DIRECTION_UINT32        enDir
)
{
    /* 获取上行Filter */
    if ((TAF_APS_IPF_DIRECTION_UL == enDir)&&(!TAF_APS_IPF_IS_UL_FILTER_FULL()))
    {
        return TAF_APS_IPF_GET_UL_FILTER_PTR(TAF_APS_IPF_GET_UL_FILTER_NUM());
    }

    TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IpfGetFreeFilter, Filter Queue Full.");

    /* 增加统计信息 */
    /* TAF_APS_IPF_OM_ADD_FILTER_FULL_CNT(); */

    return VOS_NULL_PTR;
}
VOS_INT32 TAF_APS_IpfCompare(
    const VOS_VOID                     *arg1,
    const VOS_VOID                     *arg2
)
{
    VOS_UINT16                          usVar1;
    VOS_UINT16                          usVar2;
    IPF_FILTER_CONFIG_S*                pstPara1;
    IPF_FILTER_CONFIG_S*                pstPara2;

    pstPara1        = (IPF_FILTER_CONFIG_S*) arg1;
    pstPara2        = (IPF_FILTER_CONFIG_S*) arg2;

    usVar1          = pstPara1->stMatchInfo.unFltChain.Bits.u16FltPri;
    usVar2          = pstPara2->stMatchInfo.unFltChain.Bits.u16FltPri;

    /* IP Filter的优先级从小到大排序 */
    if (usVar1 > usVar2)
    {
        return 1;
    }
    else if (usVar1 < usVar2)
    {
        return -1;
    }
    else
    {
        return 0;
    }
}
VOS_UINT32 TAF_APS_IpfGenerateFilterWithoutTFT(
    VOS_UINT8                           ucPdpId
)
{
    VOS_UINT8                           ucRabId;
    APS_PDP_CONTEXT_ENTITY_ST          *pstPdpEntity;

    /* 获取该PDPID对应的RabId */
    ucRabId      = TAF_APS_GetPdpEntNsapi(ucPdpId);

    /* 获取该PDPID的PDP实体内容地址 */
    pstPdpEntity = TAF_APS_GetPdpEntInfoAddr(ucPdpId);

    /* check ip type: ipv4, ipv4v6 */
    if ( (APS_ADDR_DYNAMIC_IPV4 == pstPdpEntity->PdpAddr.ucPdpTypeNum)
      || (APS_ADDR_STATIC_IPV4 == pstPdpEntity->PdpAddr.ucPdpTypeNum)
      || (MN_APS_ADDR_IPV4V6 == pstPdpEntity->PdpAddr.ucPdpTypeNum) )
    {
        if (PS_FAIL == TAF_APS_IpfGenerateBaseIpv4Filter(&(pstPdpEntity->PdpAddr), ucRabId))
        {
            TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IpfGenerateFilterWithoutTFT: Generate Ipv4 Filter Fail.");
            return PS_FAIL;
        }
    }
#if (FEATURE_ON == FEATURE_IPV6)
    /* check ip type: ipv6, ipv4v6 */
    if ( (MN_APS_ADDR_IPV6 == pstPdpEntity->PdpAddr.ucPdpTypeNum)
      || (MN_APS_ADDR_IPV4V6 == pstPdpEntity->PdpAddr.ucPdpTypeNum) )
    {
        if ( (VOS_FALSE == pstPdpEntity->bitOpIpv6RaInfo)
          || (0 == pstPdpEntity->stIpv6RaInfo.ulPrefixNum) )
        {
            return PS_SUCC;
        }

        if (PS_FAIL ==  TAF_APS_IpfGenerateBaseIpv6Filter(pstPdpEntity->stIpv6RaInfo.astPrefixList[0].aucPrefix, ucRabId))
        {
            TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IpfGenerateFilterWithoutTFT: Generate Ipv6 Filter Fail.");
            return PS_FAIL;
        }
    }
#endif

    return PS_SUCC;
}


VOS_UINT32 TAF_APS_IpfGenerateUlNdisFilters(VOS_VOID)
{
    VOS_UINT32                          ulIndex        = 0;

    /* 将所有UL NDIS所需数据包的FILTER配置到上行FILTER队列中 */
    for (ulIndex = 0; ulIndex < TAF_APS_IPF_CUR_UL_NDIS_FILTER_NUM; ulIndex++)
    {
        if (PS_FAIL == TAF_APS_IpfAddUlNdisFilter(ulIndex))
        {
            TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IpfGenerateUlNdisFilters:TAF_APS_IpfAddUlNdisFilter Failed.");
            return PS_FAIL;
        }
    }

    return PS_SUCC;
}
VOS_UINT32 TAF_APS_IpfGenerateFilters(VOS_VOID)
{
    VOS_UINT8                           ucPdpId         = VOS_NULL;

    /* 清空当前所有Filter */
    TAF_APS_IPF_SET_UL_FILTER_NUM(0);

    /* 当上行NDIS FILTER有效时，将所有UL NDIS所需数据包的FILTER配置到上行
       FILTER队列中 */
    if (TAF_APS_UL_NDIS_FILTER_VALID == TAF_APS_IPF_GET_UL_NDIS_FILTER_FLAG())
    {
        if (PS_SUCC != TAF_APS_IpfGenerateUlNdisFilters())
        {
            TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IpfGenerateFilters:TAF_APS_IpfGenerateUlNdisFilters Failed.");
            return PS_FAIL;
        }
    }

    for (ucPdpId = 0; ucPdpId < TAF_APS_MAX_PDPID; ucPdpId++)
    {
        if (VOS_FALSE == TAF_APS_CheckPdpServiceActivated(ucPdpId))
        {
            /* PDP未激活，返回 */
            continue;
        }

        if (APS_PDP_ACT_PRI == TAF_APS_GetPdpEntActType(ucPdpId))
        {
            if(PS_FAIL == TAF_APS_IpfGenerateFilterWithoutTFT(ucPdpId))
            {
                TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IpfGenerateFilters: TAF_APS_IPF Generate Default Bearer Filter Failed.");
                return PS_FAIL;
            }
        }
        else
        {
            TAF_NORMAL_LOG(WUEPS_PID_TAF, "TAF_APS_IpfGenerateFilters: GU can't support TFT.");
        }
    }

    return PS_SUCC;
}
VOS_VOID TAF_APS_IpfFilterSort(
    IPF_FILTER_CONFIG_S                *pstFilter,
    VOS_UINT32                          ulNum
)
{
    /* 调用C语言的库函数qsort对pstFilter进行快速排序 */
    qsort(pstFilter, ulNum, sizeof(IPF_FILTER_CONFIG_S), (TAF_APS_IPF_COMP_FUNC)TAF_APS_IpfCompare);
}
VOS_VOID TAF_APS_SetUlNdisFilterValidFlag(
    TAF_APS_UL_NDIS_FILTER_FLAG_ENUM_UINT32   enUlNdisFilterFlag
)
{
    TAF_APS_IPF_SET_UL_NDIS_FILTER_FLAG(enUlNdisFilterFlag);
}


VOS_UINT32 TAF_APS_IpfAddUlNdisFilter(
    VOS_UINT32                          ulFilterId
)
{
    TAF_APS_IPF_UL_NDIS_FILTER_INFO    *pstUlNdisFilter = VOS_NULL_PTR;
    IPF_FILTER_CONFIG_S                *pstIpFilter     = VOS_NULL_PTR;

    if (ulFilterId >= TAF_APS_IPF_UL_NDIS_FILTER_BUTT)
    {
        TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IpfAddUlNdisFilter, Wrong Filter Type");
        return PS_FAIL;
    }

    /* 从Filter队列中找到下一个空闲的Filter */
    pstIpFilter = TAF_APS_IpfGetFreeFilter(TAF_APS_IPF_DIRECTION_UL);
    if (VOS_NULL_PTR == pstIpFilter)
    {
        TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IpfAddUlNdisFilter Get Free Filter Failed.");
        return PS_FAIL;
    }

    PS_MEM_SET(pstIpFilter, 0x0, sizeof(IPF_FILTER_CONFIG_S));

    pstUlNdisFilter = TAF_APS_IPF_GET_UL_NDIS_USER_FILTER(ulFilterId);

    pstIpFilter->u32FilterID = ulFilterId;

    pstIpFilter->stMatchInfo.unFltCodeType.Bits.u16Code   = pstUlNdisFilter->usIcmpCode;
    pstIpFilter->stMatchInfo.unFltCodeType.Bits.u16Type   = pstUlNdisFilter->usIcmpType;
    pstIpFilter->stMatchInfo.unDstPort.Bits.u16DstPortHi  = pstUlNdisFilter->usPortHi;
    pstIpFilter->stMatchInfo.unDstPort.Bits.u16DstPortLo  = pstUlNdisFilter->usPortLo;
    pstIpFilter->stMatchInfo.unNextHeader.u32Protocol     = pstUlNdisFilter->ucProtocolId;

    if (TAF_APS_IPF_IPTYPE_IPV6 == pstUlNdisFilter->ucIpType)
    {
        PS_MEM_CPY(pstIpFilter->stMatchInfo.u8DstAddr,
                        pstUlNdisFilter->aucDstAdrr,
                        TAF_IPV6_ADDR_LEN);

        PS_MEM_CPY(pstIpFilter->stMatchInfo.u8DstMsk,
                        pstUlNdisFilter->aucDstMask,
                        TAF_IPV6_ADDR_LEN);
    }
    else
    {
        PS_MEM_CPY(pstIpFilter->stMatchInfo.u8DstAddr,
                        pstUlNdisFilter->aucDstAdrr,
                        TAF_IPV4_ADDR_LEN);

        PS_MEM_CPY(pstIpFilter->stMatchInfo.u8DstMsk,
                        pstUlNdisFilter->aucDstMask,
                        TAF_IPV4_ADDR_LEN);
    }

    pstIpFilter->stMatchInfo.unFltRuleCtrl.Bits.FltType     = pstUlNdisFilter->ucIpType;
    pstIpFilter->stMatchInfo.unFltRuleCtrl.Bits.FltCodeEn   = pstUlNdisFilter->bitOpCode;
    pstIpFilter->stMatchInfo.unFltRuleCtrl.Bits.FltTypeEn   = pstUlNdisFilter->bitOpType;
    pstIpFilter->stMatchInfo.unFltRuleCtrl.Bits.FltNhEn     = pstUlNdisFilter->bitOpProtocolId;
    pstIpFilter->stMatchInfo.unFltRuleCtrl.Bits.FltRPortEn  = pstUlNdisFilter->bitOpPort;
    pstIpFilter->stMatchInfo.unFltRuleCtrl.Bits.FltRAddrEn  = pstUlNdisFilter->bitOpDstAdrr;
    pstIpFilter->stMatchInfo.unFltRuleCtrl.Bits.FltBid      = TAF_APS_IPF_CONV_ULNDISFILTER_TO_BID(ulFilterId);
    pstIpFilter->stMatchInfo.unFltChain.Bits.u16FltPri      = pstUlNdisFilter->usPriority;
    pstIpFilter->stMatchInfo.unFltRuleCtrl.Bits.FltEn       = VOS_TRUE;

    /* 增加上行Filter数目 */
    TAF_APS_IPF_ADD_UL_FILTER_NUM();

    return PS_SUCC;
}

#if (FEATURE_OFF == FEATURE_SKB_EXP)    

VOS_UINT32 TAF_APS_IpfGenerateBaseIpv4Filter(
    const APS_PDP_ADDR_ST              *pstPdpAddr,
    VOS_UINT8                           ucRabId
)
{
    VOS_UINT32                          ulIndex         = 0;
    IPF_FILTER_CONFIG_S                *pstFilter       = VOS_NULL_PTR;

    /* 从Filter队列中找到下一个空闲的Filter */
    pstFilter = TAF_APS_IpfGetFreeFilter(TAF_APS_IPF_DIRECTION_UL);
    if (VOS_NULL_PTR == pstFilter)
    {
        TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IPF Get Free Filter Failed.");
        return PS_FAIL;
    }

    PS_MEM_SET(pstFilter, 0x0, sizeof(IPF_FILTER_CONFIG_S));

    /* 填写IP Filter参数 */
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltType = TAF_APS_IPF_IPTYPE_IPV4;
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltLAddrEn = VOS_TRUE;

    for (ulIndex = 0; ulIndex < TAF_IPV4_ADDR_LEN; ulIndex++)
    {
        pstFilter->stMatchInfo.u8SrcAddr[ulIndex]   = pstPdpAddr->aucIpAddr[ulIndex];
    }

    /* 此值表示mask中0的个数  */
    pstFilter->stMatchInfo.u32LocalAddressMsk = 0;

    /* Precedence = 256 */
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltBid = ucRabId;
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltEn  = VOS_TRUE;
    pstFilter->stMatchInfo.unFltChain.Bits.u16FltPri = TAF_APS_IPF_LOWEST_PRI;


    /* Bearer Id */
    pstFilter->u32FilterID = TAF_APS_IPF_UL_IPV4_FILTER_ID(ucRabId, 0);

    /* 增加上行Filter数目 */
    TAF_APS_IPF_ADD_UL_FILTER_NUM();

    return PS_SUCC;
}

#if (FEATURE_ON == FEATURE_IPV6)

VOS_UINT32 TAF_APS_IpfGenerateBaseIpv6Filter(
    VOS_UINT8                          *pucPdpAddr,
    VOS_UINT8                           ucRabId
)
{
    VOS_UINT32                          ulIndex         = 0;
    IPF_FILTER_CONFIG_S                *pstFilter       = VOS_NULL_PTR;

    VOS_UINT8                           aucInvalidIpv6Prefix[TAF_IPV6_PREFIX_LEN] = {0};

    /* 检查IPv6前缀是否有效，如果无效，则不配置IPF，直接返回 */
    if (0 == PS_MEM_CMP(pucPdpAddr,
                        aucInvalidIpv6Prefix,
                        TAF_IPV6_PREFIX_LEN))
    {
        TAF_NORMAL_LOG(WUEPS_PID_TAF, "TAF_APS_IpfGenerateBaseIpv6Filter IPv6 prefix invalid.");
        return PS_SUCC;
    }

    /* 从Filter队列中找到下一个空闲的Filter */
    pstFilter = TAF_APS_IpfGetFreeFilter(TAF_APS_IPF_DIRECTION_UL);
    if (VOS_NULL_PTR == pstFilter)
    {
        TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IpfGenerateBaseIpv6Filter Get Free Filter Failed.");
        return PS_FAIL;
    }

    PS_MEM_SET(pstFilter, 0x0, sizeof(IPF_FILTER_CONFIG_S));

    /* 填写IP Filter参数 */
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltType       = TAF_APS_IPF_IPTYPE_IPV6;
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltLAddrEn    = VOS_TRUE;

    /* IPv6只过滤64bit前缀 */
    for (ulIndex = 0; ulIndex < TAF_IPV6_ADDR_LEN/2; ulIndex++)
    {
        pstFilter->stMatchInfo.u8SrcAddr[ulIndex]       = pucPdpAddr[ulIndex];
    }

    /* 此值表示mask中64的个数  */
    pstFilter->stMatchInfo.u32LocalAddressMsk = 64;

    /* Precedence = 256 */
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltBid    = ucRabId;
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltEn     = VOS_TRUE;
    pstFilter->stMatchInfo.unFltChain.Bits.u16FltPri    = TAF_APS_IPF_LOWEST_PRI;


    /* Bearer Id */
    pstFilter->u32FilterID = TAF_APS_IPF_UL_IPV6_FILTER_ID(ucRabId, 0);

    /* 增加上行Filter数目 */
    TAF_APS_IPF_ADD_UL_FILTER_NUM();

    return PS_SUCC;
}
#endif


VOS_VOID TAF_APS_ChangeUlIpfFilterType(
    MODEM_ID_ENUM_UINT16                enModemId
)
{
    VOS_UINT32                          ulCnt;
    IPF_FILTER_CONFIG_S                *pstFilter = VOS_NULL_PTR;

    for (ulCnt = 0; ulCnt < TAF_APS_IPF_GET_UL_FILTER_NUM(); ulCnt ++)
    {
        pstFilter = TAF_APS_IPF_GET_UL_FILTER_PTR(ulCnt);

        TAF_APS_IPF_CLR_EX_FILTER_FLG(pstFilter->u32FilterID);

        /*Modem1设置为扩展过滤器，每条过滤器链的第一个过滤器一定是基本过滤器 */
        if ((MODEM_ID_0 != enModemId) && (0 != ulCnt))
        {
            TAF_APS_IPF_SET_EX_FILTER_FLG(pstFilter->u32FilterID);
        }
    }

    return;
}
VOS_UINT32 TAF_APS_IpfConfigUlFilter(VOS_UINT8 ucPdpId)
{
    VOS_UINT32                          ulIpFilterNum   = 0;
    IPF_FILTER_CONFIG_S                *pstFilterList   = 0;
    IPF_FILTER_CHAIN_TYPE_E             eFilterChainhead;
    MODEM_ID_ENUM_UINT16                enModemId;
    
    /* 打印进入该函数 */
    TAF_INFO_LOG(WUEPS_PID_TAF, "TAF_APS_IpfConfigUlFilter is entered.");

    /* 遍历所有TFT，生成IP Filter */
    if (PS_FAIL == TAF_APS_IpfGenerateFilters())
    {
        TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IpfConfigUlFilter: Generate All Filters Fail.");

        /* 增加统计信息 */
        /* TAF_APS_IPF_OM_ADD_UL_FILTER_ERR_CNT(); */
        return PS_FAIL;
    }

    /* 调用qsort对所有Filter进行排序 */
    ulIpFilterNum = TAF_APS_IPF_GET_UL_FILTER_NUM();
    pstFilterList = TAF_APS_IPF_GET_UL_FILTER_PTR(0);

    TAF_APS_IpfFilterSort(pstFilterList, ulIpFilterNum);

    /* 调用驱动接口， 将Filter列表 配置到硬件加速器中 */
    /* Modem0的过滤器号为0， Modem1的过滤器号为1 */
    enModemId = VOS_GetModemIDFromPid(WUEPS_PID_TAF);

    if (enModemId > MODEM_ID_BUTT)
    {
        return PS_FAIL;
    }

    TAF_APS_ChangeUlIpfFilterType(enModemId);

    if (MODEM_ID_0 == enModemId)
    {
        eFilterChainhead = IPF_MODEM0_ULFC;
    }
    else
    {
        eFilterChainhead = IPF_MODEM1_ULFC;
    }

    /* 记录配置的过滤规则 */
    if (VOS_TRUE == g_ulDebugPrintIpfFilterFlg)
    {   
        vos_printf("TAF_APS_IpfConfigUlFilter: ulIpFilterNum is %d\r\n", ulIpFilterNum);
        
        g_ulDebugIpfFilterNum = ulIpFilterNum;

        PS_MEM_CPY(g_astDebugIpfFilterConfig, pstFilterList, ulIpFilterNum * sizeof(IPF_FILTER_CONFIG_S));
    }
    
    if (PS_SUCC != BSP_IPF_SetFilter(eFilterChainhead, (IPF_FILTER_CONFIG_S *)pstFilterList, ulIpFilterNum))
    {
        TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IpfConfigUlFilter: BSP Config All Filters Fail.");
        return PS_FAIL;
    }

    
    return PS_SUCC;
}

#else

VOS_UINT32 TAF_APS_IpfGenerateBaseIpv4Filter(
    const APS_PDP_ADDR_ST              *pstPdpAddr,
    VOS_UINT8                           ucRabId
)
{
    VOS_UINT32                          ulIndex         = 0;
    IPF_FILTER_CONFIG_S                *pstFilter       = VOS_NULL_PTR;

    /* 从Filter队列中找到下一个空闲的Filter */
    pstFilter = TAF_APS_IpfGetFreeFilter(TAF_APS_IPF_DIRECTION_UL);
    if (VOS_NULL_PTR == pstFilter)
    {
        TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IPF Get Free Filter Failed.");
        return PS_FAIL;
    }

    PS_MEM_SET(pstFilter, 0x0, sizeof(IPF_FILTER_CONFIG_S));

    /* 填写IP Filter参数 */
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltType = TAF_APS_IPF_IPTYPE_IPV4;
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltLAddrEn = VOS_TRUE;

    for (ulIndex = 0; ulIndex < TAF_IPV4_ADDR_LEN; ulIndex++)
    {
        pstFilter->stMatchInfo.u8SrcAddr[ulIndex]   = pstPdpAddr->aucIpAddr[ulIndex];
        pstFilter->stMatchInfo.u8SrcMsk[ulIndex]    = 0xFF;
    }

    /* Precedence = 256 */
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltBid = ucRabId;
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltEn  = VOS_TRUE;
    pstFilter->stMatchInfo.unFltChain.Bits.u16FltPri = TAF_APS_IPF_LOWEST_PRI;

    /* Bearer Id */
    pstFilter->u32FilterID = TAF_APS_IPF_UL_IPV4_FILTER_ID(ucRabId, 0);

    /* 增加上行Filter数目 */
    TAF_APS_IPF_ADD_UL_FILTER_NUM();

    return PS_SUCC;
}

#if (FEATURE_ON == FEATURE_IPV6)
VOS_UINT32 TAF_APS_IpfGenerateBaseIpv6Filter(
    VOS_UINT8                          *pucPdpAddr,
    VOS_UINT8                           ucRabId
)
{
    VOS_UINT32                          ulIndex         = 0;
    IPF_FILTER_CONFIG_S                *pstFilter       = VOS_NULL_PTR;

    VOS_UINT8                           aucInvalidIpv6Prefix[TAF_IPV6_PREFIX_LEN] = {0};

    /* 检查IPv6前缀是否有效，如果无效，则不配置IPF，直接返回 */
    if (0 == PS_MEM_CMP(pucPdpAddr,
                        aucInvalidIpv6Prefix,
                        TAF_IPV6_PREFIX_LEN))
    {
        TAF_NORMAL_LOG(WUEPS_PID_TAF, "TAF_APS_IpfGenerateBaseIpv6Filter IPv6 prefix invalid.");
        return PS_SUCC;
    }

    /* 从Filter队列中找到下一个空闲的Filter */
    pstFilter = TAF_APS_IpfGetFreeFilter(TAF_APS_IPF_DIRECTION_UL);
    if (VOS_NULL_PTR == pstFilter)
    {
        TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IpfGenerateBaseIpv6Filter Get Free Filter Failed.");
        return PS_FAIL;
    }

    PS_MEM_SET(pstFilter, 0x0, sizeof(IPF_FILTER_CONFIG_S));

    /* 填写IP Filter参数 */
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltType       = TAF_APS_IPF_IPTYPE_IPV6;
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltLAddrEn    = VOS_TRUE;

    /* IPv6只过滤64bit前缀 */
    for (ulIndex = 0; ulIndex < TAF_IPV6_ADDR_LEN/2; ulIndex++)
    {
        pstFilter->stMatchInfo.u8SrcAddr[ulIndex]       = pucPdpAddr[ulIndex];
        pstFilter->stMatchInfo.u8SrcMsk[ulIndex]        = 0xFF;
    }

    /* Precedence = 256 */
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltBid    = ucRabId;
    pstFilter->stMatchInfo.unFltRuleCtrl.Bits.FltEn     = VOS_TRUE;
    pstFilter->stMatchInfo.unFltChain.Bits.u16FltPri    = TAF_APS_IPF_LOWEST_PRI;

    /* Bearer Id */
    pstFilter->u32FilterID = TAF_APS_IPF_UL_IPV6_FILTER_ID(ucRabId, 0);

    /* 增加上行Filter数目 */
    TAF_APS_IPF_ADD_UL_FILTER_NUM();

    return PS_SUCC;
}
#endif
VOS_UINT32 TAF_APS_IpfConfigUlFilter(VOS_UINT8 ucPdpId)
{
    VOS_UINT32                          ulIpFilterNum   = 0;
    IPF_FILTER_CONFIG_S                *pstFilterList   = 0;

    /* 打印进入该函数 */
    TAF_INFO_LOG(WUEPS_PID_TAF, "TAF_APS_IpfConfigUlFilter is entered.");

    /* 遍历所有TFT，生成IP Filter */
    if (PS_FAIL == TAF_APS_IpfGenerateFilters())
    {
        TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IpfConfigUlFilter: Generate All Filters Fail.");

        /* 增加统计信息 */
        /* TAF_APS_IPF_OM_ADD_UL_FILTER_ERR_CNT(); */
        return PS_FAIL;
    }

    /* 调用qsort对所有Filter进行排序 */
    ulIpFilterNum = TAF_APS_IPF_GET_UL_FILTER_NUM();
    pstFilterList = TAF_APS_IPF_GET_UL_FILTER_PTR(0);

    TAF_APS_IpfFilterSort(pstFilterList, ulIpFilterNum);

    /* 记录配置的过滤规则 */
    if (VOS_TRUE == g_ulDebugPrintIpfFilterFlg)
    {   
        vos_printf("TAF_APS_IpfConfigUlFilter: ulIpFilterNum is %d\r\n", ulIpFilterNum);
    
        g_ulDebugIpfFilterNum = ulIpFilterNum;

        PS_MEM_CPY(g_astDebugIpfFilterConfig, pstFilterList, ulIpFilterNum * sizeof(IPF_FILTER_CONFIG_S));
    }

    /* 调用驱动接口， 将Filter列表 配置到硬件加速器中 */
    if (PS_SUCC != BSP_IPF_SetFilter(IPF_CHANNEL_UP, (IPF_FILTER_CONFIG_S *)pstFilterList, ulIpFilterNum))
    {
        TAF_ERROR_LOG(WUEPS_PID_TAF, "TAF_APS_IpfConfigUlFilter: BSP Config All Filters Fail.");
        return PS_FAIL;
    }

    return PS_SUCC;
}

#endif



#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif







