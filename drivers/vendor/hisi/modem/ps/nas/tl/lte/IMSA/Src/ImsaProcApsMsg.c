/******************************************************************************

   Copyright(C)2013,Hisilicon Co. LTD.

 ******************************************************************************
  File Name       : ImsaProcApsMsg.c
  Description     : 该C文件实现APS消息处理和APS消息发送
  History           :
     1.sunbing 49683      2013-06-19  Draft Enact

******************************************************************************/

/*****************************************************************************
  1 Include HeadFile
*****************************************************************************/
#include "ImsaConnManagement.h"
#include "ImsaProcApsMsg.h"
#include "TafApsApi.h"
#include "ImsaPublic.h"
#include "ImsaIntraInterface.h"
#include "ImsaProcAtMsg.h"
#include "ImsaCallManagement.h"
#include "ImsaServiceManagement.h"
#include "ImsaRegManagement.h"
/*lint -e767*/
#define    THIS_FILE_ID      PS_FILE_ID_IMSAPROCAPSMSG_C
#define    THIS_NAS_FILE_ID  NAS_FILE_ID_IMSAPROCAPSMSG_C
/*lint +e767*/

/*****************************************************************************
  1.1 Cplusplus Announce
*****************************************************************************/
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#if (FEATURE_ON == FEATURE_IMS)
/*****************************************************************************
  2 Declare the Global Variable
*****************************************************************************/
const IMSA_CONN_PS_EVT_FUNC_TBL_STRU    g_astImsaConnPsEvtFuncTbl[] =
{
    /* PS CALL */
    {ID_EVT_TAF_PS_CALL_PDP_ACTIVATE_CNF,
        IMSA_CONN_ProcTafPsEvtPdpActivateCnf},
    {ID_EVT_TAF_PS_CALL_PDP_ACTIVATE_REJ,
        IMSA_CONN_ProcTafPsEvtPdpActivateRej},
    {ID_EVT_TAF_PS_CALL_PDP_ACTIVATE_IND,
        IMSA_CONN_ProcTafPsEvtPdpActivateInd},
    {ID_EVT_TAF_PS_CALL_PDP_MODIFY_IND,
        IMSA_CONN_ProcTafPsEvtPdpModifyInd},
    {ID_EVT_TAF_PS_CALL_PDP_DEACTIVATE_CNF,
        IMSA_CONN_ProcTafPsEvtPdpDeactivateCnf},
    {ID_EVT_TAF_PS_CALL_PDP_DEACTIVATE_IND,
        IMSA_CONN_ProcTafPsEvtPdpDeactivateInd},
    {ID_EVT_TAF_PS_CALL_PDP_IPV6_INFO_IND,
        IMSA_CONN_ProcTafPsEvtPdpIpv6InfoInd},
    {ID_EVT_TAF_PS_CALL_ORIG_CNF,
        IMSA_CONN_ProcTafPsEvtCallOrigCnf},
    {ID_EVT_TAF_PS_CALL_END_CNF,
        IMSA_CONN_ProcTafPsEvtCallEndCnf},
    {ID_EVT_TAF_PS_SRVCC_CANCEL_NOTIFY_IND,
        IMSA_CONN_ProcTafPsEvtSrvccCancelInd},
};

const VOS_UINT32 g_ulImsaConnPsEvtFuncTblSize  = sizeof(g_astImsaConnPsEvtFuncTbl) / sizeof(g_astImsaConnPsEvtFuncTbl[0]);


extern VOS_VOID IMSA_CONN_WaitForIpv6InfoProc
(
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType
);
/*
extern VOS_UINT32 IMSA_CONN_SipSignalPdpActOrig
(
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType,
    VOS_UINT8                           ucCid,
    IMSA_IP_TYPE_ENUM_UINT8             enIpType
);
*/
extern VOS_VOID  IMSA_CONN_ProcActCnfBack
(
    const TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU    *pstPdpActivateCnf
);
extern VOS_VOID  IMSA_CONN_ProcIpv4ActCnf
(
    IMSA_CONN_TYPE_ENUM_UINT32                  enConnType,
    const TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU    *pstPdpActivateCnf
);
extern VOS_VOID  IMSA_CONN_ProcIpv6ActCnf
(
    IMSA_CONN_TYPE_ENUM_UINT32                  enConnType,
    const TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU    *pstPdpActivateCnf
);
extern VOS_VOID  IMSA_CONN_ProcIpv4v6ActCnf
(
    IMSA_CONN_TYPE_ENUM_UINT32                  enConnType
);
extern VOS_VOID IMSA_CONN_ProcActRejCurReqIpv4v6
(
    IMSA_CONN_TYPE_ENUM_UINT32                  enConnType,
    const TAF_PS_CALL_PDP_ACTIVATE_REJ_STRU    *pstPdpActivateRej
);
extern VOS_VOID IMSA_CONN_ProcActRejCurReqIpv4
(
    IMSA_CONN_TYPE_ENUM_UINT32                  enConnType,
    const TAF_PS_CALL_PDP_ACTIVATE_REJ_STRU    *pstPdpActivateRej
);
extern VOS_VOID IMSA_CONN_ProcActRejCurReqIpv6
(
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType,
    const TAF_PS_CALL_PDP_ACTIVATE_REJ_STRU    *pstPdpActivateRej
);

extern VOS_UINT32 IMSA_CONN_MatchIPV4V6FallBackCause
(
    TAF_PS_CAUSE_ENUM_UINT32                    enCause
);

/*****************************************************************************
  3 Function
*****************************************************************************/
/*lint -e960*/
/*lint -e961*/

VOS_VOID IMSA_CONN_ProcTafPsEvt
(
    TAF_PS_EVT_STRU                    *pstEvt
)
{
    VOS_UINT32                          i           = IMSA_NULL;
    VOS_UINT32                          ulResult    = IMSA_NULL;
    IMSA_CONN_PS_EVT_FUNC               pPsEvtFunc  = VOS_NULL_PTR;


    /* 在事件处理表中查找处理函数 */
    for ( i = 0; i < g_ulImsaConnPsEvtFuncTblSize; i++ )
    {
        if ( pstEvt->ulEvtId == g_astImsaConnPsEvtFuncTbl[i].ulEvtId )
        {
            /* 事件ID匹配 */
            pPsEvtFunc = g_astImsaConnPsEvtFuncTbl[i].pPsEvtFunc;
            break;
        }
    }

    /* 如果处理函数存在则调用 */
    if ( VOS_NULL_PTR != pPsEvtFunc )
    {
        ulResult = pPsEvtFunc(pstEvt->aucContent);
    }
    else
    {
        IMSA_ERR_LOG1("IMSA_CONN_ProcTafPsEvt: Unexpected event received! <EvtId>",
            pstEvt->ulEvtId);
        ulResult    = VOS_ERR;
    }

    if ( VOS_OK != ulResult )
    {
        IMSA_ERR_LOG1("IMSA_CONN_ProcTafPsEvt: Handle this event failed! <EvtId>",
            pstEvt->ulEvtId);
    }

    return;
}
VOS_VOID IMSA_CONN_WaitForIpv6InfoProc
(
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType
)
{
    IMSA_NORMAL_CONN_STRU              *pstNormalConn   = VOS_NULL_PTR;
    IMSA_EMC_CONN_STRU                 *pstEmcConn      = VOS_NULL_PTR;
    IMSA_IP_ADDRESS_STRU               *pstPdpIpAddr    = VOS_NULL_PTR;
    VOS_UINT32                          i               = IMSA_NULL;
    VOS_UINT8                           aucTemp[IMSA_IPV6_PREFIX_LEN] = {0};

    /* 获取PRIM PDP参数的格式 */
    if (IMSA_CONN_TYPE_NORMAL == enConnType)
    {
        pstNormalConn                   = IMSA_CONN_GetNormalConnAddr();
        for (i = 0; i < pstNormalConn->ulSipSignalPdpNum; i++)
        {
            pstPdpIpAddr = &pstNormalConn->astSipSignalPdpArray[i].stPdpAddr;
            if (((IMSA_IP_TYPE_IPV6 == pstPdpIpAddr->enIpType)
                    || (IMSA_IP_TYPE_IPV4V6 == pstPdpIpAddr->enIpType))
                && (0 == IMSA_MEM_CMP(aucTemp, pstPdpIpAddr->aucIpV6Addr, IMSA_IPV6_PREFIX_LEN)))
            {
                /* 启动等待IPV6参数定时器，等待APS的ID_EVT_TAF_PS_CALL_PDP_IPV6_INFO_IND消息，
                   不修改连接状态 */
                IMSA_CONN_StartTimer(IMSA_CONN_TYPE_NORMAL, TI_IMSA_WAIT_IPV6_INFO);

                return ;
            }
        }
    }
    else
    {
        pstEmcConn                      = IMSA_CONN_GetEmcConnAddr();
        pstPdpIpAddr = &pstEmcConn->stSipSignalPdp.stPdpAddr;
        if (((IMSA_IP_TYPE_IPV6 == pstPdpIpAddr->enIpType)
                || (IMSA_IP_TYPE_IPV4V6 == pstPdpIpAddr->enIpType))
            && (0 == IMSA_MEM_CMP(aucTemp, pstPdpIpAddr->aucIpV6Addr, IMSA_IPV6_PREFIX_LEN)))
        {
            /* 启动等待IPV6参数定时器，等待APS的ID_EVT_TAF_PS_CALL_PDP_IPV6_INFO_IND消息，
               不修改连接状态 */
            IMSA_CONN_StartTimer(IMSA_CONN_TYPE_EMC, TI_IMSA_WAIT_IPV6_INFO);

            return ;
        }
    }

    IMSA_CONN_SetupConnSucc(enConnType);
}


VOS_UINT32 IMSA_CONN_SipSignalPdpActOrig
(
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType,
    VOS_UINT8                           ucCid,
    IMSA_IP_TYPE_ENUM_UINT8             enIpType
)
{
    TAF_PS_DIAL_PARA_STRU              *pstDialParaInfo     = VOS_NULL_PTR;
    /* TAF_PDP_PRIM_CONTEXT_EXT_STRU       stPdpPrimContextExt = {0}; */
    IMSA_NORMAL_CONN_STRU              *pstNormalConn       = VOS_NULL_PTR;
    IMSA_EMC_CONN_STRU                 *pstEmcConn          = VOS_NULL_PTR;
    VOS_UINT8                           ucOpid              = IMSA_NULL;

    pstNormalConn   = IMSA_CONN_GetNormalConnAddr();
    pstEmcConn      = IMSA_CONN_GetEmcConnAddr();

    IMSA_INFO_LOG1("IMSA_CONN_SipSignalPdpActOrig: enConnType:", enConnType);
    IMSA_INFO_LOG1("IMSA_CONN_SipSignalPdpActOrig: ucCid:", ucCid);
    IMSA_INFO_LOG1("IMSA_CONN_SipSignalPdpActOrig: enIpType:", enIpType);

    /* 获取PRIM PDP参数的格式 */
    /*
    if (IMSA_CONN_TYPE_NORMAL == enConnType)
    {
        IMSA_CONN_GetPrimPdpCntFromSelSdfPara(&pstNormalConn->stSelSdfPara, &stPdpPrimContextExt);
    }
    else
    {
        IMSA_CONN_GetPrimPdpCntFromSelSdfPara(&pstEmcConn->stSelSdfPara, &stPdpPrimContextExt);
    }

    stPdpPrimContextExt.enPdpType   = enIpType;
    stPdpPrimContextExt.ucCid       = ucCid;

    IMSA_CONN_AssignOpid(enConnType, &ucOpid);

    if (VOS_ERR == TAF_PS_SetPrimPdpContextInfo(PS_PID_IMSA, IMSA_CLIENT_ID,
                                                ucOpid, &stPdpPrimContextExt))
    {
        IMSA_ERR_LOG("IMSA_CONN_SipSignalPdpActOrig:TAF_PS_SetPrimPdpContextInfo failed!");

        return IMSA_FAIL;
    }
    */

    /* 获取拨号参数 */
    pstDialParaInfo = IMSA_MEM_ALLOC(sizeof(TAF_PS_DIAL_PARA_STRU));
    if (VOS_NULL_PTR == pstDialParaInfo)
    {
        /*打印不合法信息*/
        IMSA_ERR_LOG("IMSA_CONN_SipSignalPdpActOrig:TAF_PS_DIAL_PARA_STRU ERROR: Mem alloc fail!");

        return IMSA_FAIL;
    }

    if (IMSA_CONN_TYPE_NORMAL == enConnType)
    {
        IMSA_CONN_GetImsDailParaFromSelSdfPara(&pstNormalConn->stSelSdfPara, pstDialParaInfo);

        pstNormalConn->stSelSdfPara.ucCid = ucCid;
        pstNormalConn->stSelSdfPara.enPdnType = enIpType;
    }
    else
    {
        IMSA_CONN_GetImsDailParaFromSelSdfPara(&pstEmcConn->stSelSdfPara, pstDialParaInfo);

        pstEmcConn->stSelSdfPara.ucCid = ucCid;
        pstEmcConn->stSelSdfPara.enPdnType = enIpType;
    }

    pstDialParaInfo->ucCid        = ucCid;
    pstDialParaInfo->enPdpType    = enIpType;


    IMSA_CONN_AssignOpid(enConnType, &ucOpid);
    /* IMSA_CONN_SetNormalConnOpid(ucOpid); */
    IMSA_CONN_SetOpid(enConnType, ucOpid);

    if (VOS_OK == TAF_PS_CallOrig(PS_PID_IMSA,IMSA_CLIENT_ID, ucOpid, pstDialParaInfo))
    {
        /* 启动IMS拨号定时器 */
        IMSA_CONN_StartTimer(enConnType, TI_IMSA_SIP_SIGAL_PDP_ORIG);

        /* 修改当前拨号请求的PDN类型 */
        IMSA_CONN_SaveCurReqPdnType(enConnType, enIpType);

        IMSA_MEM_FREE(pstDialParaInfo);

        return IMSA_SUCC;
    }

    IMSA_MEM_FREE(pstDialParaInfo);
    return IMSA_FAIL;
}
VOS_VOID  IMSA_CONN_ProcActCnfBack
(
    const TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU    *pstPdpActivateCnf
)
{
    VOS_UINT8                           ucCid   = IMSA_NULL;
    VOS_UINT32                          ulRet   = IMSA_FAIL;
    VOS_UINT8                           ucOpid  = IMSA_NULL;

    IMSA_INFO_LOG("IMSA_CONN_ProcActCnfBack is entered!");

    if ((VOS_TRUE == pstPdpActivateCnf->bitOpCause)
        && (TAF_PS_CAUSE_SM_NW_SINGLE_ADDR_BEARERS_ONLY_ALLOWED != pstPdpActivateCnf->enCause))
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcActCnfBack:Not Back!");

        /* 不会发起另一个SIP信令承载的建立 */

        /* 如果IPV6全局地址已获得，回复连接建立成功；否则启动等待IPV6参数定时器 */
        IMSA_CONN_WaitForIpv6InfoProc(IMSA_CONN_TYPE_NORMAL);
        return ;
    }

    if (TAF_PDP_IPV4 == pstPdpActivateCnf->stPdpAddr.enPdpType)
    {
        if (IMSA_PDP_STATE_ACTIVE == IMSA_CONN_GetSipSignalPdpState(IMSA_CONN_TYPE_NORMAL,
                                                                    TAF_PDP_IPV6))
        {
            IMSA_INFO_LOG("IMSA_CONN_ProcActCnfBack:IPV6 is already active!");

            /* 如果IPV6全局地址已获得，回复连接建立成功；否则启动等待IPV6参数定时器 */
            IMSA_CONN_WaitForIpv6InfoProc(IMSA_CONN_TYPE_NORMAL);
            return ;
        }

        /* 查找一个未激活的CID进行激活 */
        IMSA_CONN_AssignOpid(IMSA_CONN_TYPE_NORMAL, &ucOpid);
        ulRet = TAF_PS_GetUnusedCid(PS_PID_IMSA, IMSA_CLIENT_ID, ucOpid, &ucCid);
        if (VOS_OK != ulRet)
        {
            IMSA_WARN_LOG("IMSA_CONN_ProcActCnfBack:IPV4,get cid failed");

            IMSA_CONN_SetupConnSucc(IMSA_CONN_TYPE_NORMAL);
            return ;
        }

        ulRet = IMSA_CONN_SipSignalPdpActOrig(IMSA_CONN_TYPE_NORMAL, ucCid, TAF_PDP_IPV6);
        if (IMSA_SUCC != ulRet)
        {
            IMSA_WARN_LOG("IMSA_CONN_ProcActCnfBack:IPV4,IMSA_CONN_SipSignalPdpActOrig failed");

            IMSA_CONN_SetupConnSucc(IMSA_CONN_TYPE_NORMAL);
            return ;
        }
        return ;
    }
    else if (TAF_PDP_IPV6 == pstPdpActivateCnf->stPdpAddr.enPdpType)
    {
        if (IMSA_PDP_STATE_ACTIVE == IMSA_CONN_GetSipSignalPdpState(IMSA_CONN_TYPE_NORMAL,
                                                                    TAF_PDP_IPV4))
        {
            IMSA_INFO_LOG("IMSA_CONN_ProcActCnfBack:IPV4 is already active!");

            /* 如果IPV6全局地址已获得，回复连接建立成功；否则启动等待IPV6参数定时器 */
            IMSA_CONN_WaitForIpv6InfoProc(IMSA_CONN_TYPE_NORMAL);\
            return ;
        }

        /* 查找一个未激活的CID进行激活 */
        IMSA_CONN_AssignOpid(IMSA_CONN_TYPE_NORMAL, &ucOpid);
        ulRet = TAF_PS_GetUnusedCid(PS_PID_IMSA, IMSA_CLIENT_ID, ucOpid, &ucCid);
        if (VOS_OK != ulRet)
        {
            IMSA_WARN_LOG("IMSA_CONN_ProcActCnfBack:IPV6,get cid failed");

            /* 如果IPV6全局地址已获得，回复连接建立成功；否则启动等待IPV6参数定时器 */
            IMSA_CONN_WaitForIpv6InfoProc(IMSA_CONN_TYPE_NORMAL);
            return ;
        }

        ulRet = IMSA_CONN_SipSignalPdpActOrig(IMSA_CONN_TYPE_NORMAL, ucCid, TAF_PDP_IPV4);
        if (IMSA_SUCC != ulRet)
        {
            IMSA_WARN_LOG("IMSA_CONN_ProcActCnfBack:IPV6,IMSA_CONN_SipSignalPdpActOrig failed");

            /* 如果IPV6全局地址已获得，回复连接建立成功；否则启动等待IPV6参数定时器 */
            IMSA_CONN_WaitForIpv6InfoProc(IMSA_CONN_TYPE_NORMAL);
            return ;
        }
        return ;
    }
    else
    {
        ;
    }

    return;
}


VOS_VOID  IMSA_CONN_ProcIpv4ActCnf
(
    IMSA_CONN_TYPE_ENUM_UINT32                  enConnType,
    const TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU    *pstPdpActivateCnf
)
{
    IMSA_NORMAL_CONN_STRU              *pstNormalConn   = VOS_NULL_PTR;
    VOS_UINT8                           ucCid           = IMSA_NULL;
    VOS_UINT32                          ulRet           = IMSA_FAIL;
    VOS_UINT8                           ucOpid          = IMSA_NULL;

    if (IMSA_CONN_TYPE_EMC == enConnType)
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcIpv4ActCnf:EMC!");

        /* 由于3GPP协议要求同一时刻只能存在一个紧急承载，因此不会再发起另一个紧急
           承载建立 */

        IMSA_CONN_SetupConnSucc(IMSA_CONN_TYPE_EMC);

        return ;
    }

    pstNormalConn   = IMSA_CONN_GetNormalConnAddr();

    /* 如果是IPV4V6，需要激活另一个PDP */
    if (IMSA_IP_TYPE_IPV4V6 != pstNormalConn->enFirstReqPdnType)
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcIpv4ActCnf:Not ipv4v6");

        IMSA_CONN_SetupConnSucc(IMSA_CONN_TYPE_NORMAL);

        return ;
    }

    switch (pstNormalConn->enCurReqPdnType)
    {
        /* 这种情况不属于PDP回退，是前面PDP激活被拒绝后，分别发起IPV4、
           IPV6的PDP激活。*/
        case IMSA_IP_TYPE_IPV4:
            if (IMSA_PDP_STATE_ACTIVE == IMSA_CONN_GetSipSignalPdpState(IMSA_CONN_TYPE_NORMAL,
                                                                        IMSA_IP_TYPE_IPV6))
            {
                IMSA_INFO_LOG("IMSA_CONN_ProcIpv4ActCnf:ipv6 already active");

                /* 如果IPV6全局地址已获得，回复连接建立成功；否则启动等待IPV6参数定时器 */
                IMSA_CONN_WaitForIpv6InfoProc(IMSA_CONN_TYPE_NORMAL);
                return ;
            }

            /* 查找一个未激活的CID进行激活 */
            IMSA_CONN_AssignOpid(enConnType, &ucOpid);
            ulRet = TAF_PS_GetUnusedCid(PS_PID_IMSA, IMSA_CLIENT_ID, ucOpid, &ucCid);

            if (VOS_OK != ulRet)
            {
                IMSA_WARN_LOG("IMSA_CONN_ProcIpv4ActCnf:get cid failed!");

                IMSA_CONN_SetupConnSucc(IMSA_CONN_TYPE_NORMAL);
                return ;
            }

            ulRet = IMSA_CONN_SipSignalPdpActOrig(IMSA_CONN_TYPE_NORMAL, ucCid, TAF_PDP_IPV6);
            if (IMSA_SUCC != ulRet)
            {
                IMSA_WARN_LOG("IMSA_CONN_ProcIpv4ActCnf:IMSA_CONN_SipSignalPdpActOrig failed!");

                IMSA_CONN_SetupConnSucc(IMSA_CONN_TYPE_NORMAL);
                return ;
            }

            break;

        /* 这里是PDP激活回退功能实现 */
        case IMSA_IP_TYPE_IPV4V6:
            IMSA_CONN_ProcActCnfBack(pstPdpActivateCnf);
            break;

        default:
            IMSA_WARN_LOG("IMSA_CONN_ProcIpv4ActCnf:current requst Pdn Type is error!");
            break;
    }

    return;
}
VOS_VOID  IMSA_CONN_ProcIpv6ActCnf
(
    IMSA_CONN_TYPE_ENUM_UINT32                  enConnType,
    const TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU    *pstPdpActivateCnf
)
{
    IMSA_NORMAL_CONN_STRU              *pstNormalConn   = VOS_NULL_PTR;

    if (IMSA_CONN_TYPE_EMC == enConnType)
    {
        /* 由于3GPP协议要求同一时刻只能存在一个紧急承载，因此不会再发起另一个紧急
           承载建立 */

        /* 如果IPV6全局地址已获得，回复连接建立成功；否则启动等待IPV6参数定时器 */
        IMSA_CONN_WaitForIpv6InfoProc(IMSA_CONN_TYPE_EMC);

        return ;
    }

    pstNormalConn   = IMSA_CONN_GetNormalConnAddr();

    /* 如果是IPV4V6，需要激活另一个PDP */
    if (IMSA_IP_TYPE_IPV4V6 != pstNormalConn->enFirstReqPdnType)
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcIpv6ActCnf:Not ipv4v6");

        /* 如果IPV6全局地址已获得，回复连接建立成功；否则启动等待IPV6参数定时器 */
        IMSA_CONN_WaitForIpv6InfoProc(IMSA_CONN_TYPE_NORMAL);

        return ;
    }

    /* 如果是IPV4V6，需要激活另一个PDP */
    switch (pstNormalConn->enCurReqPdnType)
    {
        case TAF_PDP_IPV6:
            /* 这种情况不属于PDP回退，是前面PDP激活被拒绝后，分别发起IPV4、
               IPV6的PDP激活, IPV6激活后不再发起IPV4的PDP激活 */

            /* 如果IPV6全局地址已获得，回复连接建立成功；否则启动等待IPV6参数定时器 */
            IMSA_CONN_WaitForIpv6InfoProc(IMSA_CONN_TYPE_NORMAL);
            break;

        /* 这里是PDP激活回退功能实现 */
        case TAF_PDP_IPV4V6:

           IMSA_CONN_ProcActCnfBack(pstPdpActivateCnf);
           break;

        default:
           IMSA_WARN_LOG("IMSA_CONN_ProcIpv4ActCnf:current requst Pdn Type is error!");
           break;
    }

    return;
}


VOS_VOID  IMSA_CONN_ProcIpv4v6ActCnf
(
    IMSA_CONN_TYPE_ENUM_UINT32                  enConnType
)
{
    /* 如果IPV6全局地址已获得，回复连接建立成功；否则启动等待IPV6参数定时器 */
    IMSA_CONN_WaitForIpv6InfoProc(enConnType);
}
VOS_UINT32 IMSA_CONN_MatchIPV4V6FallBackCause
(
    TAF_PS_CAUSE_ENUM_UINT32                    enCause
)
{
    IMSA_CONN_MANAGER_STRU              *pstConnManager;
    VOS_UINT32                          ulCnt               = IMSA_NULL;

    IMSA_INFO_LOG("IMSA_CONN_MatchIPV4V6FallBackCause is entered!");

    if (TAF_PS_CAUSE_SM_NW_UNKNOWN_PDP_ADDR_OR_TYPE == enCause)
    {
        IMSA_INFO_LOG("IMSA_CONN_MatchIPV4V6FallBackCause: cause match #28!");
        return IMSA_SUCC;
    }

    pstConnManager = IMSA_CONN_GetConnManagerAddr();
    for (ulCnt = 0; ulCnt < pstConnManager->stIpv6FallBackExtCause.ulCauseNum; ulCnt++)
    {
        if (pstConnManager->stIpv6FallBackExtCause.aenPsCause[ulCnt] == enCause)
        {
            IMSA_INFO_LOG("IMSA_CONN_MatchIPV4V6FallBackCause: cause match succ!");
            return IMSA_SUCC;
        }
    }

    return IMSA_FAIL;
}


VOS_VOID IMSA_CONN_ProcActRejCurReqIpv4v6
(
    IMSA_CONN_TYPE_ENUM_UINT32                  enConnType,
    const TAF_PS_CALL_PDP_ACTIVATE_REJ_STRU    *pstPdpActivateRej
)
{
    VOS_UINT32                          ulResult            = IMSA_FAIL;
    VOS_UINT8                           ucCid               = IMSA_NULL;

    /* 这种情况，需要分别发起IPv4、IPv6的PDP激活 */
    if (IMSA_SUCC == IMSA_CONN_MatchIPV4V6FallBackCause(pstPdpActivateRej->enCause))
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcActRejCurReqIpv4v6: match fallback cause succ!");

        IMSA_CONN_GetConnSelectedCid(enConnType, ucCid);
        ulResult = IMSA_CONN_SipSignalPdpActOrig(enConnType, ucCid, IMSA_IP_TYPE_IPV4);
        if (IMSA_SUCC != ulResult)
        {
            IMSA_WARN_LOG("IMSA_CONN_ProcActRejCurReqIpv4v6:unknown pdp addr or type,IMSA_CONN_SipSignalPdpActOrig failed!");

            IMSA_CONN_SetupConnFail(enConnType, IMSA_CONN_RESULT_FAIL_CN_REJ,pstPdpActivateRej->enCause);

            return ;
        }

        return ;
    }

    if (IMSA_IP_TYPE_IPV4V6 == pstPdpActivateRej->enPdpType)
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcActRejCurReqIpv4v6:ipv4v6");

        IMSA_CONN_SetupConnFail(enConnType, IMSA_CONN_RESULT_FAIL_CN_REJ,pstPdpActivateRej->enCause);
        return ;
    }

    if ((IMSA_OP_TRUE == pstPdpActivateRej->bitOpCauseEx)
        && (TAF_PS_CAUSE_SM_NW_SINGLE_ADDR_BEARERS_ONLY_ALLOWED != pstPdpActivateRej->enCauseEx))
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcActRejCurReqIpv4v6:Causeex is not sigle addr bearers only allowed!");

        IMSA_CONN_SetupConnFail(enConnType, IMSA_CONN_RESULT_FAIL_CN_REJ,pstPdpActivateRej->enCause);
        return ;
    }

    if (IMSA_IP_TYPE_IPV4 == pstPdpActivateRej->enPdpType)
    {
        IMSA_CONN_GetConnSelectedCid(enConnType, ucCid);
        ulResult = IMSA_CONN_SipSignalPdpActOrig(enConnType, ucCid, IMSA_IP_TYPE_IPV6);
        if (IMSA_SUCC != ulResult)
        {
            IMSA_WARN_LOG("IMSA_CONN_ProcActRejCurReqIpv4v6:qos not accepted,ipv4,IMSA_CONN_SipSignalPdpActOrig failed!");

            IMSA_CONN_SetupConnFail(enConnType, IMSA_CONN_RESULT_FAIL_CN_REJ,pstPdpActivateRej->enCause);
            return ;
        }

        return ;
    }
    else
    {
        IMSA_CONN_GetConnSelectedCid(enConnType, ucCid);
        ulResult = IMSA_CONN_SipSignalPdpActOrig(enConnType, ucCid, IMSA_IP_TYPE_IPV4);
        if (IMSA_SUCC != ulResult)
        {
            IMSA_WARN_LOG("IMSA_CONN_ProcActRejCurReqIpv4v6:qos not accepted,ipv6,IMSA_CONN_SipSignalPdpActOrig failed!");

            IMSA_CONN_SetupConnFail(enConnType, IMSA_CONN_RESULT_FAIL_CN_REJ,pstPdpActivateRej->enCause);
            return ;
        }

        /* 由于IPV6已经确定不会成功，为了防止后续再尝试IPV6类型，将
           first requst pdn type设置为IPV4 */
        IMSA_CONN_SaveFirstReqPdnType(enConnType, IMSA_IP_TYPE_IPV4);

        return ;
    }
}


VOS_VOID IMSA_CONN_ProcActRejCurReqIpv4
(
    IMSA_CONN_TYPE_ENUM_UINT32                  enConnType,
    const TAF_PS_CALL_PDP_ACTIVATE_REJ_STRU    *pstPdpActivateRej
)
{
    VOS_UINT32                          ulResult            = IMSA_FAIL;
    VOS_UINT8                           ucCid               = IMSA_NULL;

    /* 用户发起IPv4v6类型的PDP激活, 而且被网络拒绝, 原因为28, 协议栈需要
       分别发起IPv4/IPv6类型的PDP激活, 协议栈首先发起IPv4, 再发起IPv6,
       如果IPV4类型的PDP激活再次被网络拒绝, 协议栈还需要尝试IPV6类型的
       PDP激活为了防止PDP激活嵌套, 如果IPv6类型的PDP激活失败, 将不再尝试
       IPv4类型的PDP激活 */
    if (IMSA_PDP_STATE_ACTIVE == IMSA_CONN_GetSipSignalPdpState(enConnType, IMSA_IP_TYPE_IPV6))
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcActRejCurReqIpv4:ipv6 already active");

        /* 如果IPV6全局地址已获得，回复连接建立成功；否则启动等待IPV6参数定时器 */
        IMSA_CONN_WaitForIpv6InfoProc(enConnType);
        return ;
    }

    IMSA_CONN_GetConnSelectedCid(enConnType, ucCid);
    ulResult = IMSA_CONN_SipSignalPdpActOrig(enConnType, ucCid, IMSA_IP_TYPE_IPV6);
    if (IMSA_SUCC != ulResult)
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcActRejCurReqIpv4:IMSA_CONN_SipSignalPdpActOrig failed!");

        IMSA_CONN_SetupConnFail(enConnType, IMSA_CONN_RESULT_FAIL_CN_REJ,pstPdpActivateRej->enCause);
        return ;
    }
}
VOS_VOID IMSA_CONN_ProcActRejCurReqIpv6
(
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType,
    const TAF_PS_CALL_PDP_ACTIVATE_REJ_STRU    *pstPdpActivateRej
)
{
    if (IMSA_PDP_STATE_ACTIVE == IMSA_CONN_GetSipSignalPdpState(enConnType, IMSA_IP_TYPE_IPV4))
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcActRejCurReqIpv6:ipv4 already active");

        IMSA_CONN_SetupConnSucc(enConnType);
        return ;
    }
    else
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcActRejCurReqIpv6:ipv4 not active,ipv6 rej!");

        IMSA_CONN_SetupConnFail(enConnType, IMSA_CONN_RESULT_FAIL_CN_REJ,pstPdpActivateRej->enCause);
        return ;
    }
}


VOS_UINT32 IMSA_CONN_ProcTafPsEvtPdpActivateCnf
(
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult            = IMSA_FAIL;
    TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU  *pstPdpActivateCnf   = VOS_NULL_PTR;
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType          = IMSA_CONN_TYPE_BUTT;
    IMSA_NORMAL_CONN_STRU              *pstNormalConn       = VOS_NULL_PTR;
    IMSA_EMC_CONN_STRU                 *pstEmcConn          = VOS_NULL_PTR;
    IMSA_PDP_CNTXT_INFO_STRU           *pstPdpInfo          = VOS_NULL_PTR;

    /* 初始化 */
    pstPdpActivateCnf  = (TAF_PS_CALL_PDP_ACTIVATE_CNF_STRU*)pEvtInfo;

    IMSA_INFO_LOG1("IMSA_CONN_ProcTafPsEvtPdpActivateCnf is entered! opid:", pstPdpActivateCnf->stCtrl.ucOpId);

    pstNormalConn                   = IMSA_CONN_GetNormalConnAddr();
    pstEmcConn                      = IMSA_CONN_GetEmcConnAddr();

    /* 根据OPID查找其关联的连接实体类型 */
    ulResult = IMSA_CONN_GetConnTypeByOpid( pstPdpActivateCnf->stCtrl.ucOpId,
                                            &enConnType);

    /* 如果查找失败，则直接退出 */
    if (IMSA_FAIL == ulResult)
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsCallEvtPdpActivateCnf:Get Opid Failed!");
        return IMSA_FAIL;
    }

    /* 不是CONNING状态，则直接退出 */
    if (IMSA_FALSE == IMSA_CONN_IsConnStatusEqual(enConnType, IMSA_CONN_STATUS_CONNING))
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsCallEvtPdpActivateCnf:CONNING state!");
        return IMSA_FAIL;
    }

    /* 如果不是缺省承载，则直接丢弃，暂时支持缺省承载类型的SIP信令承载 */
    if (IMSA_OP_TRUE == pstPdpActivateCnf->bitOpLinkdRabId)
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsCallEvtPdpActivateCnf:Illegal Bearer Type!");
        return IMSA_FAIL;
    }

    /* 存储SIP信令承载信息，包括P-CSCF、DNS、IP地址信息等 */
    if (IMSA_CONN_TYPE_NORMAL == enConnType)
    {
        if (IMSA_CONN_MAX_NORMAL_SIP_SIGNAL_PDP_NUM == pstNormalConn->ulSipSignalPdpNum)
        {
            IMSA_WARN_LOG("IMSA_CONN_ProcTafPsCallEvtPdpActivateCnf:signal pdp is already max num!");
            return IMSA_FAIL;
        }

        pstPdpInfo                      = &pstNormalConn->astSipSignalPdpArray[pstNormalConn->ulSipSignalPdpNum];

        IMSA_CONN_SaveSipSignalPdpInfo( pstPdpInfo, pstPdpActivateCnf);

        pstNormalConn->ulSipSignalPdpNum++;
    }
    else
    {
        pstPdpInfo                      = &pstEmcConn->stSipSignalPdp;

        IMSA_CONN_SaveSipSignalPdpInfo( pstPdpInfo, pstPdpActivateCnf);
    }

    /* 给REG模块配置地址对 */
    IMSA_CONN_ConfigPdpInfo2Reg(enConnType, pstPdpInfo);

    /* 给底软配置IP地址和DNS地址 */
    /* IMSA_CONN_ConfigPdpInfo2Bsp(pstPdpInfo); */

    /* 停止IMS拨号定时器 */
    IMSA_CONN_StopTimer(enConnType, TI_IMSA_SIP_SIGAL_PDP_ORIG);

    /* 给CDS配置下行过滤承载 */
    IMSA_CONN_SndCdsSetImsBearerReq();

    /* 根据PDP类型分别处理*/
    switch ( pstPdpActivateCnf->stPdpAddr.enPdpType )
    {
        case TAF_PDP_IPV4:
            IMSA_CONN_ProcIpv4ActCnf(enConnType, pstPdpActivateCnf);
            break;

        case TAF_PDP_IPV6:
            IMSA_CONN_ProcIpv6ActCnf(enConnType, pstPdpActivateCnf);
            break;

        case TAF_PDP_IPV4V6:
            IMSA_CONN_ProcIpv4v6ActCnf(enConnType);
            break;

        default:
            IMSA_WARN_LOG("IMSA_CONN_ProcTafPsCallEvtPdpActivateCnf:pdp type invaild!");
            break;
    }

    return IMSA_SUCC;
}



VOS_UINT32 IMSA_CONN_ProcTafPsEvtPdpActivateRej
(
    VOS_VOID                           *pEvtInfo
)
{
    VOS_UINT32                          ulResult            = IMSA_FAIL;
    TAF_PS_CALL_PDP_ACTIVATE_REJ_STRU  *pstPdpActivateRej   = VOS_NULL_PTR;
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType          = IMSA_CONN_TYPE_BUTT;
    IMSA_IP_TYPE_ENUM_UINT8             enFirstReqPdnType   = IMSA_IP_TYPE_BUTT;
    IMSA_IP_TYPE_ENUM_UINT8             enCurReqPdnType     = IMSA_IP_TYPE_BUTT;

    /* 初始化 */
    pstPdpActivateRej  = (TAF_PS_CALL_PDP_ACTIVATE_REJ_STRU*)pEvtInfo;

    IMSA_INFO_LOG1("IMSA_CONN_ProcTafPsEvtPdpActivateRej is entered! opid:", pstPdpActivateRej->stCtrl.ucOpId);

    /* 根据OPID查找其关联的连接实体类型 */
    ulResult = IMSA_CONN_GetConnTypeByOpid( pstPdpActivateRej->stCtrl.ucOpId,
                                            &enConnType);

    /* 如果查找失败，则直接退出 */
    if (IMSA_FAIL == ulResult)
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpActivateRej:Get Conn Type Failed!");
        return IMSA_FAIL;
    }

    /* 不是CONNING状态，则直接退出 */
    if (IMSA_FALSE == IMSA_CONN_IsConnStatusEqual(enConnType, IMSA_CONN_STATUS_CONNING))
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpActivateRej:NOT CONNING state!");
        return IMSA_FAIL;
    }

    /* 停止IMS拨号定时器 */
    IMSA_CONN_StopTimer(enConnType, TI_IMSA_SIP_SIGAL_PDP_ORIG);

    IMSA_CONN_GetConnFirstReqPdnType(enConnType, enFirstReqPdnType);
    IMSA_CONN_GetConnCurReqPdnType(enConnType, enCurReqPdnType);


    IMSA_INFO_LOG1("enFirstReqPdnType:", enFirstReqPdnType);

    /* 如果是IPV4 ONLY、IPV6 ONLY直接上报拨号失败. */
    if (IMSA_IP_TYPE_IPV4V6 != enFirstReqPdnType)
    {
        if (IMSA_TRUE == IMSA_CONN_HasActiveSipSignalPdp(enConnType))
        {
            IMSA_CONN_SndConnSetupInd(  IMSA_CONN_RESULT_SUCCESS,
                                        enConnType,
                                        IMSA_CONN_SIP_PDP_TYPE_SIGNAL);
            return IMSA_SUCC;
        }
        IMSA_CONN_SetupConnFail(enConnType, IMSA_CONN_RESULT_FAIL_CN_REJ, pstPdpActivateRej->enCause);

        return IMSA_SUCC;
    }

    /* IPV4V6则需要视具体实现分别发起IPv4，IPv6类型的PDP激活 */
    if (IMSA_IP_TYPE_IPV4V6 == enCurReqPdnType)
    {
        IMSA_CONN_ProcActRejCurReqIpv4v6(enConnType, pstPdpActivateRej);
    }
    else if (IMSA_IP_TYPE_IPV4 == enCurReqPdnType)
    {
        IMSA_CONN_ProcActRejCurReqIpv4(enConnType, pstPdpActivateRej);
    }
    else
    {
        IMSA_CONN_ProcActRejCurReqIpv6(enConnType, pstPdpActivateRej);
    }

    return IMSA_SUCC;
}
VOS_UINT32 IMSA_CONN_ProcTafPsEvtPdpActivateInd
(
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_PDP_ACTIVATE_IND_STRU  *pstPdpActivateInd   = VOS_NULL_PTR;
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType          = IMSA_CONN_TYPE_BUTT;
    IMSA_NORMAL_CONN_STRU              *pstNormalConn       = VOS_NULL_PTR;
    IMSA_EMC_CONN_STRU                 *pstEmcConn          = VOS_NULL_PTR;
    IMSA_CONN_SIP_PDP_TYPE_ENUM_UINT32  enSipPdpType        = IMSA_CONN_SIP_PDP_TYPE_BUTT;
    IMSA_PDP_CNTXT_INFO_STRU           *pstPdpContext       = VOS_NULL_PTR;
    VOS_UINT32                          ulCurSipMediaPdpNum = IMSA_NULL;

    IMSA_INFO_LOG("IMSA_CONN_ProcTafPsEvtPdpActivateInd is entered!");

    /* 初始化 */
    pstPdpActivateInd  = (TAF_PS_CALL_PDP_ACTIVATE_IND_STRU*)pEvtInfo;

    /* 如果不是专有承载，则直接退出 */
    if (IMSA_OP_TRUE != pstPdpActivateInd->bitOpLinkdRabId)
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpActivateInd:not dedicated!");
        return IMSA_FAIL;
    }

    /* 获取承载上下文 */
    if (IMSA_SUCC       != IMSA_CONN_GetPdpContextByPdpId(  IMSA_CONN_TYPE_NORMAL,
                                                            pstPdpActivateInd->ucLinkdRabId,
                                                            &enSipPdpType,
                                                            &pstPdpContext))
    {
        if (IMSA_SUCC   != IMSA_CONN_GetPdpContextByPdpId(  IMSA_CONN_TYPE_EMC,
                                                            pstPdpActivateInd->ucLinkdRabId,
                                                            &enSipPdpType,
                                                            &pstPdpContext))
        {
            IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpActivateInd:Get LinkRabId context failed!");
            return IMSA_FAIL;
        }
        else
        {
            enConnType          = IMSA_CONN_TYPE_EMC;
            pstEmcConn          = IMSA_CONN_GetEmcConnAddr();
            ulCurSipMediaPdpNum = pstEmcConn->ulSipMediaPdpNum;
        }
    }
    else
    {
        enConnType          = IMSA_CONN_TYPE_NORMAL;
        pstNormalConn       = IMSA_CONN_GetNormalConnAddr();
        ulCurSipMediaPdpNum = pstNormalConn->ulSipMediaPdpNum;
    }

    if (IMSA_CONN_SIP_PDP_TYPE_SIGNAL != enSipPdpType)
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpActivateInd:linked pdp is not signal pdp!");
        return IMSA_FAIL;
    }

    /* 不是CONN状态，则直接退出 */
    if (IMSA_FALSE == IMSA_CONN_IsConnStatusEqual(  enConnType,
                                                    IMSA_CONN_STATUS_CONN))
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpActivateInd:Not CONN state!");
        return IMSA_FAIL;
    }

    if (IMSA_CONN_MAX_NORMAL_SIP_MEDIA_PDP_NUM <= ulCurSipMediaPdpNum)
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpActivateInd:media pdp num is already 2!");
        return IMSA_FAIL;
    }

    /* 存储SIP媒体承载信息 */
    IMSA_CONN_SaveSipMediaPdpInfo(enConnType, pstPdpActivateInd);

    /* 通知SERVICE模块媒体承载建立成功 */
    IMSA_CONN_SndConnSetupInd(  IMSA_CONN_RESULT_SUCCESS,
                                enConnType,
                                IMSA_CONN_SIP_PDP_TYPE_MEDIA);

    /* 如果当前激活的是视频承载，不需要给CDS配置承载信息 */
    if ((IMSA_OP_TRUE == pstPdpActivateInd->bitOpTft) &&
        (IMSA_FALSE == IMSA_CONN_IsImsBearNeedSetToCds((IMSA_PDP_TFT_INFO_STRU *)&pstPdpActivateInd->stTft)) &&
        (IMSA_FALSE == IMSA_CONN_CheckLocalPortRange((IMSA_PDP_TFT_INFO_STRU *)&pstPdpActivateInd->stTft)))
    {
        return IMSA_SUCC;
    }
    /* 给CDS配置下行过滤承载 */
    IMSA_CONN_SndCdsSetImsBearerReq();

    return IMSA_SUCC;
}


VOS_UINT32 IMSA_CONN_ProcTafPsEvtPdpModifyInd
(
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_PDP_MODIFY_IND_STRU    *pstPdpModifyInd     = VOS_NULL_PTR;
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType          = IMSA_CONN_TYPE_BUTT;
    IMSA_CONN_SIP_PDP_TYPE_ENUM_UINT32  enSipPdpType        = IMSA_CONN_SIP_PDP_TYPE_BUTT;
    IMSA_PDP_CNTXT_INFO_STRU           *pstPdpContext       = VOS_NULL_PTR;

    IMSA_INFO_LOG("IMSA_CONN_ProcTafPsEvtPdpModifyInd is entered!");

    /* 初始化 */
    pstPdpModifyInd     = (TAF_PS_CALL_PDP_MODIFY_IND_STRU*)pEvtInfo;

    /* 获取承载上下文 */
    if (IMSA_SUCC       != IMSA_CONN_GetPdpContextByPdpId(  IMSA_CONN_TYPE_NORMAL,
                                                            pstPdpModifyInd->ucRabId,
                                                            &enSipPdpType,
                                                            &pstPdpContext))
    {
        if (IMSA_SUCC   != IMSA_CONN_GetPdpContextByPdpId(  IMSA_CONN_TYPE_EMC,
                                                            pstPdpModifyInd->ucRabId,
                                                            &enSipPdpType,
                                                            &pstPdpContext))
        {
            IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpModifyInd:Get pdp context failed!");
            return IMSA_FAIL;
        }
        else
        {
            enConnType  = IMSA_CONN_TYPE_EMC;
        }
    }
    else
    {
        enConnType      = IMSA_CONN_TYPE_NORMAL;
    }

    IMSA_INFO_LOG1("IMSA_CONN_ProcTafPsEvtPdpModifyInd: Conn type :", enConnType);

    /* 如果是IDLE状态，则直接退出 */
    if (IMSA_TRUE       == IMSA_CONN_IsConnStatusEqual(enConnType, IMSA_CONN_STATUS_IDLE))
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpModifyInd:IDLE state!");
        return IMSA_FAIL;
    }

    /* 修改SIP承载信息 */
    IMSA_CONN_ModifySipPdpInfo(enSipPdpType, pstPdpContext, pstPdpModifyInd);

    /* 如果是媒体承载，则通知SERVICE媒体承载修改 */
    if (IMSA_CONN_SIP_PDP_TYPE_MEDIA == enSipPdpType)
    {
        IMSA_CONN_SndConnMediaPdpModifyInd(enConnType);
    }

    /* 如果当前激活的是视频承载，不需要给CDS配置承载信息 */
    if ((IMSA_OP_TRUE == pstPdpModifyInd->bitOpTft) &&
        (IMSA_FALSE == IMSA_CONN_IsImsBearNeedSetToCds((IMSA_PDP_TFT_INFO_STRU *)&pstPdpModifyInd->stTft)) &&
        (IMSA_FALSE == IMSA_CONN_CheckLocalPortRange((IMSA_PDP_TFT_INFO_STRU *)&pstPdpModifyInd->stTft)))
    {
        return IMSA_SUCC;
    }
    /* 给CDS配置下行过滤承载 */
    IMSA_CONN_SndCdsSetImsBearerReq();

    return IMSA_SUCC;
}
VOS_UINT32 IMSA_CONN_ProcTafPsEvtPdpDeactivateCnf
(
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_PDP_DEACTIVATE_CNF_STRU    *pstPdpDeactivateCnf = VOS_NULL_PTR;
    VOS_UINT32                              ulResult            = IMSA_FAIL;
    IMSA_CONN_TYPE_ENUM_UINT32              enConnType          = IMSA_CONN_TYPE_BUTT;
    IMSA_CONN_SIP_PDP_TYPE_ENUM_UINT32      enSipPdpType        = IMSA_CONN_SIP_PDP_TYPE_BUTT;
    IMSA_PDP_CNTXT_INFO_STRU               *pstPdpContext       = VOS_NULL_PTR;
    VOS_UINT32                              ulRegParaInvalidFlag= IMSA_NULL;

    pstPdpDeactivateCnf  = (TAF_PS_CALL_PDP_DEACTIVATE_CNF_STRU*)pEvtInfo;

    IMSA_INFO_LOG1("IMSA_CONN_ProcTafPsEvtPdpDeactivateCnf is entered! opid:", pstPdpDeactivateCnf->stCtrl.ucOpId);

    /* 根据OPID查找其关联的连接实体类型 */
    ulResult = IMSA_CONN_GetConnTypeByOpid( pstPdpDeactivateCnf->stCtrl.ucOpId,
                                            &enConnType);

    /* 如果查找失败，则直接退出 */
    if (IMSA_FAIL == ulResult)
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpDeactivateCnf:Get Opid Failed!");
        return IMSA_FAIL;
    }

    /* 不是RELEASING状态，则直接退出 */
    if (IMSA_FALSE == IMSA_CONN_IsConnStatusEqual(enConnType, IMSA_CONN_STATUS_RELEASING))
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpDeactivateCnf:Not releasing state!");
        return IMSA_FAIL;
    }

    /* CID不存在，则直接退出 */
    if (IMSA_SUCC != IMSA_CONN_GetPdpContextByCid(  enConnType,
                                                    pstPdpDeactivateCnf->ucCid,
                                                    &enSipPdpType,
                                                    &pstPdpContext))
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpDeactivateCnf:cid not exist!");
        return IMSA_SUCC;
    }

    /* 如果不是信令承载，则直接退出 */
    if (IMSA_CONN_SIP_PDP_TYPE_SIGNAL != enSipPdpType)
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpDeactivateCnf:Not signal pdp!");
        return IMSA_FAIL;
    }

    /* 停止IMS拨号定时器 */
    IMSA_CONN_StopTimer(enConnType, TI_IMSA_SIP_SIGAL_PDP_END);

    /* 删除信令承载信息 */
    IMSA_CONN_DeletePdpInfo(enConnType, pstPdpDeactivateCnf->ucCid, &ulRegParaInvalidFlag);

    if (IMSA_TRUE == IMSA_CONN_HasActiveSipSignalPdp(enConnType))
    {
        /* 请求APS释放连接 */
        IMSA_CONN_RequestApsRelConn(enConnType);
    }
    else
    {
        IMSA_CONN_ClearConnResourceExeptMedia(enConnType);

        /* 通知SERVICE模块连接释放 */
        IMSA_CONN_SndConnRelInd(enConnType, IMSA_CONN_SIP_PDP_TYPE_SIGNAL);
    }

    return IMSA_SUCC;
}
VOS_UINT32 IMSA_CONN_ProcTafPsEvtPdpDeactivateInd
(
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_PDP_DEACTIVATE_IND_STRU    *pstPdpDeactivateInd = VOS_NULL_PTR;
    IMSA_CONN_TYPE_ENUM_UINT32              enConnType          = IMSA_CONN_TYPE_BUTT;
    IMSA_CONN_SIP_PDP_TYPE_ENUM_UINT32      enSipPdpType        = IMSA_CONN_SIP_PDP_TYPE_BUTT;
    IMSA_PDP_CNTXT_INFO_STRU               *pstPdpContext       = VOS_NULL_PTR;
    VOS_UINT32                              ulRegParaValidFlag  = IMSA_NULL;

    IMSA_INFO_LOG("IMSA_CONN_ProcTafPsEvtPdpDeactivateInd is entered!");

    /* 初始化 */
    pstPdpDeactivateInd = (TAF_PS_CALL_PDP_DEACTIVATE_IND_STRU*)pEvtInfo;

    /* 获取承载上下文 */
    if (IMSA_SUCC       != IMSA_CONN_GetPdpContextByCid(    IMSA_CONN_TYPE_NORMAL,
                                                            pstPdpDeactivateInd->ucCid,
                                                            &enSipPdpType,
                                                            &pstPdpContext))
    {
        if (IMSA_SUCC   != IMSA_CONN_GetPdpContextByCid(    IMSA_CONN_TYPE_EMC,
                                                            pstPdpDeactivateInd->ucCid,
                                                            &enSipPdpType,
                                                            &pstPdpContext))
        {
            IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpDeactivateInd:Get pdp context failed!");
            return IMSA_FAIL;
        }
        else
        {
            enConnType  = IMSA_CONN_TYPE_EMC;
        }
    }
    else
    {
        enConnType      = IMSA_CONN_TYPE_NORMAL;
    }
     /* 删除承载信息前，备份释放承载的类型和CID */
    if (IMSA_SRV_STATUS_CONN_REG == IMSA_SRV_GetEmcSrvStatus() ||
        IMSA_SRV_STATUS_CONN_REG == IMSA_SRV_GetNormalSrvStatus())
    {
        IMSA_RegSaveRegedPara((IMSA_REG_TYPE_ENUM_UINT8)enConnType,
                            pstPdpDeactivateInd->ucCid,
                            pstPdpDeactivateInd->enPdpType);
    }

    /* 删除承载信息 */
    IMSA_CONN_DeletePdpInfo(enConnType, pstPdpDeactivateInd->ucCid, &ulRegParaValidFlag);

    if (IMSA_CONN_TYPE_EMC == enConnType)
    {
        if (IMSA_CONN_SIP_PDP_TYPE_MEDIA == enSipPdpType)
        {
            IMSA_INFO_LOG("IMSA_CONN_ProcTafPsEvtPdpDeactivateInd:EMC media");

            IMSA_CONN_SndConnRelInd(enConnType, IMSA_CONN_SIP_PDP_TYPE_MEDIA);

            return IMSA_SUCC;
        }

        IMSA_INFO_LOG("IMSA_CONN_ProcTafPsEvtPdpDeactivateInd:EMC sig");

        /* 停止IMS拨号定时器 */
        IMSA_CONN_StopTimer(enConnType, TI_IMSA_SIP_SIGAL_PDP_END);

        /* 清除连接资源 */
        /* IMSA_CONN_ClearConnResource(enConnType); */
        /*IMSA_CONN_SetConnStatus(IMSA_CONN_TYPE_EMC, IMSA_CONN_STATUS_IDLE);*/
        IMSA_CONN_ClearConnResourceExeptMedia(enConnType);

        /* 通知SERVICE模块连接释放 */
        IMSA_CONN_SndConnRelInd(enConnType, IMSA_CONN_SIP_PDP_TYPE_SIGNAL);

        return IMSA_SUCC;
    }

    if (IMSA_CONN_SIP_PDP_TYPE_MEDIA == enSipPdpType)
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcTafPsEvtPdpDeactivateInd:MEDIA");

        IMSA_CONN_SndConnRelInd(enConnType, IMSA_CONN_SIP_PDP_TYPE_MEDIA);

        return IMSA_SUCC;
    }

    if (IMSA_CONN_STATUS_CONNING == IMSA_CONN_GetNormalConnStatus())
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcTafPsEvtPdpDeactivateInd:normal,conning");
        /* 停止等待IPV6参数定时器 */
        IMSA_CONN_StopTimer(enConnType, TI_IMSA_WAIT_IPV6_INFO);

        IMSA_CONN_ClearConnResourceExeptMedia(enConnType);

        IMSA_CONN_SndConnRelInd(enConnType, IMSA_CONN_SIP_PDP_TYPE_SIGNAL);

        return IMSA_SUCC;
    }

    if (IMSA_CONN_STATUS_RELEASING == IMSA_CONN_GetNormalConnStatus())
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcTafPsEvtPdpDeactivateInd:normal,releasing");

        if (IMSA_TRUE != IMSA_CONN_HasActiveSipSignalPdp(enConnType))
        {
            /* 停止IMS拨号定时器 */
            IMSA_CONN_StopTimer(enConnType, TI_IMSA_SIP_SIGAL_PDP_END);

            /* 清除连接资源 */
            IMSA_CONN_ClearConnResourceExeptMedia(enConnType);

            /* 通知SERVICE模块连接释放 */
            IMSA_CONN_SndConnRelInd(enConnType, IMSA_CONN_SIP_PDP_TYPE_SIGNAL);
        }

        return IMSA_SUCC;
    }

    if (IMSA_TRUE != IMSA_CONN_HasActiveSipSignalPdp(enConnType))
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcTafPsEvtPdpDeactivateInd:normal,conn,no active pdp!");

        /* 清除连接资源 */
        /* IMSA_CONN_ClearConnResource(enConnType); */
        /*IMSA_CONN_SetConnStatus(IMSA_CONN_TYPE_NORMAL, IMSA_CONN_STATUS_IDLE);*/
        IMSA_CONN_ClearConnResourceExeptMedia(enConnType);

        /* 通知SERVICE模块连接释放 */
        IMSA_CONN_SndConnRelInd(enConnType, IMSA_CONN_SIP_PDP_TYPE_SIGNAL);

        return IMSA_SUCC;
    }

    /* 如果注册参数失效，且还有其他激活的信令承载时，通知SERVICE模块注册参数失效 */
    if (IMSA_CONN_REG_PARA_INVALID == ulRegParaValidFlag)
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcTafPsEvtPdpDeactivateInd:normal,conn,active pdp,reg para invalid!");

        IMSA_CONN_SndConnRegParaInvalid();

        return IMSA_SUCC;
    }

    return IMSA_SUCC;
}

/* lihong00150010 ims begin 2013-01-08 防止网侧重播路由公告 */

VOS_UINT32 IMSA_CONN_IsIpv6PrefixChanged
(
    const IMSA_PDP_CNTXT_INFO_STRU             *pstPdpInfo,
    const TAF_PS_IPV6_INFO_IND_STRU            *pstIpv6InfoInd
)
{
    if (0 == IMSA_MEM_CMP(  pstPdpInfo->stPdpAddr.aucIpV6Addr,
                            pstIpv6InfoInd->stIpv6RaInfo.astPrefixList[0].aucPrefix,
                            IMSA_IPV6_PREFIX_LEN))
    {
        return IMSA_FALSE;
    }

    return IMSA_TRUE;
}
/* lihong00150010 ims end 2013-01-08 防止网侧重播路由公告 */

VOS_UINT32 IMSA_CONN_ProcTafPsEvtPdpIpv6InfoInd
(
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_IPV6_INFO_IND_STRU          *pstPsIpv6InfoInd    = VOS_NULL_PTR;
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType          = IMSA_CONN_TYPE_BUTT;
    IMSA_CONN_SIP_PDP_TYPE_ENUM_UINT32  enSipPdpType        = IMSA_CONN_SIP_PDP_TYPE_BUTT;
    IMSA_PDP_CNTXT_INFO_STRU           *pstPdpContext       = VOS_NULL_PTR;
    VOS_CHAR                            acUeAddr[IMSA_IPV6_ADDR_STRING_LEN + 1] = {0};

    IMSA_INFO_LOG("IMSA_CONN_ProcTafPsEvtPdpIpv6InfoInd is entered!");

    /* 初始化 */
    pstPsIpv6InfoInd     = (TAF_PS_IPV6_INFO_IND_STRU*)pEvtInfo;

    /* 如果没有携带前缀信息，则直接退出 */
    if (0 == pstPsIpv6InfoInd->stIpv6RaInfo.ulPrefixNum)
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpIpv6InfoInd:No prefix!");
        return IMSA_FAIL;
    }

    /* 获取承载上下文 */
    if (IMSA_SUCC       != IMSA_CONN_GetPdpContextByPdpId(  IMSA_CONN_TYPE_NORMAL,
                                                            pstPsIpv6InfoInd->ucRabId,
                                                            &enSipPdpType,
                                                            &pstPdpContext))
    {
        if (IMSA_SUCC   != IMSA_CONN_GetPdpContextByPdpId(  IMSA_CONN_TYPE_EMC,
                                                            pstPsIpv6InfoInd->ucRabId,
                                                            &enSipPdpType,
                                                            &pstPdpContext))
        {
            IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpIpv6InfoInd:Get pdp context failed!");
            return IMSA_FAIL;
        }
        else
        {
            enConnType  = IMSA_CONN_TYPE_EMC;
        }
    }
    else
    {
        enConnType      = IMSA_CONN_TYPE_NORMAL;
    }

    if (IMSA_CONN_SIP_PDP_TYPE_MEDIA == enSipPdpType)
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtPdpIpv6InfoInd:not signal pdp type!");
        return IMSA_FAIL;
    }

    /* 如果是CONN状态，则更新PDP上下文 */
    if (IMSA_TRUE == IMSA_CONN_IsConnStatusEqual(enConnType, IMSA_CONN_STATUS_CONN))
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcTafPsEvtPdpModifyInd:CONN state!");

        /* 存储IPV6信息 */
        /* lihong00150010 ims begin 2013-01-08 防止网侧重播路由公告 */
        if (IMSA_TRUE == IMSA_CONN_IsIpv6PrefixChanged(pstPdpContext, pstPsIpv6InfoInd))
        {
            IMSA_CONN_SaveIpv6Info(pstPdpContext, pstPsIpv6InfoInd);

            /* 给REG模块配置IPV6地址 */
            IMSA_CONN_ConvertIpAddress2String(  IMSA_IP_TYPE_IPV6,
                                                pstPdpContext->stPdpAddr.aucIpV6Addr,
                                                acUeAddr);

            (VOS_VOID)IMSA_RegAddrPairMgrAddUeAddr( (IMSA_REG_TYPE_ENUM_UINT8)enConnType,
                                                    IMSA_IP_TYPE_IPV6,
                                                    acUeAddr);

            /* 给底软配置IPv6地址和IPv6 DNS地址 */
            /* IMSA_CONN_ConfigPdpIPv6Info2Bsp(pstPdpContext); */
        }
        /* lihong00150010 ims end 2013-01-08 防止网侧重播路由公告 */

        return IMSA_SUCC;
    }

    /* 如果是CONNING状态，则更新PDP上下文，通知SERVICE连接建立成功 */
    if (IMSA_TRUE == IMSA_CONN_IsConnStatusEqual(enConnType, IMSA_CONN_STATUS_CONNING))
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcTafPsEvtPdpModifyInd:CONNING state!");

        /* 存储IPV6信息 */
        /* lihong00150010 ims begin 2013-01-08 防止网侧重播路由公告 */
        if (IMSA_TRUE == IMSA_CONN_IsIpv6PrefixChanged(pstPdpContext, pstPsIpv6InfoInd))
        {
            IMSA_CONN_SaveIpv6Info(pstPdpContext, pstPsIpv6InfoInd);

            /* 给REG模块配置IPV6地址 */
            IMSA_CONN_ConvertIpAddress2String(  IMSA_IP_TYPE_IPV6,
                                                pstPdpContext->stPdpAddr.aucIpV6Addr,
                                                acUeAddr);

            (VOS_VOID)IMSA_RegAddrPairMgrAddUeAddr( (IMSA_REG_TYPE_ENUM_UINT8)enConnType,
                                                    IMSA_IP_TYPE_IPV6,
                                                    acUeAddr);

            /* 给底软配置IPv6地址和IPv6 DNS地址 */
            /* IMSA_CONN_ConfigPdpIPv6Info2Bsp(pstPdpContext); */
        }
        /* lihong00150010 ims end 2013-01-08 防止网侧重播路由公告 */

        /* 如果当前还在请求IPV4的SIP信令承载建立，则等待IPV4信令承载建立完成后
           再通知SERVICE模块连接建立成功 */
        if (IMSA_TRUE == IMSA_CONN_IsEqualToSelectedCid(enConnType, pstPsIpv6InfoInd->ucCid))
        {
            /* 通知SERIVCE连接建立成功 */
            IMSA_CONN_SetupConnSucc(enConnType);
        }

        /* 停止等待IPV6参数定时器 */
        IMSA_CONN_StopTimer(enConnType, TI_IMSA_WAIT_IPV6_INFO);

        return IMSA_SUCC;
    }

    return IMSA_FAIL;
}


VOS_UINT32 IMSA_CONN_ProcTafPsEvtCallOrigCnf
(
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_ORIG_CNF_STRU          *pstCallOrigCnf  = VOS_NULL_PTR;
    VOS_UINT32                          ulResult        = IMSA_FAIL;
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType      = IMSA_CONN_TYPE_BUTT;

    pstCallOrigCnf  = (TAF_PS_CALL_ORIG_CNF_STRU*)pEvtInfo;

    IMSA_INFO_LOG1("IMSA_CONN_ProcTafPsEvtCallOrigCnf is entered! opid:", pstCallOrigCnf->stCtrl.ucOpId);

    /* 根据OPID查找其关联的连接实体类型 */
    ulResult = IMSA_CONN_GetConnTypeByOpid( pstCallOrigCnf->stCtrl.ucOpId,
                                            &enConnType);

    /* 如果查找失败，则直接退出 */
    if (IMSA_FAIL == ulResult)
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtCallOrigCnf:Get Opid Failed!");
        return IMSA_FAIL;
    }

    /* 不是CONNING状态，则直接退出 */
    if (IMSA_FALSE == IMSA_CONN_IsConnStatusEqual(enConnType, IMSA_CONN_STATUS_CONNING))
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtCallOrigCnf:Not CONNING state!");
        return IMSA_FAIL;
    }

    /* APS参数检查正确，直接退出 */
    if (TAF_PS_CAUSE_SUCCESS == pstCallOrigCnf->enCause)
    {
        return IMSA_SUCC;
    }

    /* 停止IMS拨号定时器 */
    IMSA_CONN_StopTimer(enConnType, TI_IMSA_SIP_SIGAL_PDP_ORIG);

    if (IMSA_TRUE == IMSA_CONN_HasActiveSipSignalPdp(enConnType))
    {
        /* 如果IPV6全局地址已获得，回复连接建立成功；否则启动等待IPV6参数定时器 */
        IMSA_CONN_WaitForIpv6InfoProc(enConnType);

        return IMSA_SUCC;
    }

    /* 给SERVICE回复IMSA_CONN_SETUP_IND消息，如果是TAF_PS_CAUSE_PDP_ACTIVATE_LIMIT，
           则结果值填为FAIL_PDP_ACTIVATE_LIMIT，否则填为FAIL_PARA_ERR */
    if (TAF_PS_CAUSE_PDP_ACTIVATE_LIMIT == pstCallOrigCnf->enCause)
    {
        IMSA_CONN_SetupConnFail(enConnType, IMSA_CONN_RESULT_FAIL_PDP_ACTIVATE_LIMIT, (TAF_PS_CAUSE_ENUM_UINT32)TAF_PS_CAUSE_BUTT);
    }
    else if (TAF_PS_CAUSE_OPERATION_CONFLICT == pstCallOrigCnf->enCause)
    {
        IMSA_CONN_SetupConnFail(enConnType, IMSA_CONN_RESULT_FAIL_SAME_APN_OPERATING, (TAF_PS_CAUSE_ENUM_UINT32)TAF_PS_CAUSE_BUTT);
    }
    else
    {
        IMSA_CONN_SetupConnFail(enConnType, IMSA_CONN_RESULT_FAIL_PARA_ERR, (TAF_PS_CAUSE_ENUM_UINT32)TAF_PS_CAUSE_BUTT);
    }

    return IMSA_SUCC;
}



VOS_UINT32 IMSA_CONN_ProcTafPsEvtCallEndCnf
(
    VOS_VOID                           *pEvtInfo
)
{
    TAF_PS_CALL_END_CNF_STRU           *pstCallEndCnf           = VOS_NULL_PTR;
    VOS_UINT32                          ulResult                = IMSA_FAIL;
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType              = IMSA_CONN_TYPE_BUTT;
    IMSA_CONN_SIP_PDP_TYPE_ENUM_UINT32  enSipPdpType            = IMSA_CONN_SIP_PDP_TYPE_BUTT;
    IMSA_PDP_CNTXT_INFO_STRU           *pstPdpContext           = VOS_NULL_PTR;
    VOS_UINT32                          ulRegParaInvalidFlag    = IMSA_NULL;

    pstCallEndCnf  = (TAF_PS_CALL_END_CNF_STRU*)pEvtInfo;

    IMSA_INFO_LOG1("IMSA_CONN_ProcTafPsEvtCallEndCnf is entered! opid:",pstCallEndCnf->stCtrl.ucOpId);

    /* 根据OPID查找其关联的连接实体类型 */
    ulResult = IMSA_CONN_GetConnTypeByOpid( pstCallEndCnf->stCtrl.ucOpId,
                                            &enConnType);

    /* 如果查找失败，则直接退出 */
    if (IMSA_FAIL == ulResult)
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtCallEndCnf:Get Opid Failed!");
        return IMSA_FAIL;
    }

    /* 不是RELEASING状态，则直接退出 */
    if (IMSA_FALSE == IMSA_CONN_IsConnStatusEqual(enConnType, IMSA_CONN_STATUS_RELEASING))
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtCallEndCnf:Not releasing state!");
        return IMSA_FAIL;
    }

    /* APS参数检查正确，直接退出 */
    if (TAF_PS_CAUSE_SUCCESS == pstCallEndCnf->enCause)
    {
        return IMSA_SUCC;
    }

    /* CID不存在，则直接退出 */
    if (IMSA_SUCC != IMSA_CONN_GetPdpContextByCid(  enConnType,
                                                    pstCallEndCnf->ucCid,
                                                    &enSipPdpType,
                                                    &pstPdpContext))
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTafPsEvtCallEndCnf:cid not exist!");
        return IMSA_SUCC;
    }

    /* 停止IMS拨号定时器 */
    IMSA_CONN_StopTimer(enConnType, TI_IMSA_SIP_SIGAL_PDP_END);

    /* 删除信令承载信息 */
    IMSA_CONN_DeletePdpInfo(enConnType, pstCallEndCnf->ucCid, &ulRegParaInvalidFlag);

    if (IMSA_TRUE == IMSA_CONN_HasActiveSipSignalPdp(enConnType))
    {
        /* 请求APS释放连接 */
        IMSA_CONN_RequestApsRelConn(enConnType);
    }

    return IMSA_SUCC;
}

/*****************************************************************************
 Function Name  : IMSA_CONN_ProcTafPsEvtSrvccCancelInd
 Description    : IMSA CONN模块处理SRVCC CANCEL事件
 Input          : pEvtInfo--------------事件信息指针
 Output         : VOS_VOID
 Return Value   : VOS_VOID

 History        :
      1.sunbing 49683      2013-10-14  Draft Enact
*****************************************************************************/
VOS_UINT32 IMSA_CONN_ProcTafPsEvtSrvccCancelInd
(
    VOS_VOID                           *pEvtInfo
)
{
    IMSA_INFO_LOG("IMSA_CONN_ProcTafPsEvtSrvccCancelInd is entered!");

    (VOS_VOID)pEvtInfo;

    /*清除等待异系统指示标示*/
    IMSA_CallSetSrvccFlag(IMSA_FALSE);

    /* 清除不能上报ALL RELEASED事件标识 */
    IMSA_CallSetNotReportAllReleasedFlag(IMSA_FALSE);

    /*收到该消息时，终端的异系统流程还没有启动，出了通知IMS和AT上报，不需要做特殊处理*/

    /*收到ESM/SM Notification ind事件，需要通知IMS协议栈发起re-invite流程*/
    (VOS_VOID)IMSA_CallSendImsMsgSrvcc(IMSA_IMS_INPUT_CALL_REASON_SRVCC_CANCELED);

    /*上报HO失败*/
    IMSA_SndMsgAtCirephInd(AT_IMSA_SRVCC_HANDOVER_FAILURE);

    return IMSA_SUCC;
}
VOS_VOID IMSA_CONN_ProcTimerMsgSipSignalPdpOrigExp
(
    const VOS_VOID                     *pMsg
)
{
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType = IMSA_CONN_TYPE_BUTT;

    IMSA_INFO_LOG("IMSA_CONN_ProcTimerMsgSipSignalPdpOrigExp is entered!");

    enConnType = PS_GET_REL_TIMER_PARA(pMsg);

    if (enConnType >= IMSA_CONN_TYPE_BUTT)
    {
        IMSA_ERR_LOG("IMSA_CONN_ProcTimerMsgSipSignalPdpOrigExp:Illegal Para!");
        return ;
    }

    /* 不是CONNING状态，则直接退出 */
    if (IMSA_FALSE == IMSA_CONN_IsConnStatusEqual(enConnType, IMSA_CONN_STATUS_CONNING))
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTimerMsgSipSignalPdpEndExp:Not CONNING state!");
        return ;
    }

    if (IMSA_CONN_TYPE_EMC == enConnType)
    {
        IMSA_INFO_LOG("IMSA_CONN_ProcTimerMsgSipSignalPdpOrigExp:EMC,conning!");

        IMSA_CONN_SetupConnFail(enConnType, IMSA_CONN_RESULT_FAIL_TIMER_EXP, (TAF_PS_CAUSE_ENUM_UINT32)TAF_PS_CAUSE_BUTT);

        return ;
    }

    IMSA_INFO_LOG("IMSA_CONN_ProcTimerMsgSipSignalPdpOrigExp:normal,conning!");

    if (IMSA_TRUE == IMSA_CONN_HasActiveSipSignalPdp(enConnType))
    {
        /* 如果IPV6全局地址已获得，回复连接建立成功；否则启动等待IPV6参数定时器 */
        IMSA_CONN_WaitForIpv6InfoProc(enConnType);
    }
    else
    {
        IMSA_CONN_SetupConnFail(enConnType, IMSA_CONN_RESULT_FAIL_TIMER_EXP, (TAF_PS_CAUSE_ENUM_UINT32)TAF_PS_CAUSE_BUTT);
    }

    return ;
}


VOS_VOID IMSA_CONN_ProcTimerMsgSipSignalPdpEndExp
(
    const VOS_VOID                     *pMsg
)
{
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType              = IMSA_CONN_TYPE_BUTT;
    VOS_UINT32                          ulRegParaInvalidFlag    = IMSA_NULL;
    IMSA_NORMAL_CONN_STRU              *pstNormalConn           = VOS_NULL_PTR;
    IMSA_EMC_CONN_STRU                 *pstEmcConn              = VOS_NULL_PTR;

    IMSA_INFO_LOG("IMSA_CONN_ProcTimerMsgSipSignalPdpEndExp is entered!");

    enConnType = PS_GET_REL_TIMER_PARA(pMsg);

    if (enConnType >= IMSA_CONN_TYPE_BUTT)
    {
        IMSA_ERR_LOG("IMSA_CONN_ProcTimerMsgSipSignalPdpEndExp:Illegal Para!");

        return ;
    }

    /* 不是RELEASING状态，则直接退出 */
    if (IMSA_FALSE == IMSA_CONN_IsConnStatusEqual(enConnType, IMSA_CONN_STATUS_RELEASING))
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTimerMsgSipSignalPdpEndExp:Not releasing state!");
        return ;
    }

    if (IMSA_CONN_TYPE_NORMAL == enConnType)
    {
        pstNormalConn   = IMSA_CONN_GetNormalConnAddr();

        /* 删除信令承载信息 */
        IMSA_CONN_DeletePdpInfo(    enConnType,
                                    pstNormalConn->astSipSignalPdpArray[0].ucCid,
                                    &ulRegParaInvalidFlag);
    }
    else
    {
        pstEmcConn      = IMSA_CONN_GetEmcConnAddr();

        /* 删除信令承载信息 */
        IMSA_CONN_DeletePdpInfo(    enConnType,
                                    pstEmcConn->stSipSignalPdp.ucCid,
                                    &ulRegParaInvalidFlag);
    }

    if (IMSA_TRUE == IMSA_CONN_HasActiveSipSignalPdp(enConnType))
    {
        /* 请求APS释放连接 */
        IMSA_CONN_RequestApsRelConn(enConnType);
    }
    else
    {
        IMSA_CONN_ClearConnResourceExeptMedia(enConnType);

        /* 通知SERVICE模块连接释放 */
        IMSA_CONN_SndConnRelInd(enConnType, IMSA_CONN_SIP_PDP_TYPE_SIGNAL);
    }

    return ;
}
VOS_VOID IMSA_CONN_ProcTimerMsgWaitIpv6InfoExp
(
    const VOS_VOID                     *pMsg
)
{
    IMSA_CONN_TYPE_ENUM_UINT32          enConnType              = IMSA_CONN_TYPE_BUTT;

    IMSA_INFO_LOG("IMSA_CONN_ProcTimerMsgWaitIpv6InfoExp is entered!");

    enConnType = PS_GET_REL_TIMER_PARA(pMsg);

    if (enConnType >= IMSA_CONN_TYPE_BUTT)
    {
        IMSA_ERR_LOG("IMSA_CONN_ProcTimerMsgWaitIpv6InfoExp:Illegal Para!");

        return ;
    }

    /* 不是CONNING状态，则直接退出 */
    if (IMSA_FALSE == IMSA_CONN_IsConnStatusEqual(enConnType, IMSA_CONN_STATUS_CONNING))
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTimerMsgSipSignalPdpEndExp:Not CONNING state!");
        return ;
    }

    if ((IMSA_PDP_STATE_ACTIVE == IMSA_CONN_GetSipSignalPdpState(enConnType, IMSA_IP_TYPE_IPV4))
        || (IMSA_PDP_STATE_ACTIVE == IMSA_CONN_GetSipSignalPdpState(enConnType, IMSA_IP_TYPE_IPV4V6)))
    {
        IMSA_WARN_LOG("IMSA_CONN_ProcTimerMsgSipSignalPdpEndExp:IPV4 OR IPV4V6 PDP!");

        IMSA_CONN_SetupConnSucc(enConnType);
    }

    return ;
}
/*lint +e961*/
/*lint +e960*/
#endif


#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif
/* end of ImsaProcApsMsg.c*/



