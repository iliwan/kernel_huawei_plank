


/*****************************************************************************
  1 Include HeadFile
*****************************************************************************/
#include  "NasERabmCdsMsgProc.h"
#include  "CdsErabmInterface.h"
#include  "NasERabmAppMsgProc.h"
#include  "NasERabmIpFilter.h"
#include  "NasERabmMain.h"
#include  "NasERabmRrcMsgProc.h"
#include  "NasERabmEmmMsgProc.h"
#include  "NasEsmPublic.h"


/*lint -e767*/
#define    THIS_FILE_ID            PS_FILE_ID_NASERABMCDSMSGPROC_C
#define    THIS_NAS_FILE_ID        NAS_FILE_ID_NASERABMCDSMSGPROC_C
/*lint +e767*/

/*****************************************************************************
  1.1 Cplusplus Announce
*****************************************************************************/
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
/*****************************************************************************
  2 Declare the Global Variable
*****************************************************************************/


/*****************************************************************************
  3 Function
*****************************************************************************/

VOS_VOID NAS_ERABM_CdsMsgDistr( VOS_VOID *pRcvMsg )
{
    PS_MSG_HEADER_STRU                 *pSmMsg;

    pSmMsg = (PS_MSG_HEADER_STRU*)pRcvMsg;

    /*打印进入该函数*/
    NAS_ERABM_INFO_LOG("NAS_ERABM_CdsMsgDistr is entered.");

    /*根据消息名，调用相应的消息处理函数*/
    switch (pSmMsg->ulMsgName)
    {
        /*如果收到的是CDS_ERABM_SERVICE_NOTIFY消息，调用NAS_ERABM_RcvCdsErabmServiceNotify函数*/
        case ID_CDS_ERABM_SERVICE_NOTIFY:
            NAS_ERABM_RcvCdsErabmServiceNotify((CDS_ERABM_SERVICE_NOTIFY_STRU *) pRcvMsg);
            break;

        default:
            NAS_ERABM_WARN_LOG("NAS_ERABM_CdsMsgDistr:WARNING:CDS->ERABM Message name non-existent!");
            break;
    }

    return;
}

/* lihong00150010 emergency tau&service begin */
/*****************************************************************************
 Function Name   : NAS_ERABM_IsEmcService
 Description     : 判断是否是紧急业务数据包
 Input           : ulEpsbId----------------承载号
 Output          : None
 Return          : VOS_UINT32

 History         :
     1.lihong00150010      2012-12-14  Draft Enact

*****************************************************************************/
VOS_UINT32  NAS_ERABM_IsEmcService
(
    VOS_UINT8                           ucEpsbId
)
{
    if ((ucEpsbId < NAS_ERABM_MIN_EPSB_ID) || (ucEpsbId > NAS_ERABM_MAX_EPSB_ID))
    {
        NAS_ERABM_ERR_LOG("NAS_ERABM_IsEmcService:EpsbId is illegal!");

        return VOS_FALSE;
    }

    if (ESM_ERABM_BEARER_TYPE_EMERGENCY == NAS_ERABM_GetEpsbBearerType(ucEpsbId))
    {
        return VOS_TRUE;
    }

    return VOS_FALSE;
}
/* lihong00150010 emergency tau&service end */

/*****************************************************************************
 Function Name   : NAS_ERABM_RcvCdsErabmServiceNotify
 Description     : ERABM模块CDS_ERABM_SERVICE_NOTIFY消息分发处理
 Input           : CDS_ERABM_SERVICE_NOTIFY_STRU *pRcvMsg-----------消息指针
 Output          : VOS_VOID
 Return          : VOS_VOID

 History         :
     1.lihong00150010      2011-12-06  Draft Enact
     2.lihong00150010      2012-12-14  Modify:Emergency

*****************************************************************************/
VOS_VOID  NAS_ERABM_RcvCdsErabmServiceNotify
(
    const CDS_ERABM_SERVICE_NOTIFY_STRU    *pRcvMsg
)
{
    /*打印进入该函数*/
    NAS_ERABM_INFO_LOG("NAS_ERABM_RcvCdsErabmServiceNotify is entered.");

    (VOS_VOID)pRcvMsg;

    /* 承载没有对应的DRB的场景下，并且定时器没有启动时，向EMM发起请求 */
    if (NAS_ERABM_SUCCESS == NAS_ERABM_IsAllActtiveBearerWithoutDrb())
    {
        if(NAS_ERABM_TIMER_STATE_STOPED != NAS_ERABM_IsTimerRunning(NAS_ERABM_WAIT_RB_REEST_TIMER))
        {
            NAS_ERABM_NORM_LOG("NAS_ERABM_RcvCdsErabmServiceNotify:Reest timer started!" );
            return ;
        }

        /*发送EMM_ERABM_REEST_REQ消息后，设置服务请求启动*/
        NAS_ERABM_SetEmmSrState(NAS_ERABM_SERVICE_STATE_INIT);
		/* lihong00150010 emergency tau&service begin */
        if (VOS_TRUE == NAS_ERABM_IsEmcService(pRcvMsg->ucRabId))
        {
            NAS_ERABM_SndRabmEmmReestReq(VOS_TRUE);

            NAS_ERABM_TimerStart(   NAS_ERABM_WAIT_RB_REEST_LENGTH,
                                    NAS_ERABM_WAIT_RB_REEST_TIMER,
                                    VOS_TRUE);
        }
        else
        {
            NAS_ERABM_SndRabmEmmReestReq(VOS_FALSE);

            NAS_ERABM_TimerStart(   NAS_ERABM_WAIT_RB_REEST_LENGTH,
                                    NAS_ERABM_WAIT_RB_REEST_TIMER,
                                    VOS_FALSE);
        }
		/* lihong00150010 emergency tau&service end */
    }
    else
    {
        NAS_ERABM_NORM_LOG("NAS_ERABM_RcvCdsErabmServiceNotify:Already in Connect state!" );
        NAS_ERABM_SetEmmSrState(NAS_ERABM_SERVICE_STATE_TERMIN);

        /* 通知CDS启动二次过滤 */
        NAS_ERABM_SndErabmCdsSndBuffDataInd(CDS_ERABM_SEND_BUFF_DATA_ALLOWED_TYPE_SERVICE_SUCC);
    }
}


/*lint -e960*/
/*lint -e961*/
VOS_VOID NAS_ERABM_SndErabmCdsSndBuffDataInd
(
    CDS_ERABM_SEND_BUFF_DATA_ALLOWED_TYPE_ENUM_UINT32   enSndBuffDataAllowedType
)
{

    ERABM_CDS_SEND_BUFF_DATA_IND_STRU  *pstSndBuffDataInd = VOS_NULL_PTR;

    /*分配空间和检测是否分配成功*/
    pstSndBuffDataInd = (VOS_VOID*)NAS_ERABM_ALLOC_MSG(sizeof(ERABM_CDS_SEND_BUFF_DATA_IND_STRU));
    if (VOS_NULL_PTR == pstSndBuffDataInd)
    {
        NAS_ERABM_ERR_LOG("NAS_ERABM_SndErabmCdsSndBuffDataInd:ERROR:Alloc msg fail!" );
        return;
    }

    /*清空*/
    NAS_ERABM_MEM_SET(  NAS_ERABM_GET_MSG_ENTITY(pstSndBuffDataInd),
                        NAS_ERABM_NULL,
                        NAS_ERABM_GET_MSG_LENGTH(pstSndBuffDataInd));

    /*填写消息头*/
    NAS_ERABM_WRITE_CDS_MSG_HEAD(pstSndBuffDataInd,ID_ERABM_CDS_SEND_BUFF_DATA_IND);

    pstSndBuffDataInd->enSndBuffDataAllowedType = enSndBuffDataAllowedType;

    /* 调用消息发送函数*/
    NAS_ERABM_SND_MSG(pstSndBuffDataInd);

}


VOS_VOID NAS_ERABM_SndErabmCdsFreeBuffDataInd( VOS_VOID )
{

    ERABM_CDS_FREE_BUFF_DATA_IND_STRU  *pstFreeBuffDataInd = VOS_NULL_PTR;

    /*分配空间和检测是否分配成功*/
    pstFreeBuffDataInd = (VOS_VOID*)NAS_ERABM_ALLOC_MSG(sizeof(ERABM_CDS_FREE_BUFF_DATA_IND_STRU));
    if (VOS_NULL_PTR == pstFreeBuffDataInd)
    {
        NAS_ERABM_ERR_LOG("NAS_ERABM_SndErabmCdsSndBuffDataInd:ERROR:Alloc msg fail!" );
        return;
    }

    /*清空*/
    NAS_ERABM_MEM_SET(  NAS_ERABM_GET_MSG_ENTITY(pstFreeBuffDataInd),
                        NAS_ERABM_NULL,
                        NAS_ERABM_GET_MSG_LENGTH(pstFreeBuffDataInd));

    /*填写消息头*/
    NAS_ERABM_WRITE_CDS_MSG_HEAD(pstFreeBuffDataInd,ID_ERABM_CDS_FREE_BUFF_DATA_IND);

    /* 调用消息发送函数*/
    NAS_ERABM_SND_MSG(pstFreeBuffDataInd);

}


VOS_VOID NAS_ERABM_SndErabmCdsRabCreatInd( VOS_UINT32 ulEpsbId )
{
#if (VOS_OS_VER != VOS_WIN32)

    CDS_ERABM_RAB_CREATE_IND_STRU  *pstRabCreatInd = VOS_NULL_PTR;

    /*分配空间和检测是否分配成功*/
    pstRabCreatInd = (VOS_VOID*)NAS_ERABM_ALLOC_MSG(sizeof(CDS_ERABM_RAB_CREATE_IND_STRU));

    if (VOS_NULL_PTR == pstRabCreatInd)
    {
        NAS_ERABM_ERR_LOG("NAS_ERABM_SndErabmCdsRabCreatInd:ERROR:Alloc msg fail!" );
        return;
    }

    /*清空*/
    NAS_ERABM_MEM_SET(  NAS_ERABM_GET_MSG_ENTITY(pstRabCreatInd),
                        NAS_ERABM_NULL,
                        NAS_ERABM_GET_MSG_LENGTH(pstRabCreatInd));

    /* 赋值QCI */
    pstRabCreatInd->enQci = NAS_ERABM_GetEpsbQCI(ulEpsbId);


    /*赋值 EpsbId及关联EPsbId */
    pstRabCreatInd->ucRabId = (VOS_UINT8)ulEpsbId;
    if (ESM_ERABM_BEARER_TYPE_DEDICATED == NAS_ERABM_GetEpsbBearerType(ulEpsbId))
    {
        pstRabCreatInd->ucLinkRabId = (VOS_UINT8)NAS_ERABM_GetEpsbLinkedEpsbId(ulEpsbId);
    }
    else
    {
        pstRabCreatInd->ucLinkRabId = pstRabCreatInd->ucRabId;
    }

    /*填写消息头*/
    NAS_ERABM_WRITE_CDS_MSG_HEAD(pstRabCreatInd,ID_QOS_FC_ERABM_RAB_CREATE_IND);

    /* 调用消息发送函数*/
    NAS_ERABM_SND_MSG(pstRabCreatInd);
#endif
}

VOS_VOID NAS_ERABM_SndErabmCdsRabReleaseInd( VOS_UINT32 ulEpsbId )
{
#if (VOS_OS_VER != VOS_WIN32)

    CDS_ERABM_RAB_RELEASE_IND_STRU  *pstRabReleaseInd = VOS_NULL_PTR;

    /*分配空间和检测是否分配成功*/
    pstRabReleaseInd = (VOS_VOID*)NAS_ERABM_ALLOC_MSG(sizeof(CDS_ERABM_RAB_RELEASE_IND_STRU));
    if (VOS_NULL_PTR == pstRabReleaseInd)
    {
        NAS_ERABM_ERR_LOG("NAS_ERABM_SndErabmCdsRabReleaseInd:ERROR:Alloc msg fail!" );
        return;
    }

    /*清空*/
    NAS_ERABM_MEM_SET(  NAS_ERABM_GET_MSG_ENTITY(pstRabReleaseInd),
                        NAS_ERABM_NULL,
                        NAS_ERABM_GET_MSG_LENGTH(pstRabReleaseInd));

    /*赋值 EpsbId*/
    pstRabReleaseInd->ucRabId = (VOS_UINT8)ulEpsbId;


    /*填写消息头*/
    NAS_ERABM_WRITE_CDS_MSG_HEAD(pstRabReleaseInd,ID_QOS_FC_ERABM_RAB_RELEASE_IND);

    /* 调用消息发送函数*/
    NAS_ERABM_SND_MSG(pstRabReleaseInd);
#endif
}
VOS_UINT32 CDS_ERABM_GetIpFragEpsbId
(
    VOS_UINT8                           *pucEpsbId,
    TTF_MEM_ST                          *pstIpFrag,
    VOS_UINT32                           ulIpFragLen
)
{
    VOS_UINT8                          *pucIpv4Data = VOS_NULL_PTR;
    VOS_UINT8                          *pstDataAddr = VOS_NULL_PTR;
    VOS_UINT8                          *pucIpv6Data = VOS_NULL_PTR;
    TTF_MEM_ST                         *pstIpFragTmp= pstIpFrag;
    VOS_UINT8                           ucIpVersion = NAS_ERABM_NULL;
    VOS_UINT8                           ucRslt      = NAS_ERABM_NULL;
    VOS_UINT8                           ucBearerIdTmp = NAS_ERABM_NULL;

    /* 输入参数合法性检测 */
    if (VOS_NULL_PTR == pucEpsbId)
    {
        NAS_ERABM_ERR_LOG("CDS_ERABM_GetIpFragEpsbId:pucEpsbId is NULL!");
        return PS_FAIL;
    }

    if (VOS_NULL_PTR == pstIpFragTmp)
    {
        NAS_ERABM_ERR_LOG("CDS_ERABM_GetIpFragEpsbId:pstIpFrag is NULL!");
        return PS_FAIL;
    }

    if (NAS_ERABM_NULL == ulIpFragLen)
    {
        NAS_ERABM_ERR_LOG("CDS_ERABM_GetIpFragEpsbId:ulIpFragLen is zero!");
        return PS_FAIL;
    }

    pstDataAddr = pstIpFragTmp->pData;

    /* 根据IP包头获取IP类型 */
    ucIpVersion = NAS_ERABM_GetIpVersion(pstDataAddr);

    if (NAS_ERABM_IP_VERSION_4 == ucIpVersion)
    {
        /* 译码IPV4包头，存储源IPV4地址、目的IPV4地址，identifier */
        pucIpv4Data = NAS_ERABM_GET_IP_HEADER_BUFFER();

        NAS_ERABM_DecodeIpV4Data(pstDataAddr, (NAS_ERABM_IPV4_HEADER_STRU *)pucIpv4Data);

        /* 遍历所有缺省承载，查找源IP地址匹配的承载 */
        ucRslt = NAS_ERABM_GetSrcIpv4MatchedDeftBearerId((NAS_ERABM_IPV4_HEADER_STRU *)pucIpv4Data, &ucBearerIdTmp);

        if (NAS_ERABM_SUCCESS == ucRslt)
        {
            *pucEpsbId = ucBearerIdTmp;
            return PS_SUCC;
        }

        *pucEpsbId = NAS_ERABM_IPF_INVALID_BEARER_ID;
        return PS_FAIL;
    }
    else
    {
        /* 译码IPV6包头，存储源IPV6地址 */
        pucIpv6Data = NAS_ERABM_GET_IP_HEADER_BUFFER();

        NAS_ERABM_DecodeIpV6Data(pstDataAddr, (NAS_ERABM_IPV6_HEADER_STRU *)pucIpv6Data);

        /* 遍历所有缺省承载，查找源IP地址匹配的承载 */
        ucRslt = NAS_ERABM_GetSrcIpv6MatchedDeftBearerId(   (NAS_ERABM_IPV6_HEADER_STRU *)pucIpv6Data,
                                                            &ucBearerIdTmp);

        if (NAS_ERABM_SUCCESS == ucRslt)
        {
            *pucEpsbId = ucBearerIdTmp;
            return PS_SUCC;
        }

        *pucEpsbId = NAS_ERABM_IPF_INVALID_BEARER_ID;
        return PS_FAIL;
    }
}


CDS_ERABM_TRANSFER_RESULT_ENUM_UINT32 CDS_ERABM_GetDrbId
(
    VOS_UINT8                           ucEpsbId,
    VOS_UINT8                          *pucDrbId
)
{
     /* 上行收到数据包增加统计 */
    NAS_ERABM_AddUlReceivePackageNum();

    /* 输入参数合法性检测 */
    if (VOS_NULL_PTR == pucDrbId)
    {
        NAS_ERABM_ERR_LOG("CDS_ERABM_GetDrbId:pucDrbId is NULL!");

        /* 上行丢弃数据包增加统计 */
        NAS_ERABM_AddUlDiscardPackageNum();

        return PS_FAIL;
    }

    if ((ucEpsbId < NAS_ERABM_MIN_EPSB_ID) || (ucEpsbId > NAS_ERABM_MAX_EPSB_ID))
    {
        NAS_ERABM_ERR_LOG("CDS_ERABM_GetDrbId:EpsbId is illegal!");

        /* 上行丢弃数据包增加统计 */
        NAS_ERABM_AddUlDiscardPackageNum();

        return CDS_ERABM_TRANSFER_RESULT_FAIL;
    }

    if (NAS_ERABM_RB_CONNECTED == NAS_ERABM_GetRbStateInfo(ucEpsbId))
    {
        *pucDrbId = (VOS_UINT8)NAS_ERABM_GetEpsbRbIdInfo(ucEpsbId);

        /* 增加上行发送总数据包数 */
        NAS_ERABM_AddUlSendPackageNum();

        /* 增加承载上行发送总数据包数 */
        NAS_ERABM_AddBearerSendPackageNum((VOS_UINT32)ucEpsbId);

        return CDS_ERABM_TRANSFER_RESULT_SUCC;
    }
    else if(NAS_ERABM_RB_SUSPENDED == NAS_ERABM_GetRbStateInfo(ucEpsbId))
    {
        /* 设置上行数据阻塞标志*/
        NAS_ERABM_SetUpDataPending(EMM_ERABM_UP_DATA_PENDING);
        NAS_ERABM_LOG1("CDS_ERABM_GetDrbId:DRB_SUSPENDED, set data pending = ",NAS_ERABM_GetUpDataPending());

        *pucDrbId = (VOS_UINT8)NAS_ERABM_GetEpsbRbIdInfo(ucEpsbId);

        /* 增加上行Suspend总数据包数 */
        NAS_ERABM_AddUlSuspendPackageNum();

        /* 增加承载上行Suspend总数据包数 */
        NAS_ERABM_AddBearerSuspendPackageNum((VOS_UINT32)ucEpsbId);

        return CDS_ERABM_TRANSFER_RESULT_DRB_SUSPEND;
    }
    else
    {
        /* 判断是否处于连接态 */
        if (NAS_ERABM_SUCCESS == NAS_ERABM_IsAllActtiveBearerWithoutDrb())
        {
            /* 设置上行数据阻塞标志*/
            NAS_ERABM_SetUpDataPending(EMM_ERABM_UP_DATA_PENDING);
            NAS_ERABM_LOG1("CDS_ERABM_GetDrbId:AllActtiveBearerWithoutDrb, set data pending = ",NAS_ERABM_GetUpDataPending());


            /* 增加上行IDLE总数据包数 */
             NAS_ERABM_AddUlIdlePackageNum();

            /* 增加承载上行IDLE总数据包数 */
            NAS_ERABM_AddBearerIdlePackageNum((VOS_UINT32)ucEpsbId);

            return CDS_ERABM_TRANSFER_RESULT_IDLE;
        }

        /* 对于当前处于连接态，但承载对应的DRB不存在这种暂态，暂时先返回
           CDS_ERABM_TRANSFER_RESULT_FAIL，由CDS释放内存，后续优化时再返回
           CDS_ERABM_TRANSFER_RESULT_DRB_NOT_EXIST，由CDS负责缓存数据包。*/

        /* 上行丢弃数据包增加统计 */
        NAS_ERABM_AddUlDiscardPackageNum();

        /* 承载上行丢弃数据包增加统计 */
        NAS_ERABM_AddBearerDiscardPackageNum((VOS_UINT32)ucEpsbId);

        return APP_ERABM_TRANSFER_RESULT_FAIL;
    }
}

/*****************************************************************************
 Function Name   : NAS_ERABM_GetEpsbIdByDrbId
 Description     : 根据DRB号获取EPS承载号
 Input           : ulRbId-------------------DRB号
 Output          : pulEpsbId----------------承载号指针
 Return          : VOS_UINT32

 History         :
    1.lihong00150010      2011-12-06  Draft Enact

*****************************************************************************/
VOS_UINT32 NAS_ERABM_GetEpsbIdByDrbId
(
    VOS_UINT32                           ulRbId,
    VOS_UINT32                          *pulEpsbId
)
{
    VOS_UINT32                     ulEpsbId   = NAS_ERABM_NULL;

    /*找到RBID对应的EPS承载*/
    for (ulEpsbId = NAS_ERABM_MIN_EPSB_ID; ulEpsbId <= NAS_ERABM_MAX_EPSB_ID; ulEpsbId++)
    {
        if (NAS_ERABM_EPSB_ACTIVE != NAS_ERABM_GetEpsbStateInfo(ulEpsbId))
        {
            continue;
        }

        if (NAS_ERABM_GetEpsbRbIdInfo(ulEpsbId) == ulRbId)
        {
            *pulEpsbId = ulEpsbId;
            return NAS_ERABM_SUCCESS;
        }
    }

    return NAS_ERABM_FAILURE;
}
/*lint +e961*/
/*lint +e960*/

VOS_UINT32 CDS_ERABM_GetDefaultEpsbId
(
    VOS_UINT8                           ucDrbId,
    VOS_UINT8                          *pucDeftEpsbId
)
{
    VOS_UINT32                           ulEpsbId = NAS_ERABM_NULL;

    if (VOS_NULL_PTR == pucDeftEpsbId)
    {
        NAS_ERABM_ERR_LOG("CDS_ERABM_GetDefaultEpsbId:pucEpsbId is NULL!");
        return PS_FAIL;
    }

    /* 获取DRB关联承载号 */
    if (NAS_ERABM_SUCCESS != NAS_ERABM_GetEpsbIdByDrbId(  ucDrbId,
                                                         &ulEpsbId))
    {
        NAS_ERABM_WARN_LOG("CDS_ERABM_GetDefaultEpsbId:NAS_ERABM_GetEpsbIdByDrbId failed!");

        return PS_FAIL;
    }

    /* 判断承载类型是否为缺省 */
    if (PS_TRUE == NAS_ESM_IsDefaultEpsBearerType(NAS_ERABM_GetEpsbBearerType(ulEpsbId)))
    {
        *pucDeftEpsbId = (VOS_UINT8)ulEpsbId;
    }
    else
    {
        *pucDeftEpsbId = (VOS_UINT8)NAS_ERABM_GetEpsbLinkedEpsbId(ulEpsbId);
    }

    return PS_SUCC ;
}


VOS_UINT32 CDS_ERABM_GetEpsbId
(
    VOS_UINT8                           ucDrbId,
    VOS_UINT8                          *pucEpsbId
)
{
    VOS_UINT32                           ulEpsbId = NAS_ERABM_NULL;

    if (VOS_NULL_PTR == pucEpsbId)
    {
        NAS_ERABM_ERR_LOG("CDS_ERABM_GetEpsbId:pucEpsbId is NULL!");
        return PS_FAIL;
    }

    /* 获取DRB关联承载号 */
    if (NAS_ERABM_SUCCESS != NAS_ERABM_GetEpsbIdByDrbId(  ucDrbId,
                                                         &ulEpsbId))
    {

        return PS_FAIL;
    }

    *pucEpsbId = (VOS_UINT8)ulEpsbId;

    return PS_SUCC;
}



#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

