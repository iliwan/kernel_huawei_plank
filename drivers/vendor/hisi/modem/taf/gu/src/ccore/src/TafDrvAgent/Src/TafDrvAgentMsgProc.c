

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include  "TafDrvAgentMsgProc.h"
#include  "TafDrvAgentMain.h"
#include  "AtMnInterface.h"
#include  "TafDrvAgent.h"
#include  "NasComm.h"
#include  "updatefromtf.h"
#include  "DrvInterface.h"
#include  "NVIM_Interface.h"
#include  "MmaAppLocal.h"

#include "apminterface.h"
#include "ipcmailboxinterface.h"
#include "DspInterface.h"
#include "hpaoperatertt.h"

#include "ScInterface.h"

#include "TafApsProcNvim.h"

#include "NasUtranCtrlInterface.h"

#include "TafSdcLib.h"
#if (FEATURE_ON == FEATURE_LTE)
#include "msp_nvim.h"
#endif

#include "NasUsimmApi.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*lint -e958*/

/*****************************************************************************
    协议栈打印打点方式下的.C文件宏定义
*****************************************************************************/
/*lint -e767 */
#define    THIS_FILE_ID        PS_FILE_ID_DRVAGENTMSGPROC_C
/*lint -e767 */

/*****************************************************************************
  2 全局变量定义
*****************************************************************************/
/*lint -e552 -e830*/
VOS_UINT8 g_ucGcfInd = VOS_FALSE;       /* 指示当前是否为GCF测试 */
/*lint +e552 +e830*/

#ifndef _PS_COMPILE_EDGE_ADAPT_MOIRI_B073_
extern void       TTF_SetGcfTestFlag(VOS_UINT32 ulGctTestFlag);
#endif

/* 这两个接口由第三方提供*.o文件，此处声明下 */
extern int VerifySL(char* UnlockCode, char* Key);

extern char *BSP_GU_GetVerTime(void);


VOS_UINT16 gausDevCmdBandToWDspBandTbl[] =
{
    W_FREQ_BAND1,
    W_FREQ_BAND2,
    W_FREQ_BAND3,
    W_FREQ_BAND9,
    W_FREQ_BAND7,
    W_FREQ_BAND11,
    W_FREQ_BAND8,
    W_FREQ_BAND5,
    W_FREQ_BAND6,
    W_FREQ_BAND_BUTT,
    W_FREQ_BAND_BUTT
};


AT_ARFCN_RANGE_STRU gaStWDSPBandUlAfrcn[W_FREQ_BAND_BUTT] =
{
    {0,0},     /*无效值*/
    {9612,9888},
    {9262,9538},
    {937,1288},
    {1312,1513},
    {4132,4233},
    {4162,4188},
    {2012,2338},
    {2712,2863},
    {8762,8912},
    {0,0},     /*无效值*/
    {3487,3562}
};


AT_ARFCN_RANGE_STRU gaStWDSPBandDlAfrcn[W_FREQ_BAND_BUTT] =
{
    {0,0},                                                                      /*无效值*/
    {10562,10838},                                                              /*Band1 dl Arfcn范围 */
    {9662,9938},
    {1162,1513},
    {1537,1738},
    {4357,4458},
    {4387,4413},
    {2237,2563},
    {2937,3088},
    {9237,9387},
    {0,0},                                                                      /*无效值*/
    {3712,3787}                                                                 /*Band1 dl Arfcn范围 */
};


TAF_UINT16 gausFULOffset[W_FREQ_BAND_BUTT]=
{
    0, /*无效值*/
    0,
    0,
    1525,
    1450,
    0,
    0,
    2100,
    340,
    0,
    0,
    0
};
TAF_UINT16 gausBandSepBtwnUlDl[W_FREQ_BAND_BUTT] =
{
    0,     /*无效值*/
    190,   /*I  */
    80 ,   /*II */
    95 ,   /*III    */
    400,   /*IV */
    45 ,   /*V  */
    45 ,   /*VI */
    120,   /*VII    */
    45 ,   /*VIII*/
    95 ,   /*IX */
    0,     /*无效值*/
    45     /*XI */
};


TAF_UINT16 gausFDLOffset[W_FREQ_BAND_BUTT]=
{
    0,                                                                          /*无效值*/
    0,
    0,
    1575,
    1805,
    0,
    0,
    2175,
    340,
    0,
    0,                                                                          /*无效值*/
    0
};


VOS_UINT16 gausDevCmdBandToGDspBandTbl[] =
{
    G_FREQ_BAND_BUTT,
    G_FREQ_BAND_PCS1900,
    G_FREQ_BAND_DCS1800,
    G_FREQ_BAND_BUTT,
    G_FREQ_BAND_BUTT,
    G_FREQ_BAND_BUTT,
    G_FREQ_BAND_GSM900,
    G_FREQ_BAND_GSM850,
    G_FREQ_BAND_BUTT,
    G_FREQ_BAND_BUTT,
    G_FREQ_BAND_BUTT
};


AT_ARFCN_RANGE_STRU gaStGDSPBandAfrcn[G_FREQ_BAND_BUTT] =
{
    {128,251},  /* GSM 850：     128 <= n <= 251*/
    {0,124},    /* GSM 900 :[975,1023]在判断函数中添加
                  E-GSM900：    0 <= n <= 124
                                 975 <= n <= 1023
                  P-GSM900     1 <= n <= 124*/
    {512,885},  /*DCS 1800：   512 <= n <= 885*/
    {512,810}   /*PCS 1900：   512 <= n <= 810*/
};

AT_ARFCN_RANGE_STRU                     gstGsm900SecondRange = {975,1023};

/* 统计SIMLOCK连续解锁错误的次数 */
VOS_UINT8                               gucSimLockErrTimes = 0;
/*****************************************************************************
  3 函数实现
*****************************************************************************/


VOS_UINT32 DRVAGENT_AsciiNum2DecNum(
    VOS_UINT8                          *pucAsciiNum,
    VOS_UINT8                          *pucDecNum,
    VOS_UINT32                          ulLen
)
{
    VOS_UINT32                          ulIndex         = 0;

    /* 参数指针由调用者保证不为NULL, 该处不做判断 */

    for (ulIndex = 0; ulIndex < ulLen; ulIndex++)
    {
        /* 判断是否是数字 */
        if ( ('0' <= pucAsciiNum[ulIndex]) && ('9' >= pucAsciiNum[ulIndex]) )
        {
            pucDecNum[ulIndex] = pucAsciiNum[ulIndex] - '0';
        }
        else
        {
            return VOS_ERR;
        }
    }

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_DecNum2AsciiNum(
    VOS_UINT8                          *pucDecNum,
    VOS_UINT8                          *pucAsciiNum,
    VOS_UINT32                          ulLen
)
{
    VOS_UINT32                          ulIndex         = 0;

    /* 参数指针由调用者保证不为NULL, 该处不做判断 */

    for (ulIndex = 0; ulIndex < ulLen; ulIndex++)
    {
        /* 判断是否是数字 */
        if (9 >= pucDecNum[ulIndex])
        {
            pucAsciiNum[ulIndex] = pucDecNum[ulIndex] + '0';
        }
        else
        {
            return VOS_ERR;
        }
    }

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_CheckNumCharString(
    VOS_UINT8                          *pucStr,
    VOS_UINT32                          ulLen
)
{
    VOS_UINT32                          ulLength = 0;
    VOS_UINT8                          *pucTmp   = pucStr;

    /* 参数指针由调用者保证不为NULL, 该处不做判断 */

    /*lint -e961*/
    while(ulLength++ < ulLen)
    /*lint +e961*/
    {
        /* 判断是否是数字 */
        if ( (('0' <= (*pucTmp)) && ('9' >= (*pucTmp)))
           || (('a' <= (*pucTmp)) && ('z' >= (*pucTmp)))
           || (('A' <= (*pucTmp)) && ('Z' >= (*pucTmp))))
        {
            pucTmp++;
        }
        else
        {
            return VOS_ERR;
        }
    }

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentMsidQryReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_MSID_QRY_CNF_STRU         stDrvAgentMsidQryCnf;                   /* 发送消息指针 */
    VOS_INT32                           lRslt;
    MODEM_ID_ENUM_UINT16                enModemId;

    /* 初始化 */
    pstMnAppReqMsg                                   = (MN_APP_REQ_MSG_STRU *)pMsg;

    PS_MEM_SET(&stDrvAgentMsidQryCnf, 0, sizeof(DRV_AGENT_MSID_QRY_CNF_STRU));
    stDrvAgentMsidQryCnf.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stDrvAgentMsidQryCnf.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;
    stDrvAgentMsidQryCnf.ulResult                    = DRV_AGENT_MSID_QRY_NO_ERROR;

    /*获取硬件模块名*/
    lRslt = DRV_MEM_VERCTRL((char *)stDrvAgentMsidQryCnf.acModelId,
                            TAF_MAX_MODEL_ID_LEN,
                            VER_PRODUCT_ID,
                            VERIONREADMODE);
    if (DRV_INTERFACE_RSLT_OK != lRslt)
    {
        stDrvAgentMsidQryCnf.ulResult = DRV_AGENT_MSID_QRY_READ_PRODUCT_ID_ERROR;
        NAS_WARNING_LOG(WUEPS_PID_DRV_AGENT, "DRVAGENT_RcvDrvAgentMsidQryReq:VER_PRODUCT_ID Failed!");
    }

    /*获取软件版本号*/
    lRslt = DRV_MEM_VERCTRL((char *)stDrvAgentMsidQryCnf.acSoftwareVerId,
                            TAF_MAX_REVISION_ID_LEN + 1,
                            VER_SOFTWARE,
                            VERIONREADMODE);
    if ( DRV_INTERFACE_RSLT_OK != lRslt )
    {
        stDrvAgentMsidQryCnf.ulResult |= DRV_AGENT_MSID_QRY_READ_SOFT_VER_ERROR;
        NAS_WARNING_LOG(WUEPS_PID_DRV_AGENT, "DRVAGENT_RcvDrvAgentMsidQryReq:Read Software Version Failed!");
    }

    /* 由PID获取MODEMID */
    enModemId = VOS_GetModemIDFromPid(WUEPS_PID_DRV_AGENT);

    /* 调用SC接口读取IMEI号码 */
    SC_PERS_NvRead(enModemId, en_NV_Item_IMEI, stDrvAgentMsidQryCnf.aucImei, NV_ITEM_IMEI_SIZE);

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_MSID_QRY_CNF,
                     sizeof(DRV_AGENT_MSID_QRY_CNF_STRU),
                     (VOS_UINT8 *)&stDrvAgentMsidQryCnf);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentGcfInd(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */

    /* 初始化 */
    pstMnAppReqMsg = (MN_APP_REQ_MSG_STRU *)pMsg;

    /* 设置GCF测试标志，并通知TTF */
    g_ucGcfInd = (VOS_UINT8)pstMnAppReqMsg->aucContent[0];

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentGasMntnCmd(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */
    GAS_AT_CMD_STRU                    *pstAtCmd;
    DRV_AGENT_GAS_MNTN_CMD_CNF_STRU     stDrvAgentGasMntnCmdCnf;

    /* 初始化 */
    pstMnAppReqMsg = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstAtCmd       = (GAS_AT_CMD_STRU *)pstMnAppReqMsg->aucContent;

    PS_MEM_SET(&stDrvAgentGasMntnCmdCnf, 0, sizeof(DRV_AGENT_GAS_MNTN_CMD_CNF_STRU));

    if (VOS_TRUE == TAF_SDC_IsPlatformSupportGsm())
    {
        /* 调用GAS API */
        stDrvAgentGasMntnCmdCnf.ulResult = GAS_AtCmd(pstAtCmd,
                                                    &stDrvAgentGasMntnCmdCnf.stAtCmdRslt);
    }
    else
    {
        stDrvAgentGasMntnCmdCnf.ulResult = VOS_ERR;
    }


    stDrvAgentGasMntnCmdCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stDrvAgentGasMntnCmdCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;
    stDrvAgentGasMntnCmdCnf.ucCmd                  = pstAtCmd->ucCmd;


    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_GAS_MNTN_CMD_RSP,
                     sizeof(DRV_AGENT_GAS_MNTN_CMD_CNF_STRU),
                     (VOS_UINT8 *)&stDrvAgentGasMntnCmdCnf);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentAppdmverReq(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;                                  /* 函数返回值 */
    VOS_INT32                           lRet;                                   /* 底软接口返回值 */
    DRV_AGENT_APPDMVER_QRY_CNF_STRU     stEvent;
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */

    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    /* 调用底软接口 memVersionCtrl 获取PDM版本号 */
    lRet = DRV_MEM_VERCTRL((char *)stEvent.acPdmver, AT_MAX_PDM_VER_LEN, VER_PDM, VERIONREADMODE);
    if (DRV_INTERFACE_RSLT_OK != lRet)
    {
        /* 调用memVersionCtrl失败, 返回ERROR */
        ulRet            = VOS_ERR;
        stEvent.enResult = DRV_AGENT_APPDMVER_QRY_ERROR;
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentAppdmverReq: Read Pdm Version failed!");
    }
    else
    {
        ulRet            = VOS_OK;
        stEvent.enResult = DRV_AGENT_APPDMVER_QRY_NO_ERROR;
    }

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_APPDMVER_QRY_CNF,
                     sizeof(stEvent),
                     (VOS_UINT8 *)&stEvent);

    return ulRet;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentDloadInfoReq(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;                                  /* 函数返回值 */
    DRV_AGENT_DLOADINFO_QRY_CNF_STRU    *pstEvent;
    MN_APP_REQ_MSG_STRU                 *pstMnAppReqMsg;                         /* 接收消息指针 */

    /* 初始化 */
    pstEvent = (DRV_AGENT_DLOADINFO_QRY_CNF_STRU *)PS_MEM_ALLOC(WUEPS_PID_DRV_AGENT,
                sizeof(DRV_AGENT_DLOADINFO_QRY_CNF_STRU));
    if (VOS_NULL_PTR == pstEvent)
    {
        return VOS_ERR;
    }

    PS_MEM_SET(pstEvent, 0x00, sizeof(DRV_AGENT_DLOADINFO_QRY_CNF_STRU));

    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstEvent->stAtAppCtrl.usClientId    = pstMnAppReqMsg->clientId;
    pstEvent->stAtAppCtrl.ucOpId        = pstMnAppReqMsg->opId;

    /*
    获取下载信息:
             <CR><LF>swver:<software version><CR><LF>
             <CR><LF>isover:<iso version><CR><LF>
             <CR><LF>product name:<product name><CR><LF>
             <CR><LF>product name:<WebUiVer><CR><LF>
             <CR><LF>dload type: <dload type><CR><LF>
             <CR><LF>OK<CR><LF>
     因为DRV也需要处理该AT命令，为了统一，本命令全部由DRV封装，AT只负责上报。
    */
    if (VOS_OK != (VOS_UINT32)DRV_GET_DLOAD_INFO(pstEvent->aucDlodInfo, NORMAL_DLOAD))
    {
        ulRet               = VOS_ERR;
        pstEvent->enResult  = DRV_AGENT_DLOADINFO_QRY_ERROR;
    }
    else
    {
        ulRet               = VOS_OK;
        pstEvent->enResult  = DRV_AGENT_DLOADINFO_QRY_NO_ERROR;
    }

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_DLOADINFO_QRY_CNF,
                     sizeof(DRV_AGENT_DLOADINFO_QRY_CNF_STRU),
                     (VOS_UINT8 *)pstEvent);

    PS_MEM_FREE(WUEPS_PID_DRV_AGENT, pstEvent);

    return ulRet;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentFlashInfoQry(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                        /* 接收消息指针 */
    DRV_AGENT_FLASHINFO_QRY_CNF_STRU    stEvent;
    VOS_UINT32                          ulRet;

    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    /* 获取FLASH信息 DRV_GET_DLOAD_FLASHINFO */

    ulRet = (VOS_UINT32)DRV_GET_DLOAD_FLASHINFO((DLOAD_FLASH_STRU *)&stEvent.stFlashInfo);
    if ( VOS_OK != ulRet )
    {
        stEvent.enResult = DRV_AGENT_FLASHINFO_QRY_ERROR;
        ulRet            = VOS_ERR;
    }
    else
    {
        stEvent.enResult = DRV_AGENT_FLASHINFO_QRY_NO_ERROR;
        ulRet            = VOS_OK;
    }


    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_FLASHINFO_QRY_CNF,
                     sizeof(stEvent),
                     (VOS_UINT8 *)&stEvent);

    return ulRet;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentAuthorityVerQry(VOS_VOID *pMsg)
{
    VOS_UINT32                           ulRet;
    DRV_AGENT_AUTHORITYVER_QRY_CNF_STRU  stEvent;
    MN_APP_REQ_MSG_STRU                 *pstMnAppReqMsg;                        /* 接收消息指针 */

    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    /* 调用底软接口获取鉴权协议版本号 */
    ulRet = (VOS_UINT32)DRV_GET_AUTHORITY_VERSION(stEvent.aucAuthority,
                                                  sizeof(stEvent.aucAuthority));
    if ( VOS_OK != ulRet )
    {
        stEvent.enResult = DRV_AGENT_AUTHORITYVER_QRY_ERROR;
        ulRet            = VOS_ERR;
    }
    else
    {
        stEvent.enResult = DRV_AGENT_AUTHORITYVER_QRY_NO_ERROR;
        ulRet            = VOS_OK;
    }

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_AUTHORITYVER_QRY_CNF,
                     sizeof(stEvent),
                     (VOS_UINT8 *)&stEvent);

    return ulRet;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentAuthorityIdQry(VOS_VOID *pMsg)
{
    VOS_UINT32                           ulRet;
    DRV_AGENT_AUTHORITYID_QRY_CNF_STRU   stEvent;
    MN_APP_REQ_MSG_STRU                 *pstMnAppReqMsg;                        /* 接收消息指针 */

    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    /* 调用底软接口获取鉴权标识 */
    ulRet = (VOS_UINT32)DRV_GET_AUTHORITY_ID(stEvent.aucAuthorityId,
                                             sizeof(stEvent.aucAuthorityId));
    if (VOS_OK != ulRet)
    {
        stEvent.enResult            = DRV_AGENT_AUTHORITYID_QRY_ERROR;
        ulRet                       = VOS_ERR;
    }
    else
    {
        stEvent.enResult            = DRV_AGENT_AUTHORITYID_QRY_NO_ERROR;
        ulRet                       = VOS_OK;
    }

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_AUTHORITYID_QRY_CNF,
                     sizeof(stEvent),
                     (VOS_UINT8 *)&stEvent);

    return ulRet;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentAuthVerQry(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;
    DRV_AGENT_AUTHVER_QRY_CNF_STRU      stEvent;
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */

    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    /* SIMLOCK MANAGER版本信息 */
    stEvent.ulSimLockVersion = (VOS_UINT32)DRV_GET_AUTH_VER();
    if ((AT_AUTHVER_ONE != stEvent.ulSimLockVersion)
     && (AT_AUTHVER_TWO != stEvent.ulSimLockVersion)
     && (AT_AUTHVER_THREE != stEvent.ulSimLockVersion))
    {
       ulRet            = VOS_ERR;
       stEvent.enResult = DRV_AGENT_AUTHVER_QRY_ERROR;
    }
    else
    {
       ulRet            = VOS_OK;
       stEvent.enResult = DRV_AGENT_AUTHVER_QRY_NO_ERROR;
    }

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_AUTHVER_QRY_CNF,
                     sizeof(stEvent),
                     (VOS_UINT8 *)&stEvent);

    return ulRet;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentGodloadSet(VOS_VOID *pMsg)
{
    DRV_AGENT_GODLOAD_SET_CNF_STRU       stEvent;
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                        /* 接收消息指针 */

    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;
    stEvent.enResult                    = DRV_AGENT_GODLOAD_SET_NO_ERROR;

    /* 设置升级标志 */
    DRV_SET_UPDATA_FLAG(0);

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_GODLOAD_SET_CNF,
                     sizeof(stEvent),
                     (VOS_UINT8 *)&stEvent);

    /*为了保证AT能够上报给PC，需要作一定的延时 */
    VOS_TaskDelay(AT_DLOAD_TASK_DELAY_TIME);

    /* 单板重启 */
    VOS_FlowReboot();

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentPfverQry(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                        /* 接收消息指针 */
    VOS_CHAR                           *pcVerTime = VOS_NULL_PTR;
    DRV_AGENT_PFVER_QRY_CNF_STRU        stEvent;
    VOS_UINT32                          ulVersionTimeLen;
    VOS_INT32                           lRet;

    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    /* 读取编译时间 */
    pcVerTime = (VOS_CHAR *)DRV_GET_VERSION_TIME();
    if (VOS_NULL_PTR == pcVerTime)
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentPfverQry: DRV_GET_VERSION_TIME Error.");
        stEvent.enResult = DRV_AGENT_PFVER_QRY_ERROR_GET_VERSION_TIME;
        DRVAGENT_SendMsg(WUEPS_PID_AT,
                         DRV_AGENT_PFVER_QRY_CNF,
                         sizeof(stEvent),
                         (VOS_UINT8 *)&stEvent);

        return VOS_ERR;
    }

    ulVersionTimeLen = VOS_StrLen(pcVerTime);
    if (ulVersionTimeLen >= AT_AGENT_DRV_VERSION_TIME_LEN)
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentPfverQry: DRV_GET_VERSION_TIME length Error.");
        stEvent.enResult = DRV_AGENT_PFVER_QRY_ERROR_GET_VERSION_TIME;
        DRVAGENT_SendMsg(WUEPS_PID_AT,
                         DRV_AGENT_PFVER_QRY_CNF,
                         sizeof(stEvent),
                         (VOS_UINT8 *)&stEvent);

        return VOS_ERR;
    }

    PS_MEM_SET(stEvent.stPfverInfo.acVerTime, 0x00, AT_AGENT_DRV_VERSION_TIME_LEN);
    PS_MEM_CPY(stEvent.stPfverInfo.acVerTime, pcVerTime, VOS_StrLen(pcVerTime));

    /* 获取平台软件版本号 */
    PS_MEM_SET(stEvent.stPfverInfo.aucPfVer, 0x00, (TAF_MAX_PROPLAT_LEN + 1));
    lRet = DRV_MEM_VERCTRL((char *)stEvent.stPfverInfo.aucPfVer,
                            (TAF_MAX_PROPLAT_LEN + 1),
                            VER_VXWORKS,
                            VERIONREADMODE);
    if (DRV_INTERFACE_RSLT_OK != lRet)
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentPfverQry: Read Flat Software Version Failed!");
        stEvent.enResult = DRV_AGENT_PFVER_QRY_ERROR_GET_VERSION;
        DRVAGENT_SendMsg(WUEPS_PID_AT,
                         DRV_AGENT_PFVER_QRY_CNF,
                         sizeof(stEvent),
                         (VOS_UINT8 *)&stEvent);

        return VOS_ERR;
    }

    /* 给AT模块回复消息 */
    stEvent.enResult = DRV_AGENT_PFVER_QRY_NO_ERROR;
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_PFVER_QRY_CNF,
                     sizeof(stEvent),
                     (VOS_UINT8 *)&stEvent);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentSdRebootReq(VOS_VOID *pMsg)
{
    DRV_SHUT_DOWN(DRV_SHUTDOWN_RESET);

    return VOS_OK;
}

/*lint -e830 -e438*/

VOS_UINT32 DRVAGENT_RcvDrvAgentDloadVerQryReq(VOS_VOID *pMsg)
{
    VOS_UINT32                          ulRet;
    DRV_AGENT_DLOADVER_QRY_CNF_STRU     stEvent;
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;

    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    ulRet = (VOS_UINT32)DRV_GET_DLOAD_VERSION((VOS_UINT8*)stEvent.aucVersionInfo,
                                              sizeof(stEvent.aucVersionInfo));

    if (VOS_OK != ulRet)
    {
        stEvent.enResult = DRV_AGENT_DLOADVER_QRY_ERROR;
        ulRet            = VOS_ERR;
    }
    else
    {
        stEvent.enResult = DRV_AGENT_DLOADVER_QRY_NO_ERROR;
        ulRet            = VOS_OK;
    }

    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_DLOADVER_QRY_CNF,
                     sizeof(DRV_AGENT_DLOADVER_QRY_CNF_STRU),
                     (VOS_UINT8 *)&stEvent);

    return VOS_OK;

}
/*lint +e830 +e438*/


VOS_UINT32 DRVAGENT_RcvDrvAgentSdloadSet(VOS_VOID *pMsg)
{
    DRV_AGENT_SDLOAD_SET_CNF_STRU       stEvent;
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                        /* 接收消息指针 */



    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    stEvent.enResult = DRV_AGENT_SDLOAD_SET_NO_ERROR;

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_SDLOAD_SET_CNF,
                     sizeof(stEvent),
                     (VOS_UINT8 *)&stEvent);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentCpuloadQry(VOS_VOID *pMsg)
{
    DRV_AGENT_CPULOAD_QRY_CNF_STRU      stEvent;
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                        /* 接收消息指针 */
    VOS_UINT                            ulRet;

    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    ulRet = DRV_PWRCTRL_GetCpuLoad(&stEvent.ulCurACpuLoad,
                                   &stEvent.ulCurCCpuLoad);
    if (VOS_OK != ulRet)
    {
        stEvent.enResult = DRV_AGENT_CPULOAD_QRY_ERROR;
        ulRet            = VOS_ERR;
    }
    else
    {
        stEvent.enResult = DRV_AGENT_CPULOAD_QRY_NO_ERROR;
        ulRet            = VOS_OK;
    }

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_CPULOAD_QRY_CNF,
                     sizeof(stEvent),
                     (VOS_UINT8 *)&stEvent);

    return ulRet;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentMfreelocksizeQry(VOS_VOID *pMsg)
{
    DRV_AGENT_MFREELOCKSIZE_QRY_CNF_STRU      stEvent;
    MN_APP_REQ_MSG_STRU                      *pstMnAppReqMsg;

    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    /* MFREELOCKSIZE信息填充 */
    stEvent.enResult         = DRV_AGENT_MFREELOCKSIZE_QRY_NO_ERROR;
    stEvent.lMaxFreeLockSize = DRV_GET_FREE_BLOCK_SIZE();

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_MFREELOCKSIZE_QRY_CNF,
                     sizeof(stEvent),
                     (VOS_UINT8 *)&stEvent);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentVertimeQry(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                    *pstMnAppReqMsg;
    DRV_AGENT_VERSION_TIME_STRU             stDrvAgentVersionTime;
    VOS_CHAR                               *pucVerTime;

    /* 初始化 */
    pucVerTime      = VOS_NULL_PTR;
    pstMnAppReqMsg  = (MN_APP_REQ_MSG_STRU *)pMsg;
    PS_MEM_SET(&stDrvAgentVersionTime, 0, sizeof(DRV_AGENT_VERSION_TIME_STRU));

    /* 调底软接口获取编译时间 */
    pucVerTime = (VOS_CHAR *)DRV_GET_VERSION_TIME();

    /* 拷贝到回复结构中 */
    /* 检查底软接口返回地址是否有效，无效直接返回空数据 */
    if (VOS_NULL_PTR != pucVerTime)
    {
        stDrvAgentVersionTime.ucLen = (VOS_UINT8)VOS_StrNLen(pucVerTime, AT_AGENT_DRV_VERSION_TIME_LEN);
        PS_MEM_CPY(stDrvAgentVersionTime.aucData, pucVerTime, stDrvAgentVersionTime.ucLen);
    }

    /* clientId和opid */
    stDrvAgentVersionTime.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stDrvAgentVersionTime.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;

    /* 调用DRVAGENT_SendMsg回复消息DRV_AGENT_VERTIME_QRY_CNF给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_VERTIME_QRY_CNF,
                     sizeof(DRV_AGENT_VERSION_TIME_STRU),
                     (VOS_UINT8 *)&stDrvAgentVersionTime);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentYjcxSet(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_YJCX_SET_CNF_STRU         stYjcxSetCnf;
    VOS_UINT32                          ulflashInfoLen;

    /* 初始化 */
    pstMnAppReqMsg                           = (MN_APP_REQ_MSG_STRU *)pMsg;

    PS_MEM_SET(&stYjcxSetCnf, 0, sizeof(DRV_AGENT_YJCX_SET_CNF_STRU));
    stYjcxSetCnf.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stYjcxSetCnf.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    /* 调用底软 API DRV_GET_FLASH_INFO 查询Flash信息 */
    ulflashInfoLen        = TAF_MAX_FLAFH_INFO_LEN + 1;
    stYjcxSetCnf.ulResult = (VOS_UINT32)(DRV_GET_FLASH_INFO(stYjcxSetCnf.aucflashInfo,
                                                            ulflashInfoLen));

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_YJCX_SET_CNF,
                     sizeof(DRV_AGENT_YJCX_SET_CNF_STRU),
                     (VOS_UINT8 *)&stYjcxSetCnf);

    return VOS_OK;
}



VOS_UINT32 DRVAGENT_RcvDrvAgentYjcxQry(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_YJCX_QRY_CNF_STRU         stYjcxQryCnf;
    VOS_UINT32                          ulgpioInfoLen;

    /* 初始化 */
    pstMnAppReqMsg                           = (MN_APP_REQ_MSG_STRU *)pMsg;

    PS_MEM_SET(&stYjcxQryCnf, 0, sizeof(DRV_AGENT_YJCX_QRY_CNF_STRU));
    stYjcxQryCnf.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stYjcxQryCnf.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    /* 调用底软 API DRV_GET_GPIO_INFO 查询GPIO信息 */
    ulgpioInfoLen         = TAF_MAX_GPIO_INFO_LEN + 1;
    stYjcxQryCnf.ulResult = (VOS_UINT32)DRV_GET_GPIO_INFO(stYjcxQryCnf.aucgpioInfo, ulgpioInfoLen);

    /* 调用DRVAGENT_SendMsg回复消息DRV_AGENT_YJCX_QRY_CNF给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_YJCX_QRY_CNF,
                     sizeof(DRV_AGENT_YJCX_QRY_CNF_STRU),
                     (VOS_UINT8 *)&stYjcxQryCnf);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentHardwareQry(VOS_VOID *pMsg)
{
    VOS_INT32                                   lRslt;
    MN_APP_REQ_MSG_STRU                        *pstMnAppReqMsg;
    DRV_AGENT_HARDWARE_QRY_CNF_STRU             stHardwareQryCnf;

    /* 初始化 */
    pstMnAppReqMsg = (MN_APP_REQ_MSG_STRU *)pMsg;

    PS_MEM_SET(&stHardwareQryCnf, 0, sizeof(DRV_AGENT_HARDWARE_QRY_CNF_STRU));

    stHardwareQryCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stHardwareQryCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;
    stHardwareQryCnf.ulResult               = DRV_AGENT_NO_ERROR;

    /* 使用memVersionCtrl读取硬件版本号*/
    lRslt = DRV_MEM_VERCTRL((char *)stHardwareQryCnf.aucHwVer,
                                         DRV_AGENT_MAX_HARDWARE_LEN,
                                         VER_HARDWARE,
                                         VERIONREADMODE);
    if (DRV_INTERFACE_RSLT_OK != lRslt)
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentHardwareQry:WARNING:memVersionCtrl Read Hardware Version falied!");
        stHardwareQryCnf.ulResult = DRV_AGENT_ERROR;
    }

    /* 调用DRVAGENT_SendMsg回复消息DRV_AGENT_HARDWARE_QRY_RSP给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_HARDWARE_QRY_RSP,
                     sizeof(stHardwareQryCnf),
                     (VOS_UINT8 *)&stHardwareQryCnf);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentFullHardwareQry(VOS_VOID *pMsg)
{
    VOS_INT32                                        lRslt;
    MN_APP_REQ_MSG_STRU                             *pstMnAppReqMsg;
    DRV_AGENT_FULL_HARDWARE_QRY_CNF_STRU             stFullHardwareQryCnf;

    pstMnAppReqMsg = (MN_APP_REQ_MSG_STRU *)pMsg;

    PS_MEM_SET(&stFullHardwareQryCnf, 0, sizeof(DRV_AGENT_FULL_HARDWARE_QRY_CNF_STRU));

    stFullHardwareQryCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stFullHardwareQryCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;
    stFullHardwareQryCnf.ulResult               = DRV_AGENT_NO_ERROR;

    /* 使用memVersionCtrl读取硬件版本号，*/
    lRslt = DRV_GET_PRODUCTID_INTER_VER((TAF_CHAR *)(stFullHardwareQryCnf.aucModelId), DRV_AGENT_MAX_MODEL_ID_LEN);
    if (DRV_INTERFACE_RSLT_OK != lRslt)
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentFullHardwareQry():VER_PRODUCT_ID  Failed!");
        stFullHardwareQryCnf.ulResult = DRV_AGENT_ERROR;
    }

    /*获取软件版本号*/
    lRslt = DRV_MEM_VERCTRL((char *)(stFullHardwareQryCnf.aucRevisionId),
                            DRV_AGENT_MAX_REVISION_ID_LEN + 1,
                            VER_SOFTWARE,
                            VERIONREADMODE);
    if (DRV_INTERFACE_RSLT_OK != lRslt)
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentFullHardwareQry():Read Software Version  Failed!");
        stFullHardwareQryCnf.ulResult = DRV_AGENT_ERROR;
    }

    lRslt = DRV_GET_FULL_HW_VER((TAF_CHAR *)(stFullHardwareQryCnf.aucHwVer), DRV_AGENT_MAX_HARDWARE_LEN);
    if (DRV_INTERFACE_RSLT_OK != lRslt)
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentFullHardwareQry:WARNING:memVersionCtrl Read Hardware Version falied!");
        stFullHardwareQryCnf.ulResult = DRV_AGENT_ERROR;
    }

    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_FULL_HARDWARE_QRY_RSP,
                     sizeof(stFullHardwareQryCnf),
                     (VOS_UINT8 *)&stFullHardwareQryCnf);

    return VOS_OK;
}



VOS_UINT32 DRVAGENT_String2Hex(TAF_UINT8 *nptr,TAF_UINT16 usLen,TAF_UINT32 *pRtn)
{
    TAF_UINT32 c     = 0;         /* current Char */
    TAF_UINT32 total = 0;         /* current total */
    TAF_UINT8 Length = 0;         /* current Length */

    /*lint -e961*/
    c = (TAF_UINT32)*nptr++;

    while(Length++ < usLen)
    /*lint +e961*/
    {
        if( (c  >= '0') && (c  <= '9') )
        {
            c  = c  - '0';
        }
        else if( (c  >= 'a') && (c  <= 'f') )
        {
            c  = (c  - 'a') + 10;
        }
        else if( (c  >= 'A') && (c  <= 'F') )
        {
            c  = (c  - 'A') + 10;
        }
        else
        {
            return VOS_FALSE;
        }

        if(total > 0x0FFFFFFF)              /* 发生反转 */
        {
            return VOS_FALSE;
        }
        else
        {
            total = (total << 4) + c;              /* accumulate digit */

            /*lint -e961*/
            c = (TAF_UINT32)(TAF_UINT8)*nptr++;    /* get next Char */
            /*lint +e961*/
        }
    }

    *pRtn = total;   /* return result, negated if necessary */
    return VOS_TRUE;
}
VOS_UINT32 DRVAGENT_UpdateSimlockStatusToUnlock(VOS_VOID)
{
    VOS_UINT32                          ulResult;
    TAF_CUSTOM_CARDLOCK_STATUS_STRU     stCardLockStatus;
    TAF_CUSTOM_SIM_LOCK_MAX_TIMES_STRU  stSimLockMaxTimes;


    PS_MEM_SET(&stSimLockMaxTimes, 0x00, sizeof(stSimLockMaxTimes));

    /* 获取当前最大解锁次数 */
    ulResult = NV_Read(en_NV_Item_CustomizeSimLockMaxTimes,
                      &stSimLockMaxTimes,
                      sizeof(stSimLockMaxTimes));

    if (NV_OK != ulResult)
    {
        stSimLockMaxTimes.ulLockMaxTimes = TAF_PH_CARDLOCK_DEFAULT_MAXTIME;
    }
    else
    {
        if (NV_ITEM_DEACTIVE == stSimLockMaxTimes.ulStatus)
        {
            stSimLockMaxTimes.ulLockMaxTimes = TAF_PH_CARDLOCK_DEFAULT_MAXTIME;
        }
    }

    /* Simlock校验通过，将永久解除锁卡状态  */
    stCardLockStatus.ulStatus            = NV_ITEM_ACTIVE;
    stCardLockStatus.enCardlockStatus    = TAF_OPERATOR_LOCK_NONEED_UNLOCK_CODE;
    stCardLockStatus.ulRemainUnlockTimes = stSimLockMaxTimes.ulLockMaxTimes;

    ulResult = NV_Write(en_NV_Item_CardlockStatus,
                        &stCardLockStatus,
                        sizeof(stCardLockStatus));
    if (NV_OK != ulResult)
    {
        MN_WARN_LOG("DRVAGENT_UpdateSimlockStatusToUnlock:ERROR:write en_NV_Item_CardlockStatus Fail.");
        return VOS_ERR;
    }

    ulResult = NV_SpecialNvIdBackup(en_NV_Item_CardlockStatus,
                                    &stCardLockStatus,
                                    sizeof(stCardLockStatus));
    if (NV_OK != ulResult)
    {
        MN_WARN_LOG("DRVAGENT_UpdateSimlockStatusToUnlock:ERROR:write special en_NV_Item_CardlockStatus Fail.");
        return VOS_ERR;
    }

    return VOS_OK;

}


VOS_UINT32 DRVAGENT_UpdataSimLockRemainUnlockTimes(VOS_VOID)
{
    VOS_UINT32                          ulResult;
    TAF_CUSTOM_CARDLOCK_STATUS_STRU     stCardLockStatus;


    PS_MEM_SET(&stCardLockStatus, 0x00, sizeof(TAF_CUSTOM_CARDLOCK_STATUS_STRU));

    ulResult = NV_Read(en_NV_Item_CardlockStatus,
                        &stCardLockStatus,
                        sizeof(stCardLockStatus));

    if (NV_OK != ulResult)
    {
        MN_ERR_LOG("DRVAGENT_UpdataSimLockRemainUnlockTimes:ERROR:read en_NV_Item_CardlockStatus Fail.");
        return VOS_ERR;
    }

    /* 当前解锁剩余次数已为0，直接返回 */
    if (0 == stCardLockStatus.ulRemainUnlockTimes)
    {
        return VOS_OK;
    }

    /* 剩余解锁次数减1 */
    stCardLockStatus.ulRemainUnlockTimes--;

    /* 如果剩余解锁次数为0，永久锁定 */
    if (0 == stCardLockStatus.ulRemainUnlockTimes)
    {
        stCardLockStatus.enCardlockStatus = TAF_OPERATOR_LOCK_LOCKED;
    }
    else
    {
        stCardLockStatus.enCardlockStatus = TAF_OPERATOR_LOCK_NEED_UNLOCK_CODE;
    }

    stCardLockStatus.ulStatus = NV_ITEM_ACTIVE;

    ulResult = NV_Write(en_NV_Item_CardlockStatus,
                        &stCardLockStatus,
                        sizeof(stCardLockStatus));

    if (NV_OK != ulResult)
    {
        MN_ERR_LOG("DRVAGENT_UpdataSimLockRemainUnlockTimes:ERROR:write en_NV_Item_CardlockStatus Fail.");
        return VOS_ERR;
    }

    ulResult = NV_SpecialNvIdBackup(en_NV_Item_CardlockStatus,
                                    &stCardLockStatus,
                                    sizeof(stCardLockStatus));
    if (NV_OK != ulResult)
    {
        MN_WARN_LOG("DRVAGENT_UpdataSimLockRemainUnlockTimes:ERROR:write special en_NV_Item_CardlockStatus Fail.");
        return VOS_ERR;
    }

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_GetSimLockRemainUnlockTimes(TAF_CUSTOM_CARDLOCK_STATUS_STRU *pstCardLockStatus)
{
    VOS_UINT32                          ulResult;

    ulResult = NV_Read(en_NV_Item_CardlockStatus,
                       pstCardLockStatus,
                       sizeof(TAF_CUSTOM_CARDLOCK_STATUS_STRU));

    if (NV_OK != ulResult)
    {
        MN_ERR_LOG("DRVAGENT_GetSimLockRemainUnlockTimes:ERROR:read en_NV_Item_CardlockStatus Fail.");
        return VOS_ERR;
    }

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_VerifySimlockPwdFail(MN_APP_REQ_MSG_STRU *pstMnAppReqMsg)
{
    DRV_AGENT_SET_SIMLOCK_CNF_STRU      stSetSimlockCnf;

    PS_MEM_SET(&stSetSimlockCnf, 0, sizeof(DRV_AGENT_SET_SIMLOCK_CNF_STRU));

    stSetSimlockCnf.stAtAppCtrl.usClientId  = pstMnAppReqMsg->clientId;
    stSetSimlockCnf.stAtAppCtrl.ucOpId      = pstMnAppReqMsg->opId;
    stSetSimlockCnf.ulResult                = DRV_AGENT_ERROR;

    /* 非安全镜像 */
    if (VOS_FALSE == DRV_SEC_CHECK())
    {
        DRVAGENT_UpdataSimLockRemainUnlockTimes();

        /* 错误次数增加，连续3次时，重启*/
        gucSimLockErrTimes++;

        if (DRV_AGENT_SIMLOCK_MAX_ERROR_TIMES == gucSimLockErrTimes)
        {
            /* 调用DRVAGENT_SendMsg回复消息 DRV_AGENT_SIMLOCK_SET_CNF 给AT */
            DRVAGENT_SendMsg(WUEPS_PID_AT,
                             DRV_AGENT_SIMLOCK_SET_CNF,
                             sizeof(stSetSimlockCnf),
                             (VOS_UINT8 *)&stSetSimlockCnf);

            /*为了保证AT能够上报给PC，需要作一定的延时 */
            VOS_TaskDelay(AT_DLOAD_TASK_DELAY_TIME);

            VOS_FlowReboot();

            return VOS_ERR;
        }
    }

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_VerifySimlockPwdSucc()
{
    VOS_UINT32                          ulRslt;

    /* 非安全镜像 */
    if (VOS_FALSE == DRV_SEC_CHECK())
    {
        /* 解锁成功后，全局变量清零 */
        gucSimLockErrTimes = 0;

        ulRslt = DRVAGENT_UpdateSimlockStatusToUnlock();

        /* NV可写，但写失败 */
        if (VOS_OK != ulRslt)
        {
            return VOS_ERR;
        }
    }

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentSetSimlock(VOS_VOID *pMsg)
{
    DRV_AGENT_SET_SIMLOCK_CNF_STRU                     stSetSimlockCnf;
    DRV_AGENT_SIMLOCK_SET_REQ_STRU                    *pstSetSimlockReq;
    MN_APP_REQ_MSG_STRU                               *pstMnAppReqMsg;
    VOS_BOOL                                           bCorrect;
    VOS_UINT32                                         ulRslt;
    TAF_CUSTOM_CARDLOCK_STATUS_STRU                    stCardLockStatus;


    PS_MEM_SET(&stCardLockStatus, 0x00, sizeof(stCardLockStatus));

    pstMnAppReqMsg      = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstSetSimlockReq    = (DRV_AGENT_SIMLOCK_SET_REQ_STRU*)pstMnAppReqMsg->aucContent;

    PS_MEM_SET(&stSetSimlockCnf, 0, sizeof(DRV_AGENT_SET_SIMLOCK_CNF_STRU));

    bCorrect                                = VOS_FALSE;
    stSetSimlockCnf.stAtAppCtrl.usClientId  = pstMnAppReqMsg->clientId;
    stSetSimlockCnf.stAtAppCtrl.ucOpId      = pstMnAppReqMsg->opId;
    stSetSimlockCnf.ulResult                = DRV_AGENT_NO_ERROR;

    /* 剩余解锁次数为0，将永久锁定 */
    ulRslt = DRVAGENT_GetSimLockRemainUnlockTimes(&stCardLockStatus);

    if ((VOS_OK == ulRslt)
     && (NV_ITEM_ACTIVE == stCardLockStatus.ulStatus)
     && (0 == stCardLockStatus.ulRemainUnlockTimes))
    {
        stSetSimlockCnf.ulResult = DRV_AGENT_ERROR;

        /* 调用DRVAGENT_SendMsg回复消息 DRV_AGENT_SIMLOCK_SET_CNF 给AT */
        DRVAGENT_SendMsg(WUEPS_PID_AT,
                         DRV_AGENT_SIMLOCK_SET_CNF,
                         sizeof(stSetSimlockCnf),
                         (VOS_UINT8 *)&stSetSimlockCnf);

        return VOS_OK;
    }

    /* 校验密码 */
    if (0 < pstSetSimlockReq->ulPwdLen )
    {
        if (VOS_OK == MMA_VerifyOperatorLockPwd(pstSetSimlockReq->aucPwd))
        {
            bCorrect = VOS_TRUE;
        }
    }

    /* 校验密码成功 */
    if (VOS_TRUE == bCorrect)
    {
        ulRslt = DRVAGENT_VerifySimlockPwdSucc();

        /* NV读写失败 */
        if (VOS_OK != ulRslt)
        {
            stSetSimlockCnf.ulResult = DRV_AGENT_ERROR;
        }
    }
    /* 校验密码失败 */
    else
    {
        stSetSimlockCnf.ulResult = DRV_AGENT_ERROR;

        ulRslt = DRVAGENT_VerifySimlockPwdFail(pstMnAppReqMsg);

        /* 单板重启的场景，直接返回 */
        if (VOS_OK != ulRslt)
        {
            return VOS_OK;
        }
    }

    /* 调用DRVAGENT_SendMsg回复消息 DRV_AGENT_SIMLOCK_SET_CNF 给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                    DRV_AGENT_SIMLOCK_SET_CNF,
                    sizeof(stSetSimlockCnf),
                    (VOS_UINT8 *)&stSetSimlockCnf);

    return VOS_OK;

}


VOS_UINT32 DRVAGENT_RcvDrvAgentQryRxdiv(VOS_VOID *pMsg)
{
    DRV_AGENT_QRY_RXDIV_CNF_STRU        stQryRxdivCnf;
    VOS_UINT32                          ulDataLen;
    VOS_UINT32                          aulSptBand[3];
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    VOS_UINT8                         *pucSystemAppConfig;

    pucSystemAppConfig                  = DRVAGENT_GetSystemAppConfigAddr();

    pstMnAppReqMsg      = (MN_APP_REQ_MSG_STRU *)pMsg;

    PS_MEM_SET(&stQryRxdivCnf, 0, sizeof(DRV_AGENT_QRY_RXDIV_CNF_STRU));

    stQryRxdivCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stQryRxdivCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;


    ulDataLen = 0;
    PS_MEM_SET(aulSptBand, 0x00, sizeof(aulSptBand));

    if (SYSTEM_APP_WEBUI == *pucSystemAppConfig)
    {
        /* 该NV已修改为W和G都为UINT32了, 临时修改避免越界 */

        /*E5 BAND信息通过NV项读取*/
        NV_GetLength(en_NV_Item_WG_RF_MAIN_BAND, &ulDataLen);
        if (NV_OK != NV_Read(en_NV_Item_WG_RF_MAIN_BAND, aulSptBand, ulDataLen))
        {
            PS_LOG(WUEPS_PID_MMA, 0, PS_PRINT_ERROR,
                   "Read en_NV_Item_WG_RF_MAIN_BAND Failed!\n");

            stQryRxdivCnf.ulResult = DRV_AGENT_CME_ERROR;

            DRVAGENT_SendMsg(WUEPS_PID_AT,
                             DRV_AGENT_RXDIV_QRY_CNF,
                             sizeof(stQryRxdivCnf),
                             (VOS_UINT8 *)&stQryRxdivCnf);

            return VOS_ERR;
        }
        stQryRxdivCnf.usDrvDivBands   = (VOS_UINT16)aulSptBand[0];

    }
    else
    {
        /* 获取驱动支持的RX分集，并转换成用户需要的格式 */
        stQryRxdivCnf.usDrvDivBands   = 0;

    if (VOS_OK != NV_Read(en_NV_Item_W_RF_DIV_BAND, &stQryRxdivCnf.usDrvDivBands, sizeof(stQryRxdivCnf.usDrvDivBands)))
    {
        PS_LOG(WUEPS_PID_MMA, 0, PS_PRINT_ERROR,
               "Read en_NV_Item_WG_RF_MAIN_BAND Failed!\n");

        stQryRxdivCnf.ulResult = DRV_AGENT_CME_ERROR;

        DRVAGENT_SendMsg(WUEPS_PID_AT,
                         DRV_AGENT_RXDIV_QRY_CNF,
                         sizeof(stQryRxdivCnf),
                         (VOS_UINT8 *)&stQryRxdivCnf);

        return VOS_ERR;
    }
    }

    stQryRxdivCnf.ulResult = DRV_AGENT_NO_ERROR;

    /* 获取曾经设置的RX分集，并转换成用户需要的格式 */
    if (NV_OK != NV_Read(en_NV_Item_W_RF_DIV_BAND, &stQryRxdivCnf.usCurBandSwitch,
                          sizeof(VOS_UINT16)))
    {
        PS_LOG(WUEPS_PID_MMA, 0, PS_PRINT_ERROR,
               "NV_Read en_NV_Item_W_RF_DIV_BAND fail!\n");

        stQryRxdivCnf.ulResult = DRV_AGENT_CME_ERROR;
    }

    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_RXDIV_QRY_CNF,
                     sizeof(stQryRxdivCnf),
                     (VOS_UINT8 *)&stQryRxdivCnf);

    return VOS_OK;
}

VOS_UINT32 DRVAGENT_RcvDrvAgentSetRxdiv(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                             *pstMnAppReqMsg;
    DRV_AGENT_AT_RXDIV_CNF_STRU                      stSetRxdivCnf;
    AT_DRV_AGENT_RXDIV_SET_STRU                     *pstSetRxdivReq;
    VOS_UINT16                                       usSetDivBands;
    VOS_UINT16                                       usDivBands;
    VOS_UINT16                                       usBandMask;


    usDivBands = 0;

    pstMnAppReqMsg = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstSetRxdivReq = (AT_DRV_AGENT_RXDIV_SET_STRU*)pstMnAppReqMsg->aucContent;

    PS_MEM_SET(&stSetRxdivCnf, 0, sizeof(DRV_AGENT_AT_RXDIV_CNF_STRU));

    stSetRxdivCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stSetRxdivCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;
    stSetRxdivCnf.ucRxOnOff              = pstSetRxdivReq->ucRxOnOff;

    /* 获取驱动支持的接收分集能力 */
    if (VOS_OK != NV_Read(en_NV_Item_W_RF_DIV_BAND, &usDivBands, sizeof(usDivBands)))
    {
        MN_WARN_LOG("Fail to read en_NV_Item_W_RF_DIV_BAND.");
        stSetRxdivCnf.ulResult = DRV_AGENT_CME_RX_DIV_OTHER_ERR;

        DRVAGENT_SendMsg(WUEPS_PID_AT,
                         DRV_AGENT_RXDIV_SET_CNF,
                         sizeof(stSetRxdivCnf),
                         (VOS_UINT8 *)&stSetRxdivCnf);

        return VOS_ERR;
    }

    stSetRxdivCnf.ulResult = DRVAGENT_CheckRxdivOrRxpriParaIfSupported(&usSetDivBands,
                                                                        usDivBands,
                                                                        pstSetRxdivReq->ulSetLowBands,
                                                                        pstSetRxdivReq->ulSetHighBands);
    if (DRV_AGENT_NO_ERROR != stSetRxdivCnf.ulResult)
    {
        DRVAGENT_SendMsg(WUEPS_PID_AT,
                         DRV_AGENT_RXDIV_SET_CNF,
                         sizeof(stSetRxdivCnf),
                         (VOS_UINT8 *)&stSetRxdivCnf);

        return VOS_ERR;
    }

    /*只有RXON之后才需和WDSP交互设置ANTSEL参数,RXOFF发消息给AT，由AT进行处理*/
    if (DRV_AGENT_DSP_RF_SWITCH_ON == pstSetRxdivReq->ucRxOnOff)
    {
        /*lint -e701*/
        usBandMask = (VOS_UINT16)(0x0001 << (pstSetRxdivReq->usDspBand - 1));
        /*lint +e701*/

        if (0 == (usSetDivBands & usBandMask))
        {
            /*设置的频段不是当前使用的频段*/
            stSetRxdivCnf.ulResult = DRV_AGENT_CME_RX_DIV_BAND_ERR;
        }
        else
        {
            stSetRxdivCnf.ulResult = DRV_AGENT_NO_ERROR;
        }
    }
    else
    {
        stSetRxdivCnf.ulResult = DRV_AGENT_NO_ERROR;
    }

    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_RXDIV_SET_CNF,
                     sizeof(stSetRxdivCnf),
                     (VOS_UINT8 *)&stSetRxdivCnf);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentSetNvRestore(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                             *pstMnAppReqMsg;
    DRV_AGENT_NVRESTORE_RST_STRU                     stNvRestoreCnf;

    pstMnAppReqMsg = (MN_APP_REQ_MSG_STRU *)pMsg;

    PS_MEM_SET(&stNvRestoreCnf, 0, sizeof(DRV_AGENT_NVRESTORE_RST_STRU));

    stNvRestoreCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stNvRestoreCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;

    /* 调用OAM的接口Restore所有的NV,将结果返回给AT */
    stNvRestoreCnf.ulResult               = (VOS_UINT32)NV_RestoreAll();;

    /* 调用DRVAGENT_SendMsg回复消息 DRV_AGENT_NVRESTORE_SET_CNF 给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                    DRV_AGENT_NVRESTORE_SET_CNF,
                    sizeof(stNvRestoreCnf),
                    (VOS_UINT8 *)&stNvRestoreCnf);

    return VOS_OK;

}


VOS_UINT32 DRVAGENT_RcvDrvAgentQryNvRestoreRst(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                             *pstMnAppReqMsg;
    DRV_AGENT_NVRESTORE_RST_STRU                     stNvRestoreRstCnf;
    VOS_UINT32                                       ulLoop;

    pstMnAppReqMsg = (MN_APP_REQ_MSG_STRU *)pMsg;

    PS_MEM_SET(&stNvRestoreRstCnf, 0, sizeof(DRV_AGENT_NVRESTORE_RST_STRU));

    stNvRestoreRstCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stNvRestoreRstCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;

    /* 先等待200ms再去查询恢复结果*/
    VOS_TaskDelay(200);

    /* 调用OAM的接口查询单板上次NV自动恢复的结果,将结果返回给AT */
    stNvRestoreRstCnf.ulResult               = (VOS_UINT32)NV_QueryRestoreResult();

    /* 如果还在恢复就等待100ms再次查询，最多查询25次 */
    for (ulLoop = 0; ulLoop < 25; ulLoop++)
    {
    	if (NV_RESTORE_RUNNING == stNvRestoreRstCnf.ulResult)
        {
            VOS_TaskDelay(90);

            /* 调用OAM的接口查询单板上次NV自动恢复的结果,将结果返回给AT */
            stNvRestoreRstCnf.ulResult               = (VOS_UINT32)NV_QueryRestoreResult();
        }
        else
        {
            break;
        }
    }

    /* 调用DRVAGENT_SendMsg回复消息 DRV_AGENT_NVRESTORE_SET_CNF 给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                    DRV_AGENT_NVRSTSTTS_QRY_CNF,
                    sizeof(stNvRestoreRstCnf),
                    (VOS_UINT8 *)&stNvRestoreRstCnf);

    return VOS_OK;

}
VOS_UINT32 DRVAGENT_RcvDrvAgentNvRestoreManuDefault(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                             *pstMnAppReqMsg;
    DRV_AGENT_NVRESTORE_RST_STRU                     stNvRestoreRst;

    pstMnAppReqMsg = (MN_APP_REQ_MSG_STRU *)pMsg;

    PS_MEM_SET(&stNvRestoreRst, 0, sizeof(DRV_AGENT_NVRESTORE_RST_STRU));

    stNvRestoreRst.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stNvRestoreRst.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;

    /* 调用OAM的接口恢复所有NV项为出厂设置,将结果返回给AT */

    stNvRestoreRst.ulResult               = NV_RestoreManufactureDefault();

    TAF_APS_ClearAllRabDsFlowStats();
    TAF_APS_ClearDsFlowInfoInNv();

    /* 调用DRVAGENT_SendMsg回复消息 DRV_AGENT_NVRESTORE_MANU_DEFAULT_CNF 给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                    DRV_AGENT_NVRESTORE_MANU_DEFAULT_CNF,
                    sizeof(stNvRestoreRst),
                    (VOS_UINT8 *)&stNvRestoreRst);

    return VOS_OK;

}
VOS_UINT32 DRVAGENT_RcvDrvAgentDeviceGpioplSet(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_GPIOPL_SET_REQ_STRU      *pstGpioInfo;
    DRV_AGENT_GPIOPL_SET_CNF_STRU       stGpioCnfInfo;

    PS_MEM_SET(&stGpioCnfInfo, 0, sizeof(stGpioCnfInfo));

    pstMnAppReqMsg                            = (MN_APP_REQ_MSG_STRU *)pMsg;
    stGpioCnfInfo.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stGpioCnfInfo.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    /* 调用DRV API DRV_GPIO_OPRT(0) 设置 GPIO 各电平值  */
    pstGpioInfo                               = (DRV_AGENT_GPIOPL_SET_REQ_STRU *)pstMnAppReqMsg->aucContent;
    if (VOS_OK != DRV_GPIO_OPRT(GPIO_OPRT_SET , pstGpioInfo->aucGpiopl))
    {
        stGpioCnfInfo.bFail = VOS_TRUE;
    }
    else
    {
        stGpioCnfInfo.bFail = VOS_FALSE;
    }

    /*调用接口将stGpioCnfInfo传回A核的AT PID
    消息名称为DRV_AGENT_GPIOPL_SET_CNF*/
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_GPIOPL_SET_CNF,
                     sizeof(stGpioCnfInfo),
                     (VOS_UINT8 *)&stGpioCnfInfo);

    return VOS_OK;
}



VOS_UINT32 DRVAGENT_RcvDrvAgentDeviceGpioplQry(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_GPIOPL_QRY_CNF_STRU       stGpioplQryCnf;

    PS_MEM_SET(&stGpioplQryCnf, 0, sizeof(stGpioplQryCnf));

    pstMnAppReqMsg                             = (MN_APP_REQ_MSG_STRU *)pMsg;
    stGpioplQryCnf.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stGpioplQryCnf.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    /* 调用DRV API DRV_GPIO_OPRT() 获取GPIO 各管脚电平值 */
    if (VOS_OK != DRV_GPIO_OPRT(GPIO_OPRT_GET, stGpioplQryCnf.aucGpiopl))
    {
        stGpioplQryCnf.bFail = VOS_TRUE;
    }
    else
    {
        stGpioplQryCnf.bFail = VOS_FALSE;
    }

    /*调用接口将stGpioplQryCnf传回A核的AT PID
    消息名称为DRV_AGENT_GPIOPL_QRY_CNF*/
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_GPIOPL_QRY_CNF,
                     sizeof(stGpioplQryCnf),
                     (VOS_UINT8 *)&stGpioplQryCnf);

    return VOS_OK;

}




VOS_UINT32 DRVAGENT_RcvDrvAgentDeviceDatalockSet(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_DATALOCK_SET_REQ_STRU    *pstDatalockReqInfo;
    DRV_AGENT_DATALOCK_SET_CNF_STRU     stDatalockCnfInfo;

    /* 获取消息内容 */
    pstMnAppReqMsg                             = (MN_APP_REQ_MSG_STRU *)pMsg;
    PS_MEM_SET(&stDatalockCnfInfo, 0, sizeof(stDatalockCnfInfo));
    stDatalockCnfInfo.stAtAppCtrl.usClientId   = pstMnAppReqMsg->clientId;
    stDatalockCnfInfo.stAtAppCtrl.ucOpId       = pstMnAppReqMsg->opId;
    pstDatalockReqInfo                         = (DRV_AGENT_DATALOCK_SET_REQ_STRU *)pstMnAppReqMsg->aucContent;

    /* 调用 MMA_VerifyOperatorLockPwd() 进行 DATALOCK 的校验 */
    if (VOS_OK != MMA_VerifyOperatorLockPwd(pstDatalockReqInfo->aucPwd))
    {
        stDatalockCnfInfo.bFail        = VOS_TRUE;
    }
    else
    {
        stDatalockCnfInfo.bFail        =  VOS_FALSE;
    }

    /*调用接口将stDatalockInfo传回A核的AT PID
    消息名称为DRV_AGENT_DATALOCK_SET_CNF*/
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_DATALOCK_SET_CNF,
                     sizeof(stDatalockCnfInfo),
                     (VOS_UINT8 *)&stDatalockCnfInfo);

    return VOS_OK;

}


VOS_UINT32 DRVAGENT_RcvDrvAgentDeviceTbatvoltQry(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_TBATVOLT_QRY_CNF_STRU     stTbatvoltInfo;

    PS_MEM_SET(&stTbatvoltInfo, 0, sizeof(stTbatvoltInfo));

    pstMnAppReqMsg                          = (MN_APP_REQ_MSG_STRU *)pMsg;
    stTbatvoltInfo.stAtAppCtrl.usClientId   = pstMnAppReqMsg->clientId;
    stTbatvoltInfo.stAtAppCtrl.ucOpId       = pstMnAppReqMsg->opId;

    /* 调用驱动接口获取电池电压值 */
    if (VOS_OK != DRV_HKADC_BAT_VOLT_GET((INT32*)&(stTbatvoltInfo.lBatVol)))
    {
        stTbatvoltInfo.bFail    = VOS_TRUE;
    }
    else
    {
        stTbatvoltInfo.bFail    = VOS_FALSE;
    }
    /*调用接口将stTbatvoltInfo传回A核的AT PID
    消息名称为DRV_AGENT_TBATVOLT_QRY_CNF*/
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_TBATVOLT_QRY_CNF,
                     sizeof(stTbatvoltInfo),
                     (VOS_UINT8 *)&stTbatvoltInfo);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentDeviceTmodeSet(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    VOS_UINT8                           ucUpdateFlag;

    /* 初始化 */
    pstMnAppReqMsg = (MN_APP_REQ_MSG_STRU *)pMsg;

    /* 获取升级标志 */
    ucUpdateFlag = (VOS_UINT8)pstMnAppReqMsg->aucContent[0];

    /* 设置升级标志 */
    if (VOS_TRUE == ucUpdateFlag)
    {
        DRV_SET_UPDATA_FLAG(0);
    }

    /* 单板重启函数VOS_FlowReboot在C核，则直接调用此接口，此时不需要发消息回复A核*/
    VOS_FlowReboot();

    return VOS_OK;

}


VOS_UINT32 DRVAGENT_RcvDrvAgentDeviceVersionQry(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    VOS_CHAR                           *pcVerTime = VOS_NULL_PTR;
    DRV_AGENT_VERSION_QRY_CNF_STRU      stVersionQryCnfInfo;

    PS_MEM_SET(&stVersionQryCnfInfo, 0, sizeof(stVersionQryCnfInfo));

    pstMnAppReqMsg                              = (MN_APP_REQ_MSG_STRU *)pMsg;
    stVersionQryCnfInfo.stAtAppCtrl.usClientId  = pstMnAppReqMsg->clientId;
    stVersionQryCnfInfo.stAtAppCtrl.ucOpId      = pstMnAppReqMsg->opId;

    /* 读取编译时间 AT_AGENT_VERSION_QRY_VERTIME_ERROR */
    pcVerTime  = (VOS_CHAR *)DRV_GET_VERSION_TIME();

    if (VOS_NULL_PTR == pcVerTime)
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentDeviceVersionQry: DRV_GET_VERSION_TIME Error.");
        stVersionQryCnfInfo.enResult = DRV_AGENT_VERSION_QRY_VERTIME_ERROR;
        DRVAGENT_SendMsg(WUEPS_PID_AT,
                         DRV_AGENT_VERSION_QRY_CNF,
                         sizeof(stVersionQryCnfInfo),
                         (VOS_UINT8 *)&stVersionQryCnfInfo);
        return VOS_OK;
    }

    PS_MEM_SET(stVersionQryCnfInfo.acVerTime, 0x00, AT_AGENT_DRV_VERSION_TIME_LEN);
    PS_MEM_CPY(stVersionQryCnfInfo.acVerTime, pcVerTime, VOS_StrLen(pcVerTime));

    /*获取软件版本号,目前Balong内外部软件号相同 */
    MMA_GetProductionVersion((VOS_CHAR *)stVersionQryCnfInfo.stSoftVersion.aucRevisionId);

    /* 使用DRV_GET_CDROM_VERSION读取后台版本号,目前内外部软件号相同  */
    if (VOS_OK != DRV_GET_CDROM_VERSION((VOS_CHAR *)stVersionQryCnfInfo.stIsoVer.aucIsoInfo,
                                         TAF_CDROM_VERSION_LEN))
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentDeviceVersionQry: getCdromVersion Error.");
    }
#if (FEATURE_ON == FEATURE_LTE)

    if (VOS_OK != BSP_HwGetHwVersion((char *)(stVersionQryCnfInfo.stFullHwVer.aucHwVer),
                                                      TAF_MAX_HARDWARE_LEN))
    {
        vos_printf("BSP_HwGetHwVersion Read Hardware Version falied!");
    }

    if (VOS_OK != BSP_HwGetHwVersion((char *)(stVersionQryCnfInfo.stInterHwVer.aucHwVer),
                                                      TAF_MAX_HARDWARE_LEN))
    {
        vos_printf("BSP_HwGetHwVersion Read Hardware Version falied!");
    }

    if (VOS_OK != BSP_GetProductName((char *)(stVersionQryCnfInfo.stModelId.aucModelId),
                                                      TAF_MAX_MODEL_ID_LEN))
    {
        vos_printf("BSP_GetProductName Read Product Name falied!");
    }

    /* 获取内部产品名  */
    if (VOS_OK != DRV_GET_PRODUCTID_INTER_VER((char *)(stVersionQryCnfInfo.stInterModelId.aucModelId),
                                                      TAF_MAX_MODEL_ID_LEN))
    {
        vos_printf("BSP_GetProductInnerName Read Product Name Failed!");
    }
#else
    /* 获取外部硬件版本号  */
    if (DRV_INTERFACE_RSLT_OK != DRV_GET_FULL_HW_VER((char *)(stVersionQryCnfInfo.stFullHwVer.aucHwVer),
                                                      TAF_MAX_HARDWARE_LEN))
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentDeviceVersionQry:WARNING:DRV_GET_FULL_HW_VER Read Hardware Version falied!");
    }

    /* 使用memVersionCtrl读取内部硬件版本号  */
    if(DRV_INTERFACE_RSLT_OK != DRV_MEM_VERCTRL((char *)(stVersionQryCnfInfo.stInterHwVer.aucHwVer),
                                                             TAF_MAX_HARDWARE_LEN,
                                                             VER_HARDWARE,
                                                             VERIONREADMODE))
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentDeviceVersionQry:WARNING:memVersionCtrl Read Hardware Version falied!");
    }

    /* 获取外部产品ID  */
    Taf_GetProductionID((VOS_CHAR *)stVersionQryCnfInfo.stModelId.aucModelId);

    /* 获取内部产品名  */
    if (DRV_INTERFACE_RSLT_OK != DRV_GET_PRODUCTID_INTER_VER((char *)(stVersionQryCnfInfo.stInterModelId.aucModelId),
                                                              TAF_MAX_MODEL_ID_LEN))
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentDeviceVersionQry: Get Internal VER_PRODUCT_ID  Failed!");
    }
#endif

    stVersionQryCnfInfo.enResult = DRV_AGENT_VERSION_QRY_NO_ERROR;

    /* 调用DRVAGENT_SendMsg回复消息DRV_AGENT_VERSION_QRY_CNF给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_VERSION_QRY_CNF,
                     sizeof(stVersionQryCnfInfo),
                     (VOS_UINT8 *)&stVersionQryCnfInfo);
    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentDeviceSecuBootQry(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_SECUBOOT_QRY_CNF_STRU     stSecubootQryCnfInfo;

    PS_MEM_SET(&stSecubootQryCnfInfo, 0, sizeof(stSecubootQryCnfInfo));

    pstMnAppReqMsg                               = (MN_APP_REQ_MSG_STRU *)pMsg;
    stSecubootQryCnfInfo.stAtAppCtrl.usClientId  = pstMnAppReqMsg->clientId;
    stSecubootQryCnfInfo.stAtAppCtrl.ucOpId      = pstMnAppReqMsg->opId;

    /* 判断当前版本是否已经启用安全启动*/
    if (VOS_OK != DRV_SECURE_ALREADY_USE(&(stSecubootQryCnfInfo.ucSecuBootEnable)))
    {
        stSecubootQryCnfInfo.bFail = VOS_TRUE;
    }
    else
    {
        stSecubootQryCnfInfo.bFail = VOS_FALSE;
    }

    /* 调用DRVAGENT_SendMsg回复消息DRV_AGENT_SECUBOOT_QRY_CNF给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_SECUBOOT_QRY_CNF,
                     sizeof(stSecubootQryCnfInfo),
                     (VOS_UINT8 *)&stSecubootQryCnfInfo);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentSetSecuBoot(VOS_VOID *pMsg)
{

    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_SECUBOOT_SET_CNF_STRU     stSecubootSetCnfInfo;
    VOS_INT32                           lRet;
    VOS_UINT16                          usNVSecBootEnableFlag;

    usNVSecBootEnableFlag                        = 0x00;

    PS_MEM_SET(&stSecubootSetCnfInfo, 0, sizeof(stSecubootSetCnfInfo));

    pstMnAppReqMsg                               = (MN_APP_REQ_MSG_STRU *)pMsg;
    stSecubootSetCnfInfo.stAtAppCtrl.usClientId  = pstMnAppReqMsg->clientId;
    stSecubootSetCnfInfo.stAtAppCtrl.ucOpId      = pstMnAppReqMsg->opId;
    lRet                                         = VOS_ERR;
    stSecubootSetCnfInfo.bFail                   = VOS_TRUE;

    /* 只有启动硬件加密的情况下，才能设置 */
    if (VOS_TRUE == DRV_SEC_CHECK())
    {
        if (NV_OK == NV_Read(en_NV_Item_SEC_BOOT_FLAG, &usNVSecBootEnableFlag, sizeof(VOS_UINT16)))
        {
            if(SECURE_SUPPORT == usNVSecBootEnableFlag)
            {
                /* 接口打桩致LINT不过 */
                /*lint -e774 */
                lRet = DRV_START_SECURE();
                /*lint +e774 */
            }
        }
    }
    else
    {
        stSecubootSetCnfInfo.bFail = VOS_FALSE;
    }

    if (VOS_OK == lRet)
    {
        stSecubootSetCnfInfo.bFail = VOS_FALSE;
    }

    /* 调用DRVAGENT_SendMsg回复消息DRV_AGENT_SECUBOOT_QRY_CNF给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_SECUBOOT_SET_CNF,
                     sizeof(stSecubootSetCnfInfo),
                     (VOS_UINT8 *)&stSecubootSetCnfInfo);

    return VOS_OK;
}
VOS_UINT16 DRVAGENT_GetWDLArfcnWithUlPara(
    VOS_UINT16                          usBandNo,
    VOS_UINT16                          usUlArfcn,
    DRV_AGENT_FCHAN_SET_REQ_STRU       *pstDspBandArfcn
)
{
    VOS_UINT16                          usDlArfcn;

    usDlArfcn  = usUlArfcn;
    usDlArfcn += (VOS_UINT16)(5* gausFULOffset[usBandNo]);
    usDlArfcn += (VOS_UINT16)(5* gausBandSepBtwnUlDl[usBandNo]);
    usDlArfcn -= (VOS_UINT16)(5* gausFDLOffset[usBandNo]);
    return usDlArfcn;
}


VOS_UINT16 DRVAGENT_GetWULArfcnWithDlPara(
    VOS_UINT16                          usBandNo,
    VOS_UINT16                          usDlArfcn,
    DRV_AGENT_FCHAN_SET_REQ_STRU       *pstDspBandArfcn
)
{
    VOS_UINT16                          usUlArfcn;

    usUlArfcn  = usDlArfcn;
    usUlArfcn += (VOS_UINT16)(5* gausFDLOffset[usBandNo]);
    usUlArfcn -= (VOS_UINT16)(5* gausBandSepBtwnUlDl[usBandNo]);
    usUlArfcn -= (VOS_UINT16)(5* gausFULOffset[usBandNo]);
    return usUlArfcn;
}



VOS_UINT32 DRVAGENT_CheckWBandChannelRange(DRV_AGENT_FCHAN_SET_REQ_STRU* pstDspBandArfcn)
{
    VOS_UINT16                          usChannelNo;
    VOS_UINT16                          usWDspFomatBand;

    if ((AT_BAND_1700M == pstDspBandArfcn->ucDeviceAtBand)
     && (AT_RAT_MODE_AWS == pstDspBandArfcn->ucDeviceRatMode))
    {
        usWDspFomatBand = W_FREQ_BAND4;
    }
    else
    {
        usWDspFomatBand = gausDevCmdBandToWDspBandTbl[pstDspBandArfcn->ucDeviceAtBand];
    }

    if (W_FREQ_BAND_BUTT == usWDspFomatBand)
    {
        return  DRV_AGENT_FCHAN_BAND_NOT_MATCH;
    }
    else
    {
        if (VOS_TRUE == (Taf_IsWBandSupported(usWDspFomatBand)))
        {
            usChannelNo = pstDspBandArfcn->usChannelNo;



            if ((usChannelNo <= gaStWDSPBandUlAfrcn[usWDspFomatBand].usArfcnMax)
             && (usChannelNo >= gaStWDSPBandUlAfrcn[usWDspFomatBand].usArfcnMin))
            {
                pstDspBandArfcn->stDspBandArfcn.usDspBand = usWDspFomatBand;
                pstDspBandArfcn->stDspBandArfcn.usUlArfcn= usChannelNo;
                pstDspBandArfcn->stDspBandArfcn.usDlArfcn=
                                    DRVAGENT_GetWDLArfcnWithUlPara(usWDspFomatBand,usChannelNo,pstDspBandArfcn);
                return DRV_AGENT_FCHAN_SET_NO_ERROR;
            }
            else if ((usChannelNo <= gaStWDSPBandDlAfrcn[usWDspFomatBand].usArfcnMax)
                  && (usChannelNo >= gaStWDSPBandDlAfrcn[usWDspFomatBand].usArfcnMin))
            {
                pstDspBandArfcn->stDspBandArfcn.usDspBand= usWDspFomatBand;
                pstDspBandArfcn->stDspBandArfcn.usDlArfcn= usChannelNo;
                pstDspBandArfcn->stDspBandArfcn.usUlArfcn=
                                    DRVAGENT_GetWULArfcnWithDlPara(usWDspFomatBand,usChannelNo,pstDspBandArfcn);
                return DRV_AGENT_FCHAN_SET_NO_ERROR;
            }
            else
            {
                return DRV_AGENT_FCHAN_BAND_CHANNEL_NOT_MATCH;
            }

        }
        else
        {
             return DRV_AGENT_FCHAN_BAND_NOT_MATCH;
        }
    }

}



VOS_UINT32 DRVAGENT_CheckGBandChannelRange(DRV_AGENT_FCHAN_SET_REQ_STRU* pstDspBandArfcn)
{
    VOS_UINT16                          usChannelNo;
    VOS_UINT16                          usGDspFomatBand;

    usGDspFomatBand = gausDevCmdBandToGDspBandTbl[pstDspBandArfcn->ucDeviceAtBand];

    if (G_FREQ_BAND_BUTT == usGDspFomatBand)
    {
        return DRV_AGENT_FCHAN_BAND_NOT_MATCH;
    }
    else
    {
        usChannelNo = pstDspBandArfcn->usChannelNo;

        if ((usChannelNo <= gaStGDSPBandAfrcn[usGDspFomatBand].usArfcnMax)
         && (usChannelNo >= gaStGDSPBandAfrcn[usGDspFomatBand].usArfcnMin))
        {
            pstDspBandArfcn->stDspBandArfcn.usDspBand= usGDspFomatBand;
            pstDspBandArfcn->stDspBandArfcn.usUlArfcn= usChannelNo;
            pstDspBandArfcn->stDspBandArfcn.usDlArfcn= usChannelNo;
            return DRV_AGENT_FCHAN_SET_NO_ERROR;
        }
        else if (G_FREQ_BAND_GSM900 == usGDspFomatBand)
        {
            if ((usChannelNo <= gstGsm900SecondRange.usArfcnMax)
             && (usChannelNo >= gstGsm900SecondRange.usArfcnMin))
            {

                pstDspBandArfcn->stDspBandArfcn.usDspBand = usGDspFomatBand;
                pstDspBandArfcn->stDspBandArfcn.usUlArfcn = usChannelNo;
                pstDspBandArfcn->stDspBandArfcn.usDlArfcn = usChannelNo;
                return DRV_AGENT_FCHAN_SET_NO_ERROR;
            }
            else
            {
                return DRV_AGENT_FCHAN_BAND_CHANNEL_NOT_MATCH;
            }
        }
        else
        {
            return DRV_AGENT_FCHAN_BAND_CHANNEL_NOT_MATCH;
        }
    }
}




VOS_UINT32  DRVAGENT_CheckFChanPara(DRV_AGENT_FCHAN_SET_REQ_STRU* pstDspBandArfcn)
{
    if ((AT_RAT_MODE_WCDMA == pstDspBandArfcn->ucDeviceRatMode)
     || (AT_RAT_MODE_AWS == pstDspBandArfcn->ucDeviceRatMode))
    {
        return DRVAGENT_CheckWBandChannelRange(pstDspBandArfcn);
    }
    else
    {
        return DRVAGENT_CheckGBandChannelRange(pstDspBandArfcn);
    }

}


VOS_UINT32 DRVAGENT_RcvDrvAgentDeviceFchanSet(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                 *pstMnAppReqMsg;
    DRV_AGENT_FCHAN_SET_CNF_STRU         stFchanSetCnf;
    VOS_UINT32                           ulErrCode;
    VOS_UINT16                           usLoadPhyRlt;
    VOS_UINT16                           usModemid;

    PS_MEM_SET(&stFchanSetCnf, 0, sizeof(stFchanSetCnf));

    pstMnAppReqMsg                         = (MN_APP_REQ_MSG_STRU *)pMsg;
    stFchanSetCnf.stAtAppCtrl.usClientId   = pstMnAppReqMsg->clientId;
    stFchanSetCnf.stAtAppCtrl.ucOpId       = pstMnAppReqMsg->opId;

    PS_MEM_CPY(&stFchanSetCnf.stFchanSetReq,
               (DRV_AGENT_FCHAN_SET_REQ_STRU *)pstMnAppReqMsg->aucContent,
               sizeof(stFchanSetCnf.stFchanSetReq));

    /*检查^FCHAN命令设置的参数是否符合取值要求  */
    ulErrCode = DRVAGENT_CheckFChanPara(&stFchanSetCnf.stFchanSetReq);

    if (DRV_AGENT_FCHAN_SET_NO_ERROR != ulErrCode)
    {
        stFchanSetCnf.enResult = ulErrCode;
        /*调用接口将stTbatvoltInfo传回A核的AT PID
        消息名称为AT_AGENT_FCHAN_SET_CNF*/
        DRVAGENT_SendMsg(WUEPS_PID_AT,
                        DRV_AGENT_FCHAN_SET_CNF,
                        sizeof(stFchanSetCnf),
                        (VOS_UINT8 *)&stFchanSetCnf);
        return VOS_OK;
    }

    usModemid    = VOS_GetModemIDFromPid(WUEPS_PID_DRV_AGENT);
    usLoadPhyRlt = SHPA_LoadPhy((VOS_RATMODE_ENUM_UINT32)stFchanSetCnf.stFchanSetReq.ucLoadDspMode, usModemid, UPHY_OAM_BUSINESS_TYPE_CT);

    if (VOS_FALSE == usLoadPhyRlt)
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentDeviceFchanSet: DSP Load fail!");
        stFchanSetCnf.enResult = DRV_AGENT_FCHAN_OTHER_ERR;
    }
    else
    {
        stFchanSetCnf.enResult = DRV_AGENT_FCHAN_SET_NO_ERROR;
    }

    /*调用接口将stTbatvoltInfo传回A核的AT PID
    消息名称为DRV_AGENT_FCHAN_SET_CNF*/
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_FCHAN_SET_CNF,
                     sizeof(stFchanSetCnf),
                     (VOS_UINT8 *)&stFchanSetCnf);
    return VOS_OK;

}



VOS_UINT32 DRVAGENT_CovertUserSetRxDivOrRxPriParaToMsInternal(
    VOS_UINT32                          ulSetDivLowBands,
    VOS_UINT32                          ulSetDivHighBands,
    VOS_UINT16                         *pusSetDivBands
)
{
    VOS_UINT32                          ulMsCapaDivLowBands;
    VOS_UINT32                          ulMsCapaDivHighBands;

    *pusSetDivBands      = 0;

    /*用户设置的接收分集格式如下:
        0x80000            GSM850
        0x300              GSM900
        0x80               DCS1800
        0x200000           PCS1900
        0x400000           WCDMA2100
        0x800000           WCDMA1900
        0x1000000          WCDMA1800
        0x2000000          WCDMA_AWS
        0x4000000          WCDMA850
        0x2000000000000    WCDMA900
        0x4000000000000    WCDMA1700
      而MS支持的接收分集格式如下:
        2100M/ bit1  1900M/bit2  1800M/bit3  1700M/bit4  1600M/bit5
        1500M/bit6   900M/bit7   850M/bit8   800M/bit9   450M/bit10
      需要把用户设置的接收分集转换成MS支持的格式
    */
    ulMsCapaDivLowBands  = TAF_PH_BAND_WCDMA_I_IMT_2100
                         | TAF_PH_BAND_WCDMA_II_PCS_1900
                         | TAF_PH_BAND_WCDMA_III_1800
                         | TAF_PH_BAND_WCDMA_V_850;
    ulMsCapaDivHighBands = TAF_PH_BAND_WCDMA_IX_1700
                         | TAF_PH_BAND_WCDMA_VIII_900;
    if (   (0 != (ulSetDivLowBands & (~ulMsCapaDivLowBands)))
        || (0 != (ulSetDivHighBands & (~ulMsCapaDivHighBands))))
    {
        return DRV_AGENT_CME_RX_DIV_NOT_SUPPORTED;
    }
    if (0 != (ulSetDivHighBands & TAF_PH_BAND_WCDMA_VIII_900))
    {
        *pusSetDivBands |= AT_MS_SUPPORT_RX_DIV_900;
    }
    if (0 != (ulSetDivHighBands & TAF_PH_BAND_WCDMA_IX_1700))
    {
        *pusSetDivBands |= AT_MS_SUPPORT_RX_DIV_IX_1700;
    }
    if (0 != (ulSetDivLowBands & TAF_PH_BAND_WCDMA_I_IMT_2100))
    {
        *pusSetDivBands |= AT_MS_SUPPORT_RX_DIV_2100;
    }
    if (0 != (ulSetDivLowBands & TAF_PH_BAND_WCDMA_II_PCS_1900))
    {
        *pusSetDivBands |= AT_MS_SUPPORT_RX_DIV_1900;
    }
    if (0 != (ulSetDivLowBands & TAF_PH_BAND_WCDMA_III_1800))
    {
        *pusSetDivBands |= AT_MS_SUPPORT_RX_DIV_1800;
    }
    if (0 != (ulSetDivLowBands & TAF_PH_BAND_WCDMA_V_850))
    {
        *pusSetDivBands |= AT_MS_SUPPORT_RX_DIV_850;
    }

    return DRV_AGENT_NO_ERROR;
}


VOS_UINT32 DRVAGENT_CheckRxdivOrRxpriParaIfSupported(
    VOS_UINT16                         *pusSetBands,
    VOS_UINT16                          usBands,
    VOS_UINT32                          ulSetLowBands,
    VOS_UINT32                          ulSetHighBands
)
{
    VOS_UINT32                         ulResult;
    VOS_UINT32                         i;

    /* 如果设置成0X3FFFFFFF，认为是打开所有支持的分集或主集;
       否则，把用户设置的参数转成和驱动保存的RX分集或主集对应的格式 */
    if ((TAF_PH_BAND_ANY == ulSetLowBands) && (0 == ulSetHighBands))
    {
        *pusSetBands = usBands;
    }
    else
    {
        ulResult = DRVAGENT_CovertUserSetRxDivOrRxPriParaToMsInternal(ulSetLowBands,
                                                                      ulSetHighBands,
                                                                      pusSetBands);
        if (DRV_AGENT_NO_ERROR != ulResult)
        {
            return ulResult;
        }
    }

    /* 底软支持的RX DIV格式如下:
         2100M/ bit1  1900M/bit2  1800M/bit3  1700M/bit4  1600M/bit5
         1500M/bit6   900M/bit7   850M/bit8   800M/bit9   450M/bit10
      如果打开的是底软不支持的分集或主集，返回错误 */
    for (i = 0; i < 16; i++)
    {
        if ((0 == ((usBands >> i) & 0x0001))
         && (0x0001 == ((*pusSetBands >> i) & 0x0001)))
        {
             return DRV_AGENT_CME_RX_DIV_NOT_SUPPORTED;
        }
    }

    return DRV_AGENT_NO_ERROR;

}



VOS_UINT32 DRVAGENT_RcvDrvAgentDeviceSfeatureQry(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_SFEATURE_QRY_CNF_STRU     stSfeatureQryCnf;
    AT_UE_BAND_CAPA_ST                 *pstBandFeature = VOS_NULL_PTR;

    PS_MEM_SET(&stSfeatureQryCnf, 0, sizeof(stSfeatureQryCnf));

    pstMnAppReqMsg                               = (MN_APP_REQ_MSG_STRU *)pMsg;
    stSfeatureQryCnf.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stSfeatureQryCnf.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    pstBandFeature = (AT_UE_BAND_CAPA_ST*)MN_MMA_GetBandInfo();

    /* 给AT模块回复消息 */
    /* 拷贝版本编译时间信息到消息结构 */
    PS_MEM_CPY(&stSfeatureQryCnf.stBandFeature, pstBandFeature, sizeof(stSfeatureQryCnf.stBandFeature));

    /*调用接口将stSfeatureQryCnf传回A核 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_SFEATURE_QRY_CNF,
                     sizeof(stSfeatureQryCnf),
                     (VOS_UINT8 *)&stSfeatureQryCnf);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentDeviceProdtypeQry(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_PRODTYPE_QRY_CNF_STRU     stProdTypeQryCnf;

    PS_MEM_SET(&stProdTypeQryCnf, 0, sizeof(stProdTypeQryCnf));

    pstMnAppReqMsg                               = (MN_APP_REQ_MSG_STRU *)pMsg;
    stProdTypeQryCnf.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stProdTypeQryCnf.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    /* 调用驱动接口获取产品类型 */
    stProdTypeQryCnf.ulProdType = DRV_PRODUCT_TYPE_GET();

    /*调用接口将stProdTypeQryCnf传回A核 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_PRODTYPE_QRY_CNF,
                     sizeof(stProdTypeQryCnf),
                     (VOS_UINT8 *)&stProdTypeQryCnf);

    return VOS_OK;
}



VOS_UINT32 DRVAGENT_RcvDrvAgentImsiChgQry(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_IMSICHG_QRY_CNF_STRU      stImsiChgQryCnf;

    PS_MEM_SET(&stImsiChgQryCnf, 0, sizeof(stImsiChgQryCnf));

    pstMnAppReqMsg                         = (MN_APP_REQ_MSG_STRU *)pMsg;

    stImsiChgQryCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stImsiChgQryCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;

    /*获取当前IMSI对应的符号*/
    SI_STKGetCurImsiSign(&(stImsiChgQryCnf.usDualIMSIEnable), &(stImsiChgQryCnf.ulCurImsiSign));

    /*调用接口将查询结果传回A核 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_IMSICHG_QRY_CNF,
                     sizeof(stImsiChgQryCnf),
                     (VOS_UINT8 *)&stImsiChgQryCnf);


    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentInfoRbuSet(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_INFORBU_SET_CNF_STRU      stInfoRbuCnf;

    PS_MEM_SET(&stInfoRbuCnf, 0, sizeof(stInfoRbuCnf));

    pstMnAppReqMsg                         = (MN_APP_REQ_MSG_STRU *)pMsg;

    stInfoRbuCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stInfoRbuCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;
    /*NV恢复*/
    #if ( FEATURE_ON == FEATURE_LTE )
    stInfoRbuCnf.ulRslt = NVM_BackUpFNV();
    #else
    stInfoRbuCnf.ulRslt = NV_Backup();
    #endif
    /*调用接口将查询结果传回A核 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_INFORBU_SET_CNF,
                     sizeof(stInfoRbuCnf),
                     (VOS_UINT8 *)&stInfoRbuCnf);

    return VOS_OK;
}
#if ( FEATURE_ON == FEATURE_LTE )
/*****************************************************************************
 函 数 名  : DRVAGENT_RcvDrvAgentInfoRrsSet
 功能描述  : inforbu设置请求
 输入参数  : VOS_VOID *pMsg
 输出参数  : 无
 返 回 值  : VOS_UINT32
 调用函数  :
 被调函数  :

*****************************************************************************/
VOS_UINT32 DRVAGENT_RcvDrvAgentInfoRrsSet(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_INFORRS_SET_CNF_STRU      stInfoRruCnf;

    PS_MEM_SET(&stInfoRruCnf, 0, sizeof(stInfoRruCnf));

    pstMnAppReqMsg                         = (MN_APP_REQ_MSG_STRU *)pMsg;

    stInfoRruCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stInfoRruCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;

    /*NV恢复*/
    stInfoRruCnf.ulRslt = NVM_RevertFNV();

    /*调用接口将查询结果传回A核 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_INFORRS_SET_CNF,
                     sizeof(stInfoRruCnf),
                     (VOS_UINT8 *)&stInfoRruCnf);

    return VOS_OK;
}
#endif

VOS_UINT32 DRVAGENT_RcvDrvAgentTseLrfSet(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_TSELRF_SET_REQ_STRU      *pstTseLrf;
    DRV_AGENT_TSELRF_SET_CNF_STRU       stEventCnf;
    VOS_UINT16                          usLoadPhyRlt;
    VOS_UINT16                          usModemid;

    pstMnAppReqMsg = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstTseLrf      = (DRV_AGENT_TSELRF_SET_REQ_STRU *)pstMnAppReqMsg->aucContent;

    stEventCnf.stAtAppCtrl.usClientId	  = pstMnAppReqMsg->clientId;
    stEventCnf.stAtAppCtrl.ucOpId         = pstMnAppReqMsg->opId;
    stEventCnf.stAtAppCtrl.aucReserved[0] = 0;
    stEventCnf.ucDeviceRatMode            = pstTseLrf->ucDeviceRatMode;

    /* 查询PHY是否load成功  */
    usModemid = VOS_GetModemIDFromPid(WUEPS_PID_DRV_AGENT);

    usLoadPhyRlt = SHPA_LoadPhy((VOS_RATMODE_ENUM_UINT32)pstTseLrf->ucLoadDspMode, usModemid, UPHY_OAM_BUSINESS_TYPE_CT);

    if (VOS_FALSE == usLoadPhyRlt)
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentTseLrfSet: DSP Load fail!");
        stEventCnf.enResult = DRV_AGENT_TSELRF_SET_LOADDSP_FAIL;
    }
    else
    {
        stEventCnf.enResult = DRV_AGENT_TSELRF_SET_NO_ERROR;
    }

    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_TSELRF_SET_CNF,
                     sizeof(stEventCnf),
                     (VOS_UINT8 *)&stEventCnf);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentCpnnQry(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_CPNN_QRY_CNF_STRU         stCpnnCnf;

    PS_MEM_SET(&stCpnnCnf, 0, sizeof(stCpnnCnf));

    pstMnAppReqMsg                   = (MN_APP_REQ_MSG_STRU *)pMsg;

    stCpnnCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stCpnnCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;

    /*获取当前服务状态*/
    stCpnnCnf.bNormalSrvStatus = TAF_IsNormalSrvStatus();

    /*调用接口将查询结果传回A核 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_CPNN_QRY_CNF,
                     sizeof(stCpnnCnf),
                     (VOS_UINT8 *)&stCpnnCnf);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentCpnnTest(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_CPNN_TEST_CNF_STRU        stCpnnCnf;

    PS_MEM_SET(&stCpnnCnf, 0, sizeof(stCpnnCnf));

    pstMnAppReqMsg                         = (MN_APP_REQ_MSG_STRU *)pMsg;

    stCpnnCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stCpnnCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;

    /*获取当前IMSI对应的符号*/
    stCpnnCnf.ulOplExistFlg    = NAS_USIMMAPI_IsServiceAvailable(NAS_USIM_SVR_OPLMN_LIST);
    stCpnnCnf.ulPnnExistFlg    = NAS_USIMMAPI_IsServiceAvailable(NAS_USIM_SVR_PLMN_NTWRK_NAME);

    stCpnnCnf.bNormalSrvStatus = TAF_IsNormalSrvStatus();

    /*调用接口将查询结果传回A核 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_CPNN_TEST_CNF,
                     sizeof(stCpnnCnf),
                     (VOS_UINT8 *)&stCpnnCnf);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentNvBackupSet(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_NVBACKUP_SET_CNF_STRU     stNvBackupCnf;

    PS_MEM_SET(&stNvBackupCnf, 0, sizeof(stNvBackupCnf));

    pstMnAppReqMsg                         = (MN_APP_REQ_MSG_STRU *)pMsg;

    stNvBackupCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stNvBackupCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;
    stNvBackupCnf.ulRslt = (VOS_UINT32)NV_Backup();

    /*调用接口将查询结果传回A核 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_NVBACKUP_SET_CNF,
                     sizeof(stNvBackupCnf),
                     (VOS_UINT8 *)&stNvBackupCnf);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentAdcSet(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_ADC_SET_CNF_STRU          stAdcSetCnf;
    SPY_TEMP_THRESHOLD_PARA_STRU       *pstAdcSetReq;

    PS_MEM_SET(&stAdcSetCnf, 0, sizeof(stAdcSetCnf));

    pstMnAppReqMsg                       = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstAdcSetReq                         = (SPY_TEMP_THRESHOLD_PARA_STRU *)pstMnAppReqMsg->aucContent;
    stAdcSetCnf.stAtAppCtrl.usClientId   = pstMnAppReqMsg->clientId;
    stAdcSetCnf.stAtAppCtrl.ucOpId       = pstMnAppReqMsg->opId;

    if(VOS_OK != Spy_SetTempPara(pstAdcSetReq))
    {
        stAdcSetCnf.bFail = VOS_TRUE;
    }
    else
    {
        stAdcSetCnf.bFail = VOS_FALSE;
    }

    /* 调用DRVAGENT_SendMsg回复消息DRV_AGENT_ADC_SET_CNF给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_ADC_SET_CNF,
                     sizeof(stAdcSetCnf),
                     (VOS_UINT8 *)&stAdcSetCnf);
    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentMemInfoQry(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg   = VOS_NULL_PTR;
    DRV_AGENT_MEMINFO_QRY_RSP_STRU     *pstMemInfoCnfMsg = VOS_NULL_PTR;
    AT_PID_MEM_INFO_PARA_STRU          *pstMemBuffer     = VOS_NULL_PTR;
    VOS_UINT32                          ulMemInfoCnfMsgLen;
    VOS_UINT32                          ulMemBufLen;
    VOS_UINT8                          *pucTempBuffer = VOS_NULL_PTR;

    /* 获取分配内存空间的大小 */
    ulMemBufLen = AT_PID_MEM_INFO_LEN * sizeof(AT_PID_MEM_INFO_PARA_STRU);
    ulMemInfoCnfMsgLen = ulMemBufLen + sizeof(DRV_AGENT_MEMINFO_QRY_RSP_STRU) - 4;

    pucTempBuffer = (VOS_UINT8 *)PS_MEM_ALLOC(WUEPS_PID_AT, ulMemInfoCnfMsgLen);
    if (VOS_NULL_PTR == pucTempBuffer)
    {
        MN_ERR_LOG("DRVAGENT_RcvDrvAgentMemInfoQry Mem Alloc FAILURE");
        return VOS_ERR;
    }

    /* 内存初始化 */
    PS_MEM_SET(pucTempBuffer, 0x00, ulMemInfoCnfMsgLen);

    pstMemInfoCnfMsg = (DRV_AGENT_MEMINFO_QRY_RSP_STRU *)pucTempBuffer;

    pstMnAppReqMsg = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstMemInfoCnfMsg->stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    pstMemInfoCnfMsg->stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;

    /* 获取查询类型, 查询消息中传入的类型为UINT32类型的 */
    pstMemInfoCnfMsg->ulMemQryType = *((VOS_UINT32*)pstMnAppReqMsg->aucContent);

    pstMemInfoCnfMsg->ulResult = VOS_OK;

    pstMemBuffer = (AT_PID_MEM_INFO_PARA_STRU*)pstMemInfoCnfMsg->aucData;

    switch (pstMemInfoCnfMsg->ulMemQryType)
    {
        case AT_MEMQUERY_VOS :
             /* 调用OM的接口，获取PID以及对应的内存使用情况 */
            if (VOS_ERR == VOS_AnalyzePidMemory(pstMemBuffer, ulMemBufLen, &(pstMemInfoCnfMsg->ulPidNum)))
            {
                /* 当ulResult为VOS_ERR时, DRV_AGENT_MEMINFO_QRY_CNF的处理中不再解析PidNum等参数
                   即直接向AT返回ERROR了 */
                pstMemInfoCnfMsg->ulResult = VOS_ERR;
            }

            break;

        case AT_MEMQUERY_TTF :

             /* 调用OM的接口，获取PID以及对应的内存使用情况 */
           /* if (VOS_OK != BSP_DMR_ATANALYZE(pstMemBuffer, ulMemBufLen, &(pstMemInfoCnfMsg->ulPidNum))) */
            /*{ */
            /*   pstMemInfoCnfMsg->ulResult = VOS_ERR; */
            /*} */

            break;

        default:
            pstMemInfoCnfMsg->ulResult = VOS_ERR;
            break;
    }

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_MEMINFO_QRY_CNF,
                     ulMemInfoCnfMsgLen,
                     (VOS_UINT8 *)pstMemInfoCnfMsg);

    /* 释放内存 */
    PS_MEM_FREE(WUEPS_PID_AT, pstMemInfoCnfMsg);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentTbatQry(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                 *pstMnAppReqMsg;
    DRV_AGENT_TBAT_QRY_CNF_STRU         stTbatTypeQryCnf;

    PS_MEM_SET(&stTbatTypeQryCnf, 0, sizeof(stTbatTypeQryCnf));

    pstMnAppReqMsg                               = (MN_APP_REQ_MSG_STRU *)pMsg;
    stTbatTypeQryCnf.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stTbatTypeQryCnf.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    /*  调用底软接口获取电池安装方式*/
    stTbatTypeQryCnf.ulTbatType = (VOS_UINT32)DRV_MNTN_GET_BATT_STATE();

    /*调用接口将stTbatTypeQryCnf 传回A核 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                      DRV_AGENT_TBAT_QRY_CNF,
                     sizeof(stTbatTypeQryCnf),
                     (VOS_UINT8 *)&stTbatTypeQryCnf);

    return VOS_OK;

}


VOS_UINT32 DRVAGENT_RcvDrvAgentHkAdcGet(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_HKADC_GET_CNF_STRU        stHkAdcGetCnf;
    VOS_UINT32                          ulRet;


    PS_MEM_SET(&stHkAdcGetCnf, 0, sizeof(stHkAdcGetCnf));

    pstMnAppReqMsg                       = (MN_APP_REQ_MSG_STRU *)pMsg;
    stHkAdcGetCnf.stAtAppCtrl.usClientId   = pstMnAppReqMsg->clientId;
    stHkAdcGetCnf.stAtAppCtrl.ucOpId       = pstMnAppReqMsg->opId;


    /* 调用底软接口获取电池数字电压 */
    ulRet = (VOS_UINT32)DRV_GET_BATTERY_ADC(&stHkAdcGetCnf.TbatHkadc);
    if (VOS_OK != ulRet)
    {
        stHkAdcGetCnf.enResult = DRV_AGENT_HKADC_GET_FAIL;
    }
    else
    {
        stHkAdcGetCnf.enResult = DRV_AGENT_HKADC_GET_NO_ERROR;
    }



    /* 调用DRVAGENT_SendMsg回复消息DRV_AGENT_HKADC_GET_CNF给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_HKADC_GET_CNF,
                     sizeof(stHkAdcGetCnf),
                     (VOS_UINT8 *)&stHkAdcGetCnf);
    return VOS_OK;
}


#if (FEATURE_ON == FEATURE_SECURITY_SHELL)

VOS_UINT32 DRVAGENT_GetIMEIReverse (VOS_CHAR *aucImei)
{
    VOS_CHAR                            cTemp;
    VOS_UINT8                           i;

    /* 读取IMEI信息 */
    if (NV_OK != NV_Read(en_NV_Item_IMEI, aucImei, TAF_PH_IMEI_LEN))
    {
        MN_WARN_LOG("At_SetMsIdInfo:WARNING:NVIM Read en_NV_Item_IMEI falied!");
        return VOS_ERR;
    }

    /* 逆序操作并在最后一个字符中补上'\0'  */
    for(i = 0; i < ((TAF_PH_IMEI_LEN/2)-1); i++)
    {
        cTemp = aucImei[i];

        /* IMEI需要转为ASCII码，每个字节加 '0'  */
        aucImei[i] = aucImei[(TAF_PH_IMEI_LEN-2)-i] + '0';
        aucImei[(TAF_PH_IMEI_LEN-2)-i] = cTemp + '0';
    }

    /* 中间的字节加 '0'  */
    aucImei[(TAF_PH_IMEI_LEN/2)-1] += '0';

    /* 最后的字节设置为 '\0'  */
    aucImei[TAF_PH_IMEI_LEN-1] = '\0';

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvAtSpwordSet(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;
    DRV_AGENT_SPWORD_SET_CNF_STRU       stSpWordSetCnf;
    VOS_CHAR                            acShellPwd[AT_SHELL_PWD_LEN + 1];
    VOS_CHAR                            aucImeiReverse[TAF_PH_IMEI_LEN];
    DRV_AGENT_SPWORD_SET_REQ_STRU      *pstSpwordSetReq;
    VOS_INT                             iRet;
    VOS_UINT32                          ulRslt;

    PS_MEM_SET(acShellPwd, 0, AT_SHELL_PWD_LEN + 1);
    PS_MEM_SET(aucImeiReverse, 0, TAF_PH_IMEI_LEN);
    PS_MEM_SET(&stSpWordSetCnf, 0, sizeof(stSpWordSetCnf));

    pstMnAppReqMsg                          = (MN_APP_REQ_MSG_STRU *)pMsg;
    stSpWordSetCnf.stAtAppCtrl.usClientId   = pstMnAppReqMsg->clientId;
    stSpWordSetCnf.stAtAppCtrl.ucOpId       = pstMnAppReqMsg->opId;
    stSpWordSetCnf.ulResult                 = VOS_OK;

    pstSpwordSetReq = (DRV_AGENT_SPWORD_SET_REQ_STRU *)pstMnAppReqMsg->aucContent;

    PS_MEM_CPY(acShellPwd, pstSpwordSetReq->acShellPwd, AT_SHELL_PWD_LEN);

    /* 读取经过逆序的IMEI号  */
    ulRslt = DRVAGENT_GetIMEIReverse(aucImeiReverse);
    if(VOS_OK != ulRslt)
    {
        stSpWordSetCnf.ulResult = VOS_ERR;
    }
    else
    {
        /* 调用MD5算法进行判断  */
        iRet = DRV_CARDLOCK_MD5_VERIFY(acShellPwd, aucImeiReverse);
        if(VOS_TRUE != iRet)
        {
            stSpWordSetCnf.ulResult = VOS_ERR;
        }
    }

    /* 调用DRVAGENT_SendMsg回复消息DRV_AGENT_SPWORD_SET_CNF给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_SPWORD_SET_CNF,
                     sizeof(stSpWordSetCnf),
                     (VOS_UINT8 *)&stSpWordSetCnf);
    return VOS_OK;
}
#endif

VOS_UINT32 DRVAGENT_RcvDrvAgentSetSimlockNv(VOS_VOID *pMsg)
{
    TAF_CUSTOM_CARDLOCK_STATUS_STRU                   *pstCardLockStatusReq;
    MN_APP_REQ_MSG_STRU                               *pstMnAppReqMsg;
    VOS_UINT32                                         ulRslt;

    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstCardLockStatusReq                = (TAF_CUSTOM_CARDLOCK_STATUS_STRU *)pstMnAppReqMsg->aucContent;

    ulRslt = NV_SpecialNvIdBackup(en_NV_Item_CardlockStatus,
                                  pstCardLockStatusReq,
                                  sizeof(TAF_CUSTOM_CARDLOCK_STATUS_STRU));
    if (NV_OK != ulRslt)
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentSetSimlockNv:ERROR:write special en_NV_Item_CardlockStatus Fail.");
        return VOS_ERR;
    }

    return VOS_OK;
}

VOS_UINT32 DRVAGENT_RcvDrvAgentSetStandby(VOS_VOID *pMsg)
{
    DRV_AGENT_PSTANDBY_REQ_STRU         *pstPstandbyInfo;
    MN_APP_REQ_MSG_STRU                 *pstMnAppReqMsg;

    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstPstandbyInfo                     = (DRV_AGENT_PSTANDBY_REQ_STRU *)pstMnAppReqMsg->aucContent;

    /* 调用底软提供接口C核进入低功耗模式  */
    DRV_PWRCTRL_STANDBYSTATECCPU(pstPstandbyInfo->ulStandbyTime, pstPstandbyInfo->ulSwitchTime);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentNvBackupStatReq(VOS_VOID *pMsg)
{
    DRV_AGENT_NVBACKUPSTAT_QRY_CNF_STRU stEvent;
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */

    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;
    stEvent.ulResult                    = DRV_AGENT_NO_ERROR;

    /* 调用OAM接口获取NV备份状态信息 */
    stEvent.ulNvBackupStat              = NV_BackupCheck();

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_NVBACKUPSTAT_QRY_CNF,
                     sizeof(stEvent),
                     (VOS_UINT8 *)&stEvent);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentNandBadBlockReq(VOS_VOID *pMsg)
{
    DRV_AGENT_NANDBBC_QRY_CNF_STRU     *pstEvent;
    VOS_UINT                            ulBadBlockNum;
    VOS_UINT32                          ulMaxBadBlockNum;
    VOS_UINT                           *pulBadBlockIndex;
    VOS_UINT32                          ulResult;
    VOS_UINT32                          ulLength;
    VOS_UINT32                          ulIndex;
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */

    /* 初始化 */
    ulLength            = 0;
    ulBadBlockNum       = 0;
    ulMaxBadBlockNum    = 0;
    pstEvent            = VOS_NULL_PTR;
    pulBadBlockIndex    = VOS_NULL_PTR;
    pstMnAppReqMsg      = VOS_NULL_PTR;

    /* 调用底软接口获取NAND FLASH的所有坏块索引列表信息 */
    ulResult    = (VOS_UINT32)NAND_GET_BAD_BLOCK(&ulBadBlockNum, &pulBadBlockIndex);

    if (VOS_OK == ulResult)
    {
        ulMaxBadBlockNum = (ulBadBlockNum > DRV_AGENT_NAND_BADBLOCK_MAX_NUM) ? DRV_AGENT_NAND_BADBLOCK_MAX_NUM : ulBadBlockNum;
        ulLength    = sizeof(DRV_AGENT_NANDBBC_QRY_CNF_STRU) + (ulMaxBadBlockNum * sizeof(VOS_UINT32));
    }
    else
    {
        ulLength    = sizeof(DRV_AGENT_NANDBBC_QRY_CNF_STRU);
        ulResult    = VOS_ERR;
    }

    /* 申请消息内存 */
    pstEvent = (DRV_AGENT_NANDBBC_QRY_CNF_STRU *)PS_MEM_ALLOC(WUEPS_PID_DRV_AGENT, ulLength);

    if (VOS_NULL_PTR == pstEvent)
    {
        if (VOS_OK == ulResult)
        {
            /* 释放底软申请的内存 */
            NAND_FREE_BAD_BLOCK_MEM(pulBadBlockIndex);
        }
        NAS_WARNING_LOG(WUEPS_PID_DRV_AGENT, "DRVAGENT_RcvDrvAgentNandBadBlockReq:ERROR:Memory Alloc Error for pstAppMsg ");
        return VOS_ERR;
    }

    PS_MEM_SET(pstEvent, 0x00, ulLength);
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstEvent->stAtAppCtrl.usClientId    = pstMnAppReqMsg->clientId;
    pstEvent->stAtAppCtrl.ucOpId        = pstMnAppReqMsg->opId;

    if (VOS_OK == ulResult)
    {
        pstEvent->ulResult              = DRV_AGENT_NO_ERROR;
        pstEvent->ulBadBlockNum         = ulBadBlockNum;
        for (ulIndex = 0; ulIndex < ulMaxBadBlockNum; ulIndex++)
        {
            pstEvent->aulBadBlockIndex[ulIndex] = pulBadBlockIndex[ulIndex];
        }

        /* 释放底软申请的内存 */
        NAND_FREE_BAD_BLOCK_MEM(pulBadBlockIndex);
    }
    else
    {
        pstEvent->ulResult              = DRV_AGENT_ERROR;
        pstEvent->ulBadBlockNum         = 0;
    }

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_NANDBBC_QRY_CNF,
                     ulLength,
                     (VOS_UINT8 *)pstEvent);

    PS_MEM_FREE(WUEPS_PID_DRV_AGENT, pstEvent);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentNandDevInfoReq(VOS_VOID *pMsg)
{
    DRV_AGENT_NANDVER_QRY_CNF_STRU      stEvent;
    NAND_DEV_INFO_S                     stDevInfo;
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */

    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    PS_MEM_SET(&stDevInfo, 0x00, sizeof(stDevInfo));

    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;
    stEvent.ulResult                    = DRV_AGENT_NO_ERROR;

    /* 调用底软接口获取NAND FLASH的型号信息 */
    if (VOS_OK == NAND_GET_DEV_INFO(&stDevInfo))
    {
        PS_MEM_CPY(&stEvent.stNandDevInfo, &stDevInfo, sizeof(DRV_AGENT_NAND_DEV_INFO_STRU));
        stEvent.ulResult                = DRV_AGENT_NO_ERROR;
    }
    else
    {
        stEvent.ulResult                = DRV_AGENT_ERROR;
    }

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_NANDVER_QRY_CNF,
                     sizeof(stEvent),
                     (VOS_UINT8 *)&stEvent);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentChipTempReq(VOS_VOID *pMsg)
{
    DRV_AGENT_CHIPTEMP_QRY_CNF_STRU     stEvent;
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */

    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;
    stEvent.ulResult                    = DRV_AGENT_NO_ERROR;

    /* 调用底软接口获取PA、SIM卡和电池的温度信息 */
    if (VOS_OK != DRV_HKADC_GET_TEMP(HKADC_TEMP_PA0, VOS_NULL_PTR, (short *)&(stEvent.lGpaTemp), HKADC_CONV_DELAY))
    {
        stEvent.lGpaTemp = DRV_AGENT_CHIP_TEMP_ERR;
    }
    if (VOS_OK != DRV_HKADC_GET_TEMP(HKADC_TEMP_PA0, VOS_NULL_PTR, (short *)&(stEvent.lWpaTemp), HKADC_CONV_DELAY))
    {
        stEvent.lWpaTemp = DRV_AGENT_CHIP_TEMP_ERR;
    }

    /* 目前只支持GU，L模PA直接返回ERROR */
    stEvent.lLpaTemp = DRV_AGENT_CHIP_TEMP_ERR;

    if (VOS_OK != DRV_HKADC_GET_TEMP(HKADC_TEMP_SIM_CARD, VOS_NULL_PTR, (short *)&(stEvent.lSimTemp), HKADC_CONV_DELAY))
    {
        stEvent.lSimTemp = DRV_AGENT_CHIP_TEMP_ERR;
    }
    if (VOS_OK != DRV_HKADC_GET_TEMP(HKADC_TEMP_BATTERY, VOS_NULL_PTR, (short *)&(stEvent.lBatTemp), HKADC_CONV_DELAY))
    {
        stEvent.lBatTemp = DRV_AGENT_CHIP_TEMP_ERR;
    }
    stEvent.ulResult    = DRV_AGENT_NO_ERROR;

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_CHIPTEMP_QRY_CNF,
                     sizeof(stEvent),
                     (VOS_UINT8 *)&stEvent);

    return VOS_OK;
}



VOS_UINT32 DRVAGENT_RcvDrvAgentAntStateInd(VOS_VOID *pMsg)
{
    DRV_AGENT_ANT_STATE_IND_STRU        stAntState;
    MN_APP_SAR_ANTENSTATUS_MSG_STRU    *pSpyMsg;

    pSpyMsg = (MN_APP_SAR_ANTENSTATUS_MSG_STRU *)pMsg;

    PS_MEM_SET(&stAntState, 0 ,sizeof(DRV_AGENT_ANT_STATE_IND_STRU));

    stAntState.stAtAppCtrl.usClientId = MN_CLIENT_ID_BROADCAST;

    stAntState.usAntState = (VOS_UINT16)pSpyMsg->lAntenStatus;

    /* 调用DRVAGENT_SendMsg回复消息DRV_AGENT_ANTSTATE_QRY_IND_STRU给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_ANTSTATE_QRY_IND,
                     sizeof(stAntState),
                     (VOS_UINT8 *)&stAntState);
    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentSARReductionSet(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */
    MN_APP_SAR_INFO_STRU                stSpyToDsp;                             /* 发给DSP事件结构 */
    MODEM_ID_ENUM_UINT16                enModemId;

    /* 初始化 */
    PS_MEM_SET(&stSpyToDsp, 0, sizeof(stSpyToDsp));
    pstMnAppReqMsg  = (MN_APP_REQ_MSG_STRU *)pMsg;

    /* 获取功率等级 */
    stSpyToDsp.ulSarReduction = (VOS_UINT32)(*(VOS_UINT16 *)pstMnAppReqMsg->aucContent);

#if (FEATURE_ON == FEATURE_LTE)
    /* 支持LTE时需要配置LTE */
    if (VOS_TRUE == TAF_SDC_IsPlatformSupportLte())
    {
        L_ExtSarPowerReductionPRI(stSpyToDsp.ulSarReduction);
    }
#endif

    /* 获取当前的ModemId */
    enModemId       = VOS_GetModemIDFromPid(WUEPS_PID_DRV_AGENT);

    stSpyToDsp.ulSarType = PHY_OM_SAR_MASK_REDUCTION;

    /* 调用SPY接口发消息给DSP */
    Spy_SarSendToDsp(enModemId, &stSpyToDsp);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentSetMaxLockTms(VOS_VOID *pMsg)
{
    TAF_CUSTOM_CARDLOCK_STATUS_STRU                     stCardLockStatus;
    TAF_CUSTOM_SIM_LOCK_MAX_TIMES_STRU                 *pstCardLockMaxlockTmsReq;
    DRV_AGENT_MAX_LOCK_TMS_SET_CNF_STRU                 stMaxLockTmsSetCnf;
    MN_APP_REQ_MSG_STRU                                *pstMnAppReqMsg;
    VOS_UINT32                                          ulRslt;

    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstCardLockMaxlockTmsReq            = (TAF_CUSTOM_SIM_LOCK_MAX_TIMES_STRU *)pstMnAppReqMsg->aucContent;

    PS_MEM_SET(&stMaxLockTmsSetCnf, 0, sizeof(stMaxLockTmsSetCnf));
    stMaxLockTmsSetCnf.stAtAppCtrl.usClientId   = pstMnAppReqMsg->clientId;
    stMaxLockTmsSetCnf.stAtAppCtrl.ucOpId       = pstMnAppReqMsg->opId;
    stMaxLockTmsSetCnf.ulResult                 = VOS_OK;

    /* 当前处于硬加密的时候 */
    if (VOS_TRUE == DRV_SEC_CHECK())
    {
        stMaxLockTmsSetCnf.ulResult = VOS_OK;
    }
    else
    {
        ulRslt = NV_Write(en_NV_Item_CustomizeSimLockMaxTimes,
                           pstCardLockMaxlockTmsReq,
                           sizeof(TAF_CUSTOM_SIM_LOCK_MAX_TIMES_STRU));
        if (NV_OK != ulRslt)
        {
            MN_WARN_LOG("DRVAGENT_RcvDrvAgentSetMaxLockTms():en_NV_Item_CustomizeSimLockMaxTimes NV Write Fail!");
            stMaxLockTmsSetCnf.ulResult = VOS_ERR;

            DRVAGENT_SendMsg(WUEPS_PID_AT,
                             DRV_AGENT_MAX_LOCK_TIMES_SET_CNF,
                             sizeof(stMaxLockTmsSetCnf),
                             (VOS_UINT8 *)&stMaxLockTmsSetCnf);
            return VOS_ERR;
        }

        ulRslt = NV_Read(en_NV_Item_CardlockStatus,
                           &stCardLockStatus,
                           sizeof(stCardLockStatus));
        if (NV_OK != ulRslt)
        {
            MN_WARN_LOG("DRVAGENT_RcvDrvAgentSetMaxLockTms:fail to read en_NV_Item_CardlockStatus");
            stMaxLockTmsSetCnf.ulResult = VOS_ERR;

            DRVAGENT_SendMsg(WUEPS_PID_AT,
                             DRV_AGENT_MAX_LOCK_TIMES_SET_CNF,
                             sizeof(stMaxLockTmsSetCnf),
                             (VOS_UINT8 *)&stMaxLockTmsSetCnf);
            return VOS_ERR;
        }

        /* 更新锁卡状态  */
        stCardLockStatus.ulRemainUnlockTimes = pstCardLockMaxlockTmsReq->ulLockMaxTimes;

        ulRslt = NV_Write(en_NV_Item_CardlockStatus,
                            &stCardLockStatus,
                            sizeof(stCardLockStatus));
        if (NV_OK != ulRslt)
        {
            MN_WARN_LOG("DRVAGENT_RcvDrvAgentSetMaxLockTms:ERROR:write en_NV_Item_CardlockStatus Fail.");
            stMaxLockTmsSetCnf.ulResult = VOS_ERR;

            DRVAGENT_SendMsg(WUEPS_PID_AT,
                             DRV_AGENT_MAX_LOCK_TIMES_SET_CNF,
                             sizeof(stMaxLockTmsSetCnf),
                             (VOS_UINT8 *)&stMaxLockTmsSetCnf);
            return VOS_ERR;
        }

        /* 备份simlockNV */
        ulRslt = NV_SpecialNvIdBackup(en_NV_Item_CardlockStatus,
                                      &stCardLockStatus,
                                      sizeof(TAF_CUSTOM_CARDLOCK_STATUS_STRU));
        if (NV_OK != ulRslt)
        {
            MN_WARN_LOG("DRVAGENT_RcvDrvAgentSetMaxLockTms:ERROR:write special en_NV_Item_CardlockStatus Fail.");
        }
    }

    /* 调用DRVAGENT_SendMsg回复消息DRV_AGENT_MAX_LOCK_TIMES_SET_CNF给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_MAX_LOCK_TIMES_SET_CNF,
                     sizeof(stMaxLockTmsSetCnf),
                     (VOS_UINT8 *)&stMaxLockTmsSetCnf);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentSetApSimSt(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                    *pstMnAppReqMsg;
    DRV_AGENT_AP_SIMST_SET_REQ_STRU        *pstApSimStSetReq;
    DRV_AGENT_AP_SIMST_SET_CNF_STRU         stApSimStSetCnf;

    pstMnAppReqMsg                          = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstApSimStSetReq                        = (DRV_AGENT_AP_SIMST_SET_REQ_STRU *)pstMnAppReqMsg->aucContent;;

    PS_MEM_SET(&stApSimStSetCnf, 0, sizeof(stApSimStSetCnf));
    stApSimStSetCnf.stAtAppCtrl.usClientId   = pstMnAppReqMsg->clientId;
    stApSimStSetCnf.stAtAppCtrl.ucOpId       = pstMnAppReqMsg->opId;
    stApSimStSetCnf.ulResult                 = VOS_OK;

    if (DRV_AGENT_USIM_OPERATE_DEACT == pstApSimStSetReq->ulUsimState)
    {
        /* 调用USIM接口，去激活(U)SIM卡 */
        if (USIMM_API_SUCCESS != NAS_USIMMAPI_DeactiveCardReq(WUEPS_PID_TAF))
        {
            stApSimStSetCnf.ulResult            = VOS_ERR;
        }
    }
    else
    {
        /* 目前不支持激活USIM卡，直接返回OK */
        stApSimStSetCnf.ulResult                = VOS_OK;
    }

    /* 调用DRVAGENT_SendMsg回复消息DRV_AGENT_AP_SIMST_SET_CNF给AT */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_AP_SIMST_SET_CNF,
                     sizeof(stApSimStSetCnf),
                     (VOS_UINT8 *)&stApSimStSetCnf);

    return VOS_OK;
}
DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32 DRVAGENT_ConvertScErr(
    SC_ERROR_CODE_ENUM_UINT32           enErrCode
)
{
    switch(enErrCode)
    {
        case SC_ERROR_CODE_NO_ERROR:
            return DRV_AGENT_PERSONALIZATION_NO_ERROR;

        case SC_ERROR_CODE_OPEN_FILE_FAIL:
        case SC_ERROR_CODE_READ_FILE_FAIL:
        case SC_ERROR_CODE_WRITE_FILE_FAIL:
            return DRV_AGENT_PERSONALIZATION_FLASH_ERROR;

        case SC_ERROR_CODE_VERIFY_SIGNATURE_FAIL:
        case SC_ERROR_CODE_VERIFY_PUB_KEY_SIGNATURE_FAIL:
            return DRV_AGENT_PERSONALIZATION_SIGNATURE_FAIL;

        case SC_ERROR_CODE_DK_INCORRECT:
            return DRV_AGENT_PERSONALIZATION_DK_INCORRECT;

        case SC_ERROR_CODE_RSA_ENCRYPT_FAIL:
            return DRV_AGENT_PERSONALIZATION_RSA_ENCRYPT_FAIL;

        case SC_ERROR_CODE_RSA_DECRYPT_FAIL:
            return DRV_AGENT_PERSONALIZATION_RSA_DECRYPT_FAIL;

        case SC_ERROR_CODE_GET_RAND_NUMBER_FAIL:
            return DRV_AGENT_PERSONALIZATION_GET_RAND_NUMBER_FAIL;

        case SC_ERROR_CODE_IDENTIFY_FAIL:
        case SC_ERROR_CODE_IDENTIFY_NOT_FINISH:
            return DRV_AGENT_PERSONALIZATION_IDENTIFY_FAIL;

        case SC_ERROR_CODE_WRITE_HUK_FAIL:
            return DRV_AGENT_PERSONALIZATION_WRITE_HUK_FAIL;

        case SC_ERROR_CODE_LOCK_CODE_INVALID:
        case SC_ERROR_CODE_CREATE_KEY_FAIL:
        case SC_ERROR_CODE_GENERATE_HASH_FAIL:
        case SC_ERROR_CODE_AES_ECB_ENCRYPT_FAIL:
        case SC_ERROR_CODE_ALLOC_MEM_FAIL:
        case SC_ERROR_CODE_UNLOCK_KEY_INCORRECT:
        case SC_ERROR_CODE_UNLOCK_STATUS_ABNORMAL:
        case SC_ERROR_CODE_BUTT:
        default:
            /* 上述错误以及其他错误，返回OTHER_ERROR */
            return DRV_AGENT_PERSONALIZATION_OTHER_ERROR;
    }
}
VOS_UINT32 DRVAGENT_RcvDrvAgentHukSetReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_HUK_SET_REQ_STRU         *pstHukSetReq;
    DRV_AGENT_HUK_SET_CNF_STRU          stHukSetCnf;
    VOS_UINT32                          ulResult;

    /* 初始化 */
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstHukSetReq                        = (DRV_AGENT_HUK_SET_REQ_STRU *)pstMnAppReqMsg->aucContent;
    PS_MEM_SET(&stHukSetCnf, 0x00, sizeof(DRV_AGENT_HUK_SET_CNF_STRU));
    stHukSetCnf.stAtAppCtrl.usClientId  = pstMnAppReqMsg->clientId;
    stHukSetCnf.stAtAppCtrl.ucOpId      = pstMnAppReqMsg->opId;
    stHukSetCnf.enResult                = DRV_AGENT_PERSONALIZATION_ERR_BUTT;
    ulResult                            = VOS_NULL;

    /* 调用SC模块接口, 写入HUK */
    ulResult = SC_FAC_WriteHUK(pstHukSetReq->aucHUK, DRV_AGENT_HUK_LEN);

    /* 将返回的错误码转换后发送给AT */
    stHukSetCnf.enResult                = DRVAGENT_ConvertScErr(ulResult);

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_HUK_SET_CNF,
                     sizeof(DRV_AGENT_HUK_SET_CNF_STRU),
                     (VOS_UINT8 *)&stHukSetCnf);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentFacAuthPubkeySetReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                    *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_FACAUTHPUBKEY_SET_REQ_STRU   *pstFacAuthPubkeysetReq;
    DRV_AGENT_FACAUTHPUBKEY_SET_CNF_STRU    stFacAuthPubkeySetCnf;
    VOS_UINT32                              ulResult;

    /* 初始化 */
    pstMnAppReqMsg                                  = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstFacAuthPubkeysetReq                          = (DRV_AGENT_FACAUTHPUBKEY_SET_REQ_STRU *)pstMnAppReqMsg->aucContent;
    PS_MEM_SET(&stFacAuthPubkeySetCnf, 0x00, sizeof(DRV_AGENT_FACAUTHPUBKEY_SET_CNF_STRU));
    stFacAuthPubkeySetCnf.stAtAppCtrl.usClientId    = pstMnAppReqMsg->clientId;
    stFacAuthPubkeySetCnf.stAtAppCtrl.ucOpId        = pstMnAppReqMsg->opId;
    stFacAuthPubkeySetCnf.enResult                  = DRV_AGENT_PERSONALIZATION_ERR_BUTT;
    ulResult                                        = VOS_NULL;

    /* 调用SC模块接口, 写入产线鉴权公钥 */
    ulResult = SC_FAC_SetFacAuthPubKey((SC_SET_FAC_AUTH_PUB_KEY_STRU *)pstFacAuthPubkeysetReq);

    /* 将返回的错误码转换后发送给AT */
    stFacAuthPubkeySetCnf.enResult                  = DRVAGENT_ConvertScErr(ulResult);

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_FACAUTHPUBKEY_SET_CNF,
                     sizeof(DRV_AGENT_FACAUTHPUBKEY_SET_CNF_STRU),
                     (VOS_UINT8 *)&stFacAuthPubkeySetCnf);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentIdentifyStartSetReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                    *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_IDENTIFYSTART_SET_CNF_STRU    stIdentifyStartSetCnf;
    SC_IDENTIFY_START_RESPONSE_STRU         stIdentifyStartRsp;
    VOS_UINT32                              ulResult;

    /* 初始化 */
    pstMnAppReqMsg                                  = (MN_APP_REQ_MSG_STRU *)pMsg;
    PS_MEM_SET(&stIdentifyStartSetCnf, 0x00, sizeof(DRV_AGENT_IDENTIFYSTART_SET_CNF_STRU));
    PS_MEM_SET(&stIdentifyStartRsp, 0x00, sizeof(SC_IDENTIFY_START_RESPONSE_STRU));
    stIdentifyStartSetCnf.stAtAppCtrl.usClientId    = pstMnAppReqMsg->clientId;
    stIdentifyStartSetCnf.stAtAppCtrl.ucOpId        = pstMnAppReqMsg->opId;
    stIdentifyStartSetCnf.enResult                  = DRV_AGENT_PERSONALIZATION_ERR_BUTT;
    ulResult                                        = VOS_NULL;

    /* 调用SC模块接口, 获取随机数加密密文 */
    ulResult = SC_FAC_StartIdentify(&stIdentifyStartRsp);

    /* 将返回的错误码转换后发送给AT */
    stIdentifyStartSetCnf.enResult                  = DRVAGENT_ConvertScErr(ulResult);

    /* 填充消息结构体 */
    if (DRV_AGENT_PERSONALIZATION_NO_ERROR == stIdentifyStartSetCnf.enResult)
    {
        PS_MEM_CPY(stIdentifyStartSetCnf.aucRsaText,
                   stIdentifyStartRsp.aucIdentifyStartRsp,
                   DRV_AGENT_RSA_CIPHERTEXT_LEN);
    }

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_IDENTIFYSTART_SET_CNF,
                     sizeof(DRV_AGENT_IDENTIFYSTART_SET_CNF_STRU),
                     (VOS_UINT8 *)&stIdentifyStartSetCnf);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentIdentifyEndSetReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_IDENTIFYEND_SET_REQ_STRU *pstIdentifyEndSetReq;
    DRV_AGENT_IDENTIFYEND_SET_CNF_STRU  stIdentifyEndSetCnf;
    VOS_UINT32                          ulResult;

    /* 初始化 */
    pstMnAppReqMsg                              = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstIdentifyEndSetReq                        = (DRV_AGENT_IDENTIFYEND_SET_REQ_STRU *)pstMnAppReqMsg->aucContent;
    PS_MEM_SET(&stIdentifyEndSetCnf, 0x00, sizeof(DRV_AGENT_IDENTIFYEND_SET_CNF_STRU));
    stIdentifyEndSetCnf.stAtAppCtrl.usClientId  = pstMnAppReqMsg->clientId;
    stIdentifyEndSetCnf.stAtAppCtrl.ucOpId      = pstMnAppReqMsg->opId;
    stIdentifyEndSetCnf.enResult                = DRV_AGENT_PERSONALIZATION_ERR_BUTT;
    ulResult                                    = VOS_NULL;

    /* 调用SC模块接口, 完成产线鉴权 */
    ulResult = SC_FAC_EndIdentify((SC_IDENTIFY_END_REQUEST_STRU *)pstIdentifyEndSetReq);

    /* 将返回的错误码转换后发送给AT */
    stIdentifyEndSetCnf.enResult                = DRVAGENT_ConvertScErr(ulResult);

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_IDENTIFYEND_SET_CNF,
                     sizeof(DRV_AGENT_IDENTIFYEND_SET_CNF_STRU),
                     (VOS_UINT8 *)&stIdentifyEndSetCnf);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentSimlockDataWriteSetReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                        *pstMnAppReqMsg;                 /* 接收消息指针 */
    DRV_AGENT_SIMLOCKDATAWRITE_SET_REQ_STRU    *pstSimlockDataWriteSetReq;
    DRV_AGENT_SIMLOCKDATAWRITE_SET_CNF_STRU     stSimlockDataWriteSetCnf;
    VOS_UINT32                                  ulResult;

    /* 初始化 */
    pstMnAppReqMsg                                  = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstSimlockDataWriteSetReq                       = (DRV_AGENT_SIMLOCKDATAWRITE_SET_REQ_STRU *)pstMnAppReqMsg->aucContent;
    PS_MEM_SET(&stSimlockDataWriteSetCnf,
               0x00,
               sizeof(DRV_AGENT_SIMLOCKDATAWRITE_SET_CNF_STRU));
    stSimlockDataWriteSetCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stSimlockDataWriteSetCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;
    stSimlockDataWriteSetCnf.enResult               = DRV_AGENT_PERSONALIZATION_ERR_BUTT;
    ulResult                                        = VOS_NULL;


    /* 调用SC模块接口, 写入锁网锁卡数据 */
    ulResult = SC_PERS_WriteSimLockData((SC_WRITE_SIMLOCK_DATA_STRU *)pstSimlockDataWriteSetReq->aucCategoryData);

    /* 将返回的错误码转换后发送给AT */
    stSimlockDataWriteSetCnf.enResult               = DRVAGENT_ConvertScErr(ulResult);

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_SIMLOCKDATAWRITE_SET_CNF,
                     sizeof(DRV_AGENT_SIMLOCKDATAWRITE_SET_CNF_STRU),
                     (VOS_UINT8 *)&stSimlockDataWriteSetCnf);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentPhoneSimlockInfoQryReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                    *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_PHONESIMLOCKINFO_QRY_CNF_STRU stPhoneSimlockInfoQryCnf;
    SC_SIMLOCK_INFO_STRU                    stSimlockInfo;
    VOS_UINT32                              ulResult;
    VOS_UINT8                               i;

    /* 初始化 */
    pstMnAppReqMsg                                  = (MN_APP_REQ_MSG_STRU *)pMsg;
    PS_MEM_SET(&stSimlockInfo,
               0x00,
               sizeof(SC_SIMLOCK_INFO_STRU));
    PS_MEM_SET(&stPhoneSimlockInfoQryCnf,
               0x00,
               sizeof(DRV_AGENT_PHONESIMLOCKINFO_QRY_CNF_STRU));
    stPhoneSimlockInfoQryCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stPhoneSimlockInfoQryCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;
    stPhoneSimlockInfoQryCnf.enResult               = DRV_AGENT_PERSONALIZATION_ERR_BUTT;
    ulResult                                        = VOS_NULL;

    /* 调用SC模块接口, 查询锁网锁卡信息 */
    ulResult = SC_PERS_GetSimlockInfo(&stSimlockInfo);

    /* 将返回的错误码转换后发送给AT */
    stPhoneSimlockInfoQryCnf.enResult               = DRVAGENT_ConvertScErr(ulResult);

    /* 填写消息结构 */
    if (DRV_AGENT_PERSONALIZATION_NO_ERROR == stPhoneSimlockInfoQryCnf.enResult)
    {
        for (i = 0; i < DRV_AGENT_SUPPORT_CATEGORY_NUM; i++)
        {
            stPhoneSimlockInfoQryCnf.astCategoryInfo[i].enCategory  = stSimlockInfo.astSimlockCategory[i].enCategory;
            stPhoneSimlockInfoQryCnf.astCategoryInfo[i].enIndicator = stSimlockInfo.astSimlockCategory[i].enIndicator;
            stPhoneSimlockInfoQryCnf.astCategoryInfo[i].ucGroupNum  = stSimlockInfo.astSimlockCategory[i].ucGroupNum;
            PS_MEM_CPY(stPhoneSimlockInfoQryCnf.astCategoryInfo[i].astLockCode,
                       stSimlockInfo.astSimlockCategory[i].astLockCode,
                       (DRV_AGENT_PH_LOCK_CODE_GROUP_NUM * sizeof(DRV_AGENT_PH_LOCK_CODE_STRU)));

        }
    }

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_PHONESIMLOCKINFO_QRY_CNF,
                     sizeof(DRV_AGENT_PHONESIMLOCKINFO_QRY_CNF_STRU),
                     (VOS_UINT8 *)&stPhoneSimlockInfoQryCnf);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentSimlockDataReadQryReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                    *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_SIMLOCKDATAREAD_QRY_CNF_STRU  stSimlockDataReadQryCnf;
    SC_SIMLOCK_INFO_STRU                    stSimlockInfo;
    VOS_UINT32                              ulResult;
    VOS_UINT8                               i;

    /* 初始化 */
    pstMnAppReqMsg                                  = (MN_APP_REQ_MSG_STRU *)pMsg;
    PS_MEM_SET(&stSimlockInfo, 0x00, sizeof(SC_SIMLOCK_INFO_STRU));
    PS_MEM_SET(&stSimlockDataReadQryCnf,
               0x00,
               sizeof(DRV_AGENT_SIMLOCKDATAREAD_QRY_CNF_STRU));
    stSimlockDataReadQryCnf.stAtAppCtrl.usClientId  = pstMnAppReqMsg->clientId;
    stSimlockDataReadQryCnf.stAtAppCtrl.ucOpId      = pstMnAppReqMsg->opId;
    stSimlockDataReadQryCnf.enResult                = DRV_AGENT_PERSONALIZATION_ERR_BUTT;
    ulResult                                        = VOS_NULL;

    /* 调用SC模块接口, 查询锁网锁卡安全数据 */
    ulResult = SC_PERS_GetSimlockInfo(&stSimlockInfo);

    /* 将返回的错误码转换后发送给AT */
    stSimlockDataReadQryCnf.enResult                = DRVAGENT_ConvertScErr(ulResult);

    /* 填写消息结构 */
    if (DRV_AGENT_PERSONALIZATION_NO_ERROR == stSimlockDataReadQryCnf.enResult)
    {
        for (i = 0; i < DRV_AGENT_SUPPORT_CATEGORY_NUM; i++)
        {
            stSimlockDataReadQryCnf.astCategoryData[i].enCategory           = stSimlockInfo.astSimlockCategory[i].enCategory;
            stSimlockDataReadQryCnf.astCategoryData[i].enIndicator          = stSimlockInfo.astSimlockCategory[i].enIndicator;
            stSimlockDataReadQryCnf.astCategoryData[i].enStatus             = stSimlockInfo.astSimlockCategory[i].enStatus;
            stSimlockDataReadQryCnf.astCategoryData[i].ucMaxUnlockTimes     = stSimlockInfo.astSimlockCategory[i].ucMaxUnlockTimes;
            stSimlockDataReadQryCnf.astCategoryData[i].ucRemainUnlockTimes  = stSimlockInfo.astSimlockCategory[i].ucRemainUnlockTimes;
        }
    }

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_SIMLOCKDATAREAD_QRY_CNF,
                     sizeof(DRV_AGENT_SIMLOCKDATAREAD_QRY_CNF_STRU),
                     (VOS_UINT8 *)&stSimlockDataReadQryCnf);

    return VOS_OK;
}


DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32 DRVAGENT_UpdateImei(
    VOS_UINT8                           aucImei[],
    VOS_UINT32                          ulLen
)
{
    VOS_UINT8                           aucImeiNum[DRV_AGENT_PH_PHYNUM_IMEI_NV_LEN];
    VOS_UINT8                           ucCheckData;
    VOS_UINT8                           i;

    PS_MEM_SET(aucImeiNum, 0x00, DRV_AGENT_PH_PHYNUM_IMEI_NV_LEN);

    /* IMEI 长度检查: 用户输入的IMEI长度应为14位的IMEI和1位的CHECK NUM，共15位 */
    if (DRV_AGENT_PH_PHYNUM_IMEI_LEN != ulLen)
    {
        return DRV_AGENT_PERSONALIZATION_PH_PHYNUM_LEN_ERROR;
    }

    /* 检查IMEI号值是否合法 */
    /* 转换IMEI数字字符串为数字串 */
    if (VOS_OK != DRVAGENT_AsciiNum2DecNum(aucImei, aucImeiNum, ulLen))
    {
        return DRV_AGENT_PERSONALIZATION_PH_PHYNUM_VALUE_ERROR;
    }
    /* IMEI 校验检查: IMEI信息由IMEI(TAC8位,SNR6位)和校验位两部分组成
       参考协议: 3GPP 23003 B.2 Computation of CD for an IMEI和B.3 Example of computation */
    ucCheckData = 0;
    for (i = 0; i < (DRV_AGENT_PH_PHYNUM_IMEI_LEN - 1); i += 2)
    {
        ucCheckData += aucImeiNum[i]
                       + ((aucImeiNum[i + 1] + aucImeiNum[i + 1]) / 10)
                       + ((aucImeiNum[i + 1] + aucImeiNum[i + 1]) % 10);
    }
    ucCheckData = (10 - (ucCheckData % 10)) % 10;
    if (ucCheckData != aucImeiNum[DRV_AGENT_PH_PHYNUM_IMEI_LEN - 1])
    {
        return DRV_AGENT_PERSONALIZATION_PH_PHYNUM_VALUE_ERROR;
    }

    /* 写IMEI号到NV项中 */
    if (NV_OK != NV_Write(en_NV_Item_IMEI, aucImeiNum, DRV_AGENT_PH_PHYNUM_IMEI_NV_LEN))
    {
         return DRV_AGENT_PERSONALIZATION_OTHER_ERROR;
    }

    return DRV_AGENT_PERSONALIZATION_NO_ERROR;
}
DRV_AGENT_PERSONALIZATION_ERR_ENUM_UINT32 DRVAGENT_UpdateSn(
    VOS_UINT8                           aucSn[],
    VOS_UINT32                          ulLen
)
{
    VOS_UINT8                           aucSnNV[DRV_AGENT_PH_PHYNUM_SN_NV_LEN];

    /* 默认填充为0xFF */
    PS_MEM_SET(aucSnNV, (VOS_CHAR)0xFF, DRV_AGENT_PH_PHYNUM_SN_NV_LEN);

    /* 检查SN号长度 */
    if (DRV_AGENT_PH_PHYNUM_SN_LEN != ulLen)
    {
        return DRV_AGENT_PERSONALIZATION_PH_PHYNUM_LEN_ERROR;
    }

    /* 检查是否为数字字母字符串, 不是则直接返回错误 */
    if (VOS_OK != DRVAGENT_CheckNumCharString(aucSn, ulLen))
    {
        return DRV_AGENT_PERSONALIZATION_PH_PHYNUM_VALUE_ERROR;
    }

    /* 拷贝设置的16位SN参数到NV目标数组中 */
    PS_MEM_CPY(aucSnNV, aucSn, DRV_AGENT_PH_PHYNUM_SN_LEN);

    if (NV_OK != NV_Write(en_NV_Item_Serial_Num,
                          aucSnNV,
                          DRV_AGENT_PH_PHYNUM_SN_NV_LEN))
    {
        return DRV_AGENT_PERSONALIZATION_OTHER_ERROR;
    }

    /* 写SN号到NV项中 */
    return DRV_AGENT_PERSONALIZATION_NO_ERROR;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentPhonePhynumSetReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_PHONEPHYNUM_SET_REQ_STRU *pstPhonePhynumSetReq;
    DRV_AGENT_PHONEPHYNUM_SET_CNF_STRU  stPhonePhynumSetCnf;
    VOS_UINT8                           aucPhynum[DRV_AGENT_PH_PHYNUM_LEN];
    VOS_UINT32                          ulPhynumLen;
    VOS_UINT32                          ulResult;
    VOS_UINT16                          usModemId;

    /* 初始化 */
    pstMnAppReqMsg                              = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstPhonePhynumSetReq                        = (DRV_AGENT_PHONEPHYNUM_SET_REQ_STRU *)pstMnAppReqMsg->aucContent;
    PS_MEM_SET(&stPhonePhynumSetCnf,
               0x00,
               sizeof(DRV_AGENT_PHONEPHYNUM_SET_CNF_STRU));
    PS_MEM_SET(aucPhynum, 0x00, DRV_AGENT_PH_PHYNUM_LEN);
    stPhonePhynumSetCnf.stAtAppCtrl.usClientId  = pstMnAppReqMsg->clientId;
    stPhonePhynumSetCnf.stAtAppCtrl.ucOpId      = pstMnAppReqMsg->opId;
    stPhonePhynumSetCnf.enResult                = DRV_AGENT_PERSONALIZATION_ERR_BUTT;
    ulResult                                    = VOS_NULL;

    if (DRV_AGENT_PH_PHYNUM_IMEI == pstPhonePhynumSetReq->enPhynumType)
    {
        ulPhynumLen                                 = DRV_AGENT_PH_PHYNUM_IMEI_LEN;
    }
    else
    {
        ulPhynumLen                                 = DRV_AGENT_PH_PHYNUM_SN_LEN;
    }

    /* 调用SC模块接口, 对物理号密文进行RSA解密 */
    ulResult    = SC_FAC_RsaDecrypt(pstPhonePhynumSetReq->aucPhynumValue,
                                    DRV_AGENT_RSA_CIPHERTEXT_LEN,
                                    aucPhynum,
                                    &ulPhynumLen);

    /* 将返回的错误码转换后发送给AT */
    stPhonePhynumSetCnf.enResult                = DRVAGENT_ConvertScErr(ulResult);

    /* 把物理号写入NV项 */
    if (DRV_AGENT_PERSONALIZATION_NO_ERROR == stPhonePhynumSetCnf.enResult)
    {
        switch(pstPhonePhynumSetReq->enPhynumType)
        {
            case DRV_AGENT_PH_PHYNUM_IMEI:
                stPhonePhynumSetCnf.enResult = DRVAGENT_UpdateImei(aucPhynum, ulPhynumLen);
                break;
            case DRV_AGENT_PH_PHYNUM_SN:
                stPhonePhynumSetCnf.enResult = DRVAGENT_UpdateSn(aucPhynum, ulPhynumLen);
                break;
            default:
                stPhonePhynumSetCnf.enResult = DRV_AGENT_PERSONALIZATION_PH_PHYNUM_TYPE_ERROR;
                break;
        }
    }

    /* 根据clientId获得ModemId */
    usModemId = VOS_GetModemIDFromPid(WUEPS_PID_DRV_AGENT);

    /* 写入IMEI密文 */
    if ((DRV_AGENT_PERSONALIZATION_NO_ERROR == stPhonePhynumSetCnf.enResult)
      &&(DRV_AGENT_PH_PHYNUM_IMEI == pstPhonePhynumSetReq->enPhynumType))
    {
        stPhonePhynumSetCnf.enResult = SC_FAC_WriteIMEI(usModemId,
                                                        pstPhonePhynumSetReq->aucPhynumValue,
                                                        DRV_AGENT_RSA_CIPHERTEXT_LEN);
    }

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_PHONEPHYNUM_SET_CNF,
                     sizeof(DRV_AGENT_PHONEPHYNUM_SET_CNF_STRU),
                     (VOS_UINT8 *)&stPhonePhynumSetCnf);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentPhonePhynumQryReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_PHONEPHYNUM_QRY_CNF_STRU  stPhonePhynumQryCnf;
    VOS_UINT8                           aucImeiNum[DRV_AGENT_PH_PHYNUM_IMEI_NV_LEN];
    VOS_UINT8                           aucImeiStr[DRV_AGENT_PH_PHYNUM_IMEI_LEN];
    VOS_UINT8                           aucSnStr[DRV_AGENT_PH_PHYNUM_SN_NV_LEN];
    VOS_UINT32                          ulImeiLen;
    VOS_UINT32                          ulSnLen;
    VOS_UINT32                          ulImeiRst;
    VOS_UINT32                          ulSnRst;
    VOS_UINT8                           ucCheckData;
    VOS_UINT8                           i;

    /* 初始化 */
    pstMnAppReqMsg                              = (MN_APP_REQ_MSG_STRU *)pMsg;
    PS_MEM_SET(aucImeiNum,  0x00,   DRV_AGENT_PH_PHYNUM_IMEI_NV_LEN);
    PS_MEM_SET(aucSnStr,    0x00,   DRV_AGENT_PH_PHYNUM_SN_NV_LEN);
    PS_MEM_SET(&stPhonePhynumQryCnf,
               0x00,
               sizeof(DRV_AGENT_PHONEPHYNUM_QRY_CNF_STRU));
    stPhonePhynumQryCnf.stAtAppCtrl.usClientId  = pstMnAppReqMsg->clientId;
    stPhonePhynumQryCnf.stAtAppCtrl.ucOpId      = pstMnAppReqMsg->opId;
    stPhonePhynumQryCnf.enResult                = DRV_AGENT_PERSONALIZATION_ERR_BUTT;
    ulImeiRst                                   = VOS_NULL;
    ulSnRst                                     = VOS_NULL;
    ulImeiLen                                   = DRV_AGENT_RSA_CIPHERTEXT_LEN;
    ulSnLen                                     = DRV_AGENT_RSA_CIPHERTEXT_LEN;
    ucCheckData                                 = 0;

    /* 从NV项中读取物理号 */
    /* 读取IMEI */
    ulImeiRst = NV_Read(en_NV_Item_IMEI, aucImeiNum, DRV_AGENT_PH_PHYNUM_IMEI_NV_LEN);
    ulSnRst = NV_Read(en_NV_Item_Serial_Num, aucSnStr, DRV_AGENT_PH_PHYNUM_SN_NV_LEN);
    if ( (NV_OK != ulImeiRst) || (NV_OK != ulSnRst) )
    {
        stPhonePhynumQryCnf.enResult            = DRV_AGENT_PERSONALIZATION_OTHER_ERROR;
    }
    else
    {
        /* IMEI号要进行特殊处理, 并将数字串转换为AscII码字符串 */
        /* IMEI 校验检查: IMEI信息由IMEI(TAC8位,SNR6位)和校验位两部分组成
           参考协议: 3GPP 23003 B.2 Computation of CD for an IMEI和B.3 Example of computation */
        ucCheckData = 0;
        for (i = 0; i < (DRV_AGENT_PH_PHYNUM_IMEI_LEN - 1); i += 2)
        {
            ucCheckData += aucImeiNum[i]
                           + ((aucImeiNum[i + 1] + aucImeiNum[i + 1]) / 10)
                           + ((aucImeiNum[i + 1] + aucImeiNum[i + 1]) % 10);
        }
        ucCheckData                                     = (10 - (ucCheckData % 10)) % 10;
        aucImeiNum[DRV_AGENT_PH_PHYNUM_IMEI_LEN - 1]    = ucCheckData;

        if (VOS_OK == DRVAGENT_DecNum2AsciiNum(aucImeiNum, aucImeiStr, DRV_AGENT_PH_PHYNUM_IMEI_LEN))
        {
            /* 调用SC模块接口, 对物理号进行RSA加密 */
            ulImeiRst   = SC_FAC_RsaEncrypt(aucImeiStr,
                                            DRV_AGENT_PH_PHYNUM_IMEI_LEN,
                                            stPhonePhynumQryCnf.aucImeiRsa,
                                            &ulImeiLen);
            ulSnRst     = SC_FAC_RsaEncrypt(aucSnStr,
                                            DRV_AGENT_PH_PHYNUM_SN_LEN,
                                            stPhonePhynumQryCnf.aucSnRsa,
                                            &ulSnLen);
            if (SC_ERROR_CODE_NO_ERROR != ulImeiRst)
            {
                stPhonePhynumQryCnf.enResult            = DRVAGENT_ConvertScErr(ulImeiRst);
            }
            else if (SC_ERROR_CODE_NO_ERROR != ulSnRst)
            {
                stPhonePhynumQryCnf.enResult            = DRVAGENT_ConvertScErr(ulSnRst);
            }
            else
            {
                stPhonePhynumQryCnf.enResult            = DRV_AGENT_PERSONALIZATION_NO_ERROR;
            }
        }
        else
        {
            stPhonePhynumQryCnf.enResult                = DRV_AGENT_PERSONALIZATION_OTHER_ERROR;
        }

    }

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_PHONEPHYNUM_QRY_CNF,
                     sizeof(DRV_AGENT_PHONEPHYNUM_QRY_CNF_STRU),
                     (VOS_UINT8 *)&stPhonePhynumQryCnf);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentPortctrlTmpSetReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_PORTCTRLTMP_SET_REQ_STRU *pstPortCtrlTmpSetReq;
    DRV_AGENT_PORTCTRLTMP_SET_CNF_STRU  stPortCtrTmplSetCnf;
    VOS_UINT32                          ulResult;

    /* 初始化 */
    pstMnAppReqMsg                              = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstPortCtrlTmpSetReq                        = (DRV_AGENT_PORTCTRLTMP_SET_REQ_STRU *)pstMnAppReqMsg->aucContent;
    PS_MEM_SET(&stPortCtrTmplSetCnf, 0x00, sizeof(DRV_AGENT_PORTCTRLTMP_SET_CNF_STRU));
    stPortCtrTmplSetCnf.stAtAppCtrl.usClientId  = pstMnAppReqMsg->clientId;
    stPortCtrTmplSetCnf.stAtAppCtrl.ucOpId      = pstMnAppReqMsg->opId;

    /* 调用SC模块接口, 校验端口锁密码 */
    ulResult                                    = SC_FAC_VerifyPortPassword(pstPortCtrlTmpSetReq->aucPortPassword,
                                                                            DRV_AGENT_PORT_PASSWORD_LEN);

    /* 将返回的错误码转换后发送给AT */
    stPortCtrTmplSetCnf.enResult                = DRVAGENT_ConvertScErr(ulResult);

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_PORTCTRLTMP_SET_CNF,
                     sizeof(DRV_AGENT_PORTCTRLTMP_SET_CNF_STRU),
                     (VOS_UINT8 *)&stPortCtrTmplSetCnf);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentPortAttribSetReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                    *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_PORTATTRIBSET_SET_REQ_STRU   *pstPortAttribSetReq;
    DRV_AGENT_PORTATTRIBSET_SET_CNF_STRU    stPortAttribSetCnf;
    SC_SET_PORT_ATTRIBUTE_STRU              stScPortAttrib;
    VOS_UINT32                              ulResult;

    /* 初始化 */
    pstMnAppReqMsg                             = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstPortAttribSetReq                        = (DRV_AGENT_PORTATTRIBSET_SET_REQ_STRU *)pstMnAppReqMsg->aucContent;
    PS_MEM_SET(&stPortAttribSetCnf, 0x00, sizeof(DRV_AGENT_PORTATTRIBSET_SET_CNF_STRU));
    stPortAttribSetCnf.stAtAppCtrl.usClientId  = pstMnAppReqMsg->clientId;
    stPortAttribSetCnf.stAtAppCtrl.ucOpId      = pstMnAppReqMsg->opId;

    /* 设置通信端口的初始状态 */
    if (DRV_AGENT_PORT_STATUS_OFF == pstPortAttribSetReq->enPortStatus)
    {
        stScPortAttrib.enStatus                = SC_PORT_STATUS_OFF;
    }
    else
    {
        stScPortAttrib.enStatus                = SC_PORT_STATUS_ON;
    }
    /* 设置通信端口的密码 */
    PS_MEM_CPY(stScPortAttrib.aucRsaPwd, pstPortAttribSetReq->aucPortPassword, DRV_AGENT_RSA_CIPHERTEXT_LEN);

    /* 调用SC模块接口 */
    ulResult                                   = SC_FAC_SetPortAttrib(&stScPortAttrib);

    /* 将返回的错误码转换后发送给AT */
    stPortAttribSetCnf.enResult                = DRVAGENT_ConvertScErr(ulResult);

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_PORTATTRIBSET_SET_CNF,
                     sizeof(DRV_AGENT_PORTATTRIBSET_SET_CNF_STRU),
                     (VOS_UINT8 *)&stPortAttribSetCnf);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentPortAttribQryReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                    *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_PORTATTRIBSET_QRY_CNF_STRU    stPortAttribQryCnf;
    VOS_UINT32                              ulResult;
    SC_PORT_STATUS_ENUM_UINT32              enStatus;

    /* 初始化 */
    enStatus                                    = SC_PORT_STATUS_BUTT;

    pstMnAppReqMsg                              = (MN_APP_REQ_MSG_STRU *)pMsg;
    PS_MEM_SET(&stPortAttribQryCnf, 0x00, sizeof(DRV_AGENT_PORTATTRIBSET_QRY_CNF_STRU));
    stPortAttribQryCnf.stAtAppCtrl.usClientId   = pstMnAppReqMsg->clientId;
    stPortAttribQryCnf.stAtAppCtrl.ucOpId       = pstMnAppReqMsg->opId;

    /* 调用SC模块接口, 查询通信端口的永久状态 */
    ulResult = SC_FAC_GetPortAttrib(&enStatus);

    if (SC_PORT_STATUS_OFF == enStatus)
    {
        stPortAttribQryCnf.enPortStatus        = DRV_AGENT_PORT_STATUS_OFF;
    }
    else if (SC_PORT_STATUS_ON == enStatus)
    {
        stPortAttribQryCnf.enPortStatus        = DRV_AGENT_PORT_STATUS_ON;
    }
    else
    {
        stPortAttribQryCnf.enPortStatus        = DRV_AGENT_PORT_STATUS_BUTT;
    }
    /* 将返回的错误码转换后发送给AT */
    stPortAttribQryCnf.enResult                = DRVAGENT_ConvertScErr(ulResult);

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_PORTATTRIBSET_QRY_CNF,
                     sizeof(DRV_AGENT_PORTATTRIBSET_QRY_CNF_STRU),
                     (VOS_UINT8 *)&stPortAttribQryCnf);

    return VOS_OK;
}


VOS_UINT32 DRVAGENT_RcvDrvAgentOpwordSetReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                    *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_OPWORD_SET_REQ_STRU          *pstOpwordSetReq;
    DRV_AGENT_OPWORD_SET_CNF_STRU           stOpwordSetCnf;
    VOS_UINT32                              ulResult;

    /* 初始化 */
    pstMnAppReqMsg                         = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstOpwordSetReq                        = (DRV_AGENT_OPWORD_SET_REQ_STRU *)pstMnAppReqMsg->aucContent;
    PS_MEM_SET(&stOpwordSetCnf, 0x00, sizeof(DRV_AGENT_OPWORD_SET_CNF_STRU));
    stOpwordSetCnf.stAtAppCtrl.usClientId  = pstMnAppReqMsg->clientId;
    stOpwordSetCnf.stAtAppCtrl.ucOpId      = pstMnAppReqMsg->opId;

    /* AP-Modem形态时调用SC模块接口验证端口锁密码,调用SC模块接口, 校验端口锁密码 */
    ulResult                               = SC_FAC_VerifyPortPassword(pstOpwordSetReq->aucPortPassword,
                                                                       DRV_AGENT_PORT_PASSWORD_LEN);

    /* 将返回的错误码转换后发送给AT */
    stOpwordSetCnf.enResult                = DRVAGENT_ConvertScErr(ulResult);

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_OPWORD_SET_CNF,
                     sizeof(DRV_AGENT_OPWORD_SET_CNF_STRU),
                     (VOS_UINT8 *)&stOpwordSetCnf);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentSwverSetReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                        /* 接收消息指针 */
    VOS_CHAR                           *pcVerTime = VOS_NULL_PTR;
    DRV_AGENT_SWVER_SET_CNF_STRU        stEvent;
    VOS_UINT32                          ulVersionTimeLen;

    /* 初始化 */
    PS_MEM_SET(&stEvent, 0x00, sizeof(stEvent));
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    stEvent.stAtAppCtrl.usClientId      = pstMnAppReqMsg->clientId;
    stEvent.stAtAppCtrl.ucOpId          = pstMnAppReqMsg->opId;

    /* 读取编译时间 */
    pcVerTime = (VOS_CHAR *)DRV_GET_VERSION_TIME();
    if (VOS_NULL_PTR == pcVerTime)
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentSwverSetReq: DRV_GET_VERSION_TIME Error.");
        stEvent.enResult = DRV_AGENT_ERROR;
        DRVAGENT_SendMsg(WUEPS_PID_AT,
                         DRV_AGENT_SWVER_SET_CNF,
                         sizeof(stEvent),
                         (VOS_UINT8 *)&stEvent);

        return VOS_ERR;
    }

    ulVersionTimeLen = VOS_StrLen(pcVerTime);
    if (ulVersionTimeLen >= AT_AGENT_DRV_VERSION_TIME_LEN)
    {
        MN_WARN_LOG("DRVAGENT_RcvDrvAgentSwverSetReq: DRV_GET_VERSION_TIME length Error.");
        stEvent.enResult = DRV_AGENT_ERROR;
        DRVAGENT_SendMsg(WUEPS_PID_AT,
                         DRV_AGENT_SWVER_SET_CNF,
                         sizeof(stEvent),
                         (VOS_UINT8 *)&stEvent);

        return VOS_ERR;
    }


    PS_MEM_CPY(stEvent.stSwverInfo.acVerTime, pcVerTime, VOS_StrLen(pcVerTime));

    /*获取软件版本号*/
    MMA_GetProductionVersion((VOS_CHAR *)stEvent.stSwverInfo.aucSWVer);

    /* 给AT模块回复消息 */
    stEvent.enResult = DRV_AGENT_NO_ERROR;
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_SWVER_SET_CNF,
                     sizeof(stEvent),
                     (VOS_UINT8 *)&stEvent);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentCcpuMemQryReq(VOS_VOID *pMsg)
{
    TTF_MemCcpuCheckPoolLeak();

    return VOS_OK;

}


#if (FEATURE_ON == FEATURE_VSIM)

VOS_UINT32 DRVAGENT_RcvDrvAgentHvpdhSetReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                        /* 接收消息指针 */
    SC_ERROR_CODE_ENUM_UINT32           enResult;
    VOS_UINT32                          ulResult;
    DRV_AGENT_HVPDH_REQ_STRU           *pstHvpdhReq;
    DRV_AGENT_HVPDH_CNF_STRU            stHvpdhCnf;
    MODEM_ID_ENUM_UINT16                enModemId;

    /* 初始化 */
    pstMnAppReqMsg                      = (MN_APP_REQ_MSG_STRU *)pMsg;
    pstHvpdhReq                         = (DRV_AGENT_HVPDH_REQ_STRU *)pstMnAppReqMsg->aucContent;
    PS_MEM_SET(&stHvpdhCnf, 0x00, sizeof(stHvpdhCnf));
    stHvpdhCnf.stAtAppCtrl.usClientId   = pstMnAppReqMsg->clientId;
    stHvpdhCnf.stAtAppCtrl.ucOpId       = pstMnAppReqMsg->opId;

    /* 由PID获取MODEMID */
    enModemId = VOS_GetModemIDFromPid(WUEPS_PID_DRV_AGENT);

    enResult = SC_FAC_SetDhKey( enModemId,
                                (SC_DH_KEY_TYPE_ENUM_UINT32)pstHvpdhReq->enKeyType,
                                pstHvpdhReq->ulKeyLen,
                                pstHvpdhReq->aucKey);
    switch (enResult)
    {
        case SC_ERROR_CODE_NO_ERROR:
            ulResult = VOS_OK;
            stHvpdhCnf.enResult = DRV_AGENT_HVPDH_NO_ERROR;
            break;

        case SC_ERROR_CODE_IDENTIFY_NOT_FINISH:
            ulResult = VOS_ERR;
            stHvpdhCnf.enResult = DRV_AGENT_HVPDH_AUTH_UNDO;
            MN_WARN_LOG("DRVAGENT_RcvDrvAgentHvpdhSetReq: enResult is SC_ERROR_CODE_IDENTIFY_NOT_FINISH!");
            break;

        case SC_ERROR_CODE_NV_READ_FAIL:
            ulResult = VOS_ERR;
            stHvpdhCnf.enResult = DRV_AGENT_HVPDH_NV_READ_FAIL;
            MN_WARN_LOG("DRVAGENT_RcvDrvAgentHvpdhSetReq: enResult is SC_ERROR_CODE_NV_READ_FAIL!");
            break;

        case SC_ERROR_CODE_NV_WRITE_FAIL:
            ulResult = VOS_ERR;
            stHvpdhCnf.enResult = DRV_AGENT_HVPDH_NV_WRITE_FAIL;
            MN_WARN_LOG("DRVAGENT_RcvDrvAgentHvpdhSetReq: enResult is SC_ERROR_CODE_NV_WRITE_FAIL!");
            break;

        default:
            ulResult = VOS_ERR;
            stHvpdhCnf.enResult = DRV_AGENT_HVPDH_OTHER_ERROR;
            MN_WARN_LOG("DRVAGENT_RcvDrvAgentHvpdhSetReq: enResult is abnormal!");
            break;
    }

    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_HVPDH_CNF,
                     sizeof(stHvpdhCnf),
                     (VOS_UINT8 *)&stHvpdhCnf);

    return ulResult;
}
#endif
VOS_UINT32 DRVAGENT_RcvDrvAgentNvManufactureExtSet(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                          *pstMnAppReqMsg;
    DRV_AGENT_NVMANUFACTUREEXT_SET_CNF_STRU       stNvManuFactureExtCnf;

    PS_MEM_SET(&stNvManuFactureExtCnf, 0, sizeof(stNvManuFactureExtCnf));

    pstMnAppReqMsg                         = (MN_APP_REQ_MSG_STRU *)pMsg;

    stNvManuFactureExtCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stNvManuFactureExtCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;
    stNvManuFactureExtCnf.ulRslt = (VOS_UINT32)NV_RestoreManufactureExt();

    /*调用接口将查询结果传回A核 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_NVMANUFACTUREEXT_SET_CNF,
                     sizeof(stNvManuFactureExtCnf),
                     (VOS_UINT8 *)&stNvManuFactureExtCnf);

    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentSetAntSwitchReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU               *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_ANTSWITCH_SET_STRU      *pstAntSwitchSetPara;
    DRV_AGENT_ANTSWITCH_SET_CNF_STRU   stAntSwitchSetCnf;

    pstMnAppReqMsg      = (MN_APP_REQ_MSG_STRU*)pMsg;
    pstAntSwitchSetPara = (DRV_AGENT_ANTSWITCH_SET_STRU*)(pstMnAppReqMsg->aucContent);
    PS_MEM_SET(&stAntSwitchSetCnf,0,sizeof(DRV_AGENT_ANTSWITCH_SET_CNF_STRU));

#ifdef DMT
    stAntSwitchSetCnf.ulResult = VOS_OK;
#else
    /* do switch antenna */
    /* 根据执行结果对result赋值 */
    /* call function : int outer_rfswitch_set(BSP_U32 status)*/
    if(VOS_ERROR == DRV_OUTER_RFSWITCH_SET((pstAntSwitchSetPara->ulState)))
    {
        stAntSwitchSetCnf.ulResult = VOS_ERR;
    }
    else
    {
        stAntSwitchSetCnf.ulResult = VOS_OK;
    }
#endif

    stAntSwitchSetCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stAntSwitchSetCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_ANTSWITCH_SET_CNF,
                     sizeof(DRV_AGENT_ANTSWITCH_SET_CNF_STRU),
                     (VOS_UINT8 *)&stAntSwitchSetCnf);
    return VOS_OK;
}
VOS_UINT32 DRVAGENT_RcvDrvAgentQryAntSwitchReq(VOS_VOID *pMsg)
{
    MN_APP_REQ_MSG_STRU                *pstMnAppReqMsg;                         /* 接收消息指针 */
    DRV_AGENT_ANTSWITCH_QRY_CNF_STRU    stAntSwitchQryCnf;
    VOS_UINT32                          ulRfSwitchId;

    ulRfSwitchId   = 0;
    pstMnAppReqMsg = (MN_APP_REQ_MSG_STRU*)pMsg;
    PS_MEM_SET(&stAntSwitchQryCnf,0,sizeof(DRV_AGENT_ANTSWITCH_SET_CNF_STRU));

#ifdef DMT
    stAntSwitchQryCnf.ulState = 0;
    stAntSwitchQryCnf.ulResult = VOS_OK;
#else
    /* check antenna switch state and set ulState value */
    /* call function : int outer_rfswitch_get(BSP_U32 *status) */
    /* 根据执行结果对ulState和ulresult赋值 */
    if(VOS_ERROR == DRV_OUTER_RFSWITCH_GET((BSP_U32 *)&ulRfSwitchId))
    {
        stAntSwitchQryCnf.ulState = 0;
        stAntSwitchQryCnf.ulResult = VOS_ERR;
    }
    else
    {
        stAntSwitchQryCnf.ulState = ulRfSwitchId;
        stAntSwitchQryCnf.ulResult = VOS_OK;
    }
#endif

    stAntSwitchQryCnf.stAtAppCtrl.usClientId = pstMnAppReqMsg->clientId;
    stAntSwitchQryCnf.stAtAppCtrl.ucOpId     = pstMnAppReqMsg->opId;

    /* 给AT模块回复消息 */
    DRVAGENT_SendMsg(WUEPS_PID_AT,
                     DRV_AGENT_ANTSWITCH_QRY_CNF,
                     sizeof(DRV_AGENT_ANTSWITCH_QRY_CNF_STRU),
                     (VOS_UINT8 *)&stAntSwitchQryCnf);
    return VOS_OK;
}

/*lint +e958*/

#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif
