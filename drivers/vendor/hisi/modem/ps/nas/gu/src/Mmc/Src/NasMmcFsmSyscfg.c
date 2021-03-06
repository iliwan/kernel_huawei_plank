

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include "pslog.h"
#include "v_typdef.h"
#include "NasComm.h"
#include "NasMmlCtx.h"
#include "NasMmlLib.h"
#include "NasMmlMsgProc.h"
#include "NasMmcCtx.h"
#if (FEATURE_ON == FEATURE_LTE)
#include "MmcLmmInterface.h"
#endif
#include "NasMmcSndLmm.h"
#include "NasMmcSndGuAs.h"
#include "NasMmcFsmSyscfg.h"
#include "NasMmcTimerMgmt.h"
#include "NasMmcFsmSyscfgTbl.h"
#include "NasMmcSndMm.h"
#include "NasMmcSndGmm.h"
#include "NasMmcSndMma.h"
#include "NasMmcSndInternalMsg.h"
#include "NasComm.h"
#include "NasUtranCtrlInterface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define    THIS_FILE_ID        PS_FILE_ID_NAS_MMC_FSM_SYSCFG_C
/*****************************************************************************
  2 全局变量
*****************************************************************************/

/*****************************************************************************
  3 宏定义
*****************************************************************************/


VOS_UINT32  NAS_MMC_RcvMmaSysCfgSetReq_SysCfg_Init(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgMsg        = VOS_NULL_PTR;

    VOS_UINT32                          ulRrcConnExistFlag;
    VOS_UINT32                          ulNeedSyscfgPlmnSrch;
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enCurrRat;
    VOS_UINT32                          ulFlg;
    VOS_UINT32                          ulUsimStausFlg;
    NAS_MMC_PLMN_SELECTION_MODE_ENUM_UINT8 enPlmnSelectionMode;

    NAS_MML_PLMN_RAT_PRIO_STRU         *pstPrePrioRatList;
    NAS_MML_PLMN_RAT_PRIO_STRU          stSyscfgPrioRatList;

    pstPrePrioRatList = NAS_MML_GetMsPrioRatList();

    /* 取得当前的SYSCFG消息 */
    pstSysCfgMsg         = (MMA_MMC_SYS_CFG_SET_REQ_STRU *)pstMsg;


    /* 若用户设置的SYSCFG消息只有漫游特性改变，则不需要通知接入层 */
    if ( VOS_TRUE == pstSysCfgMsg->ucOnlyRoamParaChanged )
    {
        /* 向MMA回复SYSCFG设置成功原语 */
        NAS_MMC_SndMmaSysCfgCnf(MMA_MMC_SYS_CFG_SET_SUCCESS);

        /* 默认漫游设置不需要进行搜网 */
        ulNeedSyscfgPlmnSrch = VOS_FALSE;

        /* 判断SYSCFG对ROAM特性的设置是否需要导致搜网 */
        ulUsimStausFlg = NAS_MML_IsUsimStausValid();
        ulFlg          = NAS_MMC_CheckRoamSettingPlmnSelection_SysCfg(pstSysCfgMsg);
        if ( (VOS_TRUE == ulUsimStausFlg)
          && (VOS_TRUE == ulFlg) )
        {
            ulNeedSyscfgPlmnSrch = VOS_TRUE;
            /*手动模式时,syscfg需要触发搜网时,需要将当前正常服务的plmn和接入技术保存一下作为用户重选的plmn id和接入技术 */
            enPlmnSelectionMode = NAS_MMC_GetPlmnSelectionMode();
            if ( NAS_MMC_PLMN_SELECTION_MODE_MANUAL == enPlmnSelectionMode)
            {
                /* 保存指定搜网前驻留的PlmnID及接入技术 */
                NAS_MMC_SaveUserReselPlmnInfo();
            }
        }

        /* 保存用户设置的漫游信息 */
        NAS_MML_SetRoamCapability(pstSysCfgMsg->enRoamCapability);

        /* 通知上层状态机SYSCFG状态机运行结果，syscfg设置成功 */
        NAS_MMC_SndSysCfgRslt(VOS_TRUE, ulNeedSyscfgPlmnSrch);

        /* 退出SYSCFG状态机 */
        NAS_MMC_FSM_QuitFsmL2();

        return VOS_TRUE;
    }


    /* 保存入口消息 */
    NAS_MMC_SaveCurEntryMsg(ulEventType, pstMsg);


    /* 根据当前模信息，完成向接入层下发SYSCFG顺序表的设置  */
    NAS_MMC_SetSysCfgSendingOrder_SysCfg( NAS_MMC_GetDestModeRat_SysCfg(pstSysCfgMsg) );

    /* 判断SYSCFG设置是否需要发起搜网 */
    ulNeedSyscfgPlmnSrch = NAS_MMC_IsPlmnSelectionNeeded_SysCfg(pstSysCfgMsg);

    /* 保存搜网信息到状态机上下文中 */
    NAS_MMC_SetPlmnSearchFlag_SysCfg(ulNeedSyscfgPlmnSrch);

    /*手动模式时,syscfg需要触发搜网时,需要将当前正常服务的plmn和接入技术保存一下作为用户重选的plmn id和接入技术 */
    enPlmnSelectionMode = NAS_MMC_GetPlmnSelectionMode();
    if ( ( NAS_MMC_PLMN_SELECTION_MODE_MANUAL == enPlmnSelectionMode)
      && (VOS_TRUE == ulNeedSyscfgPlmnSrch))
    {
        /* 保存指定搜网前驻留的PlmnID及接入技术 */
        NAS_MMC_SaveUserReselPlmnInfo();
    }

    /* 保持syscfg设置前的接入技术和优先级 */
    NAS_MMC_SetPrePrioRatList_SysCfg(pstPrePrioRatList);

    /* 赋值用户设置的接入技术优先级 */
    PS_MEM_CPY(&stSyscfgPrioRatList,
               &(pstSysCfgMsg->stRatPrioList),
               sizeof(NAS_MML_PLMN_RAT_PRIO_STRU) );
    NAS_MML_SetMsSysCfgPrioRatList(&stSyscfgPrioRatList);

    /* 获取当前模的信令链接存在信息 */
    ulRrcConnExistFlag   = NAS_MML_IsRrcConnExist();

    if ( (VOS_TRUE == ulNeedSyscfgPlmnSrch) && (VOS_FALSE == ulRrcConnExistFlag) )
    {
        /* 向GMM发送搜网指示 */
        NAS_MMC_SndGmmPlmnSchInit();

        /* 向MM发送搜网指示 */
        NAS_MMC_SndMmPlmnSchInit();
    }

    /* 当前不需要搜网或不存在信令链接 */
    if ( (VOS_FALSE == ulNeedSyscfgPlmnSrch)
      || (VOS_FALSE == ulRrcConnExistFlag) )
    {
        /* 获取需要设置SYSCFG的接入技术 */
        enCurrRat             = NAS_MMC_GetNextSettingRat_SysCfg();
        NAS_MMC_SetRatModeSysCfgReq_SysCfg(enCurrRat, pstSysCfgMsg);

        return VOS_TRUE;
    }

    /* 当前SYSCFG设置完后需要搜网，且当前有信令链接存在，则进行如下设置 */
#if (FEATURE_ON == FEATURE_LTE)

    /* 取得当前的接入模式 */
    enCurrRat            = NAS_MML_GetCurrNetRatType();
    if ( NAS_MML_NET_RAT_TYPE_LTE == enCurrRat )
    {
        /* 当前为L模，向lmm下发链接释放请求  */
        NAS_MMC_SndLmmRelReq();

        NAS_MMC_SetRelRequestFlag_SysCfg(VOS_TRUE);

        /* 进行SYSCFG状态机的子状态的迁移:迁移到等待链接释放子状态 */
        NAS_MMC_FSM_SetCurrState(NAS_MMC_SYSCFG_STA_WAIT_EPS_CONN_REL_IND);

        /* 启动等待L模回复定时器 */
        NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_EPS_CONN_REL_IND, TI_NAS_MMC_WAIT_EPS_CONN_REL_IND_LEN);

        return VOS_TRUE;
    }
#endif

    /* 当前在GU模下，主动请求释放链接 */
    NAS_MMC_SndMmRelReq();
    NAS_MMC_SndGmmRelReq();

    NAS_MMC_SetSpecPlmnSearchState(NAS_MMC_SPEC_PLMN_SEARCH_RUNNING);

    NAS_MMC_SetRelRequestFlag_SysCfg(VOS_TRUE);

    /* 进行SYSCFG状态机的子状态的迁移:迁移到等待链接释放子状态 */
    NAS_MMC_FSM_SetCurrState(NAS_MMC_SYSCFG_STA_WAIT_RRC_CONN_REL_IND);

    /* 启动等待回复定时器 */
    NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_RRC_CONN_REL, TI_NAS_MMC_WAIT_RRC_CONN_REL_LEN);

    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvGasSysCfgCnf_SysCfg_WaitGasSysCfgCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{

    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgMsg          = VOS_NULL_PTR;

    NAS_MMC_ENTRY_MSG_STRU             *pstEntryMsg           = VOS_NULL_PTR;
    RRMM_SYS_CFG_CNF_STRU              *pstSysCfgCnf          = VOS_NULL_PTR;
    VOS_UINT32                          ulNeedSyscfgPlmnSrch;
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enNextRat;

    NAS_MML_PLMN_RAT_PRIO_STRU         *pstPrePrioRatList;

    /* 停止等待GAS的SYSCFG回复定时器 */
    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_GAS_SYSCFG_CNF);

    /* 若syscfg设置失败，进行错误打印，退出SYSCFG状态机 */
    pstSysCfgCnf          = (RRMM_SYS_CFG_CNF_STRU *)pstMsg;
    if ( RRMM_SYS_CFG_RESULT_FAILURE == pstSysCfgCnf->ulResult)
    {
        NAS_ERROR_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvGasSysCfgCnf_SysCfg_WaitGasSysCfgCnf:ERROR:SYSCFG SET FAIL!");

        /* 向MMA回复SYSCFG设置失败消息 */
        NAS_MMC_SndMmaSysCfgCnf(MMA_MMC_SYS_CFG_SET_FAILURE_OTHER);

        /* syscfg设置失败需要恢复之前的接入技术和优先级 */
        pstPrePrioRatList = NAS_MMC_GetPrePrioRatList_SysCfg();

        NAS_MML_SetMsSysCfgPrioRatList(pstPrePrioRatList);

        /* 通知上层状态机SYSCFG状态机运行结果，syscfg设置失败，不需要搜网 */
        NAS_MMC_SndSysCfgRslt(VOS_FALSE, VOS_FALSE);

        /* 退出SYSCFG状态机 */
        NAS_MMC_FSM_QuitFsmL2();

        return VOS_TRUE;
    }

    /* 获取syscfg状态机入口消息信息 */
    pstEntryMsg           = NAS_MMC_GetCurrEntryMsg();

    pstSysCfgMsg          = (MMA_MMC_SYS_CFG_SET_REQ_STRU *)(pstEntryMsg->aucEntryMsgBuffer);

    /* 未完成SYSCFG的所有模式设置，向接入模发送SYSCFG设置请求 */
    enNextRat             = NAS_MMC_GetNextSettingRat_SysCfg();
    if (NAS_MML_NET_RAT_TYPE_BUTT != enNextRat)
    {
        NAS_MMC_SetRatModeSysCfgReq_SysCfg(enNextRat, pstSysCfgMsg);
        return VOS_TRUE;
    }

    /* 完成了所有模式的SYSCFG设置,保存SYSCFG设置内容信息 */
    NAS_MMC_SaveUserSyscfgInfo_SysCfg(pstSysCfgMsg);

    /* SYSCFG设置完成后，进行小区信息的更新 */
    NAS_MMC_UpdateCellInfo_SysCfg();

    /* 向MMA回复SYSCFG设置成功原语 */
    NAS_MMC_SndMmaSysCfgCnf(MMA_MMC_SYS_CFG_SET_SUCCESS);

    /* 若需要发起搜网，发出由SYSCFG引起的内部搜网信息 */
    ulNeedSyscfgPlmnSrch  = NAS_MMC_GetPlmnSearchFlag_SysCfg();

    /* 通知上层状态机SYSCFG状态机运行结果，syscfg设置成功 */
    NAS_MMC_SndSysCfgRslt(VOS_TRUE, ulNeedSyscfgPlmnSrch);

    /* 退出SYSCFG状态机 */
    NAS_MMC_FSM_QuitFsmL2();

    return VOS_TRUE;
}




VOS_UINT32  NAS_MMC_RcvGasSuspendInd_SysCfg_WaitGasSysCfgCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    /* 向接入层回复挂起失败 */
    NAS_MMC_SndAsSuspendRsp(RRC_NAS_SUSPEND_FAILURE, UEPS_PID_GAS);

    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvGasSysCfgCnfExpired_SysCfg_WaitGasSysCfgCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    NAS_MML_PLMN_RAT_PRIO_STRU         *pstPrePrioRatList;

    /* 打印定时器超时异常LOG */
    NAS_ERROR_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvGasSysCfgCnfExpired_SysCfg_WaitGasSysCfgCnf():TI_NAS_MMC_WAIT_GAS_SYSCFG_CNF timeout");

    /* 向MMA回复SYSCFG设置失败 */
    NAS_MMC_SndMmaSysCfgCnf(MMA_MMC_SYS_CFG_SET_FAILURE_OTHER);


    /* syscfg设置失败需要恢复之前的接入技术和优先级 */
    pstPrePrioRatList = NAS_MMC_GetPrePrioRatList_SysCfg();

    NAS_MML_SetMsSysCfgPrioRatList(pstPrePrioRatList);

    /* 通知上层状态机SYSCFG状态机运行结果,syscfg设置失败 */
    NAS_MMC_SndSysCfgRslt(VOS_FALSE, VOS_FALSE);

    /* 退出SYSCFG状态机 */
    NAS_MMC_FSM_QuitFsmL2();

    return VOS_TRUE;
}
VOS_UINT32 NAS_MMC_RcvWasSysCfgCnf_SysCfg_WaitWasSysCfgCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{

    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgMsg          = VOS_NULL_PTR;

    NAS_MMC_ENTRY_MSG_STRU             *pstEntryMsg           = VOS_NULL_PTR;
    RRMM_SYS_CFG_CNF_STRU              *pstSysCfgCnf          = VOS_NULL_PTR;
    VOS_UINT32                          ulNeedSyscfgPlmnSrch;
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enNextRat;

    NAS_MML_PLMN_RAT_PRIO_STRU         *pstPrePrioRatList;

    /* 停止等待WAS的SYSCFG回复定时器 */
    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_WAS_SYSCFG_CNF);

    /* 若syscfg设置失败，进行错误打印，退出SYSCFG状态机 */
    pstSysCfgCnf          = (RRMM_SYS_CFG_CNF_STRU *)pstMsg;
    if ( RRMM_SYS_CFG_RESULT_FAILURE == pstSysCfgCnf->ulResult)
    {
        NAS_ERROR_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvWasSysCfgCnf_SysCfg_WaitWasSysCfgCnf:ERROR:SYSCFG SET FAIL!");

        /* 向MMA回复SYSCFG设置失败消息 */
        NAS_MMC_SndMmaSysCfgCnf(MMA_MMC_SYS_CFG_SET_FAILURE_OTHER);

        /* syscfg设置失败需要恢复之前的接入技术和优先级 */
        pstPrePrioRatList = NAS_MMC_GetPrePrioRatList_SysCfg();

        NAS_MML_SetMsSysCfgPrioRatList(pstPrePrioRatList);

        /* 通知上层状态机SYSCFG状态机运行结果，syscfg设置失败，不需要搜网 */
        NAS_MMC_SndSysCfgRslt(VOS_FALSE, VOS_FALSE);

        /* 退出SYSCFG状态机 */
        NAS_MMC_FSM_QuitFsmL2();

        return VOS_TRUE;
    }

    /* 获取syscfg状态机入口消息信息 */
    pstEntryMsg           = NAS_MMC_GetCurrEntryMsg();

    pstSysCfgMsg          = (MMA_MMC_SYS_CFG_SET_REQ_STRU *)(pstEntryMsg->aucEntryMsgBuffer);

    /* 获取需要设置SYSCFG的下一个接入模 */
    enNextRat             = NAS_MMC_GetNextSettingRat_SysCfg();
    if (NAS_MML_NET_RAT_TYPE_BUTT != enNextRat)
    {
        NAS_MMC_SetRatModeSysCfgReq_SysCfg(enNextRat, pstSysCfgMsg);
        return VOS_TRUE;
    }

    /* 完成了所有模式的SYSCFG设置,保存SYSCFG设置内容信息 */
    NAS_MMC_SaveUserSyscfgInfo_SysCfg(pstSysCfgMsg);

    /* SYSCFG设置完成后，进行小区信息的更新 */
    NAS_MMC_UpdateCellInfo_SysCfg();

    /* 向MMA回复SYSCFG设置成功原语 */
    NAS_MMC_SndMmaSysCfgCnf(MMA_MMC_SYS_CFG_SET_SUCCESS);

    /* 若需要发起搜网，发出由SYSCFG引起的内部搜网信息 */
    ulNeedSyscfgPlmnSrch = NAS_MMC_GetPlmnSearchFlag_SysCfg();

    /* 通知上层状态机SYSCFG状态机运行结果，syscfg设置成功 */
    NAS_MMC_SndSysCfgRslt(VOS_TRUE, ulNeedSyscfgPlmnSrch);

    /* 退出SYSCFG状态机 */
    NAS_MMC_FSM_QuitFsmL2();

    return VOS_TRUE;
}



VOS_UINT32  NAS_MMC_RcvWasSuspendInd_SysCfg_WaitWasSysCfgCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    /* 向接入层回复挂起失败 */
    NAS_MMC_SndAsSuspendRsp(RRC_NAS_SUSPEND_FAILURE, WUEPS_PID_WRR);

    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvWasSysCfgCnfExpired_SysCfg_WaitWasSysCfgCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    NAS_MML_PLMN_RAT_PRIO_STRU         *pstPrePrioRatList;

    /* 打印定时器超时异常LOG */
    NAS_ERROR_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvWasSysCfgCnfExpired_SysCfg_WaitWasSysCfgCnf():TI_NAS_MMC_WAIT_GAS_SYSCFG_CNF timeout");

    /* 向MMA回复SYSCFG设置失败 */
    NAS_MMC_SndMmaSysCfgCnf(MMA_MMC_SYS_CFG_SET_FAILURE_OTHER);

    /* syscfg设置失败需要恢复之前的接入技术和优先级 */
    pstPrePrioRatList = NAS_MMC_GetPrePrioRatList_SysCfg();

    NAS_MML_SetMsSysCfgPrioRatList(pstPrePrioRatList);

    /* 通知上层状态机SYSCFG状态机运行结果,syscfg设置失败 */
    NAS_MMC_SndSysCfgRslt(VOS_FALSE, VOS_FALSE);

    /* 退出SYSCFG状态机 */
    NAS_MMC_FSM_QuitFsmL2();

    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvGmmSignalingStatusInd_SysCfg_WaitRrcConnRelInd(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgMsg    = VOS_NULL_PTR;

    NAS_MMC_ENTRY_MSG_STRU             *pstEntryMsg     = VOS_NULL_PTR;
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enNextRat;
    VOS_UINT32                          ulRrcConnExistFlag;

    /* 获取SYSCFG状态机的入口消息信息 */
    pstEntryMsg         = NAS_MMC_GetCurrEntryMsg();

    pstSysCfgMsg        = (MMA_MMC_SYS_CFG_SET_REQ_STRU*)(pstEntryMsg->aucEntryMsgBuffer);

    /* 判断信令链接是否已经完成释放 */
    ulRrcConnExistFlag  = NAS_MML_IsRrcConnExist();

    if ( VOS_TRUE == ulRrcConnExistFlag )
    {
        /* 信令链接未释放完成，继续等待信令链接释放消息 */
        return VOS_TRUE;
    }

    /* 信令链接完成释放,停定时器 */
    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_RRC_CONN_REL);


    /* 取得目标模的接入技术，并发送SYSCFG请求 */
    enNextRat           = NAS_MMC_GetNextSettingRat_SysCfg();
    NAS_MMC_SetRatModeSysCfgReq_SysCfg(enNextRat, pstSysCfgMsg);

    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvMmConnInfoInd_SysCfg_WaitRrcConnRelInd(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgMsg = VOS_NULL_PTR;

    NAS_MMC_ENTRY_MSG_STRU             *pstEntryMsg  = VOS_NULL_PTR;
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enNextRat;
    VOS_UINT32                          ulRrcConnExistFlag;

    /* 获取SYSCFG状态机的入口消息信息 */
    pstEntryMsg         = NAS_MMC_GetCurrEntryMsg();

    pstSysCfgMsg        = (MMA_MMC_SYS_CFG_SET_REQ_STRU*)(pstEntryMsg->aucEntryMsgBuffer);

    /* 判断信令链接是否已经完成释放 */
    ulRrcConnExistFlag  = NAS_MML_IsRrcConnExist();

    if ( VOS_TRUE == ulRrcConnExistFlag )
    {
        /* 信令链接未释放完成，继续等待信令链接释放消息 */
        return VOS_TRUE;
    }

    /* 信令链接完成释放,停定时器 */
    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_RRC_CONN_REL);


    /* 取得目标模的接入技术，并发送SYSCFG请求 */
    enNextRat           = NAS_MMC_GetNextSettingRat_SysCfg();
    NAS_MMC_SetRatModeSysCfgReq_SysCfg(enNextRat, pstSysCfgMsg);

    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvMmcMmRelInd_SysCfg_WaitRrcConnRelInd(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgMsg = VOS_NULL_PTR;

    NAS_MMC_ENTRY_MSG_STRU             *pstEntryMsg  = VOS_NULL_PTR;
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enNextRat;
    VOS_UINT32                          ulRrcConnExistFlag;

    /* 获取SYSCFG状态机的入口消息信息 */
    pstEntryMsg  = NAS_MMC_GetCurrEntryMsg();

    pstSysCfgMsg = (MMA_MMC_SYS_CFG_SET_REQ_STRU*)(pstEntryMsg->aucEntryMsgBuffer);

    /* 判断信令链接是否已经完成释放 */
    ulRrcConnExistFlag  = NAS_MML_IsRrcConnExist();

    if ( VOS_TRUE == ulRrcConnExistFlag )
    {
        /* 信令链接未释放完成，继续等待信令链接释放消息 */
        return VOS_TRUE;
    }

    /* 信令链接完成释放,停定时器 */
    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_RRC_CONN_REL);


    /* 取得目标模的接入技术，并发送SYSCFG请求 */
    enNextRat           = NAS_MMC_GetNextSettingRat_SysCfg();
    NAS_MMC_SetRatModeSysCfgReq_SysCfg(enNextRat, pstSysCfgMsg);

    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvRrMmRelInd_SysCfg_WaitRrcConnRelInd(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgMsg = VOS_NULL_PTR;

    NAS_MMC_ENTRY_MSG_STRU             *pstEntryMsg  = VOS_NULL_PTR;
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enNextRat;
    VOS_UINT32                          ulRrcConnExistFlag;

    /* 获取SYSCFG状态机的入口消息信息 */
    pstEntryMsg  = NAS_MMC_GetCurrEntryMsg();

    pstSysCfgMsg = (MMA_MMC_SYS_CFG_SET_REQ_STRU*)(pstEntryMsg->aucEntryMsgBuffer);

    /* 判断信令链接是否已经完成释放 */
    ulRrcConnExistFlag  = NAS_MML_IsRrcConnExist();

    if ( VOS_TRUE == ulRrcConnExistFlag )
    {
        /* 信令链接未释放完成，继续等待信令链接释放消息 */
        return VOS_TRUE;
    }

    /* 信令链接完成释放,停定时器 */
    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_RRC_CONN_REL);


    /* 取得目标模的接入技术，并发送SYSCFG请求 */
    enNextRat           = NAS_MMC_GetNextSettingRat_SysCfg();
    NAS_MMC_SetRatModeSysCfgReq_SysCfg(enNextRat, pstSysCfgMsg);

    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvGmmTbfRelInd_SysCfg_WaitRrcConnRelInd(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgMsg = VOS_NULL_PTR;

    NAS_MMC_ENTRY_MSG_STRU             *pstEntryMsg  = VOS_NULL_PTR;
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enNextRat;
    VOS_UINT32                          ulRrcConnExistFlag;

    /* 获取SYSCFG状态机的入口消息信息 */
    pstEntryMsg        = NAS_MMC_GetCurrEntryMsg();

    pstSysCfgMsg       = (MMA_MMC_SYS_CFG_SET_REQ_STRU*)(pstEntryMsg->aucEntryMsgBuffer);

    /* 判断信令链接是否已经完成释放 */
    ulRrcConnExistFlag = NAS_MML_IsRrcConnExist();

    if ( VOS_TRUE == ulRrcConnExistFlag )
    {
        /* 信令链接未释放完成，继续等待信令链接释放消息 */
        return VOS_TRUE;
    }

    /* 信令链接完成释放,停定时器 */
    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_RRC_CONN_REL);


    /* 取得目标模的接入技术，并发送SYSCFG请求 */
    enNextRat           = NAS_MMC_GetNextSettingRat_SysCfg();
    NAS_MMC_SetRatModeSysCfgReq_SysCfg(enNextRat, pstSysCfgMsg);


    return VOS_TRUE;
}



VOS_UINT32  NAS_MMC_RcvWasSuspendInd_SysCfg_WaitRrcConnRelInd(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    /* 向接入层回复挂起失败 */
    NAS_MMC_SndAsSuspendRsp(RRC_NAS_SUSPEND_FAILURE, WUEPS_PID_WRR);

    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvGasSuspendInd_SysCfg_WaitRrcConnRelInd(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    /* 向接入层回复挂起失败 */
    NAS_MMC_SndAsSuspendRsp(RRC_NAS_SUSPEND_FAILURE, UEPS_PID_GAS);

    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvTiWaitRrcConnRelExpired_SysCfg_WaitRrcConnRelInd(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgMsg = VOS_NULL_PTR;

    NAS_MMC_ENTRY_MSG_STRU             *pstEntryMsg  = VOS_NULL_PTR;
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enNextRat;

    /* 打印异常信息 */
    NAS_WARNING_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvTiWaitRrcConnRelExpired_SysCfg_WaitRrcConnRelInd:TI_NAS_MMC_WAIT_RRC_CONN_REL timeout");

    /* 获取SYSCFG状态机的入口消息信息 */
    pstEntryMsg  = NAS_MMC_GetCurrEntryMsg();

    pstSysCfgMsg = (MMA_MMC_SYS_CFG_SET_REQ_STRU*)(pstEntryMsg->aucEntryMsgBuffer);

    enNextRat    = NAS_MML_NET_RAT_TYPE_BUTT;

    /* 如果信令连接存在, 而且是主动释放连接,则进行搜网动作 */
    if (VOS_TRUE == NAS_MMC_GetRelRequestFlag_SysCfg())
    {
        NAS_MMC_SetRelRequestFlag_SysCfg(VOS_FALSE);

        /* 取得目标模的接入技术，并发送SYSCFG请求 */
        enNextRat  = NAS_MMC_GetNextSettingRat_SysCfg();

        /* 向当前接入模式发送SYSCFG请求 */
        NAS_MMC_SetRatModeSysCfgReq_SysCfg(enNextRat, pstSysCfgMsg);

        /* 向MM、GMM发送搜网指示 */
        NAS_MMC_SndGmmPlmnSchInit();
        NAS_MMC_SndMmPlmnSchInit();

        return VOS_TRUE;
    }

    /* 发送主动释放请求到MM、GMM，重新启动等待连接释放定时器 */
    NAS_MMC_SetRelRequestFlag_SysCfg(VOS_TRUE);
    NAS_MMC_SetSpecPlmnSearchState(NAS_MMC_SPEC_PLMN_SEARCH_RUNNING);
    NAS_MMC_SndMmRelReq();
    NAS_MMC_SndGmmRelReq();

    NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_RRC_CONN_REL, TI_NAS_MMC_WAIT_RRC_CONN_REL_LEN);

    return VOS_TRUE;
}


#if (FEATURE_ON == FEATURE_LTE)
VOS_UINT32  NAS_MMC_RcvLmmSysCfgCnf_SysCfg_WaitLmmSysCfgCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgMsg          = VOS_NULL_PTR;

    NAS_MMC_ENTRY_MSG_STRU             *pstEntryMsg           = VOS_NULL_PTR;
    LMM_MMC_SYS_CFG_CNF_STRU           *pstSysCfgCnf          = VOS_NULL_PTR;
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enNextRat;
    VOS_UINT32                          ulNeedSyscfgPlmnSrch;

    NAS_MML_PLMN_RAT_PRIO_STRU         *pstPrePrioRatList;

    /* 停止等待LMM的SYSCFG回复定时器 */
    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_LMM_SYSCFG_CNF);

    /* 若syscfg设置失败，进行错误打印，退出SYSCFG状态机 */
    pstSysCfgCnf          = (LMM_MMC_SYS_CFG_CNF_STRU *)pstMsg;
    if ( MMC_LMM_FAIL == pstSysCfgCnf->ulRst)
    {
        NAS_ERROR_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvLmmSysCfgCnf_SysCfg_WaitLmmSysCfgCnf:ERROR:SYSCFG SET FAIL!");

        /* 向MMA回复SYSCFG设置失败消息 */
        NAS_MMC_SndMmaSysCfgCnf(MMA_MMC_SYS_CFG_SET_FAILURE_OTHER);

        /* syscfg设置失败需要恢复之前的接入技术和优先级 */
        pstPrePrioRatList = NAS_MMC_GetPrePrioRatList_SysCfg();

        NAS_MML_SetMsSysCfgPrioRatList(pstPrePrioRatList);

        /* 通知上层状态机SYSCFG状态机运行结果，syscfg设置失败，不需要搜网 */
        NAS_MMC_SndSysCfgRslt(VOS_FALSE, VOS_FALSE);

        /* 退出SYSCFG状态机 */
        NAS_MMC_FSM_QuitFsmL2();

        return VOS_TRUE;
    }

    /* 获取syscfg状态机入口消息信息 */
    pstEntryMsg  = NAS_MMC_GetCurrEntryMsg();

    pstSysCfgMsg = (MMA_MMC_SYS_CFG_SET_REQ_STRU *)(pstEntryMsg->aucEntryMsgBuffer);


    /* 未完成SYSCFG的所有模式设置，向接入模发送SYSCFG设置请求 */
    enNextRat             = NAS_MMC_GetNextSettingRat_SysCfg();
    if (NAS_MML_NET_RAT_TYPE_BUTT != enNextRat)
    {
        NAS_MMC_SetRatModeSysCfgReq_SysCfg(enNextRat, pstSysCfgMsg);

        return VOS_TRUE;
    }

    /* 完成了所有模式的SYSCFG设置,保存SYSCFG设置内容信息 */
    NAS_MMC_SaveUserSyscfgInfo_SysCfg(pstSysCfgMsg);

    /* SYSCFG设置完成后，进行小区信息的更新 */
    NAS_MMC_UpdateCellInfo_SysCfg();

    /* 向MMA回复SYSCFG设置成功原语 */
    NAS_MMC_SndMmaSysCfgCnf(MMA_MMC_SYS_CFG_SET_SUCCESS);

    /* 若需要发起搜网，发出由SYSCFG引起的内部搜网信息 */
    ulNeedSyscfgPlmnSrch  = NAS_MMC_GetPlmnSearchFlag_SysCfg();

    /* 通知上层状态机SYSCFG状态机运行结果，syscfg设置成功 */
    NAS_MMC_SndSysCfgRslt(VOS_TRUE, ulNeedSyscfgPlmnSrch);

    /* 退出SYSCFG状态机 */
    NAS_MMC_FSM_QuitFsmL2();


    return VOS_TRUE;
}


VOS_UINT32  NAS_MMC_RcvLmmSuspendInd_SysCfg_WaitLmmSysCfgCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    /* 向LMM回复挂起失败 */
    NAS_MMC_SndLmmSuspendRsp(MMC_LMM_FAIL);

    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvLmmSysCfgCnfExpired_SysCfg_WaitLmmSysCfgCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    NAS_MML_PLMN_RAT_PRIO_STRU         *pstPrePrioRatList;

    /* 打印定时器超时异常LOG */
    NAS_ERROR_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvLmmSysCfgCnfExpired_SysCfg_WaitLmmSysCfgCnf():TI_NAS_MMC_WAIT_LMM_SYSCFG_CNF timeout");

    /* 向MMA回复SYSCFG设置失败 */
    NAS_MMC_SndMmaSysCfgCnf(MMA_MMC_SYS_CFG_SET_FAILURE_OTHER);

    /* syscfg设置失败需要恢复之前的接入技术和优先级 */
    pstPrePrioRatList = NAS_MMC_GetPrePrioRatList_SysCfg();

    NAS_MML_SetMsSysCfgPrioRatList(pstPrePrioRatList);

    /* 通知上层状态机SYSCFG状态机运行结果,syscfg设置失败 */
    NAS_MMC_SndSysCfgRslt(VOS_FALSE, VOS_FALSE);

    /* 退出SYSCFG状态机 */
    NAS_MMC_FSM_QuitFsmL2();

    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvLmmMmcStatusInd_SysCfg_WaitEpsConnRelInd(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{

    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgMsg       = VOS_NULL_PTR;

    NAS_MMC_ENTRY_MSG_STRU             *pstEntryMsg        = VOS_NULL_PTR;
    LMM_MMC_STATUS_IND_STRU            *pstLmmStatusIndMsg = VOS_NULL_PTR;

    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enNextRat;

    pstLmmStatusIndMsg = (LMM_MMC_STATUS_IND_STRU*)pstMsg;

    /* 获取SYSCFG状态机的入口消息信息 */
    pstEntryMsg  = NAS_MMC_GetCurrEntryMsg();

    pstSysCfgMsg = (MMA_MMC_SYS_CFG_SET_REQ_STRU*)(pstEntryMsg->aucEntryMsgBuffer);

    if ( VOS_FALSE == pstLmmStatusIndMsg->bitOpConnState)
    {
        NAS_NORMAL_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvLmmMmcStatusInd_SysCfg_WaitEpsConnRelInd:bitOpConnState IS VOS_FALSE");
        return VOS_TRUE;
    }

    /* 更新LMM的链接状态 */
    switch (pstLmmStatusIndMsg->ulConnState)
    {
        case MMC_LMM_CONN_ESTING:
        case MMC_LMM_CONNECTED_SIG:
            NAS_MML_SetEpsSigConnStatusFlg(VOS_TRUE);
            NAS_MML_SetEpsServiceConnStatusFlg(VOS_FALSE);
            break;

        case MMC_LMM_CONNECTED_DATA:
            NAS_MML_SetEpsServiceConnStatusFlg(VOS_TRUE);
            break;

        case MMC_LMM_CONN_IDLE:
            NAS_MML_SetEpsSigConnStatusFlg(VOS_FALSE);
            NAS_MML_SetEpsServiceConnStatusFlg(VOS_FALSE);
            break;

        default:
            break;
    }

    /* 如果存在信令连接，则继续等待 */
    if (VOS_TRUE == NAS_MML_IsRrcConnExist())
    {
        return VOS_TRUE;
    }

    /* 停止等待链接释放定时器 */
    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_EPS_CONN_REL_IND);


    /* 取得目标模的接入技术，并发送SYSCFG请求 */
    enNextRat           = NAS_MMC_GetNextSettingRat_SysCfg();
    NAS_MMC_SetRatModeSysCfgReq_SysCfg(enNextRat, pstSysCfgMsg);

    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvTiWaitEpsConnRelIndExpired_SysCfg_WaitEpsConnRelInd(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgMsg = VOS_NULL_PTR;

    NAS_MMC_ENTRY_MSG_STRU             *pstEntryMsg  = VOS_NULL_PTR;

    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enNextRat;

    /* 打印异常信息 */
    NAS_WARNING_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvTiWaitEpsConnRelIndExpired_SysCfg_WaitEpsConnRelInd:TI_NAS_MMC_WAIT_EPS_CONN_REL_IND timeout");

    /* 获取SYSCFG状态机的入口消息信息 */
    pstEntryMsg  = NAS_MMC_GetCurrEntryMsg();

    pstSysCfgMsg = (MMA_MMC_SYS_CFG_SET_REQ_STRU*)(pstEntryMsg->aucEntryMsgBuffer);
    enNextRat    = NAS_MML_NET_RAT_TYPE_BUTT;

    /* 如果信令连接存在, 而且是主动释放连接,则进行搜网动作 */
    if (VOS_TRUE == NAS_MMC_GetRelRequestFlag_SysCfg())
    {
        NAS_MMC_SetRelRequestFlag_SysCfg(VOS_FALSE);


        /* 取得目标模的接入技术，并发送SYSCFG请求 */
        enNextRat           = NAS_MMC_GetNextSettingRat_SysCfg();
        NAS_MMC_SetRatModeSysCfgReq_SysCfg(enNextRat, pstSysCfgMsg);

       /* 向当前接入模式发送SYSCFG请求 */
       NAS_MMC_SetRatModeSysCfgReq_SysCfg(enNextRat, pstSysCfgMsg);

       /* 向MM、GMM发送搜网指示 */
       NAS_MMC_SndGmmPlmnSchInit();
       NAS_MMC_SndMmPlmnSchInit();

       return VOS_TRUE;
    }

    /* 发送主动释放请求到LMM，重新启动等待连接释放定时器 */
    NAS_MMC_SetRelRequestFlag_SysCfg(VOS_TRUE);
    NAS_MMC_SndLmmRelReq();
    NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_EPS_CONN_REL_IND, TI_NAS_MMC_WAIT_EPS_CONN_REL_IND_LEN);


    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvLmmSuspendInd_SysCfg_WaitEpsConnRelInd(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    /* 向LMM回复挂起失败 */
    NAS_MMC_SndLmmSuspendRsp(MMC_LMM_FAIL);

    return VOS_TRUE;
}

#endif
VOS_UINT32  NAS_MMC_IsPlmnSelectionNeeded_SysCfg(
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgSetParm
)
{
    VOS_UINT32                          ulFlg;

    /* 判断SYSCFG对接入优先级的设置是否需要导致搜网:
       若当前的接入技术被设置为无效，则需要搜网 */
    ulFlg           = NAS_MMC_IsCurrentRatSetted_SysCfg(pstSysCfgSetParm);
    if ( VOS_FALSE  == ulFlg )
    {
        return VOS_TRUE;
    }

    /* 判断SYSCFG对接BAND的设置是否需要导致搜网 */
    ulFlg           = NAS_MMC_IsCurrentBandSetted_SysCfg(pstSysCfgSetParm);
    if ( VOS_FALSE  == ulFlg )
    {
        return VOS_TRUE;
    }

    /* 判断SYSCFG对ROAM特性的设置是否需要导致搜网 */
    ulFlg           = NAS_MMC_CheckRoamSettingPlmnSelection_SysCfg(pstSysCfgSetParm);
    if ( VOS_TRUE  == ulFlg )
    {
        return VOS_TRUE;
    }

    /* SYSCFG设置不需要导致搜网 */
    return VOS_FALSE;
}
VOS_UINT32  NAS_MMC_IsCurrentBandSetted_SysCfg(
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgSetParm
)
{
    NAS_MML_MS_BAND_INFO_STRU          *pstBandInfo         = VOS_NULL_PTR;
#if (FEATURE_ON == FEATURE_LTE)
    LTE_BAND_STRU                       stCurrentLteBand;
    LTE_BAND_STRU                       stSetLteBand;
#endif
    VOS_UINT32                          ulCurrentWcdmaBand;
    VOS_UINT32                          ulSetWcdmaBand;
    VOS_UINT32                          ulCurrentGsmBand;
    VOS_UINT32                          ulSetGsmBand;

    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enCurrNetRatType;

    /* 取得当前的接入技术类型 */
    enCurrNetRatType                    = NAS_MML_GetCurrNetRatType();

    /* 获取当前的频段信息 */
    pstBandInfo                         = NAS_MML_GetCurrBandInfo();
#if (FEATURE_ON == FEATURE_LTE)

    /* 获取当前的LTE的频段 */
    PS_MEM_CPY( &(stCurrentLteBand),
                &(pstBandInfo->stLteBand),
                sizeof(LTE_BAND_STRU) );

#endif

    /* 获取当前的WCDMA的频段 */
    ulCurrentWcdmaBand                  = pstBandInfo->unWcdmaBand.ulBand;

    /* 获取当前的GSM的频段 */
    ulCurrentGsmBand                    = pstBandInfo->unGsmBand.ulBand;

#if (FEATURE_ON == FEATURE_LTE)

    /* 获取当前用户SYSCFG设置的LTE的频段 */
    PS_MEM_CPY( &(stSetLteBand),
                &(pstSysCfgSetParm->stBand.stLteBand),
                sizeof(LTE_BAND_STRU) );
#endif

    /* 获取当前用户SYSCFG设置的WCDMA的频段 */
    ulSetWcdmaBand                      = pstSysCfgSetParm->stBand.unWcdmaBand.ulBand;

    /* 获取当前用户SYSCFG设置的GSM的频段 */
    ulSetGsmBand                        = pstSysCfgSetParm->stBand.unGsmBand.ulBand;

#if (FEATURE_ON == FEATURE_LTE)

    /* 当前LTE的频段在用户设置频段中 */
    if ( (0 != (stCurrentLteBand.aulLteBand[0] & stSetLteBand.aulLteBand[0]))
      || (0 != (stCurrentLteBand.aulLteBand[1] & stSetLteBand.aulLteBand[1])) )
    {
        /* 当前LTE频段在用户设置的相应频段中，表明当前频段有效 */
        return VOS_TRUE;
    }
#endif


    /* 当驻留在TD模式下，由于频段信息肯定是被支持的，直接返回VOS_TRUE */
    if ( (NAS_UTRANCTRL_UTRAN_MODE_TDD == NAS_UTRANCTRL_GetCurrUtranMode())
      && (NAS_MML_NET_RAT_TYPE_WCDMA   == enCurrNetRatType) )
    {
        return VOS_TRUE;
    }


    /* 当前GU频段在用户设置频段中 */
    if ( (0 != (ulCurrentGsmBand & ulSetGsmBand))
      || (0 != (ulCurrentWcdmaBand & ulSetWcdmaBand)) )
    {
        /* 当前GU频段在用户设置的相应频段中，表明当前频段有效 */
        return VOS_TRUE;
    }

    /* 当前频段在不用户设置的相应频段中，表明当前频段无效 */
    return VOS_FALSE;
}



VOS_UINT32  NAS_MMC_IsCurrentRatSetted_SysCfg(
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgSetParm
)
{
    MMA_MMC_NET_RAT_TYPE_ENUM_UINT8     *pstRatPrio = VOS_NULL_PTR;              /* 接入优先级里列表 index表示优先级次序,0最高，2最低 */
    VOS_UINT8                           ucRatNum;                               /* 当前支持的接入技术个数  */
    VOS_UINT32                          i;
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enCurrRat;

    /* 取得当前的接入模式 */
    enCurrRat       = NAS_MML_GetCurrNetRatType();

    /* 取得用户当前设置的接入优先个数 */
    ucRatNum        = pstSysCfgSetParm->stRatPrioList.ucRatNum;

    /* 取得用户当前设置的接入优先级列表 */
    pstRatPrio      = pstSysCfgSetParm->stRatPrioList.aucRatPrio;

    /* 如果当前模在用户设置的接入优先级列表里，返回TRUE,否则返回FALSE */
    for ( i = 0 ; i < ucRatNum; i++ )
    {
        if ( enCurrRat == pstRatPrio[i] )
        {
            return VOS_TRUE;
        }
    }

    return VOS_FALSE;
}



VOS_UINT32  NAS_MMC_CheckRoamSettingPlmnSelection_SysCfg(
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgSetParm
)
{
    NAS_MML_ROAM_CFG_INFO_STRU         *pstRoamCfg          = VOS_NULL_PTR;
    NAS_MML_EQUPLMN_INFO_STRU          *pstEquPlmnInfo      = VOS_NULL_PTR;
    MMA_MMC_ROAM_CAPABILITY_ENUM_UINT8   enSysCfgSetRoamCapability;

    /* 取得用户当前SYSCFG设置的漫游能力信息 */
    enSysCfgSetRoamCapability = pstSysCfgSetParm->enRoamCapability;

    /* 获取当前的漫游配置信息 */
    pstRoamCfg                = NAS_MML_GetRoamCfg();

    /* 漫游特性没有打开时，不需要搜网 */
    if (VOS_FALSE == pstRoamCfg->ucRoamFeatureFlg)
    {
        return VOS_FALSE;
    }

    /* 漫游取值没有改变或者改变但不影响漫游列表范围，不需要搜网 */
    if ( (pstRoamCfg->enRoamCapability == enSysCfgSetRoamCapability)
      || (MMA_MMC_ROAM_UNCHANGE         == enSysCfgSetRoamCapability) )
    {
        return VOS_FALSE;
    }

    /* 国内漫游关闭，国际漫游的改变不需要搜网 */
    if ( ( (NAS_MML_ROAM_NATION_OFF_INTERNATION_ON  == pstRoamCfg->enRoamCapability)
        && (MMA_MMC_ROAM_NATION_OFF_INTERNATION_OFF  == enSysCfgSetRoamCapability) )
      || ( (NAS_MML_ROAM_NATION_OFF_INTERNATION_OFF == pstRoamCfg->enRoamCapability)
        && (MMA_MMC_ROAM_NATION_OFF_INTERNATION_ON   == enSysCfgSetRoamCapability) ) )
    {
        return VOS_FALSE;
    }

    /* 若当前网络不允许漫游，则需要搜网，且需要将EPLMN中不允许漫游的网络清除掉 */
    if ( VOS_FALSE == NAS_MMC_IsCurrentPlmnIdRoamingAllowed_SysCfg(pstSysCfgSetParm) )
    {
        /* 取得当前的EPLMN地址信息 */
        pstEquPlmnInfo = NAS_MML_GetEquPlmnList();

        /* 将EPLMN中的不准许漫游的网络去除 */
        NAS_MML_RemoveRoamPlmnInSrchList( &pstEquPlmnInfo->ucEquPlmnNum,
                                           pstEquPlmnInfo->astEquPlmnAddr );
        return VOS_TRUE;
    }

    return VOS_FALSE;
}


VOS_VOID  NAS_MMC_SaveUserSyscfgInfo_SysCfg(
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgMsg
)
{
    NAS_MML_MS_BAND_INFO_STRU           stMsBand;
    NAS_MML_PLMN_RAT_PRIO_STRU          stPrioRatList;

    /* 赋值用户设置的漫游信息 */
    NAS_MML_SetRoamCapability(pstSysCfgMsg->enRoamCapability);

    /* 赋值用户设置的频段信息 */
    PS_MEM_CPY( &(stMsBand.stLteBand),
                &(pstSysCfgMsg->stBand.stLteBand),
                sizeof(LTE_BAND_STRU) );
    stMsBand.unWcdmaBand.ulBand = pstSysCfgMsg->stBand.unWcdmaBand.ulBand;
    stMsBand.unGsmBand.ulBand   = pstSysCfgMsg->stBand.unGsmBand.ulBand;
    NAS_MML_SetMsSysCfgBand( &stMsBand );

    /* 赋值用户设置的接入技术优先级 */
    PS_MEM_CPY( &stPrioRatList,
                &(pstSysCfgMsg->stRatPrioList),
                sizeof(NAS_MML_PLMN_RAT_PRIO_STRU) );
    NAS_MML_SetMsSysCfgPrioRatList(&stPrioRatList);

    return ;

}
VOS_VOID  NAS_MMC_UpdateCellInfo_SysCfg(VOS_VOID)
{
    NAS_MML_MS_CFG_INFO_STRU           *pstMsCfgInfo        = VOS_NULL_PTR;
    NAS_MML_MS_SYS_CFG_INFO_STRU       *pstCurrMsSysCfgInfo = VOS_NULL_PTR;
    NAS_MML_CAMP_CELL_INFO_STRU        *pstCampCellInfo     = VOS_NULL_PTR;
    VOS_UINT32                          ulGsmOnly;
    VOS_UINT32                          ulWcdmaOnly;


    /* 获取当前的SYSCFG配置信息 */
    pstMsCfgInfo                        = NAS_MML_GetMsCfgInfo();
    pstCurrMsSysCfgInfo                 = &(pstMsCfgInfo->stMsSysCfgInfo);

    /* 由于SYSCFG设置为单模时,MMA模块会更新当前系统模式，而不是待MMC上报SYSTEMINFO时更新，因此
       设置为单模需要清除MMC维护的小区信息，以防止再次设置为双模时MMC不上报SYSTEMINFO */
    ulGsmOnly       = NAS_MML_IsGsmOnlyMode( &(pstCurrMsSysCfgInfo->stPrioRatList) );
    ulWcdmaOnly     = NAS_MML_IsWcdmaOnlyMode( &(pstCurrMsSysCfgInfo->stPrioRatList) );
    if ( (VOS_TRUE == ulGsmOnly)
      || (VOS_TRUE == ulWcdmaOnly) )
    {
        pstCampCellInfo = NAS_MML_GetCampCellInfo();
        pstCampCellInfo->ucCellNum = 0;
    }

    return ;

}



VOS_VOID NAS_MMC_SetRatModeSysCfgReq_SysCfg(
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enCurrRat,
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgMsg
)
{
    /* 根据接入模式，进行SYSCFG的设置 */
    switch ( enCurrRat )
    {

#if (FEATURE_ON == FEATURE_LTE)
        case NAS_MML_NET_RAT_TYPE_LTE:

            /* 向L模下发SYSCFG设置请求 */
            NAS_MMC_SndLmmSyscfgReq(pstSysCfgMsg);
            NAS_MMC_AddSysCfgIndex_SysCfg();

            /* 进行SYSCFG状态机的子状态的迁移 */
            NAS_MMC_FSM_SetCurrState(NAS_MMC_SYSCFG_STA_WAIT_LMM_SYSCFG_CNF);

            /* 启动等待回复定时器 */
            NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_LMM_SYSCFG_CNF, TI_NAS_MMC_WAIT_LMM_SYSCFG_CNF_LEN);
            break;
#endif

        case NAS_MML_NET_RAT_TYPE_WCDMA:

            /* 向W模下发SYSCFG设置请求 */
            NAS_MMC_SndAsSyscfgReq(pstSysCfgMsg, WUEPS_PID_WRR);
            NAS_MMC_AddSysCfgIndex_SysCfg();

            /* 进行SYSCFG状态机的子状态的迁移 */
            NAS_MMC_FSM_SetCurrState(NAS_MMC_SYSCFG_STA_WAIT_WAS_SYSCFG_CNF);

            /* 启动等待回复定时器 */
            NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_WAS_SYSCFG_CNF, TI_NAS_MMC_WAIT_WAS_SYSCFG_CNF_LEN);
            break;

        case NAS_MML_NET_RAT_TYPE_GSM:

            /* 向G模下发SYSCFG设置请求 */
            NAS_MMC_SndAsSyscfgReq(pstSysCfgMsg, UEPS_PID_GAS);
            NAS_MMC_AddSysCfgIndex_SysCfg();

            /* 进行SYSCFG状态机的子状态的迁移 */
            NAS_MMC_FSM_SetCurrState(NAS_MMC_SYSCFG_STA_WAIT_GAS_SYSCFG_CNF);

            /* 启动等待回复定时器 */
            NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_GAS_SYSCFG_CNF, TI_NAS_MMC_WAIT_GAS_SYSCFG_CNF_LEN);
            break;

        default:
            NAS_ERROR_LOG(WUEPS_PID_MMC, "NAS_MMC_SetRatModeSysCfgReq_SysCfg():Invalid net rat type");
            break;
    }

    return;
}




NAS_MML_NET_RAT_TYPE_ENUM_UINT8 NAS_MMC_GetDestModeRat_SysCfg(
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgSetParm
)
{
    VOS_UINT32                          ulFlg;
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enDestModeRat;

    /* 若当前的接入技术被设置为无效，则目标模为SYSCFG设置的优先的接入技术 */
    ulFlg             = NAS_MMC_IsCurrentRatSetted_SysCfg(pstSysCfgSetParm);
    if ( VOS_FALSE    == ulFlg )
    {
        /* 若接入技术的改变导致搜网，目标模为SYSCFG设置的优先的接入技术 */
        enDestModeRat = pstSysCfgSetParm->stRatPrioList.aucRatPrio[0];

        return enDestModeRat;
    }

    /* 否则目标模为当前的接入技术类型，若当前的接入技术为BUTT类型，
       则SYSCFG设置的先后顺序为L->W->G */
    enDestModeRat     = NAS_MML_GetCurrNetRatType();

    return enDestModeRat;
}



VOS_UINT32  NAS_MMC_IsHighPrioRatSrchNeed_SysCfg(
    MMA_MMC_SYS_CFG_SET_REQ_STRU        *pstSysCfgSetParm
)
{
    VOS_UINT8                           ucSetRatNum;                            /* 用户设置的接入技术个数  */
    MMA_MMC_NET_RAT_TYPE_ENUM_UINT8    *pstSetRatPrio = VOS_NULL_PTR;           /* 用户设置的接入优先级里列表 index表示优先级次序,0最高，2最低 */

    NAS_MML_PLMN_RAT_PRIO_STRU         *pstCurPrioRatList = VOS_NULL_PTR;       /* 当前接入优先级里列表 */
    MMA_MMC_NET_RAT_TYPE_ENUM_UINT8    *pstCurRatPrio = VOS_NULL_PTR;           /* 当前接入优先级里列表 index表示优先级次序,0最高，2最低 */
    VOS_UINT8                           ucCurRatNum;                            /* 当前支持的接入技术个数  */
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enCurrRat;


    /* 取得用户设置的接入优先个数 */
    ucSetRatNum        = pstSysCfgSetParm->stRatPrioList.ucRatNum;

    /* 取得用户设置的接入优先级列表 */
    pstSetRatPrio      = pstSysCfgSetParm->stRatPrioList.aucRatPrio;

    pstCurPrioRatList  = NAS_MML_GetMsPrioRatList();

    /* 取得当前的接入模式 */
    enCurrRat          = NAS_MML_GetCurrNetRatType();

    /* 取得当前的接入优先个数 */
    ucCurRatNum        = pstCurPrioRatList->ucRatNum;

    /* 取得当前的接入优先级列表 */
    pstCurRatPrio      = pstCurPrioRatList->aucRatPrio;

    if ( (0 == ucSetRatNum)
      || (0 == ucCurRatNum) )
    {
        return VOS_FALSE;
    }

    /* 触发依据:1、当前的最高优先级接入技术与设置的最高优先级不同 */
    /*          2、当前的RAT不是新设的最高RAT                     */
    if ( (pstSetRatPrio[0] != pstCurRatPrio[0])
      && (enCurrRat != pstSetRatPrio[0]) )
    {
        return  VOS_TRUE;
    }

    /* 默认不需要进行高优先级列表搜网 */
    return VOS_FALSE;
}

#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif


