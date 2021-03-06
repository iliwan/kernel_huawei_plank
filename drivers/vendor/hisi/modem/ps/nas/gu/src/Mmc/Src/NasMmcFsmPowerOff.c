

/*****************************************************************************
  1 头文件包含
*****************************************************************************/
#include "pslog.h"
#include "om.h"
#include "PsTypeDef.h"
#include "NasMmcFsmPoweroffTbl.h"
#include "NasMmcTimerMgmt.h"
#include "NasMmcMain.h"
#if (FEATURE_ON == FEATURE_LTE)
#include "MmcLmmInterface.h"
#endif
#include "NasMmcSndLmm.h"
#include "NasMmcSndInternalMsg.h"
#include "NasMmcCtx.h"
#include "NasMmlCtx.h"
#include "NasMmcSndMm.h"
#include "NasMmcSndMma.h"
#include "NasMmcSndGmm.h"
#include "NasMmcSndGuAs.h"
#include "NasMmcProcNvim.h"
#include "NasComm.h"
#include "NasMmcFsmPowerOff.h"
#include "NasMmlLib.h"
#include "NasMmcComFunc.h"

#include "PsRrmInterface.h"

#include "NasUtranCtrlInterface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define    THIS_FILE_ID        PS_FILE_ID_NAS_MMCFSMPOWEROFF_C

/*****************************************************************************
  2 全局变量
*****************************************************************************/


/*****************************************************************************
  3 宏定义
*****************************************************************************/



VOS_UINT32 NAS_MMC_RcvTafPowerOffReq_PowerOff_Init(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
#if   (FEATURE_ON == FEATURE_LTE)
    MMA_MMC_POWER_OFF_REQ_STRU          *pstPowerOffMsg = VOS_NULL_PTR;
#endif
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enMasterModeRat;

#if   (FEATURE_ON == FEATURE_LTE)
    pstPowerOffMsg = (MMA_MMC_POWER_OFF_REQ_STRU*)pstMsg;
#endif

    /* 保存入口消息 */
    NAS_MMC_SaveCurEntryMsg(ulEventType, pstMsg);

    /* 停止所有定时器 */
    NAS_MMC_StopAllTimer();

#if (FEATURE_ON == FEATURE_DSDS)

    /* 软关机时候需要进行去注册 */
    NAS_MMC_ProcRrmDeRegister_PowerOff();
#endif


    /* 设置当前的主模上下文 */
    NAS_MMC_SetMasterModeRat_PowerOff( NAS_MML_GetCurrNetRatType() );
    /* 获取当前主模 */
    enMasterModeRat = NAS_MMC_GetMasterModeRat_PowerOff();

    /* 主模确定以后，构造从模列表，以便后面给从模发关机请求时使用 */
    NAS_MMC_BuildSlaveModeRatList_PowerOff(enMasterModeRat);

#if   (FEATURE_ON == FEATURE_LTE)

    /* 掉卡引起的关机请求 */
    if ( ( NAS_MML_NET_RAT_TYPE_LTE         ==  enMasterModeRat)
      && ( MMA_MMC_POWER_OFF_CAUSE_SIM_REMOVE ==  pstPowerOffMsg->enCause) )
    {

        /* 通知LMM卡状态发生变化 */
        NAS_MMC_SndLmmUsimStatusReq(MMC_LMM_USIM_INVALID);

        /* 迁移到 NAS_MMC_L2_STA_POWER_OFF:NAS_MMC_POWER_OFF_STA_WAIT_LMM_USIM_STATUS_CNF状态,启动保护定时器*/
        NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_LMM_USIM_STATUS_CNF);

        NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_LMM_USIM_STATUS_CNF,TI_NAS_MMC_WAIT_LMM_USIM_STATUS_CNF_LEN);

        return VOS_TRUE;
    }


    if ( NAS_MML_NET_RAT_TYPE_LTE == enMasterModeRat )
    {

        /* 给LTE发送关机消息 */
        NAS_MMC_SndLmmStopReq();

        /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF,并启动保护定时器 */
        NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF);
        NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF_LEN);

        return VOS_TRUE;
    }

#endif

    /* 通知MM关机，并设置等待MM回复标志 */
    NAS_MMC_SndMmPowerOffReq();

    NAS_MMC_SetMmPowerOffCnfFlag_PowerOff( NAS_MMC_MM_POWER_OFF_FLG );

    /* 通知GMM关机，并设置等待GMM回复标志 */
    NAS_MMC_SndGmmPowerOffReq();

    NAS_MMC_SetMmPowerOffCnfFlag_PowerOff( NAS_MMC_GMM_POWER_OFF_FLG );

    /*****************************************************************
       规避场景:
       PS only的场景下，AT+CFUN=0关机，进行PS detach
       GMM给网侧发送detach请求后，网侧未回复detach accept或者rel ind时，
       这时通过另一个通道下发AT+CGREG进行注册状态查询。关机时，MMC给MM/
       GMM发送关机请求时，MM和GMM迁状态，迁完状态后，判断当前需要给MMC
       发送Service Status Ind指示当前CS/PS域服务状态，MMC收到MM/GMM服务
       状态上报后，会给MMA上报当前服务状态。该服务状态在AT+COPS?时会使用
       ，所以MMC给MM/GMM模块发送POWER OFF REQ之后，AT+COPS?查询结果为
       无服务。但此时CS/PS注册状态还是处于注册，注册状态将在收到MM/GMM
       CNF之后进行更新。当网侧不回复detach accept或者rel ind，GMM便不会
       MMC上报POWER OFF CNF，所以这段时间内查询AT+CGREG?和AT+COPS?将导致
       两者维护状态不一致。

       问题:MMC给MMA发送注册状态后，如果GMM还未将服务状态给MMC上报时，在
            该段时间内查询同样会出现不一致。
    *******************************************************************/
    NAS_MMC_ChangePsRegState(NAS_MML_REG_NOT_REGISTERED_NOT_SEARCH);

    /* 迁移到 NAS_MMC_L2_STA_POWER_OFF:NAS_MMC_POWER_OFF_STA_WAIT_MM_POWEROFF_CNF状态,并启动保护定时器TI_NAS_MMC_WAIT_MM_POWEROFF_CNF */
    NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_MM_POWEROFF_CNF);

    NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_MM_POWEROFF_CNF, TI_NAS_MMC_WAIT_MM_POWEROFF_CNF_LEN);

    return VOS_TRUE;
}
VOS_UINT32 NAS_MMC_RcvMmaPowerSaveReq_PowerOff_Init(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{

    /* 保存入口消息 */
    NAS_MMC_SaveCurEntryMsg(ulEventType, pstMsg);

    /* 向MM/GMM发送Cover lost指示 */
    NAS_MMC_SndMmCoverageLostInd();
    NAS_MMC_SndGmmCoverageLostInd();

    /* 向LMM发送挂起请求,启动保护定时器TI_NAS_MMC_WAIT_LMM_SUSPEND_CNF,状态迁移到NAS_MMC_POWER_OFF_STA_WAIT_LMM_SUSPEND_CNF */
    NAS_MMC_SndSuspendReq_PowerOff(NAS_MML_GetCurrNetRatType());

    return VOS_TRUE;
}


VOS_UINT32 NAS_MMC_RcvMmPowerOffCnf_PowerOff_WaitMmPoweroffCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enMasterModeRat;
    NAS_MML_PLMN_RAT_PRIO_STRU         *pstSlaveModeRatList = VOS_NULL_PTR;

    /* 获取从模关机列表 */
    pstSlaveModeRatList = NAS_MMC_GetSlaveModeRatList_PowerOff();
    enMasterModeRat     = NAS_MMC_GetMasterModeRat_PowerOff();

    /* 更新MM的关机确认标志 */
    NAS_MMC_ClearMmPowerOffCnfFlag_PowerOff( NAS_MMC_MM_POWER_OFF_FLG );

    NAS_MMC_ChangeCsRegState(NAS_MML_REG_NOT_REGISTERED_NOT_SEARCH);

    NAS_MMC_ChangeServiceState(MMA_MMC_SRVDOMAIN_CS, NAS_MMC_NO_SERVICE);

    /* 未收齐MM和GMM的关机确认消息，返回继续等待 */
    if ( NAS_MMC_MMGMM_POWER_OFF_NULL_FLG != NAS_MMC_GetMmPowerOffCnfFlg_PowerOff())
    {
        return VOS_TRUE;
    }

    NAS_MMC_StopTimer ( TI_NAS_MMC_WAIT_MM_POWEROFF_CNF );

    switch ( enMasterModeRat )
    {

#if (FEATURE_ON == FEATURE_LTE)

        case NAS_MML_NET_RAT_TYPE_LTE:

            /* 如果从模个数为0，表示平台支持单模，不需要再给其他模发送关机消息，直接退状态机 */
            if (0 == pstSlaveModeRatList->ucRatNum)
            {
                /* 清空GAS、WAS、LMM的关机确认消息记录标志 */
                NAS_MMC_ClearAllAsPowerOffCnfFlag_PowerOff();

                /* 上报给TAF，关机成功 */
                NAS_Mmc_SndMmaPowerOffCnf();

                /* 将层二运行结果通知层一，层一收到此消息后进行层一状态的迁移 */
                NAS_MMC_SndPowerOffRslt(NAS_MMC_POWEROFF_RSLT_POWER_OFF);

                /* 关机完成，退出层二状态机*/
                NAS_MMC_FSM_QuitFsmL2();

                return VOS_TRUE;
            }
            else
            {
                /* 给从模发送关机请求 */
                NAS_MMC_SndSlaveModePowerOffReq_PowerOff();

                /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF,并启动保护定时器 */
                NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF);
                NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF_LEN);
            }
            break;
#endif            
            
        case NAS_MML_NET_RAT_TYPE_WCDMA:
            
            /* 给WAS主模发送关机消息,设置等待Was回复标志 */
            NAS_MMC_SndAsPowerOffReq(WUEPS_PID_WRR);
            
            /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF,并启动保护定时器 */
            NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF);
            NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF_LEN);

            break;
            
        case NAS_MML_NET_RAT_TYPE_GSM:
            
            /* 给GAS主模发送关机消息,设置等待gas回复标志 */
            NAS_MMC_SndAsPowerOffReq(UEPS_PID_GAS);

            /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF,并启动保护定时器 */
            NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF);
            NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF_LEN);

            break;            

        /* 当前没有主模 */    
        default:            

            /* 如果从模个数为0，又没有主模，复位 */
            if (0 == pstSlaveModeRatList->ucRatNum)
            {
                /* 不可恢复错误,调用底软接口RESET */
                NAS_MML_SoftReBoot(NAS_MML_REBOOT_SCENE_MMC_NO_MASTER_AND_SLAVE_MODE);

                return VOS_TRUE;
            }
            else
            {
                /* 给从模发送关机请求 */
                NAS_MMC_SndSlaveModePowerOffReq_PowerOff();

                /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF,并启动保护定时器 */
                NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF);
                NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF_LEN);
            }
            break;
    }


    return VOS_TRUE;
}
VOS_UINT32 NAS_MMC_RcvGmmPowerOffCnf_PowerOff_WaitMmPoweroffCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enMasterModeRat;
    NAS_MML_PLMN_RAT_PRIO_STRU         *pstSlaveModeRatList = VOS_NULL_PTR;

    /* 获取从模关机列表 */
    pstSlaveModeRatList = NAS_MMC_GetSlaveModeRatList_PowerOff();
    enMasterModeRat = NAS_MMC_GetMasterModeRat_PowerOff();
    
    /* 更新GMM的关机确认标志 */
    NAS_MMC_ClearMmPowerOffCnfFlag_PowerOff( NAS_MMC_GMM_POWER_OFF_FLG );

    NAS_MMC_ChangePsRegState(NAS_MML_REG_NOT_REGISTERED_NOT_SEARCH);

    NAS_MMC_ChangeServiceState(MMA_MMC_SRVDOMAIN_PS, NAS_MMC_NO_SERVICE);

    /*  未收齐MM和GMM的关机确认消息，返回继续等待 */
    if ( NAS_MMC_MMGMM_POWER_OFF_NULL_FLG != NAS_MMC_GetMmPowerOffCnfFlg_PowerOff())
    {
        return VOS_TRUE;
    }

    NAS_MMC_StopTimer ( TI_NAS_MMC_WAIT_MM_POWEROFF_CNF );

    switch ( enMasterModeRat )
    {
    
#if (FEATURE_ON == FEATURE_LTE)

        case NAS_MML_NET_RAT_TYPE_LTE:

            /* 如果从模个数为0，表示平台支持单模，不需要再给其他模发送关机消息，直接退状态机 */
            if (0 == pstSlaveModeRatList->ucRatNum)
            {
                /* 清空GAS、WAS、LMM的关机确认消息记录标志 */
                NAS_MMC_ClearAllAsPowerOffCnfFlag_PowerOff();

                /* 上报给TAF，关机成功 */
                NAS_Mmc_SndMmaPowerOffCnf();

                /* 将层二运行结果通知层一，层一收到此消息后进行层一状态的迁移 */
                NAS_MMC_SndPowerOffRslt(NAS_MMC_POWEROFF_RSLT_POWER_OFF);

                /* 关机完成，退出层二状态机*/
                NAS_MMC_FSM_QuitFsmL2();

                return VOS_TRUE;
            }
            else
            {
                /* 给从模发送关机请求 */
                NAS_MMC_SndSlaveModePowerOffReq_PowerOff();

                /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF,并启动保护定时器 */
                NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF);
                NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF_LEN);
            }
            break;
#endif            
            
        case NAS_MML_NET_RAT_TYPE_WCDMA:
            
            /* 给WAS发送关机消息,设置等待Was回复标志 */
            NAS_MMC_SndAsPowerOffReq(WUEPS_PID_WRR);

            /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF,并启动保护定时器 */
            NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF);
            NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF_LEN);
            break;
            
        case NAS_MML_NET_RAT_TYPE_GSM:
            
            /* 给GAS发送关机消息,设置等待gas回复标志 */
            NAS_MMC_SndAsPowerOffReq(UEPS_PID_GAS);

            /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF,并启动保护定时器 */
            NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF);
            NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF_LEN);
            
            break;            

        /* 当前没有主模 */    
        default:

            /* 如果从模个数为0，又没有主模，复位 */
            if (0 == pstSlaveModeRatList->ucRatNum)
            {
                /* 不可恢复错误,调用底软接口RESET */
                NAS_MML_SoftReBoot(NAS_MML_REBOOT_SCENE_MMC_NO_MASTER_AND_SLAVE_MODE);

                return VOS_TRUE;
            }
            else
            {
                /* 给从模发送关机请求 */
                NAS_MMC_SndSlaveModePowerOffReq_PowerOff();

                /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF,并启动保护定时器 */
                NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF);
                NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF_LEN);
            }
            break;
    }


    return VOS_TRUE;
}
VOS_UINT32 NAS_MMC_RcvTiWaitMmPowerOffCnfExpired_PowerOff_WaitMmPowerOffCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enMasterModeRat;
    NAS_MML_PLMN_RAT_PRIO_STRU         *pstSlaveModeRatList = VOS_NULL_PTR;

    /* 获取从模关机列表 */
    pstSlaveModeRatList = NAS_MMC_GetSlaveModeRatList_PowerOff();
    enMasterModeRat = NAS_MMC_GetMasterModeRat_PowerOff();
    
    /* 异常打印 */
    NAS_WARNING_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvTiWaitMmPowerOffCnfExpired_PowerOff_WaitMmPowerOffCnf ENTERED");

    /* 清空MM的关机确认标志 */
    NAS_MMC_ClearAllMmPowerOffCnfFlag_PowerOff();

    NAS_MMC_ChangePsRegState(NAS_MML_REG_NOT_REGISTERED_NOT_SEARCH);
    NAS_MMC_ChangeCsRegState(NAS_MML_REG_NOT_REGISTERED_NOT_SEARCH);

    NAS_MMC_ChangeServiceState(MMA_MMC_SRVDOMAIN_CS_PS, NAS_MMC_NO_SERVICE);


    switch ( enMasterModeRat )
    {

#if (FEATURE_ON == FEATURE_LTE)

        case NAS_MML_NET_RAT_TYPE_LTE:

            /* 如果从模个数为0，表示平台支持单模，不需要再给其他模发送关机消息，直接退状态机 */
            if (0 == pstSlaveModeRatList->ucRatNum)
            {
                /* 清空GAS、WAS、LMM的关机确认消息记录标志 */
                NAS_MMC_ClearAllAsPowerOffCnfFlag_PowerOff();

                /* 上报给TAF，关机成功 */
                NAS_Mmc_SndMmaPowerOffCnf();

                /* 将层二运行结果通知层一，层一收到此消息后进行层一状态的迁移 */
                NAS_MMC_SndPowerOffRslt(NAS_MMC_POWEROFF_RSLT_POWER_OFF);

                /* 关机完成，退出层二状态机*/
                NAS_MMC_FSM_QuitFsmL2();

                return VOS_TRUE;
            }
            else
            {
                /* 给从模发送关机请求 */
                NAS_MMC_SndSlaveModePowerOffReq_PowerOff();

                /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF,并启动保护定时器 */
                NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF);
                NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF_LEN);
            }
            break;
#endif            
            
        case NAS_MML_NET_RAT_TYPE_WCDMA:
            
            /* 给WAS发送关机消息,设置等待Was回复标志 */
            NAS_MMC_SndAsPowerOffReq(WUEPS_PID_WRR);

            /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF,并启动保护定时器 */
            NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF);
            NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF_LEN);
            
            break;
            
        case NAS_MML_NET_RAT_TYPE_GSM:
            
            /* 给GAS发送关机消息,设置等待gas回复标志 */
            NAS_MMC_SndAsPowerOffReq(UEPS_PID_GAS);

            /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF,并启动保护定时器 */
            NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF);
            NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF_LEN);

            break;            

        /* 当前没有主模 */    
        default:

            /* 如果从模个数为0，又没有主模，复位 */
            if (0 == pstSlaveModeRatList->ucRatNum)
            {
                /* 不可恢复错误,调用底软接口RESET */
                NAS_MML_SoftReBoot(NAS_MML_REBOOT_SCENE_MMC_NO_MASTER_AND_SLAVE_MODE);

                return VOS_TRUE;
            }
            else
            {
                /* 给从模发送关机请求 */
                NAS_MMC_SndSlaveModePowerOffReq_PowerOff();

                /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF,并启动保护定时器 */
                NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF);
                NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF_LEN);
            }
            break;
    }


    return VOS_TRUE;
}



VOS_UINT32 NAS_MMC_RcvGasPowerOffCnf_PowerOff_WaitMasterModePowerOffCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    NAS_MML_PLMN_RAT_PRIO_STRU         *pstSlaveModeRatList = VOS_NULL_PTR;

    NAS_TRACE_HIGH("Enter!");

    /* 获取从模关机列表 */
    pstSlaveModeRatList = NAS_MMC_GetSlaveModeRatList_PowerOff();

    /* 停止收到主模回复定时器 */
    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF);

    /* 如果从模个数为0，表示平台支持单模，不需要再给其他模发送关机消息，直接退状态机 */
    if (0 == pstSlaveModeRatList->ucRatNum)
    {
        /* 清空GAS、WAS、LMM的关机确认消息记录标志 */
        NAS_MMC_ClearAllAsPowerOffCnfFlag_PowerOff();

        /* 上报给TAF，关机成功 */
        NAS_Mmc_SndMmaPowerOffCnf();

        /* 将层二运行结果通知层一，层一收到此消息后进行层一状态的迁移 */
        NAS_MMC_SndPowerOffRslt(NAS_MMC_POWEROFF_RSLT_POWER_OFF);

        /* 关机完成，退出层二状态机*/
        NAS_MMC_FSM_QuitFsmL2();

        return VOS_TRUE;
    }
    else
    {
        /* 给从模发送关机请求 */
        NAS_MMC_SndSlaveModePowerOffReq_PowerOff();

        /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF,并启动保护定时器 */
        NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF);
        NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF_LEN);
    }

    return VOS_TRUE;
}
VOS_UINT32 NAS_MMC_RcvWasPowerOffCnf_PowerOff_WaitMasterModePowerOffCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    NAS_MML_PLMN_RAT_PRIO_STRU         *pstSlaveModeRatList = VOS_NULL_PTR;

    NAS_TRACE_HIGH("%s", (NAS_UTRANCTRL_UTRAN_MODE_FDD == NAS_UTRANCTRL_GetCurrUtranMode()) ? "FDD" : "TDD");

    /* 获取从模关机列表 */
    pstSlaveModeRatList = NAS_MMC_GetSlaveModeRatList_PowerOff();

    /* 停止收到主模回复定时器 */
    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF);

    vos_printf("NAS_MMC_RcvWasPowerOffCnf_PowerOff_WaitMasterModePowerOffCnf, tick = 0x%x\r\n ", OM_GetSlice());

    /* 如果从模个数为0，表示平台支持单模，不需要再给其他模发送关机消息，直接退状态机 */
    if (0 == pstSlaveModeRatList->ucRatNum)
    {
        /* 清空GAS、WAS、LMM的关机确认消息记录标志 */
        NAS_MMC_ClearAllAsPowerOffCnfFlag_PowerOff();

        /* 上报给TAF，关机成功 */
        NAS_Mmc_SndMmaPowerOffCnf();

        /* 将层二运行结果通知层一，层一收到此消息后进行层一状态的迁移 */
        NAS_MMC_SndPowerOffRslt(NAS_MMC_POWEROFF_RSLT_POWER_OFF);

        /* 关机完成，退出层二状态机*/
        NAS_MMC_FSM_QuitFsmL2();

        return VOS_TRUE;
    }
    else
    {
        /* 给从模发送关机请求 */
        NAS_MMC_SndSlaveModePowerOffReq_PowerOff();

        /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF,并启动保护定时器 */
        NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF);
        NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF_LEN);
    }

    return VOS_TRUE;
}
VOS_UINT32 NAS_MMC_RcvTiWaitMasterModePowerOffCnfExpired_PowerOff_WaitMasterModePowerOffCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enMasterModeRat;
    NAS_MML_PLMN_RAT_PRIO_STRU         *pstSlaveModeRatList = VOS_NULL_PTR;

    /* 获取从模关机列表 */
    pstSlaveModeRatList = NAS_MMC_GetSlaveModeRatList_PowerOff();
    enMasterModeRat = NAS_MMC_GetMasterModeRat_PowerOff();

    /* 异常打印 */
    NAS_WARNING_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvTiWaitMasterModePowerOffCnfExpired_PowerOff_WaitMasterModePowerOffCnf:ENTERED");

    NAS_TRACE_HIGH("Enter!");

    switch ( enMasterModeRat )
    {

#if (FEATURE_ON == FEATURE_LTE)

        case NAS_MML_NET_RAT_TYPE_LTE:

            /* 通知MM关机，并设置等待MM回复标志 */
            NAS_MMC_SndMmPowerOffReq();
            NAS_MMC_SetMmPowerOffCnfFlag_PowerOff( NAS_MMC_MM_POWER_OFF_FLG );

            /* 通知GMM关机，并设置等待GMM回复标志 */
            NAS_MMC_SndGmmPowerOffReq();
            NAS_MMC_SetMmPowerOffCnfFlag_PowerOff( NAS_MMC_GMM_POWER_OFF_FLG );

            /* 迁移到 NAS_MMC_L2_STA_POWER_OFF:NAS_MMC_POWER_OFF_STA_WAIT_MM_POWEROFF_CNF状态,并启动保护定时器TI_NAS_MMC_WAIT_MM_POWEROFF_CNF*/
            NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_MM_POWEROFF_CNF);
            NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_MM_POWEROFF_CNF, TI_NAS_MMC_WAIT_MM_POWEROFF_CNF_LEN);

            break;
#endif

        case NAS_MML_NET_RAT_TYPE_WCDMA:

            /* 如果从模个数为0，表示平台支持单模，不需要再给其他模发送关机消息，直接退状态机 */
            if (0 == pstSlaveModeRatList->ucRatNum)
            {
                /* 清空GAS、WAS、LMM的关机确认消息记录标志 */
                NAS_MMC_ClearAllAsPowerOffCnfFlag_PowerOff();

                /* 上报给TAF，关机成功 */
                NAS_Mmc_SndMmaPowerOffCnf();

                /* 将层二运行结果通知层一，层一收到此消息后进行层一状态的迁移 */
                NAS_MMC_SndPowerOffRslt(NAS_MMC_POWEROFF_RSLT_POWER_OFF);

                /* 关机完成，退出层二状态机*/
                NAS_MMC_FSM_QuitFsmL2();

                return VOS_TRUE;
            }
            else
            {
                /* 给从模发送关机请求 */
                NAS_MMC_SndSlaveModePowerOffReq_PowerOff();

                /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF,并启动保护定时器 */
                NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF);
                NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF_LEN);
            }
            break;
            
        case NAS_MML_NET_RAT_TYPE_GSM:

            /* 如果从模个数为0，表示平台支持单模，不需要再给其他模发送关机消息，直接退状态机 */
            if (0 == pstSlaveModeRatList->ucRatNum)
            {
                /* 清空GAS、WAS、LMM的关机确认消息记录标志 */
                NAS_MMC_ClearAllAsPowerOffCnfFlag_PowerOff();

                /* 上报给TAF，关机成功 */
                NAS_Mmc_SndMmaPowerOffCnf();

                /* 将层二运行结果通知层一，层一收到此消息后进行层一状态的迁移 */
                NAS_MMC_SndPowerOffRslt(NAS_MMC_POWEROFF_RSLT_POWER_OFF);

                /* 关机完成，退出层二状态机*/
                NAS_MMC_FSM_QuitFsmL2();

                return VOS_TRUE;
            }
            else
            {
                /* 给从模发送关机请求 */
                NAS_MMC_SndSlaveModePowerOffReq_PowerOff();

                /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF,并启动保护定时器 */
                NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_SLAVE_MODE_POWEROFF_CNF);
                NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF_LEN);
            }
            break;

        /* 当前没有主模 */    
        default:
            NAS_ERROR_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvTiWaitMasterModePowerOffCnfExpired_PowerOff_WaitMasterModePowerOffCnf:NO MASTER MODE!");
            break;
    }

    return VOS_TRUE;

}



VOS_UINT32 NAS_MMC_RcvGasPowerOffCnf_PowerOff_WaitSlaveModePowerOffCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    NAS_TRACE_HIGH("Enter!");

    /* 更新GAS接入层的关机确认消息记录标志 */
    NAS_MMC_ClearAsPowerOffCnfFlag_PowerOff( NAS_MMC_GAS_POWER_OFF_FLG );

    /* 未收齐所有接入层的关机确认消息，返回继续等待 */
    if ( NAS_MMC_AS_POWER_OFF_NULL_FLG != NAS_MMC_GetAsPowerOffCnfFlg_PowerOff() )
    {
        return VOS_TRUE;
    }


    /* 当前G模为从模且收到了所有接入层的关机回复 */
    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF);

    /* 上报给TAF，关机成功 */
    NAS_Mmc_SndMmaPowerOffCnf();

    /* 将层二运行结果通知层一，层一收到此消息后进行层一状态的迁移 */
    NAS_MMC_SndPowerOffRslt(NAS_MMC_POWEROFF_RSLT_POWER_OFF);

    /* 关机完成，退出层二状态机*/
    NAS_MMC_FSM_QuitFsmL2();

    return VOS_TRUE;
}


VOS_UINT32 NAS_MMC_RcvWasPowerOffCnf_PowerOff_WaitSlaveModePowerOffCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    NAS_TRACE_HIGH("%s", (NAS_UTRANCTRL_UTRAN_MODE_FDD == NAS_UTRANCTRL_GetCurrUtranMode()) ? "FDD" : "TDD");

    /* 更新接入层WAS的关机确认消息记录标志 */
    NAS_MMC_ClearAsPowerOffCnfFlag_PowerOff( NAS_MMC_WAS_POWER_OFF_FLG );

    /* 未收齐所有接入层的关机确认消息,返回继续等待 */
    if ( NAS_MMC_AS_POWER_OFF_NULL_FLG != NAS_MMC_GetAsPowerOffCnfFlg_PowerOff() )
    {
        return VOS_TRUE;
    }

    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF);

    /* 上报给TAF，关机成功 */
    NAS_Mmc_SndMmaPowerOffCnf();

    /* 将层二运行结果通知层一，层一收到此消息后进行层一状态的迁移 */
    NAS_MMC_SndPowerOffRslt(NAS_MMC_POWEROFF_RSLT_POWER_OFF);

    /* 关机完成，退出层二状态机*/
    NAS_MMC_FSM_QuitFsmL2();

    return VOS_TRUE;
}
VOS_UINT32 NAS_MMC_RcvTiWaitSlaveModePowerOffCnfExpired_PowerOff_WaitSlaveModePowerOffCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    /* 异常打印 */
    NAS_WARNING_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvTiWaitSlaveModePowerOffCnfExpired_PowerOff_WaitSlaveModePowerOffCnf:ENTERED");

    NAS_TRACE_HIGH("Enter!");

    /* 清空GAS、WAS、LMM的关机确认消息记录标志 */
    NAS_MMC_ClearAllAsPowerOffCnfFlag_PowerOff();

    /* 上报给TAF，关机成功 */
    NAS_Mmc_SndMmaPowerOffCnf();

    /* 将层二运行结果通知层一，层一收到此消息后进行层一状态的迁移 */
    NAS_MMC_SndPowerOffRslt(NAS_MMC_POWEROFF_RSLT_POWER_OFF);

    /* 关机完成，退出层二状态机*/
    NAS_MMC_FSM_QuitFsmL2();

    return VOS_TRUE;

}



#if (FEATURE_ON == FEATURE_LTE)
VOS_UINT32 NAS_MMC_RcvLmmStopCnf_PowerOff_WaitMasterModePowerOffCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    NAS_TRACE_HIGH("Enter!");

    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF);

    /* 通知MM关机，并设置等待MM回复标志 */
    NAS_MMC_SndMmPowerOffReq();

    NAS_MMC_SetMmPowerOffCnfFlag_PowerOff( NAS_MMC_MM_POWER_OFF_FLG );

    /* 通知GMM关机，并设置等待GMM回复标志 */
    NAS_MMC_SndGmmPowerOffReq();

    NAS_MMC_SetMmPowerOffCnfFlag_PowerOff( NAS_MMC_GMM_POWER_OFF_FLG );

    /* 迁移到 NAS_MMC_L2_STA_POWER_OFF:NAS_MMC_POWER_OFF_STA_WAIT_MM_POWEROFF_CNF状态,并启动保护定时器TI_NAS_MMC_WAIT_MM_POWEROFF_CNF*/
    NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_MM_POWEROFF_CNF);

    NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_MM_POWEROFF_CNF, TI_NAS_MMC_WAIT_MM_POWEROFF_CNF_LEN);

    return VOS_TRUE;

}


VOS_UINT32 NAS_MMC_RcvLmmSuspendCnf_PowerOff_WaitLmmSuspendCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    LMM_MMC_SUSPEND_CNF_STRU           *pstSuspendCnf = VOS_NULL_PTR;

    pstSuspendCnf = (LMM_MMC_SUSPEND_CNF_STRU*)pstMsg;

    /* 停止保护定时器TI_NAS_MMC_WAIT_LMM_SUSPEND_CNF */
    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_LMM_SUSPEND_CNF);

    /* 如果挂起失败直接复位 */
    if (MMC_LMM_FAIL == pstSuspendCnf->ulRst)
    {
        /* 异常打印 */
        NAS_ERROR_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvLmmSuspendCnf_PowerOff_WaitLmmSuspendCnf: SUSPEND FAIL !");

        /* 不可恢复错误,调用底软接口RESET */
        NAS_MML_SoftReBoot(NAS_MML_REBOOT_SCENE_MMC_RECEIVE_LMM_SUSPEND_FAILURE);

        return VOS_TRUE;
    }

    /* 设置当前接入技术为BUTT */
    NAS_MML_SetCurrNetRatType(NAS_MML_NET_RAT_TYPE_BUTT);

    /* 上报给MMA Power Save成功 */
    NAS_MMC_SndMmaPowerSaveCnf();

    /* 将层二运行结果通知层一，层一收到此消息后进行层一状态的迁移 */
    NAS_MMC_SndPowerOffRslt(NAS_MMC_POWEROFF_RSLT_POWER_SAVE);

    /* 关机完成，退出层二状态机 */
    NAS_MMC_FSM_QuitFsmL2();

    return VOS_TRUE;
}


VOS_UINT32 NAS_MMC_RcvTiWaitLmmSuspendCnfExpired_PowerOff_WaitLmmSuspendCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    /* 异常打印 */
    NAS_ERROR_LOG(WUEPS_PID_MMC, "NAS_MMC_RcvTiWaitLmmSuspendCnfExpired_PowerOff_WaitLmmSuspendCnf: Enter !");

    /* 复位 */
    NAS_MML_SoftReBoot(NAS_MML_REBOOT_SCENE_MMC_WAIT_LMM_SUSPEND_CNF_EXPIRED);

    return VOS_TRUE;
}
VOS_UINT32 NAS_MMC_RcvLmmStopCnf_PowerOff_WaitSlaveModePowerOffCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    NAS_TRACE_HIGH("Enter!");

    /* 更新接入层LTE的关机确认消息记录标志 */
    NAS_MMC_ClearAsPowerOffCnfFlag_PowerOff( NAS_MMC_LTE_POWER_OFF_FLG );

    /* 未收齐所有接入层的关机确认消息，返回继续等待 */
    if ( NAS_MMC_AS_POWER_OFF_NULL_FLG != NAS_MMC_GetAsPowerOffCnfFlg_PowerOff() )
    {
        return VOS_TRUE;
    }

    NAS_MMC_StopTimer(TI_NAS_MMC_WAIT_SLAVE_MODE_POWEROFF_CNF);

    /* 上报给TAF，关机成功 */
    NAS_Mmc_SndMmaPowerOffCnf();

    /* 将层二运行结果通知层一，层一收到此消息后进行层一状态的迁移 */
    NAS_MMC_SndPowerOffRslt(NAS_MMC_POWEROFF_RSLT_POWER_OFF);

    /* 关机完成，退出层二状态机*/
    NAS_MMC_FSM_QuitFsmL2();

    return VOS_TRUE;
}
VOS_UINT32  NAS_MMC_RcvLmmUsimStatusCnf_PowerOff_WaitLmmUsimStatusCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
    /* MMC停止定时器: TI_NAS_MMC_WAIT_LMM_USIM_STATUS_CNF */
    NAS_MMC_StopTimer( TI_NAS_MMC_WAIT_LMM_USIM_STATUS_CNF );

#if   (FEATURE_ON == FEATURE_LTE)

    if ( NAS_MML_NET_RAT_TYPE_LTE == NAS_MMC_GetMasterModeRat_PowerOff() )
    {
    
        /* 给LTE主模发送关机消息 */
        NAS_MMC_SndLmmStopReq();

        /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF,并启动10s保护定时器 */
        NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF);

        NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF_LEN);

        return VOS_TRUE;
    }

#endif

    /* 通知MM关机，并设置等待MM回复标志 */
    NAS_MMC_SndMmPowerOffReq();

    NAS_MMC_SetMmPowerOffCnfFlag_PowerOff( NAS_MMC_MM_POWER_OFF_FLG );

    /* 通知GMM关机，并设置等待GMM回复标志 */
    NAS_MMC_SndGmmPowerOffReq();

    NAS_MMC_SetMmPowerOffCnfFlag_PowerOff( NAS_MMC_GMM_POWER_OFF_FLG );

    /* 迁移到 NAS_MMC_L2_STA_POWER_OFF:NAS_MMC_POWER_OFF_STA_WAIT_MM_POWEROFF_CNF状态,并启动保护定时器TI_NAS_MMC_WAIT_MM_POWEROFF_CNF*/
    NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_MM_POWEROFF_CNF);

    NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_MM_POWEROFF_CNF, TI_NAS_MMC_WAIT_MM_POWEROFF_CNF_LEN);

    return VOS_TRUE;

}


VOS_UINT32  NAS_MMC_RcvTiWaitLmmUsimStatusExpired_PowerOff_WaitLmmUsimStatusCnf(
    VOS_UINT32                          ulEventType,
    struct MsgCB                       *pstMsg
)
{
#if   (FEATURE_ON == FEATURE_LTE)

    if ( NAS_MML_NET_RAT_TYPE_LTE == NAS_MMC_GetMasterModeRat_PowerOff() )
    {
    
        /* 给LTE发送关机消息 */
        NAS_MMC_SndLmmStopReq();

        /* 迁移状态到NAS_MMC_POWEROFF::NAS_MMC_POWER_OFF_STA_WAIT_AS_POWEROFF_CNF,并启动10s保护定时器 */
        NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_MASTER_MODE_POWEROFF_CNF);

        NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF, TI_NAS_MMC_WAIT_MASTER_MODE_POWEROFF_CNF_LEN);

        return VOS_TRUE;
    }
#endif

    /* 通知MM关机，并设置等待MM回复标志 */
    NAS_MMC_SndMmPowerOffReq();

    NAS_MMC_SetMmPowerOffCnfFlag_PowerOff( NAS_MMC_MM_POWER_OFF_FLG );

    /* 通知GMM关机，并设置等待GMM回复标志 */
    NAS_MMC_SndGmmPowerOffReq();

    NAS_MMC_SetMmPowerOffCnfFlag_PowerOff( NAS_MMC_GMM_POWER_OFF_FLG );

    /* 迁移到 NAS_MMC_L2_STA_POWER_OFF:NAS_MMC_POWER_OFF_STA_WAIT_MM_POWEROFF_CNF状态,并启动保护定时器TI_NAS_MMC_WAIT_MM_POWEROFF_CNF*/
    NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_MM_POWEROFF_CNF);

    NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_MM_POWEROFF_CNF, TI_NAS_MMC_WAIT_MM_POWEROFF_CNF_LEN);

    return VOS_TRUE;
}
#endif


VOS_UINT32  NAS_MMC_SndSlaveModePowerOffReq_PowerOff(VOS_VOID)
{
    NAS_MML_PLMN_RAT_PRIO_STRU                 *pstSlaveModeRatList = VOS_NULL_PTR;
    VOS_UINT32                                  i;

    /* 获取从模关机列表 */
    pstSlaveModeRatList = NAS_MMC_GetSlaveModeRatList_PowerOff();

    /* 平台不是单模时，给从模发送关机消息 */
    for (i = 0; i < pstSlaveModeRatList->ucRatNum; i++)
    {
        /* 给GAS发送关机消息,设置等待gas回复标志 */
        if (NAS_MML_NET_RAT_TYPE_GSM == pstSlaveModeRatList->aucRatPrio[i])
        {
            NAS_MMC_SndAsPowerOffReq(UEPS_PID_GAS);
            NAS_MMC_SetAsPowerOffCnfFlag_PowerOff( NAS_MMC_GAS_POWER_OFF_FLG );
        }

        /* 给WAS发送关机消息,设置等待Was回复标志 */
        else if (NAS_MML_NET_RAT_TYPE_WCDMA == pstSlaveModeRatList->aucRatPrio[i])
        {
            NAS_MMC_SndAsPowerOffReq(WUEPS_PID_WRR);
            NAS_MMC_SetAsPowerOffCnfFlag_PowerOff( NAS_MMC_WAS_POWER_OFF_FLG );
        }

        /* 给LMM发送关机消息,设置等待LMM回复标志 */
#if (FEATURE_ON == FEATURE_LTE)
        else if (NAS_MML_NET_RAT_TYPE_LTE == pstSlaveModeRatList->aucRatPrio[i])
        {
            NAS_MMC_SndLmmStopReq();
            NAS_MMC_SetAsPowerOffCnfFlag_PowerOff( NAS_MMC_LTE_POWER_OFF_FLG );
        }
#endif
        else
        {
        }
    }

    return VOS_TRUE;

}



#if (FEATURE_ON == FEATURE_DSDS)
VOS_VOID NAS_MMC_ProcRrmDeRegister_PowerOff(VOS_VOID)
{
    MODEM_ID_ENUM_UINT16                usModemId;

    /* 取得当前MODEM的ID信息  */
    usModemId = VOS_GetModemIDFromPid(WUEPS_PID_MMC);

    /* 如果当前NV未开启DSDS,则不向RRM发送关机去注册 */
    if ( VOS_FALSE == NAS_MML_GetDsdsRfShareFlg() )
    {
        return;
    }

    /* 在MODEM0时候，向RRM发送W下的去注册信息 */
    if ( MODEM_ID_0 == usModemId )
    {
        NAS_MMC_SndRrmDeRegisterInd(MODEM_ID_0,
                                    RRM_PS_TASK_TYPE_NAS_SEARCH,
                                    RRM_PS_RAT_TYPE_WCDMA);
    }

    /* 在MODEM1时候，向RRM发送G下的去注册信息 */
    if ( MODEM_ID_1 == usModemId )
    {
        NAS_MMC_SndRrmDeRegisterInd(MODEM_ID_1,
                                    RRM_PS_TASK_TYPE_NAS_SEARCH,
                                    RRM_PS_RAT_TYPE_GSM);
    }

    return;
}

#endif


VOS_VOID NAS_MMC_SndSuspendReq_PowerOff(
    NAS_MML_NET_RAT_TYPE_ENUM_UINT8     enRat
)
{
    /* 状态更新为当前未驻留 */
    NAS_MMC_SetAsCellCampOn(NAS_MMC_AS_CELL_NOT_CAMP_ON);
    NAS_MMC_SetSpecPlmnSearchState(NAS_MMC_SPEC_PLMN_SEARCH_RUNNING);

    NAS_MMC_SetAsAnyCampOn(VOS_FALSE);

    /* 根据不同的接入技术设置等待搜网回复的状态 */
    switch (enRat)
    {
#if (FEATURE_ON == FEATURE_LTE)
        case NAS_MML_NET_RAT_TYPE_LTE:
            NAS_MMC_SndLmmSuspendReq();
            NAS_MMC_FSM_SetCurrState(NAS_MMC_POWER_OFF_STA_WAIT_LMM_SUSPEND_CNF);
            NAS_MMC_StartTimer(TI_NAS_MMC_WAIT_LMM_SUSPEND_CNF, TI_NAS_MMC_WAIT_LMM_SUSPEND_CNF_LEN);
            break;
#endif

        case NAS_MML_NET_RAT_TYPE_WCDMA:
            NAS_WARNING_LOG(WUEPS_PID_MMC, "NAS_MMC_SndSuspendReq_PowerOff: Not support WCDMA PowerSave.");
            break;

        case NAS_MML_NET_RAT_TYPE_GSM:
            NAS_WARNING_LOG(WUEPS_PID_MMC, "NAS_MMC_SndSuspendReq_PowerOff: Not support GSM PowerSave.");
            break;

        default:
            NAS_WARNING_LOG(WUEPS_PID_MMC, "NAS_MMC_SndSuspendReq_PowerOff: Rat not support.");
            break;
    }

    return;
}

#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

