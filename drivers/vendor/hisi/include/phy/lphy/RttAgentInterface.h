/******************************************************************************

                  版权所有 (C), 2001-2011, 华为技术有限公司

 ******************************************************************************
  文 件 名   : RttAgentInterface.h
  版 本 号   : 初稿
  作    者   : x00312156
  生成日期   : 2015年1月27日
  最近修改   :
  功能描述   : 定义RTT AGENT和其他模块的接口，包括与A核Errlog
  的接口，与TLPHY的接口

  函数列表   :
  修改历史   :
------------------------------------------------------------------------------
  1.日    期   : 	2015年1月27日
    作    者   : 	x00312156
    修改内容   : 	创建文件

******************************************************************************/

/*****************************************************************************
  1 其他头文件包含
*****************************************************************************/

#ifndef __RTTAGENT_INTERFACE_H__
#define __RTTAGENT_INTERFACE_H__


#ifndef LPS_RTT
#include "vos.h"
#else
#define VOS_MSG_HEADER
#endif


#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */


/*****************************************************************************
  2 宏定义
*****************************************************************************/
#define ERRLOG_STATUS_CLOSE   ( 0 )
#define ERRLOG_STATUS_OPEN    ( 1 )

#define TLPHY_ERR_LOG_CTRL_LEVEL_NULL         ( 0 )   /* ErrLog等级未定义*/
#define TLPHY_ERR_LOG_CTRL_LEVEL_CRITICAL     ( 1 )   /* ErrLog等级为紧急 */
#define TLPHY_ERR_LOG_CTRL_LEVEL_MAJOR        ( 2 )   /* ErrLog等级为重要 */
#define TLPHY_ERR_LOG_CTRL_LEVEL_MINOR        ( 3 )   /* ErrLog等级为次要 */
#define TLPHY_ERR_LOG_CTRL_LEVEL_WARNING      ( 4 )   /* ErrLog等级为提示 */

#define TLPHY_OM_SEND_MSG_COUNT               ( 3 )   /*TLPHY每次申请重传OM消息的条数*/
#define TLPHY_OM_SEND_CONTENT_LENGTH_IN_16BIT ( 2 )   /*TLPHY重传OM消息信息长度*/
#define TLPHY_RTTAGENT_MSG_HEADLEN_IN_8BIT    ( 8 )   /* enMsgType+ulMsgLen 的字节长度*/
/*****************************************************************************
  3 枚举定义
*****************************************************************************/

/*****************************************************************************
 枚举名    : RTTAGENT_TLPHY_MSGTYPE_ENUM_UINT32
 枚举说明  : TLPHY和RTT代理之间的消息类型
*****************************************************************************/
enum RTTAGENT_TLPHY_MSGTYPE_ENUM
{
    /* MBX 发送给AGENT的消息类型 */
	MBX_TO_RTTAGENT_REQ = 0,
	/* TPHY发送给代理的消息类型 */
	TPHY_AGENT_ERRLOG_REQ,                    /* TPHY上报Errlog请求 */
	TPHY_AGENT_STORE_OM_REQ,                  /* TPHY上报OM缓存请求 */
	TPHY_AGENT_SEND_OM_REQ,                   /* TPHY上报OM重传请求 */

	/* LPHY发送给代理的消息类型 */
	LPHY_AGENT_ERRLOG_REQ = 32,               /* LPHY上报Errlog请求 */
	LPHY_AGENT_STORE_OM_REQ,                  /* LPHY上报OM缓存请求 */
	LPHY_AGENT_SEND_OM_REQ,                   /* LPHY上报OM重传请求 */

    /* 以下是RTT AGENT发送给TLPHY的消息类型 */
	AGENT_TO_TLPHY_INFO_START = 63,

	AGENT_TLPHY_ERRLOG_CTRL_INFO,             /* 代理发送给TLPHY 的ERRLOG配置 */
	/* 代理发送给TPHY 的消息类型 */
	AGENT_TPHY_SEND_OM_CNF,                   /* TPHY OM消息重传确认 */

	/* 代理发送给LPHY 的消息类型 */
	AGENT_LPHY_SEND_OM_CNF,                   /* LPHY OM消息重传确认 */
	AGENT_TLPHY_MSG_BUTT
};
typedef VOS_UINT32 RTTAGENT_TLPHY_MSGTYPE_ENUM_UINT32;

/*****************************************************************************
  4 消息头定义
*****************************************************************************/


/*****************************************************************************
  5 消息定义
*****************************************************************************/


/*****************************************************************************
  6 STRUCT定义
*****************************************************************************/

/*****************************************************************************
 结构名    : TPHY_ERRLOG_TAS_INFO_STRU
 结构说明  :TPHY和A核Errlog之间的接口数据结构
*****************************************************************************/
typedef struct
{
    VOS_UINT32         ulAntSwitchSlice;     /* TAS切换的时间戳 */
    VOS_UINT16         usDpdtState;          /* 切换后的DPDT状态，0直通，1交叉 */
    VOS_INT16          ssAntValuemain;       /* 切换后的主集天线接收信号测量值 */
    VOS_INT16          ssSwitchDelta;        /* 主辅天线测量值Delta */
    VOS_UINT16         usBlankType;          /* 切换时的状态 */
    VOS_UINT16         usTsEn;               /* 是否有TAS授权，0无授权，1有授权 */
    VOS_UINT16         usAgentSwitchFlag;    /* 是否为代理切换，0非代理切，1代理切 */
    VOS_UINT16         usTasState;           /* 切换时的TAS状态，HAPPY/UNHAPPY 等 */
    VOS_UINT16         usReserve;            /* 预留，保持四字节对齐 */
}TPHY_ERRLOG_TAS_INFO_STRU;

/*****************************************************************************
 结构名    : LPHY_ERRLOG_TAS_INFO_STRU
 结构说明  :LPHY和A核Errlog之间的接口数据结构
*****************************************************************************/
typedef struct
{
    VOS_UINT32         ulAntSwitchSlice;      /* TAS切换的时间戳 */
    VOS_UINT16         usDpdtState;           /* 切换后的DPDT状态，0直通，1交叉 */
    VOS_INT16          ssAntValuemain;        /* 切换后的主集天线接收信号测量值 */
    VOS_INT16          ssSwitchDelta;         /* 主辅天线测量值Delta */
    VOS_UINT16         usBlankType;           /* 切换时的状态 */
    VOS_UINT16         usTsEn;                /* 是否有TAS授权，0无授权，1有授权 */
    VOS_UINT16         usAgentSwitchFlag;     /* 是否为代理切换，0非代理切，1代理切 */
    VOS_UINT16         usTasState;            /* 切换时的TAS状态，HAPPY/UNHAPPY 等 */
    VOS_UINT16         usReserve;             /* 预留，保持四字节对齐 */
}LPHY_ERRLOG_TAS_INFO_STRU;

/*****************************************************************************
 结构名    : RTTAGENT_TLPHY_MSG_STRU
 结构说明  :RTT AGENT和TLPHY的接口消息结构体
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    RTTAGENT_TLPHY_MSGTYPE_ENUM_UINT32    enMsgType;       /* 消息类型 */
    VOS_UINT32                            ulMsgLen;        /* 消息长度acuContent的实际字长度 */
    VOS_UINT8                             aucContent[4];   /* 消息内容 */
}RTTAGENT_TLPHY_MSG_STRU;

/*****************************************************************************
 结构名    : TPHY_AGENT_ERRLOG_REQ_STRU
 结构说明  :RTT AGENT和TPHY的天线切换关键消息结构体
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    RTTAGENT_TLPHY_MSGTYPE_ENUM_UINT32    enMsgType;        /* 消息类型为TPHY_AGENT_ERRLOG_REQ */
    VOS_UINT32                            ulMsgLen;         /* 消息长度为sizeof(PHY_ERRLOG_TPHY_TAS_INFO_STRU) /2*/
    TPHY_ERRLOG_TAS_INFO_STRU             stTphyTasInfo;    /* TPHY天线切换关键信息 */
}TPHY_AGENT_ERRLOG_REQ_STRU;


/*****************************************************************************
 结构名    :LPHY_AGENT_ERRLOG_REQ_STRU
 结构说明  :RTT AGENT和TPHY的天线切换关键消息结构体
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    RTTAGENT_TLPHY_MSGTYPE_ENUM_UINT32     enMsgType;        /* 消息类型为LPHY_AGENT_ERRLOG_REQ */
    VOS_UINT32                             ulMsgLen;         /* 消息长度为sizeof(PHY_ERRLOG_LPHY_TAS_INFO_STRU) /2*/
    LPHY_ERRLOG_TAS_INFO_STRU              stLphyTasInfo;    /* LPHY天线切换关键信息 */
}LPHY_AGENT_ERRLOG_REQ_STRU;


/*****************************************************************************
 结构名    : TLPHY_AGENT_SEND_OM_REQ_STRU
 结构说明  :RTT AGENT和TLPHY的OM重传消息结构体
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER
    RTTAGENT_TLPHY_MSGTYPE_ENUM_UINT32     enMsgType;         /* 消息类型为TPHY_AGENT_SEND_OM_REQ、LPHY_AGENT_SEND_OM_REQ */
    VOS_UINT32                             ulMsgLen;          /* 消息长度为2 */
    VOS_UINT32                             ulOmSendMsgCount;  /* 重发的OM消息条数 */
}TLPHY_AGENT_SEND_OM_REQ_STRU;

/*****************************************************************************
 结构名    : AGENT_TLPHY_SEND_OM_CNF_STRU
 结构说明  :RTT AGENT和TLPHY的OM重传消息确认结构体
*****************************************************************************/
typedef struct
{
    RTTAGENT_TLPHY_MSGTYPE_ENUM_UINT32     enMsgType;          /* 消息类型为AGENT_TPHY_SEND_OM_CNF、AGENT_LPHY_SEND_OM_CNF */
    VOS_UINT32                             ulMsgLen;           /* 消息长度为2 */
    VOS_UINT32                             ulOmRemainMsgCount; /* 剩余的OM消息条数 */
}AGENT_TLPHY_SEND_OM_CNF_STRU;

/*****************************************************************************
结构名    : AGENT_TLPHY_ERRLOG_CTRL_INFO_STRU
结构说明  : RTT AGENT转发给TLPHY的ERRLOG控制信息
*****************************************************************************/
typedef struct
{
    RTTAGENT_TLPHY_MSGTYPE_ENUM_UINT32     enMsgType;          /* 消息类型为AGENT_TLPHY_ERRLOG_CTRL_INFO */
    VOS_UINT32                             ulMsgLen;           /* 消息长度为2 */
    VOS_UINT16                             usErrLogCtrlFlag;   /* ERRLOG打开标识，0关闭，1打开 */
    VOS_UINT16                             usAlmLevel;         /* ERRLOG上报级别 */
}AGENT_TLPHY_ERRLOG_CTRL_INFO_STRU;



/*****************************************************************************
  7 UNION定义
*****************************************************************************/


/*****************************************************************************
  8 OTHERS定义
*****************************************************************************/


/*****************************************************************************
  9 全局变量声明
*****************************************************************************/


/*****************************************************************************
  10 函数声明
*****************************************************************************/


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif /* __RTTAGENT_INTERFACE_H__ */
