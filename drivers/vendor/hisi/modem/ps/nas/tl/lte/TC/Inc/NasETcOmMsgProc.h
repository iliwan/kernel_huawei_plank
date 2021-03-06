/******************************************************************************

    Copyright(C)2008,Hisilicon Co. LTD.

 ******************************************************************************
  File Name       : NasTcOmMsgProc.h
  Description     : NasTcOmMsgProc.c header file
  History         :
     1.lihong       2010-04-15     Draft Enact
     2.
******************************************************************************/

#ifndef __NASTCOMMSGPROC_H__
#define __NASTCOMMSGPROC_H__

/*****************************************************************************
  1 Include Headfile
*****************************************************************************/
#include    "vos.h"
#include    "OmCommon.h"

/*****************************************************************************
  1.1 Cplusplus Announce
*****************************************************************************/
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
  #pragma pack(*)    设置字节对齐方式
*****************************************************************************/
#if (VOS_OS_VER != VOS_WIN32)
#pragma pack(4)
#else
#pragma pack(push, 4)
#endif
/*****************************************************************************
  2 macro
*****************************************************************************/


/*****************************************************************************
  3 Massage Declare
*****************************************************************************/


/*****************************************************************************
  4 Enum
*****************************************************************************/
/*****************************************************************************
 枚举名    : NAS_ETC_AIR_MSG_DIR_ENUM
 枚举说明  : 命令类型取值
*****************************************************************************/
enum    NAS_ETC_AIR_MSG_DIR_ENUM
{
    NAS_ETC_AIR_MSG_DIR_ENUM_UP         = 0x00,
    NAS_ETC_AIR_MSG_DIR_ENUM_DOWN             ,

    NAS_ETC_AIR_MSG_DIR_BUTT
};
typedef VOS_UINT8   NAS_ETC_AIR_MSG_DIR_ENUM_UINT8 ;


/*****************************************************************************
   5 STRUCT
*****************************************************************************/


/*****************************************************************************
  6 UNION
*****************************************************************************/


/*****************************************************************************
  7 Extern Global Variable
*****************************************************************************/


/*****************************************************************************
  8 Fuction Extern
*****************************************************************************/
extern VOS_VOID NAS_ETC_SndAirMsgReportInd(  const VOS_UINT8 *pucData,
                                                       VOS_UINT32 ulLength,
                                                       OM_PS_AIR_MSG_ENUM_UINT8 enMsgId,
                                                       NAS_ETC_AIR_MSG_DIR_ENUM_UINT8 enMsgDir);

/*****************************************************************************
  9 OTHERS
*****************************************************************************/


#if (VOS_OS_VER != VOS_WIN32)
#pragma pack()
#else
#pragma pack(pop)
#endif


#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

#endif /* end of NasTcOmMsgProc.h */
