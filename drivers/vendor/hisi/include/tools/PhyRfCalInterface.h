

/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/

#ifndef __PHYRFCALINTERFACE_H__
#define __PHYRFCALINTERFACE_H__


#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


/*****************************************************************************
  2 �궨��
*****************************************************************************/


#define GPHY_RF_CAL_TX_ON                   ( 0x5555 )                              /* �ϻ������У�ʹ�ܷ��� */
#define GPHY_RF_CAL_TX_OFF                  ( 0xaaaa )                              /* �ϻ������У�ֹͣ���� */



/* Mask code Used for PHY_RF_CAL_W_SELF_CAL_REQ_STRU */
#define MASK_SELF_CAL_TX_IQ_MISMATCH        ( 1<<0 )
#define MASK_SELF_CAL_W_RX_DCR              ( 1<<1 )
#define MASK_SELF_CAL_W_RX_IP2              ( 1<<2 )

/* Mask code Used for PHY_RF_CAL_W_TRX_PARA_CFG_REQ_STRU */
#define MASK_W_TRX_CFG_TX_AFC               ( 1<<0 )
#define MASK_W_TRX_CFG_TX_CFIX              ( 1<<1 )
#define MASK_W_TRX_CFG_TX_ARFCN             ( 1<<2 )
#define MASK_W_TRX_CFG_TX_ONOFF             ( 1<<3 )
#define MASK_W_TRX_CFG_TX_RFIC_MODE         ( 1<<4 )
#define MASK_W_TRX_CFG_TX_PAMODE            ( 1<<5 )
#define MASK_W_TRX_CFG_TX_POWER_PARA        ( 1<<6 )
#define MASK_W_TRX_CFG_TX_APT               ( 1<<7 )
#define MASK_W_TRX_CFG_PD_ONOFF             ( 1<<8 )
#define MASK_W_TRX_CFG_TX_UPA               ( 1<<9 )
#define MASK_W_TRX_CFG_SELF_CAL             ( 1<<10 )

#define MASK_W_TRX_CFG_RX_ARFCN             ( 1<<16 )
#define MASK_W_TRX_CFG_RX_CROSS_ARFCN       ( 1<<17 )
#define MASK_W_TRX_CFG_RX_ONOFF             ( 1<<18 )
#define MASK_W_TRX_CFG_RX_ANTSEL            ( 1<<19 )
#define MASK_W_TRX_CFG_RX_AGC_GAIN          ( 1<<20 )

/* Mask code Used for PHY_RF_CAL_W_TRX_FAST_CAL_REQ_STRU_usTxMask */
#define MASK_W_TRX_FAST_CAL_REQ_TXMASK_HDET     ( 1<<0 )
#define MASK_W_TRX_FAST_CAL_REQ_TXMASK_APT      ( 1<<1 )
#define MASK_W_TRX_FAST_CAL_REQ_TXMASK_VGA      ( 1<<2 )
#define MASK_W_TRX_FAST_CAL_REQ_TXMASK_DCOFFSET ( 1<<3 )

/* Mask code Used for PHY_RF_CAL_W_PD_PARA_CFG_REQ_STRU */
#define MASK_W_PD_PARA_CFG_THROUGH          ( 1<<0 )
#define MASK_W_PD_PARA_CFG_DC_OFFSET        ( 1<<1 )
#define MASK_W_PD_PARA_CFG_VGA              ( 1<<2 )

/* W Rx AGC GAIN COUNT */
#define W_RX_NOBLOCK_AGC_GAIN_COUNT         ( 8 )
#define W_RX_BLOCK_AGC_GAIN_COUNT           ( 8 )

#define W_TRX_MAX_STEP_COUNT                ( 16 )
#define W_TRX_MAX_SWEEP_FRAME_COUNT         ( 38 )  /* PCһ���·���UE�����ݰ����8K���� */
#define W_TRX_MAX_REPORT_COUNT              ( 900 ) /* DSPһ���ϱ���������������Rssi At1(0.125dBm)+Rssi At2(0.125dBm)+PD������� */

/* WģУ׼�ϱ�ʱ�ɹ�ʧ�ܱ�ʶ */
#define WPHY_TOOL_CAL_RESULT_RPT_SUCCESS    ( 0 )

/* Wģ��У׼��Ƶ�������� */
#define SELF_CAL_BAND_ID_MAX_COUNT          (10)

#define WG_BBP_RF_REG_WR_MAX_COUNT          ( 8 )
/*  G TRX CFG MARCO */
/* Mask code Used for RF_CAL_G_TX_PARA_CFG_REQ_STRU */
#define MASK_CAL_RF_G_TX_AFC                ( 1<<0 )  /* ���е���Ƶ�ʿ���ֵ */
#define MASK_CAL_RF_G_TX_ARFCN              ( 1<<1 )  /* ����Ƶ���Ƿ���Ч */
#define MASK_CAL_RF_G_TX_ONOFF              ( 1<<2 )  /* ���з��俪���Ƿ���Ч */
#define MASK_CAL_RF_G_TX_DATA_PATTERN       ( 1<<3 )  /* ���е����������Ƿ���Ч */
#define MASK_CAL_RF_G_TX_CFIX               ( 1<<4 )  /* ����Cfix�Ƿ���Ч */
#define MASK_CAL_RF_G_TX_SLOT_CFG           ( 1<<5 )  /* ���е�ʱ϶�����Ƿ���Ч */


/* Mask code Used for RF_CAL_G_RX_PARA_CFG_REQ_STRU */
#define MASK_CAL_RF_G_RX_ARFCN              ( 1<<0 )  /* �·�Ƶ�� */
#define MASK_CAL_RF_G_RX_MODE               ( 1<<1 )  /* �·�����ģʽ */
#define MASK_CAL_RF_G_RX_AGCMODE            ( 1<<2 )  /* �·�����ģʽ */
#define MASK_CAL_RF_G_RX_AGCGAIN            ( 1<<3 )  /* �·�AGC��λ */

/* Mask code User for PHY_RF_CAL_G_TX_FAST_CAL_REQ_STRU */
#define MASK_G_TX_FAST_CAL_REQ_TXMASK_APT   ( 1<<0 )  /* APTʹ��*/

#define G_TX_PARA_MAX_SLOT_CNT_PER_FRAME    ( 4 )

#define G_TX_MAX_STEP_COUNT                 ( 7 )       /* ��ǰֻ֧��4ʱ϶*/
#define G_TRX_MAX_SWEEP_FRAME_COUNT         ( 120 )
#define G_RX_MAX_STEP_COUNT                 ( 7 )
#define G_RX_MAX_RSSI_COUNT                 ( G_TRX_MAX_SWEEP_FRAME_COUNT * G_RX_MAX_STEP_COUNT )
#define G_RX_AGC_GAIN_COUNT                 ( 8 )
#define W_GAUGE_RESULT_SIZE                 ( 13 )      /* 32KУ׼�ϱ����ݸ��� */
/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/


/*****************************************************************************
 ö����    :PHY_TOOL_MSG_ID_ENUM_UINT16
 Э�����  :
 ASN.1���� :
 ö��˵��  :RF CAL MSG ID ENUM
*****************************************************************************/
enum PHY_TOOL_MSG_ID_ENUM
{
    /* WCDMA RF����У׼�ӿ�ԭ���б� */
    ID_TOOL_WPHY_CAL_TRX_FAST_CAL_REQ       = 0x1240,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_W_TRX_FAST_CAL_REQ_STRU */

    ID_TOOL_WPHY_CAL_PD_PARA_CFG_REQ        = 0x1241,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_PD_PARA_CFG_REQ_STRU */

    /* WCDMA RF��У׼�ӿ�ԭ���б� */
    ID_TOOL_WPHY_CAL_SELF_CAL_REQ           = 0x1242,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_W_SELF_CAL_REQ_STRU */

    /* WCDMA RF����У׼�ӿ�ԭ���б� */
    ID_TOOL_WPHY_CAL_TRX_PARA_CFG_REQ       = 0x1243,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_W_TRX_PARA_CFG_REQ_STRU */
    ID_TOOL_WPHY_CAL_RX_RSSI_MEAS_REQ       = 0x1244,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_W_RX_RSSI_MEAS_REQ_STRU */
    ID_WPHY_TOOL_GAUGE_REQ                  = 0x1245,                           /* _H2ASN_MsgChoice  WPHY_TOOL_GAUGE_REQ_STRU */

    /* W�Ĵ�����д�ӿ� */
    ID_TOOL_WPHY_WR_RFIC_REG_REQ             = 0x1246,
    ID_TOOL_WPHY_WR_BBP_REG_REQ              = 0x1247,

    ID_RRC_PHY_SWITCH_MOANT_IND             = 0x1250,                           /* _H2ASN_MsgChoice  RRC_PHY_SWITCH_MOANT_IND_STRU */

    /* W RFͨ��CNF */
    ID_WPHY_TOOL_CAL_RF_MSG_CNF             = 0x21F0,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_W_RF_MSG_CNF_STRU */

    ID_WPHY_TOOL_CAL_TX_POWER_DETECT_IND    = 0x21F1,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_W_RF_TX_PD_IND_STRU */
    ID_WPHY_TOOL_GAUGE_CNF                  = 0x21F2,                           /* _H2ASN_MsgChoice  WPHY_TOOL_GAUGE_CNF_STRU */
    ID_WPHY_TOOL_GAUGE_IND                  = 0x21F3,                           /* _H2ASN_MsgChoice  WPHY_TOOL_GAUGE_IND_STRU */

    ID_WPHY_TOOL_CAL_TRX_FAST_CAL_IND       = 0x21F4,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_W_TRX_FAST_CAL_IND_STRU */
    ID_WPHY_TOOL_CAL_SELF_CAL_IND           = 0x21F5,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_W_SELF_CAL_IND_STRU */

    ID_WPHY_TOOL_CAL_RX_RSSI_MEAS_IND       = 0x21F6,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_W_RX_RSSI_MEAS_IND_STRU */


    ID_WPHY_TOOL_R_RFIC_REG_IND              = 0x21F8,
    ID_WPHY_TOOL_R_BBP_REG_IND               = 0x21F9,


    /* GSM RF����У׼�ӿ�ԭ���б� */
    ID_TOOL_GPHY_CAL_RX_FAST_CAL_REQ        = 0x1740,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_G_RX_FAST_CAL_REQ_STRU */
    ID_TOOL_GPHY_CAL_TX_FAST_CAL_REQ        = 0x1741,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_G_TX_FAST_CAL_REQ_STRU */

    /* GSM ��У׼�ӿ�ԭ���б� */
    ID_TOOL_GPHY_CAL_SELF_CAL_REQ           = 0x1742,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_G_SELF_CAL_REQ_STRU */
    ID_TOOL_GPHY_CAL_RX_DCR_CAL_REQ         = 0x1743,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_G_RX_DCR_REQ_STRU */

    /* GSM RF����У׼�ӿ�ԭ���б� */
    ID_TOOL_GPHY_CAL_TX_PARA_CFG_REQ        = 0x1744,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_G_TX_PARA_CFG_REQ_STRU */
    ID_TOOL_GPHY_CAL_RX_PARA_CFG_REQ        = 0x1745,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_G_RX_PARA_CFG_REQ_STRU */
    ID_TOOL_GPHY_CAL_RX_RSSI_MEAS_REQ       = 0x1746,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_G_RX_RSSI_MEAS_REQ_STRU */

    ID_TOOL_GPHY_WR_RFIC_REG_REQ             = 0x1747,
    ID_TOOL_GPHY_WR_BBP_REG_REQ              = 0x1748,

    ID_MPH_SWITCH_M1XO_IND                  = 0x1753,                           /* _H2ASN_MsgChoice MPH_SWITCH_M1XO_IND_STRU */
    /* G RFͨ��CNF */
    ID_GPHY_TOOL_CAL_RF_MSG_CNF             = 0x7120,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_G_RF_MSG_CNF_STRU */

    ID_GPHY_TOOL_CAL_RX_FAST_CAL_IND        = 0x7121,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_G_RX_FAST_CAL_IND_STRU */

    ID_GPHY_TOOL_CAL_SELF_CAL_IND           = 0x7122,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_G_SELF_CAL_IND_STRU */
    ID_GPHY_TOOL_CAL_RX_DCR_CAL_IND         = 0x7123,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_G_RX_DCR_RPT_IND_STRU */
    ID_GPHY_TOOL_CAL_RX_RSSI_MEAS_IND       = 0x7124,                           /* _H2ASN_MsgChoice  PHY_RF_CAL_G_RX_RSSI_MEAS_IND_STRU */

    ID_GPHY_TOOL_R_RFIC_REG_IND              = 0x7126,
    ID_GPHY_TOOL_R_BBP_REG_IND               = 0x7127,

};
typedef UINT16 PHY_TOOL_MSG_ID_ENUM_UINT16;


/*****************************************************************************
 ö����    :RF_CAL_SELF_CAL_ERR_CODE_ENUM_UINT16
 Э�����  :
 ASN.1���� :
 ö��˵��  :��������У׼ʧ��ԭ��˵��
*****************************************************************************/
enum RF_CAL_SELF_CAL_ERR_CODE_ENUM
{
    RF_CAL_SELF_CAL_SUCCESS                               = 0,
    RF_CAL_SELF_CAL_FAIL                                  = 1,
    RF_CAL_SELF_CAL_IP2_MEM_ALLOC_FAIL                    = 2,                  /* IP2У׼ʱ,����uncache�ڴ�ʧ�� */
    RF_CAL_SELF_CAL_IP2_GREATER_THAN_FAIL_THRESHOLD       = 3,                  /* �Ҳ�������ʧ�����޵ĵ�,����ЩƵ���Ǻõ�,������˫������̫�� */
    RF_CAL_SELF_CAL_IP2_SAMPLE_DATA_FAIL                  = 4,                  /* ����ʧ��,˵��EDMAͨ������������� */
    RF_CAL_SELF_CAL_IQMISMATCH_CORR_FAIL                  = 5,                  /* BBP�������ʧ�� */
    RF_CAL_SELF_CAL_IQMISMATCH_OVER_CODE                  = 6,                  /* A,P,I,Q��������һ�����ֳ���[-64,63] */
    RF_CAL_SELF_CAL_DCR_CORR_FAIL                         = 7,                  /* DCR�������ʧ�� */
    RF_CAL_SELF_CAL_DCR_ITERATIVE_FAIL                    = 8,                  /* ����������Ȼ����������Ҫ��У׼ʧ�� */
    RF_CAL_SELF_CAL_BUTT
};
typedef UINT16 RF_CAL_SELF_CAL_ERR_CODE_ENUM_UINT16;


/*****************************************************************************
 ö����    :W_TX_RFIC_MODE_ENUM_UINT8
 Э�����  :
 ASN.1���� :
 ö��˵��  :RF CAL W TRX FAST ENUM
*****************************************************************************/
enum W_TX_RFIC_MODE_ENUM
{
    W_TX_RFIC_MODE_NORMAL              = 0,
    W_TX_RFIC_MODE_VOICE,
    W_TX_RFIC_MODE_BUTT
};
typedef UINT16 W_TX_RFIC_MODE_ENUM_UINT16;


/*****************************************************************************
 ö����    :W_TX_POWER_CTRL_MODE_ENUM_UINT16
 Э�����  :
 ASN.1���� :
 ö��˵��  :RF CAL W TRX FAST ENUM
*****************************************************************************/
enum W_TX_POWER_CTRL_MODE_ENUM
{
    W_TX_CAL_POWER_CTRL_POWER              = 0,
    W_TX_CAL_POWER_CTRL_POWER_ATTEN,
    W_TX_CAL_POWER_CTRL_REGISTER,
    W_TX_CAL_POWER_CTRL_BUTT
};
typedef UINT16 W_TX_POWER_CTRL_MODE_ENUM_UINT16;


/*****************************************************************************
 ö����    :W_FAST_STEP_WIDTH_ENUM_UINT16
 Э�����  :
 ASN.1���� :
 ö��˵��  :RF CAL W TRX FAST ENUM
*****************************************************************************/

enum W_FAST_STEP_WIDTH_ENUM
{
    WIDTH_2MS                               = 2,
    WIDTH_10MS                              = 10,
    WIDTH_20MS                              = 20,
    WIDTH_BUTT
};
typedef UINT16 W_FAST_STEP_WIDTH_ENUM_UINT16;

/* W PAģʽ */
enum  W_TX_PA_MODE_ENUM
{
    PA_MODE_AUTO  = 0,
    PA_MODE_HIGH,
    PA_MODE_MID,
    PA_MODE_LOW,
    PA_MODE_BUTT
};

enum  W_RX_ANT_ENUM
{
    W_RX_ANT1 = 1,  // main ant
    W_RX_ANT2 = 2,  // diversity ant
    W_RX_BUTT
};

/* W Rx �ز�ģʽ 0:���ز�, 1:˫�ز� */
enum  W_RX_CARRIER_MODE_ENUM
{
    W_RX_CARRIER_MODE_SC = 0,
    W_RX_CARRIER_MODE_DC = 1,
};

/* W Rx BLOCKģʽ 0: No Block,   1:Block; */
enum W_RX_BLOCK_MODE_ENUM
{
    W_RX_WITHOUT_BLOCK = 0,
    W_RX_WITH_BLOCK,
};

/* W Rx ��λ����ģʽ 0:��λ�Զ����� 1:��λǿ�� */
enum W_RX_AGC_CTRL_MODE_ENUM
{
    W_RX_AGC_CTRL_AUTO = 0,
    W_RX_AGC_CTRL_APPOINTED,
};

/*****************************************************************************
 ö����    :G_TX_MODULATION_TYPE_ENUM
 Э�����  :
 ASN.1���� :
 ö��˵��  :
*****************************************************************************/
enum G_TX_MODULATION_TYPE_ENUM
{
    MODE_GMSK                               = 0,
    MODE_8PSK                               = 1,
    MODE_BUTT
};
typedef UINT16 G_TX_MODULATION_TYPE_ENUM_UINT16;

/*****************************************************************************
 ö����    :G_TX_POWER_CTRL_MODE_ENUM_UINT16
 Э�����  :
 ASN.1���� :
 ö��˵��  :
*****************************************************************************/
enum G_TX_POWER_CTRL_MODE_ENUM
{
    G_TX_CAL_POWER_CTRL_TX_AGC                  = 0,
    G_TX_CAL_POWER_CTRL_POWER,
    G_TX_CAL_POWER_CTRL_POWER_ATTEN,
    G_TX_CAL_POWER_CTRL_REGISTER,
    G_TX_CAL_POWER_CTRL_BUTT
};
typedef UINT16 G_TX_POWER_CTRL_MODE_ENUM_UINT16;




enum G_RX_WAVE_TYPE_ENUM
{
    RX_BURST     = 0,
    RX_CONTINOUS = 1,
    RX_TYPE_BUTT
};

enum G_RX_MEAS_MODE_ENUM
{
    AGC_SLOW = 0,
    AGC_FAST = 1,
    AGC_BUTT
};

/*****************************************************************************
  4 ��Ϣͷ����
*****************************************************************************/


/*****************************************************************************
  5 ��Ϣ����
*****************************************************************************/


/*****************************************************************************
  6 STRUCT����
*****************************************************************************/
/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_W_TX_UPA_PARA_STRU
 Э�����  :
 �ṹ˵��  : WCDMA RF����У׼�ӿ� -- UPA���� ( ��ʱ�������� )
*****************************************************************************/
typedef struct
{
    /* ����Ĳ����Ƿ���UPA��Ҫʹ�õ� */
    UINT16                              usBec;
    UINT16                              usBed1;
    UINT16                              usBed2;
    UINT16                              usBc;
    UINT16                              usBd;
    UINT16                              usTxSlotFormat;     /* ����ģʽ:�������ʱ϶��ʽ */
    UINT16                              usTxChanNum;        /* ������� */
}PHY_RF_CAL_W_TX_UPA_PARA_STRU;

/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_W_TX_REG_CTRL_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    UINT16                              usRficGainCtrl;
    INT16                               sDbbAtten10th;
}PHY_RF_CAL_W_TX_REG_CTRL_STRU;

/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_W_TX_POWER_PARA_UNION
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef union
{
    INT16                               sTxPower10th;
    INT16                               sTxPowerAtten10th;
    PHY_RF_CAL_W_TX_REG_CTRL_STRU       stTxRegCtrlPara;
}PHY_RF_CAL_W_TX_POWER_PARA_UNION;


/*****************************************************************************
 �ṹ��    : W_RX_AGC_GAIN_CFG_STRU
 Э�����  :
 �ṹ˵��  : WCDMA RF������У׼�ӿ�Rx Agc Gain����λ����
            BIT[15] : 0:No Block�� 1:Block;
            BIt[14] : 0:���ز���   1��˫�ز�
            BIT[13] : 0:��λ�Զ����� 1:��λǿ��
            BIT[2:0]: 0:��һ��(������ߵ�),��������
*****************************************************************************/
typedef struct
{
    UINT16                              AgcGainLvl:3;
    UINT16                                        :5;
    UINT16                                        :5;
    UINT16                              GainLvlMode:1;  /* 0 - ��λ�Զ������� 1- ǿ�Ƶ�λ */
    UINT16                              CarrierMode:1;  /* 0 - ���ز��� 1 - ˫�ز� */
    UINT16                              BlockMode:1;    /* 0 - no block, 1 - block */
}W_RX_AGC_GAIN_CFG_STRU;

/*****************************************************************************
 �ṹ��    : W_TX_PA_PARA_CFG_STRU
 Э�����  :
 �ṹ˵��  : WCDMA RF����У׼�ӿ�
*****************************************************************************/
typedef struct
{
    UINT16                              ucPaVcc:8;                              /* PA Vcc �ĵ�ѹ������ */
    UINT16                              ucPaBias:8;                             /* PA Bias��ѹ�����֣�MMMB PAʱ��������Ч����ͨPAʱWDSPֱ�Ӷ������ֶ� */
}W_TX_PA_PARA_CFG_STRU;

typedef struct
{
    UINT16                              ucPdDcOffset:8;                          /* PD DCOFFSET��ֵ,ȡֵ��Χ[0,31] */
    UINT16                              ucPdVga:8;                               /* PD VGA��ֵ,����bit1��ʾ˥���Ƿ�򿪣�Bit[6:4]��ʾVGA��ȡֵ */
}W_TX_PD_PARA_CFG_STRU;

typedef struct
{
    UINT16                              ucRficMode:8;                             /* RFIC�Ĺ���ģʽ��0:����ģʽ��1:Voiceģʽ */ /*W_TX_RFIC_MODE_ENUM_UINT8*/
    UINT16                              ucTxPaMode:8;                             /* 0:�Զ�����;1:������;2:������;3:������ */
}W_TX_RFIC_PA_MODE_STRU;


typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* ԭ������ */
    UINT16                              usRsv;                                  /* ����λ   */

    UINT32                              ulMask;                                 /* ����λ������bitλ��ʾ������ֶ��Ƿ���Ч��bitλ��ӳ���ϵ�μ�MASK_W_TRX_CFG_* */

    /* Afc Para Cfg */
    UINT16                              usAfc;                                  /* AFC������ */
    UINT16                              usCfix;                                 /* DCXO Cfix �Ŀ����֣�ȡֵ��ΧΪ[0,15] */

    /* Tx Para Cfg */
    UINT16                              usTxBand;                               /* WģBAND:1��ʾBAND1,2��ʾBAND2,�������� */
    UINT16                              usTxChannel;                            /* WģTXƵ���,��BAND1��9750 */
    UINT16                              usTxEnable;                             /* 0:��ʹ��,1:ʹ�� */
    W_TX_RFIC_PA_MODE_STRU              stTxRficPaMode;
    W_TX_POWER_CTRL_MODE_ENUM_UINT16    usTxPowerCtrlMode;                      /* ���ʿ���ģʽ����unTxPowerParaʹ��ͬ�������롣
                                                                                    0������ģʽ����ʱunTxPowerPara.usTxPower10th��Ч��
                                                                                    1������˥��ģʽ����ʱunTxPowerPara.usTxPowerAtten10th��Ч��
                                                                                    2���Ĵ������Ʒ�ʽ����ʱunTxPowerPara.stTxRegCtrlPara��Ч��*/
    PHY_RF_CAL_W_TX_POWER_PARA_UNION    unTxPowerPara;                          /* ���ʿ��Ʋ�������ucTxPowerCtrlModeʹ��ͬ�������� */

    /* Pa Volt Para Cfg */
    W_TX_PA_PARA_CFG_STRU               stPaParaCfg;
    UINT16                              usSelfCal;                              /* ��У׼��Ŀ�����и�8bit�� 
                                                                                    0 - ����ģʽ�����ߴ���У׼ģʽ�ص�����ģʽ
                                                                                    1 - W IIP2��У׼����ģʽ����ʱ���߱�֤�·���Tx channel = Rx Channel 
                                                                                    2 - W IQ Mismatch��У׼ģʽ����ʱ���߱�֤�·���Rx Channel = Tx Channel
                                                                                    3 - G IQ Mismatch��У׼ģʽ��GSMģʽ�±�����ֻ��1���ŵ��ţ���ʱ��DSP�Լ�ѡ��
                                                                                        Tx Band��Tx channel
                                                                                        ����Tx Band���壺 0-GSM850,1-GSM900��2-DCS1800��3-PCS1900
                                                                                   ���е�8bit���壺
                                                                                   W IIP2У׼ģʽ�£�
                                                                                   0 - ����+�ּ�
                                                                                   1 - ����
                                                                                   W/G IQ MismatchУ׼ģʽ�£�
                                                                                   0 - feedback
                                                                                   1 - ֱ�ӷ��͵����߿�

                                                                                   ע�⣺����У׼ģʽ�£���������ҲӦ������������
                                                                                   ע�⣺�������У׼ģʽ���˵�����ģʽ��DSP��Ҫ��RFIC��BBP���û�����ģʽ
                                                                                */

    /* Rx Para Cfg */
    UINT16                              usRxBand;                               /* WģBAND:1��ʾBAND1,2��ʾBAND2,�������� */
    UINT16                              usRxChannel;                            /* WģRXƵ���,��BAND1��10700 */
    UINT16                              usRxCrossBand;                          /* ��Ƶ������Band��
                                                                                    ����û�ʹ�ܸ��ֶ�*����AGC������ΪusRxBand��Ӧ��AGC����
                                                                                    ������Band��Ƶ������ΪusRxCrossBand��usRxCrossChannel */
    UINT16                              usRxCrossChannel;                       /* ��Ƶ������Ƶ�� */

    UINT16                              usRxEnable;                             /* 0:��ʹ��,1:ʹ�� */
    UINT16                              usRxAntSel;                             /* 1:��������;2:�ּ����� */
    W_RX_AGC_GAIN_CFG_STRU              stRxAgcGain;                            /* BIT[15] : 0:No Block�� 1:Block;
                                                                                   BIt[14] : 0:���ز���   1��˫�ز�
                                                                                   BIT[13] : 0:��λ�Զ����� 1:��λǿ��
                                                                                   BIT[2:0]: 0:��һ��(������ߵ�),�������� */
    UINT16                              usRsv3;                                 /* �ṹ���� */

    /* ����Ĳ����Ƿ���UPA��Ҫʹ�õ�--Ϊ�˲�Ӱ�����е�AT����,���ڸýṹ�����������ر��� */
    UINT16                              usUpaEnable;                            /* LMT����UPA�źŴ򿪹ر�.0:�ر�;1:�� */
    UINT16                              usTxCarrMode;                           /* TX�ز�ģʽ.0:���ز�;1:˫�ز� */
    PHY_RF_CAL_W_TX_UPA_PARA_STRU       stPrimCarr;                             /* ���ز���صĲ��� */
    PHY_RF_CAL_W_TX_UPA_PARA_STRU       stSecondCarr;                           /* ���ز���صĲ��� */

}PHY_RF_CAL_W_TRX_PARA_CFG_REQ_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_W_PD_PARA_CFG_REQ_STRU
 Э�����  :
 �ṹ˵��  : W PD��������ԭ��
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* ԭ������ */
    UINT16                              usRsv;                                  /* ����λ */

    UINT16                              usMask;                                 /* refer to MASK_CAL_W_PD_* */

    /* PD Cfg */
    UINT16                              usPdInputThrough;                       /* 0 - �ر�PD�������źţ� 1 - ��PD�������ź� */
    W_TX_PD_PARA_CFG_STRU               stTxPdPara;                             /* PD VGA���� PD DC�Ĳ��� */
}PHY_RF_CAL_W_PD_PARA_CFG_REQ_STRU;

/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_W_RF_MSG_CNF_STRU
 Э�����  :
 �ṹ˵��  : W TRX ������У׼ͨ��CNF
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;
    UINT16                              usRecMsgID;                             /* ��Ӧ���·�Msg ID */
    UINT16                              usErrorCode;
}PHY_RF_CAL_W_RF_MSG_CNF_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_W_RF_TX_PD_IND_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv1;
    INT16                               sPdHkadc;
    UINT16                              usRsv2;
}PHY_RF_CAL_W_RF_TX_PD_IND_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_W_RX_RSSI_MEAS_REQ_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;
    UINT16                              usMeasNum;
    UINT16                              usInterval;
}PHY_RF_CAL_W_RX_RSSI_MEAS_REQ_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_W_RX_RSSI_MEAS_IND_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;
    INT16                               sRSSI;
    UINT16                              usAgcState;
}PHY_RF_CAL_W_RX_RSSI_MEAS_IND_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_W_SELF_CAL_REQ_STRU
 Э�����  : ��У׼��У׼���Band
 �ṹ˵��  : WCDMA RF Self Cal�ӿ�
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;
    UINT16                              usSelfCalMask;                          /* reference to MASK_SELF_CAL_* */
    UINT16                              usModemIndex;                           /* 0-modem0,1-modem1 */
    UINT32                              ulBandMask;                             /* ����Bitλ�ж��Ƿ�֧����ЩBand�����и���Msg ID�ж���W band����G Band */
    UINT32                              ulBandExtMask;                          /* ��չ�ã�ĿǰԤ�� */
}PHY_RF_CAL_W_SELF_CAL_REQ_STRU;


/*****************************************************************************
 �ṹ��    : NV_TX_IQ_MISMATCH_DCR_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    INT16                               sAmp;
    INT16                               sPhase;
    INT16                               sDci;
    INT16                               sDcq;
}NV_TX_IQ_MISMATCH_STRU;

/*****************************************************************************
 �ṹ��    : RESULT_TX_IQ_MISMATCH_DCR_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    INT16                               sAmpCorr;
    INT16                               sDcCorr;
}RESULT_TX_IQ_MISMATCH_STRU;

/*****************************************************************************
 �ṹ��    : RX_IQ_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    INT16                               sI;
    INT16                               sQ;
}RX_IQ_STRU;


/*****************************************************************************
 �ṹ��    : ANY_CARRIER_DC_OFFSET_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    RX_IQ_STRU                          stNoBlockDcOffset[W_RX_NOBLOCK_AGC_GAIN_COUNT];
    RX_IQ_STRU                          stBlockDcOffset[W_RX_BLOCK_AGC_GAIN_COUNT];
}ANY_CARRIER_DC_OFFSET_STRU;

/*****************************************************************************
 �ṹ��    : ANY_ANT_ANY_CARRIER_DC_OFFSET_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    ANY_CARRIER_DC_OFFSET_STRU          stCarrier[2];                                    /* ����0��ʾSC��1��ʾDC */
}ANY_ANT_ANY_CARRIER_DC_OFFSET_STRU;

/*****************************************************************************
 �ṹ��    : NV_W_RX_DCOFFSET_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    ANY_ANT_ANY_CARRIER_DC_OFFSET_STRU  stAnt[2];                                /* ����0��ʾAT1,1��ʾAT2 */
}NV_W_RX_DCOFFSET_STRU;

/*****************************************************************************
 �ṹ��    : RESULT_W_RX_DCOFFSET_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef NV_W_RX_DCOFFSET_STRU RESULT_W_RX_DCOFFSET_STRU;

/*****************************************************************************
 �ṹ��    : ANY_CHAN_W_RX_IP2_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    RX_IQ_STRU                          stDivOn;
    RX_IQ_STRU                          stDivOff;
}ANY_CHAN_W_RX_IP2_STRU;

/*****************************************************************************
 �ṹ��    : NV_W_RX_IP2_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    ANY_CHAN_W_RX_IP2_STRU              stChan[3];                                  /* 0�����ŵ���1�����ŵ���2�����ŵ� */
}NV_W_RX_IP2_STRU;

/*****************************************************************************
 �ṹ��    : W_RX_IMD2_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    INT16                               sIMD2;
    INT16                               sRsv;
}W_RX_IMD2_STRU;

/*****************************************************************************
 �ṹ��    : ANY_CHAN_W_RX_IMD2_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    W_RX_IMD2_STRU                      stDivOn;
    W_RX_IMD2_STRU                      stDivOff;
}ANY_CHAN_W_RX_IMD2_STRU;

/*****************************************************************************
 �ṹ��    : RESULT_W_RX_IP2_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    ANY_CHAN_W_RX_IMD2_STRU  stChan[3];                                  /* 0�����ŵ���1�����ŵ���2�����ŵ� */
}RESULT_W_RX_IP2_STRU;

/*****************************************************************************
 �ṹ��    : ANY_BAND_W_SELF_CAL_IND_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    UINT16                              usBandId;
    UINT16                              usRsv;
    NV_TX_IQ_MISMATCH_STRU              stNvTxIqMismatch;
    RESULT_TX_IQ_MISMATCH_STRU          stResultTxIqMismatch;
    NV_W_RX_DCOFFSET_STRU               stNvRxDcOffset;
    RESULT_W_RX_DCOFFSET_STRU           stResultRxDcOffset;
    NV_W_RX_IP2_STRU                    stNvRxIp2;
    RESULT_W_RX_IP2_STRU                stResultRxIp2;
}ANY_BAND_WG_SELF_CAL_IND_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_W_SELF_CAL_IND_STRU
 Э�����  : TDB����Ҫ֧�ֱ䳤
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;
    UINT16                              usErrCode;                              /* Reference to RF_CAL_SELF_CAL_* */
    UINT16                              usErrBand;                              /*���У׼ʧ�ܵ�Ƶ��*/
    UINT16                              usSelfCalMask;                          /*���DSP��У׼��*/
    UINT16                              usBandCnt;                              /*���DSPƵ�θ���*/
    ANY_BAND_WG_SELF_CAL_IND_STRU       astSelfCalRlt[SELF_CAL_BAND_ID_MAX_COUNT];
}PHY_RF_CAL_W_SELF_CAL_IND_STRU;

/*****************************************************************************
 �ṹ��    : ANY_STEP_PARA_STRU
 Э�����  :
 �ṹ˵��  : WCDMA RF����У׼����Step�Ĳ���
*****************************************************************************/
typedef struct
{
    W_RX_AGC_GAIN_CFG_STRU              stRxAgcGain;                            /* BIt[15] : 0: No Block,   1:Block;
                                                                                   BIT[14] : 0:���ز���     1:˫�ز�
                                                                                   BIT[13] : 0:��λ�Զ����� 1:��λǿ��
                                                                                   BIT[2:0]: 0:��һ��(������ߵ�)����������*/
    W_TX_RFIC_PA_MODE_STRU              stTxRficPaMode;
    PHY_RF_CAL_W_TX_POWER_PARA_UNION    unTxPowerPara;
    W_TX_PA_PARA_CFG_STRU               stPaParaCfg;
    W_TX_PD_PARA_CFG_STRU               stTxPdPara;                              /* PD VGA���� PD DC�Ĳ��� */
}ANY_STEP_PARA_STRU;


/*****************************************************************************
 �ṹ��    : W_TRX_FAST_FRAME_STRU
 Э�����  :
 �ṹ˵��  : WCDMA RF����У׼�ӿ�
*****************************************************************************/
typedef struct
{
    UINT16                              usBand;
    UINT16                              usStepCnt;                              /* [1, 16] */
    UINT16                              usTxArfcn;
    UINT16                              usRxArfcn;
    UINT16                              usTxStepPattern;
    UINT16                              usRxStepPattern;
    ANY_STEP_PARA_STRU                  astStepData[W_TRX_MAX_STEP_COUNT];
}W_TRX_FAST_FRAME_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_W_TRX_FAST_CAL_REQ_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;

    UINT16                              usTxMask;                               /* BIT[3]: PD DCOFFSET�Ƿ���Ч
                                                                                   BIT[2]: PD VGA�Ƿ���Ч
                                                                                   BIT[1]: APT�Ƿ���Ч
                                                                                   BIT[0]: PD����Ƿ�ʹ��*/ /* Reference to MASK_W_TRX_FAST_CAL_REQ_TXMASK_* */
    W_TX_POWER_CTRL_MODE_ENUM_UINT16    usTxPowerCtrlMode;                      /* ���ʿ���ģʽ����unTxPowerParaʹ��ͬ�������롣
                                                                                   0������ģʽ�� ��ʱunTxPowerPara.usTxPower10th��Ч��
                                                                                   1������˥��ģʽ����ʱunTxPowerPara.usTxPowerAtten10th��Ч��
                                                                                   2���Ĵ������Ʒ�ʽ����ʱunTxPowerPara.stTxRegCtrlPara��Ч��*/

    W_FAST_STEP_WIDTH_ENUM_UINT16       usStepWidthMs;                          /* Reference to W_FAST_STEP_WIDTH_ENUM */
    UINT16                              usRsv2;

    UINT16                              usTxFrameCnt;                           /* [1, W_TRX_MAX_SWEEP_FRAME_CNT] */
    UINT16                              usRxFrameCnt;                           /* [1, W_TRX_MAX_SWEEP_FRAME_CNT] */

    /* �ӿ��ĵ��а�����󳤶ȶ��壬���㲿��ֱ��ʹ�øýṹ�����ڴ棬
       ��Ϣ��ʵ�ʳ���Ϊ��Ч֡�� */
    W_TRX_FAST_FRAME_STRU               astSweepFrame[W_TRX_MAX_SWEEP_FRAME_COUNT];
}PHY_RF_CAL_W_TRX_FAST_CAL_REQ_STRU;



/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_W_TRX_FAST_CAL_IND_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;
    UINT16                              usRssiCnt;                              /* RSSI����ֵ�ĸ��� */
    UINT16                              usPowerDetectorCnt;

    /* �ӿ��ĵ��а�����󳤶ȶ��壬���㲿��ֱ��ʹ�øýṹ�����ڴ棬
       ��Ϣ��ʵ�ʳ���Ϊ��Ч֡�� */
    INT16                               asReportData[W_TRX_MAX_REPORT_COUNT];     /*Rssi At1(0.125dBm)+Rssi At2(0.125dBm)+PD������� */
}PHY_RF_CAL_W_TRX_FAST_CAL_IND_STRU;

/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_G_TX_REG_CTRL_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    UINT16                              usRficGainCtrl;                         /* RF Gain�Ŀ��ƼĴ���ֵ����RF Gain��BB Gain��϶��� */
    INT16                               sDbbAtten10th;                          /* Dbb��˥��ֵ��ȡֵ��Χ[-70,+10] */
}PHY_RF_CAL_G_TX_REG_CTRL_STRU;

/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_G_TX_POWER_PARA_UNION
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef union
{
    UINT16                              usTxAgc;                                /* ��ӦTx Vpa����ģʽ */
    INT16                               sTxPower10th;                           /* ��Ӧ����ģʽ */
    INT16                               sTxPowerAtten10th;                      /* ����˥��ģʽ */
    PHY_RF_CAL_G_TX_REG_CTRL_STRU       stTxRegCtrlPara;                        /* �Ĵ�������ģʽ */
}PHY_RF_CAL_G_TX_POWER_PARA_UNION;

/*****************************************************************************
 �ṹ��    : G_RF_SINGLE_SLOT_CFG_STRU
 Э�����  :
 �ṹ˵��  : G TX GSM RF����У׼�ӿ�
*****************************************************************************/
typedef struct
{
    UINT16                              ucTxModType:8;                          /* ������Ʒ�ʽ:0��ʾGMSK����;1��ʾ8PSK����  G_TX_MODULATION_TYPE_ENUM_UINT8 */
    UINT16                              ucTxPowerCtrlMode:8;                    /* ������Ʒ�ʽ��G_TX_POWER_CTRL_MODE_ENUM_UINT16
                                                                                    0��GMSK��ѹ����,�˷�ʽ��usTxVpaҪ���ã�
                                                                                    1�����ʿ���,�˷�ʽ��usTxPower10thҪ���ã�
                                                                                    2������˥��ģʽ���˷�ʽ��sTxPowerAtten10thҪ���ã�
                                                                                    3���Ĵ�������ģʽ���˷�ʽ��stTxRegCtrlParaҪ����*/
}G_TX_MODE_TYPE_POWER_CTRL_CFG_STRU;

typedef struct
{
    UINT16                              usTxMode;                               /* 0�� burst,1:Continue */
    G_TX_MODE_TYPE_POWER_CTRL_CFG_STRU  stTxModTypePowerCtrl;
    PHY_RF_CAL_G_TX_POWER_PARA_UNION    unTxPowerPara;

    UINT16                              usPaVcc;                                /* EDGE PA Vcc���Ƶ�ѹ��Ŀǰ��֧�� */
    UINT16                              usPaVramp;                              /* EDGE PA Vramp���Ƶ�ѹ���ڵ��Ʒ�ʽΪ8PSK���ǹ��ʿ���ģʽ����Ч */
    UINT16                              usPaGainIndex;                          /* linea pa��������( 0:auto,1:ultra high,2:high,3:mid,4:low ) */
    UINT16                              usRsv;                                  /* ���� */
}G_RF_SINGLE_SLOT_CFG_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_G_TX_PARA_CFG_REQ_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;

    UINT32                              ulMask;                                 /* Reference to MASK_CAL_RF_G_TX_* */
    UINT16                              usAfc;
    UINT16                              usCfix;                                 /* DCXO Cfix �Ŀ����� */
    UINT16                              usFreqNum;                              /* (Band << 12) | Arfcn */
    UINT16                              usTxEnable;                             /* ����ʹ�ܿ���:0x5555-ʹ�ܷ���;0xAAAA-ֹͣ����;TSC 0; */
    UINT16                              usDataPattern;                          /* 0��All 0��1��All 1��2��Random */
    UINT16                              usSlotCnt;                              /* ����ʱ϶��������Χ1~4��8,����ָ������ʹ����Щʱ϶��DSP�Զ�����1~4ʱ϶���� */
    G_RF_SINGLE_SLOT_CFG_STRU           astSlotCfg[G_TX_PARA_MAX_SLOT_CNT_PER_FRAME]; /* ÿ��ʱ϶��������� */
}PHY_RF_CAL_G_TX_PARA_CFG_REQ_STRU;

/*****************************************************************************
 �ṹ��    : G_SELF_CAL_RESULT_STRU
 Э�����  :
 �ṹ˵��  : GSM RF��У׼�ӿ�
             ����Gģ��У׼��Req�ӿ���Wģ��ͬ
*****************************************************************************/
typedef PHY_RF_CAL_W_SELF_CAL_REQ_STRU PHY_RF_CAL_G_SELF_CAL_REQ_STRU;

/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_G_SELF_CAL_IND_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef PHY_RF_CAL_W_SELF_CAL_IND_STRU PHY_RF_CAL_G_SELF_CAL_IND_STRU;

/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_G_RX_PARA_CFG_REQ_STRU
 Э�����  :
 �ṹ˵��  : G Rx
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv1;

    UINT16                              usMask;                                 /* Reference to MASK_CAL_RF_G_RX_* */
    UINT16                              usFreqNum;                              /* (Band << 12) | Arfcn */
    UINT16                              usRxMode;                               /* 0:burst����; 1:��������;Ŀǰֻ֧��burst���շ�ʽ */
    UINT16                              usAGCMode;                              /* Fast AGC,Slow AGC */
    UINT16                              usAGCGain;                              /* AGC��λ��0-��һ������ */
    UINT16                              usRsv2;
}PHY_RF_CAL_G_RX_PARA_CFG_REQ_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_G_RX_RSSI_MEAS_REQ_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv1;
    UINT16                              usMeasNum;
    UINT16                              usRsv2;
}PHY_RF_CAL_G_RX_RSSI_MEAS_REQ_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_G_RX_RSSI_MEAS_IND_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;
    INT16                               sRSSI;
    UINT16                              usRsv2;
}PHY_RF_CAL_G_RX_RSSI_MEAS_IND_STRU;

/*****************************************************************************
 �ṹ��    : G_RF_TX_STEP_STRU
 Э�����  :
 �ṹ˵��  : GSM RF����У׼֡�ṹ
*****************************************************************************/
typedef struct
{
    PHY_RF_CAL_G_TX_POWER_PARA_UNION    unTxPowerPara;
    UINT16                              usPaVcc;
    UINT16                              usPaVramp;                              /* EDGE Pa���Ƶ�ѹ */
    UINT16                              usPaGainIndex;                          /* linea pa��������( 0:auto,1:ultra high,2:high,3:mid,4:low ) */
}G_RF_TX_STEP_STRU;

/*****************************************************************************
 �ṹ��    : G_RF_TX_SEQUENCE_STRU
 Э�����  :
 �ṹ˵��  : GSM RF����У׼�ӿ�
*****************************************************************************/
typedef struct
{
    UINT16                              usChannel;
    UINT16                              usStepPattern;                          /* ��Bitλ��ʾ��ǰʱ϶�Ƿ��� */

    G_RF_TX_STEP_STRU                   astStepValue[G_TX_MAX_STEP_COUNT];        /*��ǰ���ֻ֧����ʱ϶*/
}G_RF_TX_SEQUENCE_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_G_TX_FAST_CAL_REQ_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;

    UINT16                              usTxMask;                               /* Bit[0]:APT�Ƿ���Ч
                                                                                ��MASKλMASK_G_TX_FAST_CAL_REQ_TXMASK_APT��ʾ*/

    G_TX_MODE_TYPE_POWER_CTRL_CFG_STRU  stTxModTypePowerCtrl;

    UINT16                              usFrameCnt;
    UINT16                              usRsv2;                                 /* ������չԤ�� */

    /* �ӿ��ĵ��а�����󳤶ȶ��壬���㲿��ֱ��ʹ�øýṹ�����ڴ棬
       ��Ϣ��ʵ�ʳ���Ϊ��Ч֡�� */
    G_RF_TX_SEQUENCE_STRU               astTxSequence[G_TRX_MAX_SWEEP_FRAME_COUNT];
}PHY_RF_CAL_G_TX_FAST_CAL_REQ_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_G_RF_MSG_CNF_STRU
 Э�����  :
 �ṹ˵��  : G TRX ������У׼ͨ��CNF
*****************************************************************************/
typedef PHY_RF_CAL_W_RF_MSG_CNF_STRU PHY_RF_CAL_G_RF_MSG_CNF_STRU;
typedef PHY_RF_CAL_W_RF_MSG_CNF_STRU PHY_RF_CAL_WG_RF_MSG_CNF_STRU;


/*****************************************************************************
 �ṹ��    : G_RF_RX_SEQUENCE_STRU
 Э�����  :
 �ṹ˵��  : G Rx
*****************************************************************************/
typedef struct
{
    UINT16                              usChannel;
    UINT16                              ausAgcGain[G_RX_MAX_STEP_COUNT];          /* ÿ֡������7��������λ */
}G_RF_RX_SEQUENCE_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_G_RX_FAST_CAL_REQ_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;

    UINT16                              usFrameCnt;                             /* ����֡�� */
    UINT16                              usRsv2;

    /* �ӿ��ĵ��а�����󳤶ȶ��壬���㲿��ֱ��ʹ�øýṹ�����ڴ棬
       ��Ϣ��ʵ�ʳ���Ϊ��Ч֡�� */
    G_RF_RX_SEQUENCE_STRU               astRxSequence[G_TRX_MAX_SWEEP_FRAME_COUNT];
}PHY_RF_CAL_G_RX_FAST_CAL_REQ_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_G_RX_FAST_CAL_IND_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv1;

    UINT16                              usRssiNum;                              /* �������������ΪG_RX_MAX_RSSI_CNT��,������ͬ��֡ */
    UINT16                              usRsv2;

    /* �ӿ��ĵ��а�����󳤶ȶ��壬���㲿��ֱ��ʹ�øýṹ�����ڴ棬
       ��Ϣ��ʵ�ʳ���Ϊ��Ч֡�� */
    INT16                               asRssiValue[G_RX_MAX_RSSI_COUNT];         /* ÿ֡�ϱ�7���㣬���G_RX_MAX_RSSI_CNT�� */
}PHY_RF_CAL_G_RX_FAST_CAL_IND_STRU;


/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_G_RX_DCR_START_REQ_STRU
 Э�����  :
 �ṹ˵��  : G Rx DCR
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv1;

    UINT16                              usBandMask;                             /* Bit0:GSM850; Bit1:GSM900; Bit2:DCS; Bit3:PCS; */
    UINT16                              usRsv2;
}PHY_RF_CAL_G_RX_DCR_REQ_STRU;

/*****************************************************************************
 �ṹ��    : NV_G_RX_DCOFFSET_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    INT16                               sInitDcocI;
    INT16                               sInitDcocQ;
    INT16                               sDcI;
    INT16                               sDcQ;
    INT16                               sRemainDcocI;
    INT16                               sRemainDcocQ;
}G_RX_DCR_STRU;

typedef struct
{
    G_RX_DCR_STRU                       astGain0[16];
}NV_G_RX_DCOFFSET_GAIN0_STRU;

typedef struct
{
    NV_G_RX_DCOFFSET_GAIN0_STRU         stGain0Dc;
    G_RX_DCR_STRU                       astOtherGainDc[G_RX_AGC_GAIN_COUNT - 1];
    NV_G_RX_DCOFFSET_GAIN0_STRU         stCrossBandGain0Dc;
    G_RX_DCR_STRU                       astCrossBandOtherGainDc[G_RX_AGC_GAIN_COUNT - 1];
}NV_G_RX_DCOFFSET_STRU;

/*****************************************************************************
 �ṹ��    : ANY_BAND_G_RX_DCOFFSET_IND_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    UINT16                              usBand;
    UINT16                              usRsv;

    NV_G_RX_DCOFFSET_STRU               stNvRxDcr;
}ANY_BAND_G_RX_DCOFFSET_IND_STRU;

/*****************************************************************************
 �ṹ��    : PHY_RF_CAL_G_RX_DCR_IND_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv1;

    UINT16                              usErrCode;                              /* Error code */
    UINT16                              usErrBand;                              /* ���У׼ʧ�ܵ�Ƶ�� */

    UINT16                              usBandCnt;
    UINT16                              usRsv2;

    /* �ӿ��ĵ��а�����󳤶ȶ��壬���㲿��ֱ��ʹ�øýṹ�����ڴ棬
       ��Ϣ��ʵ�ʳ���Ϊ��Ч֡�� */
    ANY_BAND_G_RX_DCOFFSET_IND_STRU     astBand[5];
}PHY_RF_CAL_G_RX_DCR_IND_STRU;

/*****************************************************************************
 �ṹ��    : WPHY_TOOL_GAUGE_REQ_STRU
 Э�����  :
 �ṹ˵��  : ����32K���������������ֹͣ
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;
    UINT32                              ulAction;                               /* 1-����32K����;0-ֹͣ32K���� */
}WPHY_TOOL_GAUGE_REQ_STRU;

/*****************************************************************************
 �ṹ��    : WPHY_TOOL_GAUGE_CNF_STRU
 Э�����  :
 �ṹ˵��  : ����32K���������������ֹͣ��ԭ��ظ�
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;
    UINT32                              ulAction;                               /* 1-����32K����;0-ֹͣ32K���� */
}WPHY_TOOL_GAUGE_CNF_STRU;

/*****************************************************************************
 �ṹ��    : WPHY_TOOL_GAUGE_IND_STRU
 Э�����  :
 �ṹ˵��  : ����32K����������ϱ�
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;
    UINT32                              aulData[W_GAUGE_RESULT_SIZE];
}WPHY_TOOL_GAUGE_IND_STRU;

/*****************************************************************************
 �ṹ��    : WR_REG_STRU
 Э�����  :
 �ṹ˵��  :
*****************************************************************************/
typedef struct
{
    UINT32                              ulRegAdd;
    UINT32                              ulRegValue;
}WR_REG_STRU;

/*****************************************************************************
 �ṹ��    : WPHY_RF_WR_RFIC_REG_REQ_STRU
 Э�����  :
 �ṹ˵��  : TOOLͨ��DSP��дRFIC�ļĴ�����Ҫ������/�������¾���Ч
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;

    UINT8                               ucWriteReadFlag;                        /* 0:Read����ʱ��Ҫ�ظ�CNF��IND */
    UINT8                               ucChannelNo;                            /* ��Ҫ��ȡRF��Ӧ��ͨ����:0:��ʾͨ��0,1:��ʾͨ��1 */
    UINT16                              usRegCnt;                               /* 1~1024 */

    /* �ӿ��ĵ��а�����󳤶ȶ��壬���㲿��ֱ��ʹ�øýṹ�����ڴ棬
       ��Ϣ��ʵ�ʳ���Ϊ��Ч֡�� */
    WR_REG_STRU                         astRegData[WG_BBP_RF_REG_WR_MAX_COUNT];
}WPHY_RF_WR_RFIC_REG_REQ_STRU;

/*****************************************************************************
 �ṹ��    : WPHY_RF_WR_RFIC_REG_IND_STRU
 Э�����  :
 �ṹ˵��  : TOOLͨ��DSP��дRFIC�ļĴ�����Ҫ������/�������¾���Ч
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;

    UINT16                              usWriteReadFlag;                        /* 0:Read */
    UINT16                              usRegCnt;                               /* 1~1024 */

    /* �ӿ��ĵ��а�����󳤶ȶ��壬���㲿��ֱ��ʹ�øýṹ�����ڴ棬
       ��Ϣ��ʵ�ʳ���Ϊ��Ч֡�� */
    WR_REG_STRU                         astRegData[WG_BBP_RF_REG_WR_MAX_COUNT];
}WPHY_RF_WR_RFIC_REG_IND_STRU;

/*****************************************************************************
 �ṹ��    : WPHY_RF_WR_BBP_REG_REQ_STRU
 Э�����  :
 �ṹ˵��  : TOOLͨ��BBP��дRFIC�ļĴ�����Ҫ������/�������¾���Ч
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;

    UINT16                              usWriteReadFlag;                        /* 0:Read����ʱ��Ҫ�ظ�CNF��IND
                                                                                   1:Write����ʱֻ��Ҫ�ظ�CNF*/
    UINT16                              usRegCnt;                               /* 1~1024 */

    /* �ӿ��ĵ��а�����󳤶ȶ��壬���㲿��ֱ��ʹ�øýṹ�����ڴ棬
       ��Ϣ��ʵ�ʳ���Ϊ��Ч֡�� */
    WR_REG_STRU                         astRegData[WG_BBP_RF_REG_WR_MAX_COUNT];
}WPHY_RF_WR_BBP_REG_REQ_STRU;

/*****************************************************************************
 �ṹ��    : WPHY_RF_WR_RFIC_REG_IND_STRU
 Э�����  :
 �ṹ˵��  : TOOLͨ��DSP��дBBP�ļĴ�����Ҫ������/�������¾���Ч
*****************************************************************************/
typedef struct
{
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* _H2ASN_Skip */ /* ԭ������ */
    UINT16                              usRsv;

    UINT16                              usWriteReadFlag;                        /* 0:Read */
    UINT16                              usRegCnt;                               /* 1~1024 */

    /* �ӿ��ĵ��а�����󳤶ȶ��壬���㲿��ֱ��ʹ�øýṹ�����ڴ棬
       ��Ϣ��ʵ�ʳ���Ϊ��Ч֡�� */
    WR_REG_STRU                         astRegData[WG_BBP_RF_REG_WR_MAX_COUNT];
}WPHY_RF_WR_RFIC_BBP_IND_STRU;

/*****************************************************************************
 �ṹ��    : GPHY_RF_WR_RFIC_REG_REQ_STRU
 Э�����  :
 �ṹ˵��  : TOOLͨ��DSP��дRFIC�ļĴ�����Ҫ������/�������¾���Ч
*****************************************************************************/
typedef  WPHY_RF_WR_RFIC_REG_REQ_STRU GPHY_RF_WR_RFIC_REG_REQ_STRU;


/*****************************************************************************
 �ṹ��    : GPHY_RF_WR_RFIC_REG_IND_STRU
 Э�����  :
 �ṹ˵��  : TOOLͨ��DSP��дRFIC�ļĴ�����Ҫ������/�������¾���Ч
*****************************************************************************/
typedef  WPHY_RF_WR_RFIC_REG_IND_STRU GPHY_RF_WR_RFIC_REG_IND_STRU;


/*****************************************************************************
 �ṹ��    : GPHY_RF_WR_BBP_REG_REQ_STRU
 Э�����  :
 �ṹ˵��  : TOOLͨ��BBP��дRFIC�ļĴ�����Ҫ������/�������¾���Ч
*****************************************************************************/
typedef WPHY_RF_WR_BBP_REG_REQ_STRU GPHY_RF_WR_BBP_REG_REQ_STRU;

/*****************************************************************************
 �ṹ��    : GPHY_RF_WR_RFIC_REG_IND_STRU
 Э�����  :
 �ṹ˵��  : TOOLͨ��DSP��дBBP�ļĴ�����Ҫ������/�������¾���Ч
*****************************************************************************/
typedef WPHY_RF_WR_RFIC_BBP_IND_STRU GPHY_RF_WR_RFIC_BBP_IND_STRU;


/*****************************************************************************
 �ṹ��    : MPH_SWITCH_M1XO_IND_STRU
 Э�����  :
 �ṹ˵��  : �ڷ�����BTʱ��������Ϣ֪ͨGPHY�л�UEģʽ������ȫ��ͨ���ԡ�
             0:modem1������tcxo1 1:modem1������tcxo0��
             ��Ϣ��Ҫ��LOAD PHY֮�����á�
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                                              /* ģ��Э��ջ����Ϣ������VOSͷ */
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* ԭ������ */
    UINT16                              usToolId;                                  /* ����λ */
    UINT16                              usUeMode;                               /* 0:modem1������tcxo1 1:modem1������tcxo0 */
    UINT16                              usResvered;
}MPH_SWITCH_M1XO_IND_STRU;

/*****************************************************************************
 �ṹ��    : RRC_PHY_SWITCH_MOANT_IND_STRU
 Э�����  :
 �ṹ˵��  : �ڷ�����BTʱ��������Ϣ֪ͨWPHY�л�UEģʽ������ȫ��ͨ���ԡ�
             0:w��Ƶ�ι����������� 1:W B8�����ڸ�����.
*****************************************************************************/
typedef struct
{
    VOS_MSG_HEADER                                                              /* ģ��Э��ջ����Ϣ������VOSͷ */
    PHY_TOOL_MSG_ID_ENUM_UINT16         usMsgID;                                /* ԭ������ */
    UINT16                              usToolId;                               /* ����λ */
    UINT16                              usUeMode;                               /* 0:w��Ƶ�ι����������� 1:W B8�����ڸ����� */
    UINT16                              usResvered;
}RRC_PHY_SWITCH_MOANT_IND_STRU;
#ifdef __cplusplus
    #if __cplusplus
        }
    #endif
#endif

#endif /* end of PhyRfCalInterface.h */
