/**************************************************************
CAUTION : This file is Auto Generated by VBA based on *.xls.
          So, don't modify this file manually!
***************************************************************/
#ifndef UDP_IOS_AO_CONFIG_H_
#define UDP_IOS_AO_CONFIG_H_

/*���ùܽŸ��ù�ϵ���ڲ��������Լ���������*/
#define UDP_IOS_AO_CONFIG \
do{\
\
/*����PMU(13��PIN)*/\
    /*pmu_auxdac0_ssi�ܽŸ�������*/\
    OUTSET_IOS_AO_IOM_CTRL4;\
\
    /*pmu_auxdac1_ssi�ܽŸ�������*/\
    SET_IOS_PMU_AUXDAC1_SSI_CTRL1_1;\
    OUTSET_IOS_AO_IOM_CTRL5;\
    CLR_IOS_GPIO0_1_CTRL1_1;\
    /*pmu_auxdac1_ssi�ܽ�����������*/\
    NASET_IOS_AO_IOM_CTRL5;\
\
\
/*����USIM0��3��PIN��*/\
\
/*����USIM1(3��PIN��*/\
    /*gpio0[12]�ܽ�����������*/\
    PUSET_IOS_AO_IOM_CTRL16;\
\
\
/*����UART0��2��PIN��*/\
\
/*����GPIO(5��PIN��*/\
    /*gpio0[16]�ܽ�����������*/\
    NASET_IOS_AO_IOM_CTRL20;\
\
    /*gpio0[17]�ܽ�����������*/\
    PUSET_IOS_AO_IOM_CTRL21;\
\
    /*gpio0[18]�ܽ�����������*/\
    NASET_IOS_AO_IOM_CTRL22;\
\
    /*gpio0[19]�ܽ�����������*/\
    NASET_IOS_AO_IOM_CTRL23;\
\
\
/*����MMC1(6��PIN��*/\
    /*mmc1_clk�ܽŸ�������*/\
    SET_IOS_MMC1_CLK_CTRL1_1;\
    OUTSET_IOS_AO_IOM_CTRL24;\
    CLR_IOS_GPIO0_20_CTRL1_1;\
    /*mmc1_clk�ܽ�����������*/\
    NASET_IOS_AO_IOM_CTRL24;\
\
    /*mmc1_cmd�ܽŸ�������*/\
    SET_IOS_MMC1_CTRL1_1;\
    CLR_IOS_GPIO0_21_CTRL1_1;\
    /*mmc1_cmd�ܽ�����������*/\
    PUSET_IOS_AO_IOM_CTRL25;\
\
    /*mmc1_data[0]�ܽŸ�������*/\
    SET_IOS_MMC1_CTRL1_1;\
    CLR_IOS_GPIO0_22_CTRL1_1;\
    /*mmc1_data[0]�ܽ�����������*/\
    PUSET_IOS_AO_IOM_CTRL26;\
\
    /*mmc1_data[1]�ܽŸ�������*/\
    SET_IOS_MMC1_CTRL1_1;\
    CLR_IOS_GPIO0_23_CTRL1_1;\
    /*mmc1_data[1]�ܽ�����������*/\
    PUSET_IOS_AO_IOM_CTRL27;\
\
    /*mmc1_data[2]�ܽŸ�������*/\
    SET_IOS_MMC1_CTRL1_1;\
    CLR_IOS_GPIO0_24_CTRL1_1;\
    /*mmc1_data[2]�ܽ�����������*/\
    PUSET_IOS_AO_IOM_CTRL28;\
\
    /*mmc1_data[3]�ܽŸ�������*/\
    SET_IOS_MMC1_CTRL1_1;\
    CLR_IOS_GPIO0_25_CTRL1_1;\
    /*mmc1_data[3]�ܽ�����������*/\
    PUSET_IOS_AO_IOM_CTRL29;\
\
\
/*����JTAG_DFM_MODE(1��PIN��*/\
\
/*����HSIC��2��PIN��*/\
\
}while(0)

/*�ܽ����ú�for drv*/
#define UDP_IOS_CONFIG \
do{\
    UDP_IOS_AO_CONFIG;\
    UDP_IOS_PD_CONFIG;\
}while(0)

#endif
