dtb-y += PLK_CL00_VC_config.dtb
dtb-y += PLK_L01_VA_config.dtb
dtb-y += PLK_L01_VB_config.dtb
dtb-y += PLK_UL00_VA_config.dtb
dtb-y += PLK_AL10_VA_config.dtb
dtb-y += PLK_AL10_VC_config.dtb
dtb-y += PLK_L01_VC_config.dtb
dtb-y += PLK_AL10_VD_config.dtb
dtb-y += PLK_UL00_VE_config.dtb
dtb-y += PLK_UL00_VD_config.dtb
dtb-y += PLK_CL00_VB_config.dtb
dtb-y += PLK_L02_VB_config.dtb
dtb-y += PLK_CL00_VA_config.dtb
dtb-y += PLK_TL00_VA_config.dtb
dtb-y += PLK_TL00_VB_config.dtb
dtb-y += PLK_L02_VC_config.dtb
dtb-y += PLK_CL00_VD_config.dtb
dtb-y += PLK_TL00_VD_config.dtb
dtb-y += PLK_TL00H_VA_config.dtb
dtb-y += PLK_L02_VA_config.dtb
dtb-y += PLK_UL00_VB_config.dtb
dtb-y += PLK_AL10_VB_config.dtb
dtb-y += PLK_TL00_VC_config.dtb
dtb-y += PLK_TL00H_VB_config.dtb

targets += dtbs

dtbs: $(addprefix $(obj)/, $(dtb-y))
	$(Q)rm -f $(obj)/../*.dtb

clean-files := *.dtb
