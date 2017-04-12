#KERNELSRC := ~/Work/android-kernel/nexus5/msm
#PWD := $(shell pwd)

ifeq ($(CONFIG_SEATTLE),y)
EXTRA_CFLAGS += -DPLATFORM_HI3XXX
endif

EXTRA_CFLAGS += -I$(KBUILD_SRC)/drivers/
obj-$(CONFIG_DTS_EAGLE) += dts_eagle_drv.o

#build:
#   make -C $(KERNELSRC) M=$(PWD) modules

#clean:
#   make -C $(KERNELSRC) M=$(PWD) clean

