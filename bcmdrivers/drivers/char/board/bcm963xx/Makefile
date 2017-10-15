# Makefile for the bcm963xx board drivers
#


obj-$(CONFIG_BCM_BOARD_API) := board.o bcm63xx_flash.o bcm63xx_led.o bcm63xx_gpio.o pushbutton.o

ifneq ($(strip $(CONFIG_COMPAT)),)
    obj-$(CONFIG_BCM_BOARD_API) += compat_board.o
endif

ifneq ($(strip $(BUILD_IEEE1905)),)
obj-$(CONFIG_BCM_BOARD_API) += ieee1905_module.o    
endif

ifneq ($(strip $(BUILD_6802_MOCA)),)
    obj-$(CONFIG_BCM_BOARD_API) += bbsi/bbsi.o
    obj-$(CONFIG_BCM_BOARD_API) += bbsi/bbsiExecSeq.o
    obj-$(CONFIG_BCM_BOARD_API) += moca/6802/init.o
else
    obj-$(CONFIG_BCM_BOARD_API) += spidevices.o
endif

ifneq ($(strip $(CONFIG_BCM_CPLD1)),)
    obj-$(CONFIG_BCM_BOARD_API) += bcmcpld1.o
	EXTRA_CFLAGS += -DCONFIG_BCM_CPLD1
endif

ifneq ($(strip $(CONFIG_MTD_NAND)),)
	EXTRA_CFLAGS += -DBUILD_NAND
endif

ifneq ($(strip $(CONFIG_BCM_PLC_BOOT)),)
    obj-$(CONFIG_BCM_BOARD_API) += homeplugd_module.o
endif

ifneq ($(strip $(subst ", ,$(BUILD_BRCM_XDSL_DISTPOINT))),)
    obj-$(CONFIG_BCM_BOARD_API) += dsldsp_operation.o
    obj-$(CONFIG_BCM_BOARD_API) += xdsl_distpoint.o
	EXTRA_CFLAGS += -DBRCM_XDSL_DISTPOINT
endif
ifneq ($(strip $(BUILD_BRCM_FTTDP)),)
	EXTRA_CFLAGS += -DBRCM_FTTDP
endif

ifeq ($(BUILD_IEEE1905),y)
	EXTRA_CFLAGS += -DSUPPORT_IEEE1905
endif
 
ifeq ($(strip $(BRCM_CHIP)),63268)
ifneq ($(strip $(BUILD_SECURE_BOOT)),)
ifeq ($(strip $(BUILD_NVRAM_3K)),y)
	EXTRA_CFLAGS += -DINC_BTRM_BOOT=1
endif
endif
endif
 
EXTRA_CFLAGS += -I. -Ibcmdrivers/drivers/include/bcm963xx -Ibcmdrivers/shared/include/bcm963xx -Ibcmdrivers/shared/include/bcm963xx -Ibcmdrivers/shared/include/../flash -Ibcmdrivers/shared/misc
EXTRA_CFLAGS += -Ibcmdrivers/shared/include/pmc
#EXTRA_CFLAGS += -Werror -Wfatal-errors
EXTRA_CFLAGS += -g

ifneq ($(strip $(CONFIG_BCM_WLAN)),)
	EXTRA_CFLAGS += -DWIRELESS
endif

-include $(TOPDIR)/Rules.make

clean:
	rm -f core *.o *.a *.s

