# Note: CONFIG_MIPS_BRCM is no longer defined with the new kernel...
# CONFIG_BCM_IN_KERNEL is not defined with the new...
# Ifs in Makefiles can’t do Ors...
# So cat strings together, and if one of them is 'y' ...
ifeq ($(CONFIG_MIPS_BRCM)$(CONFIG_BCM_IN_KERNEL),y)

# Linux
obj-y		+= boardparms.o bp_funcs.o

ifneq ($(strip $(BRCM_VOICE_SUPPORT)),)
obj-y		+= boardparms_voice.o
EXTRA_CFLAGS += -DCONFIG_BOARDPARMS_VOICE
endif

EXTRA_CFLAGS += -DCONFIG_BCM9$(BRCM_CHIP) -Ibcmdrivers/shared/include/bcm963xx -Ibcmdrivers/drivers/include/bcm963xx

ifeq ($(MOCA_LAN_DISCONN),y)
EXTRA_CFLAGS += -DCONFIG_NO_MOCA_LAN
endif

ifeq ($(MOCA_WAN_DISCONN),y)
EXTRA_CFLAGS += -DCONFIG_NO_MOCA_WAN
endif

-include $(TOPDIR)/Rules.make

endif


