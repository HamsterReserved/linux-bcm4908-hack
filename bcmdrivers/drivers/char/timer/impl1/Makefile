# File: bcmdrivers/opensource/char/timer
#
# Makefile for the BCM963xx external timer driver

obj-$(CONFIG_BCM_EXT_TIMER) += bcm963xx_timer.o

EXTRA_CFLAGS += -Ibcmdrivers/drivers/include/bcm963xx -Ibcmdrivers/shared/include/bcm963xx
EXTRA_CFLAGS += -Werror -Wfatal-errors

-include $(TOPDIR)/Rules.make

clean:
	rm -f core *.o *.a *.s

