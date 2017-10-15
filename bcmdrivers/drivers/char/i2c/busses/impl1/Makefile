# File: bcmdrivers/broadcom/char/i2c/busses/Makefile
#
# Makefile for the BCM6816 I2C Adapter+Algorithm driver.
#

obj-$(CONFIG_BCM_I2C_BUS) += i2c_bcm6xxx.o

EXTRA_CFLAGS += -Ibcmdrivers/drivers/include/bcm963xx
EXTRA_CFLAGS += -I$(INC_BRCMBOARDPARMS_PATH)/bcm963xx
EXTRA_CFLAGS += -Ibcmdrivers/shared/include/bcm963xx
EXTRA_CFLAGS += -Werror
 
clean:
	rm -f core *.o *.a *.s .*.cmd *.ko

