#
# Makefile for the bcm963xx PCIe host controller drivers
#  for ARM and MIPS based platforms with 4.1 kernel onwards
#

PCIE_HCD_PATH=bcmdrivers/bus/pci/host
EXTRA_CFLAGS += -I$(PCIE_HCD_PATH)/common
EXTRA_CFLAGS += -I. -Ibcmdrivers/drivers/include/bcm963xx -Ibcmdrivers/shared/include/bcm963xx -Ibcmdrivers/shared/boardparms/bcm963xx
EXTRA_CFLAGS += -Ibcmdrivers/shared/include/pmc

#
# ARM platforms
#
ifeq ($(filter y,$(CONFIG_ARM) $(CONFIG_ARM64)),)
else
EXTRA_CFLAGS += -I$(PCIE_HCD_PATH)/arm
obj-$(CONFIG_BCM_PCI) += arm/pcie-bcm963xx.o
ifeq ("$(CONFIG_ARM64)" ,"y")
#temporary until fill DT is implemented for arm64 platforms
obj-$(CONFIG_BCM_PCI) += ../../../../../../kernel/$(notdir $(KERNEL_DIR))/drivers/pci/setup-irq.o
endif
endif

obj-$(CONFIG_BCM_PCI) += common/pcie_common.o

-include $(TOPDIR)/Rules.make

clean:
	rm -f core *.o *.a *.s

