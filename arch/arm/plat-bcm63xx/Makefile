# SHARED := ../../../../../../../src/shared

AFLAGS_plat-head.o        := -DTEXT_OFFSET=$(TEXT_OFFSET)

obj-y += clock.o
# it seems ARMv7 share the same headsmp.S file, if so, we should rename the
# current files
obj-$(CONFIG_SMP) += platsmp.o plat-ca9mp-headsmp.o
obj-$(CONFIG_HOTPLUG_CPU) += hotplug.o

obj-$(CONFIG_PLAT_CA9_MPCORE) += ca9mp_core.o
obj-$(CONFIG_PLAT_CA9_MPCORE_TIMER) += ca9mp_timer.o
obj-$(CONFIG_PLAT_B15_CORE) += b15_core.o
obj-$(CONFIG_CACHE_L310) += cache-l310.o
obj-$(CONFIG_PLAT_BCM63138) += bcm63138.o
obj-$(CONFIG_PLAT_BCM63148) += bcm63148.o
obj-$(CONFIG_PLAT_BCM63XX_EXT_TIMER) += bcm63xx_timer.o
obj-$(CONFIG_ARM_BCM63XX_CPUFREQ) += bcm63xx_cpufreq.o
obj-$(CONFIG_PLAT_BCM63XX_ACP) += bcm63xx_acp.o

obj-$(CONFIG_BCM_PCI) += pci-bcm63xx.o pcie-bcm63xx.o
obj-$(CONFIG_BCM_PCIE_PLATFORM) += bcm63xx_pcie.o
obj-$(CONFIG_USB_EHCI_HCD) += bcm63xx_usb.o 
obj-$(CONFIG_SATA_AHCI_PLATFORM) += bcm63xx_sata.o 
obj-$(CONFIG_BUZZZ) += buzzz.o
obj-$(CONFIG_PCI_MSI) += pcie-msi-bcm63xx.o
obj-$(CONFIG_BCM_M2M_DMA) += bcm63xx_m2mdma.o

EXTRA_CFLAGS    += -I$(INC_BRCMBOARDPARMS_PATH)/$(BRCM_BOARD) -I$(SRCBASE)/include -I$(INC_BRCMDRIVER_PUB_PATH)/$(BRCM_BOARD) -I$(INC_BRCMSHARED_PUB_PATH)/$(BRCM_BOARD) -I$(INC_BRCMSHARED_PUB_PATH)/pmc

## 20151208, TimLiu Add ZyXEL compile flags.
ifeq ($(strip ${ZYXEL}),y)
EXTRA_CFLAGS += -DZYXEL=1
ifneq ("$(strip ${ZYXEL_PRODUCT})","")
EXTRA_CFLAGS += -DZYPRJ_$(ZYXEL_PRODUCT)=1
endif
#__ZyXEL__, for ZyXEL hardware depend misc.
ifeq ($(strip ${ZYXEL_QTN_WIFI_5G_SUPPORT}),y)
EXTRA_CFLAGS += -DZYXEL_QTN_WIFI_5G_SUPPORT
endif
ifeq ($(strip ${ZYXEL_QTN_SW_RESET}),y)
EXTRA_CFLAGS += -DZYXEL_QTN_SW_RESET
endif
ifeq ($(strip ${ZYXEL_WPS_SPOTLIGHT}),y)
EXTRA_CFLAGS += -DZYXEL_WPS_SPOTLIGHT
endif
ifeq ($(strip ${ZYXEL_SFP_MODULE_SUPPORT}),y)
EXTRA_CFLAGS += -DZYXEL_SFP_MODULE_SUPPORT
endif
ifeq ($(strip ${ZYXEL_SFP_DETECT_PIN}),y)
EXTRA_CFLAGS += -DZYXEL_SFP_DETECT_PIN
endif
ifeq ($(strip ${ZYXEL_SFP_TX_FAULT_PIN}),y)
EXTRA_CFLAGS += -DZYXEL_SFP_TX_FAULT_PIN
endif
#ZYXEL USB3.0 or USB2.0 can be set by user manually
ifeq ($(strip ${ZYXEL_USB_SET_MANUALLY}),y)
EXTRA_CFLAGS += -DZYXEL_USB_SET_MANUALLY
endif
else
EXTRA_CFLAGS += -DZYXEL=0
endif
