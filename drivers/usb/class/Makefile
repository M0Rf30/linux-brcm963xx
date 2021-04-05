#
# Makefile for USB Class drivers
# (one step up from the misc category)
#

##20130822,TimLiu support USB LED
ifeq ($(strip $(ZYXEL)),y)
EXTRA_CFLAGS += -I$(INC_BRCMDRIVER_PUB_PATH)/$(BRCM_BOARD) -I$(INC_BRCMSHARED_PUB_PATH)/$(BRCM_BOARD)
EXTRA_CFLAGS += -DZYXEL=1
ifneq ("$(strip ${ZYXEL_PRODUCT})","")
EXTRA_CFLAGS += -DZYPRJ_$(ZYXEL_PRODUCT)=1
endif

endif

obj-$(CONFIG_USB_ACM)		+= cdc-acm.o
obj-$(CONFIG_USB_PRINTER)	+= usblp.o
obj-$(CONFIG_USB_WDM)		+= cdc-wdm.o
obj-$(CONFIG_USB_TMC)		+= usbtmc.o
