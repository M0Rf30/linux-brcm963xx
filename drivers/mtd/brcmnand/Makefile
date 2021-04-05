#
# Makefile for the Broadcom NAND MTD
#

obj-$(CONFIG_MTD_BRCMNAND)		+=  bcm63xx-nand.o brcmnand_base.o brcmnand_bbt.o
## obj-$(CONFIG_MTD_BRCMNAND_EDU)		+= edu.o
obj-$(CONFIG_MTD_BRCMNAND_CORRECTABLE_ERR_HANDLING)	+= brcmnand_cet.o
EXTRA_CFLAGS	+= -I $(TOPDIR)/include/asm-generic -I$(INC_BRCMDRIVER_PUB_PATH)/$(BRCM_BOARD) -I$(INC_BRCMSHARED_PUB_PATH)/$(BRCM_BOARD)

## 20130822, TimLiu add ZyXEL compile flags
#ifdef VENDOR_ZYXEL
ifeq ($(strip ${ZYXEL}),y)
EXTRA_CFLAGS += -DZYXEL=1
ifneq ("$(strip ${ZYXEL_PRODUCT})","")
EXTRA_CFLAGS += -DZYPRJ_$(ZYXEL_PRODUCT)=1
endif
ifeq ($(strip ${ZYXEL_PARTITION}),y)
EXTRA_CFLAGS += -DZYXEL_PARTITION=1
endif
endif
