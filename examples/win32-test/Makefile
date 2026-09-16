ifndef PATCH_COMPILER2
$(error "PATCH_COMPILER2 not defined")
endif

SRCS      := config.c hooks.cpp
PATCH_ASM := patch_def.asm
TARGET    := pe32

OUTDIR        := build
PACKAGES      := 1
OUTPUT_SYMBOL := win32_test_patch
ALLOW_OVERLAP := 1

.PHONY: all clean

all: patch-all

include $(PATCH_COMPILER2)/mk/patch.mk

clean: patch-clean
