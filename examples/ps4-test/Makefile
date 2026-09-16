ifndef PS4_PAYLOAD_SDK
$(error "PS4_PAYLOAD_SDK not defined")
endif

ifndef PATCH_COMPILER2
$(error "PATCH_COMPILER2 not defined")
endif

SRCS      := config.c hooks.cpp
PATCH_ASM := patch_def.asm

OUTDIR        := build
BASE          := auto
PACKAGES      := 1
OUTPUT_SYMBOL := ps4_test_patch
ALLOW_OVERLAP := 1
PLATFORM_FORMAT := ps4-xml
FORMAT_SCRIPT   := ../../template/formatters/ps4_xml.py

export PC2_CC            := $(PS4_PAYLOAD_SDK)/bin/clang
export PC2_CXX           := $(PS4_PAYLOAD_SDK)/bin/clang++
export PC2_LLD           := $(PS4_PAYLOAD_SDK)/bin/ld.lld
export PC2_OBJCOPY       := $(PS4_PAYLOAD_SDK)/bin/llvm-objcopy
export PC2_EXTRA_CFLAGS := -Os

.PHONY: all clean

all: patch-all

include $(PATCH_COMPILER2)/mk/patch.mk

clean: patch-clean
