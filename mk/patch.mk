PY3     ?= python3
OUTDIR  ?= build
TARGET  ?= elf64

PC2 := $(PY3) $(PATCH_COMPILER2)/tools/pc2.py

PC2_FLAGS := --outdir $(OUTDIR) --target $(TARGET)

ifdef V
PC2_FLAGS += -v
endif

ifdef PATCH_ASM
PC2_FLAGS += --patch-asm $(PATCH_ASM)
endif

ifdef BASE
PC2_FLAGS += --base $(BASE)
endif

ifneq ($(TARGET),pe32)
ifdef TEXT_BASE
PC2_FLAGS += --text $(TEXT_BASE)
endif
ifdef RODATA_BASE
PC2_FLAGS += --rodata $(RODATA_BASE)
endif
ifdef DATA_BASE
PC2_FLAGS += --data $(DATA_BASE)
endif
endif

ifdef OUTPUT_SYMBOL
PC2_FLAGS += --output-symbol $(OUTPUT_SYMBOL)
endif
ifdef PACKAGES
PC2_FLAGS += --packages
endif
ifdef ALLOW_OVERLAP
PC2_FLAGS += --allow-overlap
endif
ifdef PLATFORM_FORMAT
PC2_FLAGS += --format $(PLATFORM_FORMAT)
endif
ifdef FORMAT_SCRIPT
PC2_FLAGS += --format-script $(FORMAT_SCRIPT)
endif
ifdef NAME
PC2_FLAGS += --name "$(NAME)"
endif
ifdef APP_VER
PC2_FLAGS += $(foreach v,$(APP_VER),--app-ver "$(v)")
endif
ifdef APP_ELF
PC2_FLAGS += --app-elf "$(APP_ELF)"
endif
ifdef TITLE_ID
PC2_FLAGS += $(foreach id,$(TITLE_ID),--title-id "$(id)")
endif

.PHONY: patch-all patch-build patch-dump patch-clean

$(OUTDIR):
	mkdir -p $(OUTDIR)

patch-all patch-build: $(SRCS) $(PATCH_ASM) | $(OUTDIR)
	$(PC2) $(SRCS) $(PC2_FLAGS)

patch-clean:
	rm -rf $(OUTDIR)
