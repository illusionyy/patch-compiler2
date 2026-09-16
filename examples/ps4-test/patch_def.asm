.patch_titleid "CUSA00000"
.patch_titleid "CUSA00001"

.patch
.patch_title "ps4 test patch"
.patch_note ""
.patch_author ""
.patch_version "1"
.patch_name "ps4-test"
.patch_app_ver "01.00"
.patch_app_ver "01.01"
.patch_app_elf "eboot.bin"
.patch_rodata_base 0x200000
.patch_data_base 0x300000
.code
.main

.addr 0x1266
call function1

.addr 0x1442
function2_hook:
call function2

.addr g_config.threshold
.friendly "config threshold"
.long 42

.patch
.patch_title "ps4 test patch 2"
.patch_note ""
.patch_author ""
.patch_version "1"
.patch_name ""
.patch_app_ver "01.00"
.patch_app_elf "eboot.bin"
.code

.addr g_config.max_players
.friendly "max players"
.byte 16
