.patch
.patch_title "win32 test patch"
.patch_note ""
.patch_author ""
.patch_version "1"
.code
.main

.addr function1
call function1

.addr function2
call function2

.addr g_config.threshold
.friendly "config threshold"
.long 42

.patch
.patch_title "win32 test patch 2"
.patch_note ""
.patch_author ""
.patch_version "1"
.code

.addr g_config.max_players
.friendly "max players"
.long 8
