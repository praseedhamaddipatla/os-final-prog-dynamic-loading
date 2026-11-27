#!/bin/bash
# builds the gcc made helper elfs into ../033.dir (run: ./build.sh)
set -e
cd "$(dirname "$0")"
OUT=../033.dir
COMMON="-O1 -nostdlib -ffreestanding -fno-stack-protector -mgeneral-regs-only -fno-asynchronous-unwind-tables -Wl,--build-id=none -Wl,-z,separate-code -Wl,-z,noexecstack -Wl,-z,norelro"
EXE="-static -fno-pie -no-pie"
PIE="-static-pie -fPIE -DEXPECT_PIE"

gcc $COMMON $EXE        -o $OUT/ok_exec           probe.c
gcc $COMMON $PIE        -o $OUT/ok_pie            probe.c
gcc $COMMON $EXE -DFAULT_RODATA   -o $OUT/fault_exec_rodata   probe.c
gcc $COMMON $EXE -DFAULT_TEXT     -o $OUT/fault_exec_text     probe.c
gcc $COMMON $EXE -DFAULT_NX_DATA  -o $OUT/fault_exec_nx_data  probe.c
gcc $COMMON $EXE -DFAULT_NX_BSS   -o $OUT/fault_exec_nx_bss   probe.c
gcc $COMMON $PIE -DFAULT_RODATA   -o $OUT/fault_pie_rodata    probe.c
gcc $COMMON $PIE -DFAULT_NX_DATA  -o $OUT/fault_pie_nx_data   probe.c

python3 mkelfs.py $OUT
