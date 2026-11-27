/*
 * probe.c: tiny no-libc program used to build the gcc made test elfs
 * built a few ways (see build.sh): non-pie, static-pie, and "fault" versions
 * exit code 0 = all good, 1..7 = which check broke, 42 = a FAULT_ test
 * survived something that should have killed it
 */
#include <stdint.h>

#ifndef PIE_BASE
#define PIE_BASE 0x555555554000ull   // has to match MAIN_BASE in elf.cc
#endif

static void quit(int code) {
  long ret;
  asm volatile("syscall" : "=a"(ret) : "0"(60L), "D"((long)code) : "rcx", "r11", "memory");
  for (;;) {}
}

// lives in .rodata
static const char word[] = "elf-loader-rodata";

// lives in .data (has a real initial value in the file)
static volatile unsigned long magic = 0x1122334455667788ul;
static volatile unsigned char table[100] = {1, 2, 3, 4, 5};

// lives in .bss: must be all zero, even the part right after .data in the same page
static volatile unsigned char big[3 * 4096 + 123];
static volatile unsigned long small;

// bytes of a function that is just "ret", sits in .data / .bss for the NX tests
static volatile unsigned char ret_in_data[16] = {0xc3};
static volatile unsigned char ret_in_bss[16];

static int inRange(uintptr_t a) {
#ifdef EXPECT_PIE
  return a >= PIE_BASE && a < PIE_BASE + 0x100000;
#else
  return a >= 0x400000 && a < 0x1000000;
#endif
}

__attribute__((noinline, used)) int checks(void) {
  int i;
  // 1. rodata has the right bytes
  const char want[] = "elf-loader-rodata";
  for (i = 0; i < (int)sizeof(want); i++)
    if (word[i] != want[i]) return 1;

  // 2. data starts with its initial values
  if (magic != 0x1122334455667788ul) return 2;
  if (table[0] != 1 || table[4] != 5 || table[5] != 0) return 3;

  // 3. bss is all zeros (the first bytes share a page w/ .data and the file junk)
  for (i = 0; i < (int)sizeof(big); i++)
    if (big[i] != 0) return 4;
  if (small != 0) return 4;

  // 4. data and bss are writable, even across page edges
  magic = 5;
  if (magic != 5) return 5;
  for (i = 0; i < (int)sizeof(big); i++) big[i] = (unsigned char)(i + 1);
  for (i = 0; i < (int)sizeof(big); i++)
    if (big[i] != (unsigned char)(i + 1)) return 6;

  // 5. everything ended up where we expect (bias worked)
  if (!inRange((uintptr_t)&word[0]) || !inRange((uintptr_t)&magic) ||
      !inRange((uintptr_t)&big[0]) || !inRange((uintptr_t)&checks))
    return 7;
  return 0;
}

__attribute__((force_align_arg_pointer)) void _start(void) {
#if defined(FAULT_RODATA)
  *(volatile char *)&word[0] = 'X';          // rodata is read only -> SIGSEGV
  quit(42);
#elif defined(FAULT_TEXT)
  *(volatile unsigned char *)&checks = 0x90; // text is r-x -> SIGSEGV
  quit(42);
#elif defined(FAULT_NX_DATA)
  ((void (*)(void))ret_in_data)();           // data is not executable -> SIGSEGV
  quit(42);
#elif defined(FAULT_NX_BSS)
  ret_in_bss[0] = 0xc3;
  ((void (*)(void))ret_in_bss)();            // bss is not executable -> SIGSEGV
  quit(42);
#else
  quit(checks());
#endif
}
