/*
 * elf parse + map (ELF::parse and ELF::map in structures/elf.cc)
 *
 * this whole test is just this one file. for every case init builds a tiny
 * elf image in memory, writes it to a file, forks and execves it. what we
 * expect depends on the kind of case:
 *
 *   OK      the program checks itself (seg contents, bss is zero, data is
 *           writable, it sits where the loader said it would) and exits 0
 *   SPREAD  a pie that exits with a number made from its own address. we run
 *           it 8 times and the number has to change (aslr works)
 *   FAULT   the program does something its seg perms dont allow (write to a
 *           read only page or to text, run code from data or bss). it has to
 *           die with SIGSEGV (wait4 status 11). if it lives it exits 42
 *   REJECT  the image breaks exactly ONE rule in ELF::parse so the kernel
 *           must refuse it. either execve returns an error or the kernel
 *           kills the child, both end up as exit code 127
 *
 * every image has the same shape: page 0 = headers (R), page 1 = code (RX),
 * and for some a data seg at +0x200000 (RW, 8 bytes in the file, 0x3000 in
 * memory, rest of the file page is 0xAA junk that has to read back as zero)
 *
 * the machine code blobs are tiny asm programs (see the comment on each one)
 */

#include <fcntl.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

// set these to 0 when testing on a normal linux box or if ASLR_ON is false in aslr.h
#ifndef CHECK_BASE
#define CHECK_BASE 1   // pie has to land at MAIN_BASE + slide
#endif
#ifndef CHECK_ASLR
#define CHECK_ASLR 1   // aslr_spread: address has to change between runs
#endif
#ifndef DIR_PREFIX
#define DIR_PREFIX "/" // where the generated files go
#endif

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

#define PAGE 0x1000UL
#define IMG_MAX 0x4000UL
#define MAIN_BASE 0x555555554000UL // has to match MAIN_BASE in elf.cc
#define SLIDE_MAX 0x40000000UL     // 2^18 pages, has to match SLIDE_PAGES in elf.cc
#define VA_END (1UL << 47)

#define ET_EXEC 2
#define ET_DYN 3
#define PT_LOAD 1
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_PHDR 6
#define PT_GNU_STACK 0x6474e551UL
#define PT_GNU_RELRO 0x6474e552UL
#define PF_X 1
#define PF_W 2
#define PF_R 4

#define OK 0
#define REJECT 1
#define FAULT 2
#define SPREAD 3

/* ---------------------------------------------------------------- machine code */

// xor edi,edi; mov eax,60; syscall  (just exit(0))
static const u8 exit0Code[] = {0x31, 0xff, 0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05};

// checks that rip is in [EXPECT, EXPECT+LIMIT), then data seg has the 8 byte magic,
// the junk after it reads as 0 (partial page zeroing), bss pages are 0, data and
// bss are writable, and the header page is readable. exit code says which check broke
// (1 = address, 2..6 = the others). EXPECT and LIMIT get patched in at runtime
static const u8 gapCode[] = {
    0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0xbb, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x48, 0x29, 0xd8, 0x48, 0xb9, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x48, 0x39, 0xc8, 0x73, 0x78, 0x48,
    0x8d, 0x1d, 0xd6, 0xef, 0x1f, 0x00, 0x48, 0xb8, 0x88, 0x77, 0x66, 0x55,
    0x44, 0x33, 0x22, 0x11, 0x48, 0x39, 0x03, 0x75, 0x69, 0x48, 0x83, 0x7b,
    0x08, 0x00, 0x75, 0x69, 0x48, 0x83, 0xbb, 0xf8, 0x0f, 0x00, 0x00, 0x00,
    0x75, 0x5f, 0x48, 0x83, 0xbb, 0x00, 0x10, 0x00, 0x00, 0x00, 0x75, 0x5c,
    0x48, 0x83, 0xbb, 0xf8, 0x2f, 0x00, 0x00, 0x00, 0x75, 0x52, 0x48, 0xc7,
    0x43, 0x10, 0x34, 0x12, 0x00, 0x00, 0x48, 0x81, 0x7b, 0x10, 0x34, 0x12,
    0x00, 0x00, 0x75, 0x47, 0x48, 0xc7, 0x83, 0xf8, 0x2f, 0x00, 0x00, 0x78,
    0x56, 0x00, 0x00, 0x48, 0x81, 0xbb, 0xf8, 0x2f, 0x00, 0x00, 0x78, 0x56,
    0x00, 0x00, 0x75, 0x2f, 0x48, 0x8d, 0x0d, 0x71, 0xef, 0xff, 0xff, 0x81,
    0x39, 0x7f, 0x45, 0x4c, 0x46, 0x75, 0x27, 0x31, 0xff, 0xeb, 0x28, 0xbf,
    0x01, 0x00, 0x00, 0x00, 0xeb, 0x21, 0xbf, 0x02, 0x00, 0x00, 0x00, 0xeb,
    0x1a, 0xbf, 0x03, 0x00, 0x00, 0x00, 0xeb, 0x13, 0xbf, 0x04, 0x00, 0x00,
    0x00, 0xeb, 0x0c, 0xbf, 0x05, 0x00, 0x00, 0x00, 0xeb, 0x05, 0xbf, 0x06,
    0x00, 0x00, 0x00, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05,
};
// exits with ((rip >> 12) & 0x3f) + 1
static const u8 aslrCode[] = {
    0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0xc1, 0xe8, 0x0c, 0x83,
    0xe0, 0x3f, 0x8d, 0x78, 0x01, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05,
};
// writes to the header page (read only)
static const u8 roCode[] = {
    0x48, 0x8d, 0x05, 0xf9, 0xef, 0xff, 0xff, 0xc6, 0x00, 0x00, 0xbf, 0x2a,
    0x00, 0x00, 0x00, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05,
};
// writes to its own code page (r-x)
static const u8 textCode[] = {
    0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00, 0xc6, 0x00, 0x90, 0xbf, 0x2a,
    0x00, 0x00, 0x00, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05,
};
// calls the first byte of the data seg (which is a ret, but data isnt executable)
static const u8 nxDataCode[] = {
    0x48, 0x8d, 0x05, 0xf9, 0xef, 0x1f, 0x00, 0xff, 0xd0, 0xbf, 0x2a, 0x00,
    0x00, 0x00, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05,
};
// writes a ret into bss and calls it (bss isnt executable)
static const u8 nxBssCode[] = {
    0x48, 0x8d, 0x05, 0xf9, 0xef, 0x1f, 0x00, 0xc6, 0x80, 0x00, 0x10, 0x00,
    0x00, 0xc3, 0x48, 0x8d, 0x80, 0x00, 0x10, 0x00, 0x00, 0xff, 0xd0, 0xbf,
    0x2a, 0x00, 0x00, 0x00, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05,
};
#define GAP_EXPECT_OFF 9
#define GAP_LIMIT_OFF 22

/* ---------------------------------------------------------------- elf builder */

struct Ph {
  u32 type, flags;
  u64 off, vaddr, filesz, memsz, align;
};

struct Blob {
  u64 off;
  const u8 *data;
  u64 len;
};

// everything about the image we are building
static struct {
  u8 ident[16];
  u16 type, machine, phentsize;
  int phnum;       // what the header says (< 0 = the real count)
  u64 entry, phoff;
  int count;       // real number of program headers
  struct Ph ph[72];
  struct Blob blobs[8];
  int nblobs;
  long size;       // file size override (< 0 = natural size)
  const u8 *raw;   // not an elf at all, just these bytes
  u64 rawLen;
} s;

static u8 img[IMG_MAX];
static u8 gapBuf[sizeof(gapCode)];
static u8 dataBuf[PAGE];
static u8 longInterp[257];
static const u8 *code = exit0Code;
static u64 codeLen = sizeof(exit0Code);

static void put16(u8 *p, u64 v) { p[0] = (u8)v; p[1] = (u8)(v >> 8); }
static void put32(u8 *p, u64 v) { put16(p, v); put16(p + 2, v >> 16); }
static void put64(u8 *p, u64 v) { put32(p, v); put32(p + 4, v >> 32); }

static void ph(u32 type, u32 flags, u64 off, u64 vaddr, u64 filesz, u64 memsz, u64 align) {
  struct Ph *p = &s.ph[s.count++];
  p->type = type;
  p->flags = flags;
  p->off = off;
  p->vaddr = vaddr;
  p->filesz = filesz;
  p->memsz = memsz;
  p->align = align;
}

// same as ph() but puts it at the front of the table
static void phFront(u32 type, u32 flags, u64 off, u64 vaddr, u64 filesz, u64 memsz, u64 align) {
  int i;
  for (i = s.count; i > 0; i--) s.ph[i] = s.ph[i - 1];
  s.count++;
  s.ph[0].type = type;
  s.ph[0].flags = flags;
  s.ph[0].off = off;
  s.ph[0].vaddr = vaddr;
  s.ph[0].filesz = filesz;
  s.ph[0].memsz = memsz;
  s.ph[0].align = align;
}

static void blob(u64 off, const u8 *data, u64 len) {
  s.blobs[s.nblobs].off = off;
  s.blobs[s.nblobs].data = data;
  s.blobs[s.nblobs].len = len;
  s.nblobs++;
}

static void reset(void) {
  int i;
  for (i = 0; i < (int)sizeof(s); i++) ((u8 *)&s)[i] = 0;
  s.ident[0] = 0x7f;
  s.ident[1] = 'E';
  s.ident[2] = 'L';
  s.ident[3] = 'F';
  s.ident[4] = 2; // 64 bit
  s.ident[5] = 1; // little endian
  s.ident[6] = 1;
  s.machine = 62;
  s.phentsize = 56;
  s.phnum = -1;
  s.phoff = 64;
  s.size = -1;
}

// the standard image: header page (R) + code page (RX). code lands at v0 + 0x1000
static void base(u16 etype, u64 v0) {
  reset();
  s.type = etype;
  ph(PT_LOAD, PF_R, 0, v0, PAGE, PAGE, PAGE);
  ph(PT_LOAD, PF_R | PF_X, PAGE, v0 + PAGE, codeLen, codeLen, PAGE);
  blob(PAGE, code, codeLen);
  s.entry = v0 + PAGE;
}

// RW seg: 8 bytes in the file (the magic) then 0xAA junk to the end of the file page
static void addData(u64 v0, int firstByte) {
  int i;
  for (i = 0; i < (int)PAGE; i++) dataBuf[i] = 0xAA;
  put64(dataBuf, 0x1122334455667788UL);
  if (firstByte >= 0) dataBuf[0] = (u8)firstByte;
  ph(PT_LOAD, PF_R | PF_W, 0x2000, v0 + 0x200000, 8, 0x3000, PAGE);
  blob(0x2000, dataBuf, PAGE);
}

// base + data seg + the self checking program
static void gapElf(u16 etype, u64 v0, u64 expect, u64 limit) {
  int i;
  for (i = 0; i < (int)sizeof(gapCode); i++) gapBuf[i] = gapCode[i];
  put64(gapBuf + GAP_EXPECT_OFF, expect);
  put64(gapBuf + GAP_LIMIT_OFF, limit);
  code = gapBuf;
  codeLen = sizeof(gapCode);
  base(etype, v0);
  addData(v0, -1);
}

// pie version, the address check only happens if CHECK_BASE
static void pieElf(u64 v0) {
  if (CHECK_BASE) gapElf(ET_DYN, v0, MAIN_BASE + PAGE, SLIDE_MAX + 0x100);
  else gapElf(ET_DYN, v0, 0, ~0UL);
}

// base + data seg + one of the fault programs
static void faultElf(u16 etype, u64 v0, const u8 *c, u64 n, int dataFirstByte) {
  code = c;
  codeLen = n;
  base(etype, v0);
  addData(v0, dataFirstByte);
}

// a valid PT_INTERP (or a broken one) on top of the standard pie
static void interp(const u8 *str, u64 len, u64 off, u64 filesz, int times) {
  int i;
  base(ET_DYN, 0);
  blob(off < 0x10000 ? off : 0x1100, str, len);
  for (i = 0; i < times; i++) ph(PT_INTERP, PF_R, off, 0x1100, filesz, filesz, 1);
}

// turns the spec into bytes in img, returns how long the file is
static u64 pack(void) {
  int i, j, cnt;
  u64 len;

  for (i = 0; i < (int)IMG_MAX; i++) img[i] = 0;

  if (s.raw) {
    for (i = 0; i < (int)s.rawLen; i++) img[i] = s.raw[i];
    return s.rawLen;
  }

  cnt = s.phnum < 0 ? s.count : s.phnum;
  for (i = 0; i < 16; i++) img[i] = s.ident[i];
  put16(img + 16, s.type);
  put16(img + 18, s.machine);
  put32(img + 20, 1);
  put64(img + 24, s.entry);
  put64(img + 32, s.phoff);
  put16(img + 52, 64);
  put16(img + 54, s.phentsize);
  put16(img + 56, (u64)cnt);

  // program header table always goes right after the elf header
  for (i = 0; i < s.count; i++) {
    u8 *p = img + 64 + 56 * i;
    put32(p, s.ph[i].type);
    put32(p + 4, s.ph[i].flags);
    put64(p + 8, s.ph[i].off);
    put64(p + 16, s.ph[i].vaddr);
    put64(p + 24, s.ph[i].vaddr);
    put64(p + 32, s.ph[i].filesz);
    put64(p + 40, s.ph[i].memsz);
    put64(p + 48, s.ph[i].align);
  }
  len = 64 + 56 * (u64)s.count;

  for (i = 0; i < s.nblobs; i++) {
    for (j = 0; j < (int)s.blobs[i].len; j++) img[s.blobs[i].off + j] = s.blobs[i].data[j];
    if (s.blobs[i].off + s.blobs[i].len > len) len = s.blobs[i].off + s.blobs[i].len;
  }

  if (s.size >= 0) len = (u64)s.size;
  return len;
}

/* ---------------------------------------------------------------- the cases */

// ok: segments, bss, bias
static void mk_ok_exec(void) { gapElf(ET_EXEC, 0x400000, 0x401000, 0x100); }          // normal static exe
static void mk_ok_exec_fixed(void) { gapElf(ET_EXEC, 0x10000000, 0x10001000, 0x100); } // no bias for ET_EXEC
static void mk_ok_pie_gap(void) { pieElf(0); }          // bias = MAIN_BASE (+ slide), hole between segs
static void mk_ok_pie_low(void) { pieElf(0x1000); }     // lowest vaddr isnt 0
static void mk_ok_pie_high(void) { pieElf(0x400000); }  // big lowest vaddr

// extra headers (PT_PHDR, PT_NOTE, PT_GNU_STACK, PT_GNU_RELRO, memsz 0 load) just get ignored
static void mk_ok_extras(void) {
  pieElf(0);
  phFront(PT_PHDR, PF_R, 64, 64, 56 * 8, 56 * 8, 8);
  ph(PT_NOTE, PF_R, 0x1000, 0x1000, 0, 0, 4);
  ph(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 16);
  ph(PT_GNU_RELRO, PF_R, 0x2000, 0x200000, PAGE, PAGE, 1);
  ph(PT_LOAD, PF_R, 0, 0x5000, 0, 0, PAGE);
}

// exactly MAX_LOADS (16) loads: header, code and 14 bss only pages
static void mk_ok_loads_16(void) {
  int i;
  base(ET_DYN, 0);
  for (i = 0; i < 14; i++) ph(PT_LOAD, PF_R | PF_W, PAGE, 0x3000 + i * PAGE, 0, PAGE, PAGE);
}

// exactly MAX_PH (64) program headers
static void mk_ok_phnum_64(void) {
  int i;
  base(ET_DYN, 0);
  for (i = 0; i < 62; i++) ph(PT_NOTE, PF_R, 0, 0, 0, 0, 4);
}

// aslr: exits with the page bits of its own address
static void mk_aslr_spread(void) {
  code = aslrCode;
  codeLen = sizeof(aslrCode);
  base(ET_DYN, 0);
}

// fault: segment perms from p_flags
static void mk_fault_exec_rodata(void) { faultElf(ET_EXEC, 0x400000, roCode, sizeof(roCode), -1); }
static void mk_fault_exec_text(void) { faultElf(ET_EXEC, 0x400000, textCode, sizeof(textCode), -1); }
static void mk_fault_exec_nx_data(void) { faultElf(ET_EXEC, 0x400000, nxDataCode, sizeof(nxDataCode), 0xc3); }
static void mk_fault_exec_nx_bss(void) { faultElf(ET_EXEC, 0x400000, nxBssCode, sizeof(nxBssCode), -1); }
static void mk_fault_pie_rodata(void) { faultElf(ET_DYN, 0, roCode, sizeof(roCode), -1); }
static void mk_fault_pie_nx_data(void) { faultElf(ET_DYN, 0, nxDataCode, sizeof(nxDataCode), 0xc3); }

// reject: one broken rule each (the standard pie with exit(0) code, then break 1 thing)
static void std0(void) { base(ET_DYN, 0); }

static void mk_bad_magic(void) { std0(); s.ident[0] = 0x7e; }
static void mk_bad_class32(void) { std0(); s.ident[4] = 1; }
static void mk_bad_endian(void) { std0(); s.ident[5] = 2; }
static void mk_bad_type_rel(void) { std0(); s.type = 1; }
static void mk_bad_type_core(void) { std0(); s.type = 4; }
static void mk_bad_machine(void) { std0(); s.machine = 183; }
static void mk_bad_phentsize(void) { std0(); s.phentsize = 32; }
static void mk_bad_phnum_zero(void) { std0(); s.phnum = 0; }
static void mk_bad_phnum_65(void) {   // 65 real headers, one too many
  int i;
  std0();
  for (i = 0; i < 63; i++) ph(PT_NOTE, PF_R, 0, 0, 0, 0, 4);
}
static void mk_bad_phoff_past_eof(void) { std0(); s.phoff = 0x100000; }
static void mk_bad_phtable_past_eof(void) { std0(); s.phoff = PAGE + sizeof(exit0Code) - 56; }
static void mk_bad_short_file(void) { std0(); s.size = 40; }
static void mk_bad_empty(void) { std0(); s.size = 0; }
static void mk_bad_text(void) {       // not an elf at all
  static const u8 text[] = "this is not an elf file, just some text. "
                           "this is not an elf file, just some text. "
                           "this is not an elf file, just some text. ";
  reset();
  s.raw = text;
  s.rawLen = sizeof(text) - 1;
}
static void mk_bad_filesz_gt_memsz(void) { std0(); s.ph[1].filesz = 0x20; s.ph[1].memsz = 0x10; }
static void mk_bad_offset_past_eof(void) { std0(); s.ph[1].off = 0x10000; }
static void mk_bad_data_past_eof(void) { std0(); s.ph[1].filesz = 0x5000; s.ph[1].memsz = 0x5000; }
static void mk_bad_misaligned(void) { std0(); s.ph[1].vaddr = 0x1010; }
static void mk_bad_vaddr_va_end(void) { std0(); s.ph[1].vaddr = VA_END; }
static void mk_bad_memsz_past_va_end(void) { std0(); s.ph[1].vaddr = VA_END - PAGE; s.ph[1].memsz = 0x2000; }
static void mk_bad_exec_low_vaddr(void) { base(ET_EXEC, 0); }  // ET_EXEC cant start below the first user page
static void mk_bad_overlap(void) { std0(); s.ph[0].memsz = 0x2000; }
static void mk_bad_order(void) {      // segs out of order
  struct Ph temp;
  std0();
  temp = s.ph[0];
  s.ph[0] = s.ph[1];
  s.ph[1] = temp;
}
static void mk_bad_align_not_pow2(void) { std0(); s.ph[1].align = 3; }
static void mk_bad_too_many_loads(void) {  // 17 loads, one too many
  int i;
  std0();
  for (i = 0; i < 15; i++) ph(PT_LOAD, PF_R | PF_W, PAGE, 0x3000 + i * PAGE, 0, PAGE, PAGE);
}
static void mk_bad_entry_outside(void) { std0(); s.entry = 0x10000; }
static void mk_bad_entry_at_end(void) { std0(); s.entry = 0x2000; }  // high end is exclusive
static void mk_bad_no_load(void) {
  std0();
  s.count = 0;
  ph(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 16);
  ph(PT_NOTE, PF_R, 0, 0, 0, 0, 4);
}
static void mk_bad_empty_load(void) {  // only a load with memsz 0
  std0();
  s.count = 0;
  ph(PT_LOAD, PF_R, 0, 0, 0, 0, PAGE);
}
static void mk_bad_interp_no_nul(void) { interp((const u8 *)"/lib/ld-no-nul.so", 17, 0x1100, 17, 1); }
static void mk_bad_interp_too_long(void) {
  int i;
  longInterp[0] = '/';
  for (i = 1; i < 256; i++) longInterp[i] = 'a';
  longInterp[256] = 0;
  interp(longInterp, 257, 0x1100, 257, 1);
}
static void mk_bad_interp_empty(void) { interp((const u8 *)"", 1, 0x1100, 1, 1); }
static void mk_bad_interp_two(void) { interp((const u8 *)"/lib/ld-a.so", 13, 0x1100, 13, 2); }
static void mk_bad_interp_past_eof(void) { interp((const u8 *)"/lib/ld-b.so", 13, 0x100000, 13, 1); }
static void mk_bad_interp_missing(void) {  // totally valid, but there is no such file
  interp((const u8 *)"/lib/ld-does-not-exist.so", 26, 0x1100, 26, 1);
}

/* ---------------------------------------------------------------- the table */

struct Case {
  const char *name;
  int kind;
  void (*make)(void);
};

static struct Case cases[] = {
    {"ok_exec", OK, mk_ok_exec},
    {"ok_exec_fixed", OK, mk_ok_exec_fixed},
    {"ok_pie_gap", OK, mk_ok_pie_gap},
    {"ok_pie_low", OK, mk_ok_pie_low},
    {"ok_pie_high", OK, mk_ok_pie_high},
    {"ok_extras", OK, mk_ok_extras},
    {"ok_loads_16", OK, mk_ok_loads_16},
    {"ok_phnum_64", OK, mk_ok_phnum_64},
    {"aslr_spread", SPREAD, mk_aslr_spread},
    {"fault_exec_rodata", FAULT, mk_fault_exec_rodata},
    {"fault_exec_text", FAULT, mk_fault_exec_text},
    {"fault_exec_nx_data", FAULT, mk_fault_exec_nx_data},
    {"fault_exec_nx_bss", FAULT, mk_fault_exec_nx_bss},
    {"fault_pie_rodata", FAULT, mk_fault_pie_rodata},
    {"fault_pie_nx_data", FAULT, mk_fault_pie_nx_data},
    {"bad_magic", REJECT, mk_bad_magic},
    {"bad_class32", REJECT, mk_bad_class32},
    {"bad_endian", REJECT, mk_bad_endian},
    {"bad_type_rel", REJECT, mk_bad_type_rel},
    {"bad_type_core", REJECT, mk_bad_type_core},
    {"bad_machine", REJECT, mk_bad_machine},
    {"bad_phentsize", REJECT, mk_bad_phentsize},
    {"bad_phnum_zero", REJECT, mk_bad_phnum_zero},
    {"bad_phnum_65", REJECT, mk_bad_phnum_65},
    {"bad_phoff_past_eof", REJECT, mk_bad_phoff_past_eof},
    {"bad_phtable_past_eof", REJECT, mk_bad_phtable_past_eof},
    {"bad_short_file", REJECT, mk_bad_short_file},
    {"bad_empty", REJECT, mk_bad_empty},
    {"bad_text", REJECT, mk_bad_text},
    {"bad_filesz_gt_memsz", REJECT, mk_bad_filesz_gt_memsz},
    {"bad_offset_past_eof", REJECT, mk_bad_offset_past_eof},
    {"bad_data_past_eof", REJECT, mk_bad_data_past_eof},
    {"bad_misaligned", REJECT, mk_bad_misaligned},
    {"bad_vaddr_va_end", REJECT, mk_bad_vaddr_va_end},
    {"bad_memsz_past_va_end", REJECT, mk_bad_memsz_past_va_end},
    {"bad_exec_low_vaddr", REJECT, mk_bad_exec_low_vaddr},
    {"bad_overlap", REJECT, mk_bad_overlap},
    {"bad_order", REJECT, mk_bad_order},
    {"bad_align_not_pow2", REJECT, mk_bad_align_not_pow2},
    {"bad_too_many_loads", REJECT, mk_bad_too_many_loads},
    {"bad_entry_outside", REJECT, mk_bad_entry_outside},
    {"bad_entry_at_end", REJECT, mk_bad_entry_at_end},
    {"bad_no_load", REJECT, mk_bad_no_load},
    {"bad_empty_load", REJECT, mk_bad_empty_load},
    {"bad_interp_no_nul", REJECT, mk_bad_interp_no_nul},
    {"bad_interp_too_long", REJECT, mk_bad_interp_too_long},
    {"bad_interp_empty", REJECT, mk_bad_interp_empty},
    {"bad_interp_two", REJECT, mk_bad_interp_two},
    {"bad_interp_past_eof", REJECT, mk_bad_interp_past_eof},
    {"bad_interp_missing", REJECT, mk_bad_interp_missing},
};

#define COUNT (int)(sizeof(cases) / sizeof(cases[0]))

/* ---------------------------------------------------------------- running them */

// writes the decimal digits of n at out, returns how many chars
static int digits(int n, char *out) {
  char rev[12];
  int len = 0, i;
  if (n == 0) rev[len++] = '0';
  while (n > 0) {
    rev[len++] = (char)('0' + n % 10);
    n = n / 10;
  }
  for (i = 0; i < len; i++) out[i] = rev[len - 1 - i];
  return len;
}

static int copy(char *to, const char *from) {
  int i = 0;
  while (from[i] != 0) {
    to[i] = from[i];
    i++;
  }
  return i;
}

// "<tag>: <name> (status <n>)" or without the status part if n < 0
static void report(const char *tag, const char *name, int status) {
  char line[128];
  int n = copy(line, tag);
  n += copy(line + n, name);
  if (status >= 0) {
    n += copy(line + n, " (status ");
    n += digits(status, line + n);
    line[n++] = ')';
  }
  line[n] = 0;
  puts(line);
}

// makes the file for this case, returns 0 if it worked
static int makeFile(const struct Case *c, char *path) {
  u64 len, done = 0;
  int fd, n;

  // directory + name (done in 2 steps on purpose, the order args get evaluated isnt guaranteed)
  n = copy(path, DIR_PREFIX);
  n += copy(path + n, c->name);
  path[n] = 0; // copy() doesnt put the \0 at the end

  code = exit0Code;
  codeLen = sizeof(exit0Code);
  c->make();
  len = pack();

  fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0755);
  if (fd < 0) return -1;
  while (done < len) {
    long got = write(fd, img + done, len - done);
    if (got <= 0) {
      close(fd);
      return -1;
    }
    done += (u64)got;
  }
  close(fd);
  return 0;
}

// runs the file in a child, returns the wait4 status or -1 if something broke
static int run(char *path) {
  int status = 0;
  long child = fork();
  if (child < 0) return -1;
  if (child == 0) {
    char *argv[] = {path, 0};
    char *envp[] = {0};
    execve(path, argv, envp);
    _exit(127); // execve came back, so the file was refused
  }
  if (wait4(child, &status, 0, 0) != child) return -1;
  return status;
}

#ifdef DUMP
// only for checking the builder on a normal machine: just writes all the files
int main(void) {
  char path[128];
  int i;
  for (i = 0; i < COUNT; i++) makeFile(&cases[i], path);
  return 0;
}
#else
int main(void) {
  int failed = 0;
  int i;

  for (i = 0; i < COUNT; i++) {
    char path[128];
    int status = -1;
    int good = 0;

    if (makeFile(&cases[i], path) == 0) status = run(path);

    if (cases[i].kind == SPREAD) {
      // aslr: run it a few more times, 2 different exit codes means the base moved
      int j, differ = 0;
      good = (status >= (1 << 8) && status <= (64 << 8));
      for (j = 0; j < 7; j++) {
        int again = run(path);
        if (again != status) differ = 1;
        if (again < (1 << 8) || again > (64 << 8)) good = 0;
      }
      if (CHECK_ASLR && !differ) good = 0;
    } else if (cases[i].kind == OK) {
      good = (status == 0);
    } else if (cases[i].kind == REJECT) {
      good = (status == (127 << 8));
    } else {
      good = (status == 11); // killed by SIGSEGV
    }

    if (good) {
      report("PASS: ", cases[i].name, -1);
    } else {
      report("FAIL: ", cases[i].name, status);
      failed++;
    }
  }

  if (failed == 0) {
    char line[128];
    int n = copy(line, "*** PASS: elf parse and map (");
    n += digits(COUNT, line + n);
    n += copy(line + n, " cases)");
    line[n] = 0;
    puts(line);
    return 0;
  }

  {
    char line[128];
    int n = copy(line, "*** FAIL: ");
    n += digits(failed, line + n);
    n += copy(line + n, " of ");
    n += digits(COUNT, line + n);
    n += copy(line + n, " cases failed");
    line[n] = 0;
    puts(line);
  }
  return 1;
}
#endif
