/* Copyright (C) 2026 Ahmed Gheith and contributors.
 *
 * Use restricted to classroom projects.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * elf parse + map (ELF::parse and ELF::map in structures/elf.cc)
 *
 * init forks a child for every file in the table below and execves it.
 * what we expect depends on the kind of file:
 *
 *   OK      the program checks itself (seg contents, bss is zero, data is
 *           writable, it sits where the loader said it would) and exits 0
 *   FAULT   the program does something its seg perms dont allow (write to
 *           rodata or text, run code from data or bss). it has to die with
 *           SIGSEGV (wait4 status 11). if it lives it exits 42
 *   REJECT  the file breaks exactly ONE rule in ELF::parse so the kernel
 *           must refuse it. either execve returns an error or the kernel
 *           kills the child, both end up as exit code 127
 *
 * files come from ../033.gen (build.sh + mkelfs.py). probe.c and gap.S in
 * there show what the OK programs check
 *
 *   ok_exec / ok_pie            gcc made, no libc: ET_EXEC and static pie
 *                               (pie has to land at 0x555555554000)
 *   ok_exec_fixed               ET_EXEC at 0x10000000, no bias
 *   ok_pie_gap                  pie w/ a hole + bss seg, the rest of the
 *                               page after .data has to be zeroed
 *   ok_pie_low / ok_pie_high    pie where lowest vaddr isnt 0 (bias math)
 *   ok_extras                   PT_PHDR, PT_NOTE, PT_GNU_STACK, PT_GNU_RELRO
 *                               and a memsz 0 PT_LOAD all get accepted
 *   ok_loads_16 / ok_phnum_64   the limits are inclusive
 *   fault_*                     seg perms come from p_flags
 *   bad_*                       one broken rule each
 */

#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#define OK 0
#define REJECT 1
#define FAULT 2

struct Case {
  const char *name;
  int kind;
};

static struct Case cases[] = {
    {"ok_exec", OK},
    {"ok_pie", OK},
    {"ok_exec_fixed", OK},
    {"ok_pie_gap", OK},
    {"ok_pie_low", OK},
    {"ok_pie_high", OK},
    {"ok_extras", OK},
    {"ok_loads_16", OK},
    {"ok_phnum_64", OK},
    {"fault_exec_rodata", FAULT},
    {"fault_exec_text", FAULT},
    {"fault_exec_nx_data", FAULT},
    {"fault_exec_nx_bss", FAULT},
    {"fault_pie_rodata", FAULT},
    {"fault_pie_nx_data", FAULT},
    {"bad_magic", REJECT},
    {"bad_class32", REJECT},
    {"bad_endian", REJECT},
    {"bad_type_rel", REJECT},
    {"bad_type_core", REJECT},
    {"bad_machine", REJECT},
    {"bad_phentsize", REJECT},
    {"bad_phnum_zero", REJECT},
    {"bad_phnum_65", REJECT},
    {"bad_phoff_past_eof", REJECT},
    {"bad_phtable_past_eof", REJECT},
    {"bad_short_file", REJECT},
    {"bad_empty", REJECT},
    {"bad_text", REJECT},
    {"bad_filesz_gt_memsz", REJECT},
    {"bad_offset_past_eof", REJECT},
    {"bad_data_past_eof", REJECT},
    {"bad_misaligned", REJECT},
    {"bad_vaddr_va_end", REJECT},
    {"bad_memsz_past_va_end", REJECT},
    {"bad_exec_low_vaddr", REJECT},
    {"bad_overlap", REJECT},
    {"bad_order", REJECT},
    {"bad_align_not_pow2", REJECT},
    {"bad_too_many_loads", REJECT},
    {"bad_entry_outside", REJECT},
    {"bad_entry_at_end", REJECT},
    {"bad_no_load", REJECT},
    {"bad_empty_load", REJECT},
    {"bad_interp_no_nul", REJECT},
    {"bad_interp_too_long", REJECT},
    {"bad_interp_empty", REJECT},
    {"bad_interp_two", REJECT},
    {"bad_interp_past_eof", REJECT},
    {"bad_interp_missing", REJECT},
};

#define COUNT (int)(sizeof(cases) / sizeof(cases[0]))

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

// runs one file in a child, returns the wait4 status or -1 if something broke
static int run(const char *name) {
  char path[64];
  int status = 0;
  path[0] = '/';
  copy(path + 1, name);
  path[1 + copy(path + 1, name)] = 0;

  long child = fork();
  if (child < 0) return -1;
  if (child == 0) {
    char *argv[] = {path, 0};
    char *envp[] = {0};
    execve(path, argv, envp);
    _exit(127); // execve came back, so the file was refused
  }
  if (wait4(child, &status, 0, NULL) != child) return -1;
  return status;
}

int main(void) {
  int failed = 0;
  int i;

  for (i = 0; i < COUNT; i++) {
    int status = run(cases[i].name);
    int good = 0;

    if (cases[i].kind == OK) {
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
