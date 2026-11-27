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

#pragma once

#include "filesystem/ext2.h"
#include "lib/shared.h"
#include "async/sync.h"
#include <cstdint>

/*
 * elf loader: 64-bit, little-endian, x86-64
 * handles ET_EXEC and ET_DYN (pie)
 * parse() checks one image, map() puts it in memory
 */
namespace ELF {

// limits so i can use plain arrs
constexpr int MAX_LOADS = 16;
constexpr int MAX_INTERP = 256;
constexpr int MAX_PH = 64;

// which spot to use for pie image
constexpr int PLACE_MAIN = 0;
constexpr int PLACE_INTERP = 1;

// one PT_LOAD seg (addrs NOT biased yet)
struct Seg {
  uint64_t vaddr = 0;
  uint64_t offset = 0;
  uint64_t filesz = 0;
  uint64_t memsz = 0;
  uint32_t flags = 0;
};

// result of parse(), all unbiased
struct Info {
  bool ok = false;
  bool isPie = false;       // true if ET_DYN
  uint64_t entry = 0;
  uint64_t phoff = 0;
  uint16_t phent = 0;
  uint16_t phnum = 0;

  bool hasPhdr = false;     // PT_PHDR showed up
  uint64_t phdrVaddr = 0;

  uint64_t lowAddr = 0;     // page aligned start of whole image
  uint64_t highAddr = 0;    // page aligned end of whole image

  int segCount = 0;
  Seg segs[MAX_LOADS];

  bool hasInterp = false;
  char interp[MAX_INTERP];

  bool hasStack = false;    // PT_GNU_STACK
  bool stackExec = false;

  bool hasRelro = false;    // PT_GNU_RELRO
  uint64_t relroVaddr = 0;
  uint64_t relroSize = 0;
};

//result of map(), real runtime addrs
struct Loaded {
  bool ok = false;
  uint64_t entry = 0;       // entry+bias (use for AT_ENTRY / rip)
  uint64_t bias = 0;        // 0 for ET_EXEC
  uint64_t phdr = 0;        // where prog headers in mem (AT_PHDR)
  uint16_t phent = 0;       // AT_PHENT
  uint16_t phnum = 0;       // AT_PHNUM
  uint64_t base = 0;        // lowest addr of image (AT_BASE for interp)
  uint64_t end = 0;         // end of image
};

// read+check one elf file, doesnt touch mem
extern sync<Info> parse(StrongRef<Node> file);

// map image using what parse() gave. place= PLACE_MAIN or PLACE_INTERP
extern sync<Loaded> map(StrongRef<Node> file, const Info &info, int place);

//old api for static exes (parse+map in one go, returns 0 on fail)
extern sync<uint64_t> load(StrongRef<Node> file);

} // namespace ELF
