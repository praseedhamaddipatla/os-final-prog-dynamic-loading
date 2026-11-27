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


 // minimal ELF loader, just enough to load user programs.
 //   - statically linked
 //   - no relocation
 //   - x86_64 only
 //   - minimal sanity checks
 //   - expects all segments to be properly aligned
 //   - ...
 //
 // Modify to your liking 

#include "pcb.h"
#include "elf.h"

#include "memory/physmem.h"
#include "lib/shared.h"
#include "memory/vmm.h"

namespace {

// elf consts
constexpr uint16_t ET_EXEC = 2;
constexpr uint16_t ET_DYN = 3;
constexpr uint16_t EM_X86_64 = 62;

constexpr uint32_t PT_LOAD = 1;
constexpr uint32_t PT_INTERP = 3;
constexpr uint32_t PT_PHDR = 6;
constexpr uint32_t PT_GNU_STACK = 0x6474e551;
constexpr uint32_t PT_GNU_RELRO = 0x6474e552;

constexpr uint32_t PF_X = 1;
constexpr uint32_t PF_W = 2;
constexpr uint32_t PF_R = 4;

// where pie stuff goes
//only pickBase() uses these so aslr can change later
constexpr uint64_t MAIN_BASE = 0x555555554000ull;
constexpr uint64_t INTERP_BASE = 0x7ffff7fc0000ull;

// raw elf header straight from file
struct [[gnu::packed]] RawHeader {
  uint8_t ident[16];
  uint16_t type;
  uint16_t machine;
  uint32_t version;
  uint64_t entry;
  uint64_t phoff;
  uint64_t shoff;
  uint32_t flags;
  uint16_t ehsize;
  uint16_t phentsize;
  uint16_t phnum;
  uint16_t shentsize;
  uint16_t shnum;
  uint16_t shstrndx;
};
static_assert(sizeof(RawHeader) == 64);

// raw prog header
struct [[gnu::packed]] RawPh {
  uint32_t type;
  uint32_t flags;
  uint64_t offset;
  uint64_t vaddr;
  uint64_t paddr;
  uint64_t filesz;
  uint64_t memsz;
  uint64_t align;
};
static_assert(sizeof(RawPh) == 56);

uint64_t roundDown(uint64_t x) { return x & ~(FRAME_SIZE - 1); }

// x=VA_END so  cant overflow
uint64_t roundUp(uint64_t x) { return roundDown(x + FRAME_SIZE - 1); }

// picks base addr for pie image. ONE place so aslr is easy
uint64_t pickBase(int place) {
  if (place == ELF::PLACE_INTERP) return INTERP_BASE;
  return MAIN_BASE;
}

// checks one PT_LOAD (unbiased addrs)
bool goodSeg(const RawPh &p, uint64_t fileSize, bool isPie) {
  if (p.filesz > p.memsz) return false;
  if (p.vaddr >= VMM::VA_END) return false;
  if (p.memsz > VMM::VA_END - p.vaddr) return false;
  // file bytes gotta be inside the file
  if (p.offset > fileSize) return false;
  if (p.filesz > fileSize - p.offset) return false;
  // file page has to land on a virtual page, like mmap needs
  if ((p.vaddr % FRAME_SIZE) != (p.offset % FRAME_SIZE)) return false;
  // static exes cant start below the first user page
  if (!isPie && p.vaddr < VMM::VA_START.va()) return false;
  // align (if set) must be power of 2. we only promise page alignment tho
  if (p.align > 1 && (p.align & (p.align - 1)) != 0) return false;
  return true;
}

// maps one PT_LOAD with  bias added
sync<bool> mapSeg(StrongRef<Node> file, const ELF::Seg &seg, uint64_t bias) {

  // real addrs after bias
  uint64_t begSeg = roundDown(seg.vaddr + bias);
  uint64_t dataEnd = seg.vaddr + bias + seg.filesz;
  uint64_t fileEnd = roundUp(dataEnd);
  uint64_t endSeg = roundUp(seg.vaddr + bias + seg.memsz);

  // turn elf flags into mmap prot
  int prot = 0;
  if (seg.flags & PF_R) prot = prot | VMM::PROT_READ;
  if (seg.flags & PF_W) prot = prot | VMM::PROT_WRITE;
  if (seg.flags & PF_X) prot = prot | VMM::PROT_EXEC;
  bool canWrite = (seg.flags & PF_W) != 0;

  // part that comes from file
  if (seg.filesz != 0) {
    uint64_t len = fileEnd - begSeg;
    void *got = co_await VMM::mmap((void *)begSeg, len, prot,
                                   VMM::MAP_PRIVATE | VMM::MAP_FIXED, file,
                                   roundDown(seg.offset));
    if (got != (void *)begSeg) co_return false;

    // zero leftover bytes in last file page (start of bss) only if writable
    if (canWrite && fileEnd > dataEnd) {
      memset((void *)dataEnd, 0, fileEnd - dataEnd);
    }
  }

  // bss needs own anon pages
  uint64_t anonStart = begSeg;
  if (seg.filesz != 0) anonStart = fileEnd;
  if (endSeg > anonStart) {
    uint64_t len = endSeg - anonStart;
    void *got = co_await VMM::mmap((void *)anonStart, len, prot,
                                   VMM::MAP_PRIVATE | VMM::MAP_ANONYMOUS | VMM::MAP_FIXED,
                                   {}, 0);
    if (got != (void *)anonStart) co_return false;
  }

  co_return true;
}

} // namespace

sync<ELF::Info> ELF::parse(StrongRef<Node> file) {
  Info info; // starts out w ok = false
  RawPh ph[MAX_PH];

  uint64_t fileSize = co_await file->size_in_bytes();
  if (fileSize < sizeof(RawHeader)) co_return info;

  // read header into kernel mem (not whole file)
  RawHeader h;
  int64_t got = co_await file->read_all(0, sizeof(RawHeader), (char *)&h);
  if (got != (int64_t)sizeof(RawHeader)) co_return info;

  // check magic, 64 bit, little endian
  if (h.ident[0] != 0x7F || h.ident[1] != 'E' || h.ident[2] != 'L' || h.ident[3] != 'F')
    co_return info;
  if (h.ident[4] != 2 || h.ident[5] != 1) co_return info;

  // exec or pie only, x86-64 only
  if (h.type != ET_EXEC && h.type != ET_DYN) co_return info;
  if (h.machine != EM_X86_64) co_return info;
  if (h.phentsize != sizeof(RawPh)) co_return info;
  if (h.phnum == 0 || h.phnum > MAX_PH) co_return info;

  // prog header table has to fit in file
  if (h.phoff > fileSize) co_return info;
  uint64_t tableSize = (uint64_t)h.phnum * h.phentsize;
  if (tableSize > fileSize - h.phoff) co_return info;

  got = co_await file->read_all(h.phoff, tableSize, (char *)ph);
  if (got != (int64_t)tableSize) co_return info;

  info.isPie = (h.type == ET_DYN);
  info.entry = h.entry;
  info.phoff = h.phoff;
  info.phent = h.phentsize;
  info.phnum = h.phnum;
  info.lowAddr = ~0ull; // gets smaller as we see segs

  for (int i = 0; i < h.phnum; i++) {
    RawPh &p = ph[i];

    if (p.type == PT_LOAD) {
      if (p.memsz == 0) continue; // nothing to map
      if (!goodSeg(p, fileSize, info.isPie)) co_return info;
      if (info.segCount >= MAX_LOADS) co_return info;

      // segs have to be in order+not overlap
      if (info.segCount > 0) {
        ELF::Seg &prev = info.segs[info.segCount - 1];
        if (p.vaddr < prev.vaddr + prev.memsz) co_return info;
      }

      ELF::Seg &s = info.segs[info.segCount];
      s.vaddr = p.vaddr;
      s.offset = p.offset;
      s.filesz = p.filesz;
      s.memsz = p.memsz;
      s.flags = p.flags;
      info.segCount++;

      // track span of whole image
      uint64_t lo = roundDown(p.vaddr);
      uint64_t hi = roundUp(p.vaddr + p.memsz);
      if (lo < info.lowAddr) info.lowAddr = lo;
      if (hi > info.highAddr) info.highAddr = hi;
    }
    else if (p.type == PT_INTERP) {
      // path string, needs \0 at end +only 1 allowed
      if (info.hasInterp) co_return info;
      if (p.filesz < 2 || p.filesz > MAX_INTERP) co_return info;
      if (p.offset > fileSize || p.filesz > fileSize - p.offset) co_return info;

      got = co_await file->read_all(p.offset, p.filesz, info.interp);
      if (got != (int64_t)p.filesz) co_return info;
      if (info.interp[p.filesz - 1] != 0) co_return info;
      info.hasInterp = true;
    }
    else if (p.type == PT_PHDR) {
      info.hasPhdr = true;
      info.phdrVaddr = p.vaddr;
    }
    else if (p.type == PT_GNU_STACK) {
      info.hasStack = true;
      info.stackExec = (p.flags & PF_X) != 0;
    }
    else if (p.type == PT_GNU_RELRO) {
      info.hasRelro = true;
      info.relroVaddr = p.vaddr;
      info.relroSize = p.memsz;
    }
  }

  // need at least 1 loadable seg
  if (info.segCount == 0) {
    info.lowAddr = 0;
    co_return info;
  }

  // entry has to be inside image
  if (info.entry < info.lowAddr || info.entry >= info.highAddr) co_return info;

  info.ok = true;
  co_return info;
}

sync<ELF::Loaded> ELF::map(StrongRef<Node> file, const Info &info, int place) {
  Loaded res; // ok = false for now

  if (!info.ok) co_return res;

  // find where prog headers will be in mem (ld.so needs for AT_PHDR)
  // if PT_PHDR there use it, if not find seg w table
  uint64_t phdrVaddr = 0;
  bool foundPhdr = false;
  if (info.hasPhdr) {
    phdrVaddr = info.phdrVaddr;
    foundPhdr = true;
  } else {
    for (int i = 0; i < info.segCount; i++) {
      const Seg &s = info.segs[i];
      if (info.phoff >= s.offset && info.phoff < s.offset + s.filesz) {
        phdrVaddr = s.vaddr + (info.phoff - s.offset);
        foundPhdr = true;
        break;
      }
    }
  }
  if (!foundPhdr) co_return res;

  uint64_t bias = 0;
  uint64_t span = info.highAddr - info.lowAddr;
  void *resv = nullptr; // the reservation (pie only)

  if (info.isPie) {
    // reserve whole span as PROT_NONE w/o MAP_FIXED
    uint64_t hint = pickBase(place);
    resv = co_await VMM::mmap((void *)hint, span, VMM::PROT_NONE,
                              VMM::MAP_PRIVATE | VMM::MAP_ANONYMOUS, {}, 0);
    if (resv == VMM::MAP_FAILED) {
      // hint was no good, let the kernel pick a spot
      resv = co_await VMM::mmap(nullptr, span, VMM::PROT_NONE,
                                VMM::MAP_PRIVATE | VMM::MAP_ANONYMOUS, {}, 0);
      if (resv == VMM::MAP_FAILED) co_return res;
    }
    // unsigned wrap fine bc cancels out when add vaddr back
    bias = (uint64_t)resv - info.lowAddr;
  }

  // map each seg (MAP_FIXED lands inside pie reservation)
  for (int i = 0; i < info.segCount; i++) {
    bool good = co_await mapSeg(file, info.segs[i], bias);
    if (!good) {
      // give back reservation so no leak
      if (resv != nullptr) co_await VMM::munmap(resv, span);
      co_return res;
    }
  }

  res.ok = true;
  res.entry = info.entry + bias;
  res.bias = bias;
  res.phdr = phdrVaddr + bias;
  res.phent = info.phent;
  res.phnum = info.phnum;
  res.base = info.lowAddr + bias;
  res.end = info.highAddr + bias;
  co_return res;
}

// old, only for programs with no interpreter
sync<uint64_t> ELF::load(StrongRef<Node> file) {
  Info info = co_await parse(file);
  if (!info.ok) co_return 0;

  // dont run a dynamic exe w/o interpreter, it would crash
  if (info.hasInterp) co_return 0;

  Loaded res = co_await map(file, info, PLACE_MAIN);
  if (!res.ok) co_return 0;
  co_return res.entry;
}