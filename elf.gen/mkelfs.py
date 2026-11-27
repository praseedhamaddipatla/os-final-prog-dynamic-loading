#!/usr/bin/env python3
"""
mkelfs.py: makes the hand built elf files for test 033 (elf parse + map tests)
usage: python3 mkelfs.py <033.dir>
also writes src/init.c and ../033.ok

every file here is built from one small template and then 1 thing is broken,
so each bad_ file trips exactly one rule in ELF::parse
"""
import os, struct, subprocess, sys, tempfile

OUT = sys.argv[1] if len(sys.argv) > 1 else "../033.dir"
HERE = os.path.dirname(os.path.abspath(__file__))

PAGE = 0x1000
PT_LOAD, PT_INTERP, PT_NOTE, PT_PHDR = 1, 3, 4, 6
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552
PF_X, PF_W, PF_R = 1, 2, 4
ET_EXEC, ET_DYN = 2, 3
MAIN_BASE = 0x555555554000        # has to match MAIN_BASE in elf.cc
VA_END = 1 << 47
EXIT0 = bytes([0x31, 0xFF, 0xB8, 0x3C, 0, 0, 0, 0x0F, 0x05])  # xor edi,edi; mov eax,60; syscall


def ph(t, flags, off, vaddr, filesz, memsz, align=PAGE):
    return dict(type=t, flags=flags, off=off, vaddr=vaddr, filesz=filesz, memsz=memsz, align=align)


class Elf:
    def __init__(self, etype=ET_DYN):
        self.ident = bytearray(b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8))
        self.etype, self.machine, self.entry = etype, 62, 0
        self.phoff, self.phentsize, self.phnum = 64, 56, None
        self.phdrs, self.blobs, self.size = [], [], None

    def pack(self):
        n = len(self.phdrs) if self.phnum is None else self.phnum
        head = bytes(self.ident) + struct.pack(
            "<HHIQQQIHHHHHH", self.etype, self.machine, 1, self.entry,
            self.phoff, 0, 0, 64, self.phentsize, n, 0, 0, 0)
        assert len(head) == 64
        table = b"".join(struct.pack("<IIQQQQQQ", p["type"], p["flags"], p["off"], p["vaddr"],
                                     p["vaddr"], p["filesz"], p["memsz"], p["align"])
                         for p in self.phdrs)
        buf = bytearray(head + table)
        for off, data in self.blobs:
            if len(buf) < off + len(data):
                buf.extend(bytes(off + len(data) - len(buf)))
            buf[off:off + len(data)] = data
        if self.size is not None:
            if self.size < len(buf):
                del buf[self.size:]
            else:
                buf.extend(bytes(self.size - len(buf)))
        return bytes(buf)


def std(etype, v0, code):
    """header page (R) + code page (RX). code lands at v0 + 0x1000"""
    e = Elf(etype)
    e.phdrs = [ph(PT_LOAD, PF_R, 0, v0, PAGE, PAGE),
               ph(PT_LOAD, PF_R | PF_X, PAGE, v0 + PAGE, len(code), len(code))]
    e.blobs = [(PAGE, code)]
    e.entry = v0 + PAGE
    return e


def add_data(e, v0):
    """RW segment: 8 bytes in the file (+ 0xAA junk to the page end), 0x3000 in memory"""
    e.phdrs.append(ph(PT_LOAD, PF_R | PF_W, 0x2000, v0 + 0x200000, 8, 0x3000))
    e.blobs.append((0x2000, struct.pack("<Q", 0x1122334455667788) + b"\xAA" * (PAGE - 8)))


def asm(v0, expect):
    """assemble gap.S so that its code sits at v0+0x1000"""
    with tempfile.TemporaryDirectory() as d:
        o, x, b = (os.path.join(d, n) for n in ("g.o", "g.elf", "g.bin"))
        a = ["as", "-o", o, os.path.join(HERE, "gap.S")]
        if expect is not None:
            a[1:1] = ["--defsym", "USE_EXPECT=1"]
        subprocess.check_call(a)
        l = ["ld", "-Ttext=0x%x" % (v0 + PAGE), "--defsym", "DATA=0x%x" % (v0 + 0x200000),
             "--defsym", "HDR=0x%x" % v0, "-o", x, o]
        if expect is not None:
            l += ["--defsym", "EXPECT=0x%x" % expect]
        subprocess.check_call(l)
        subprocess.check_call(["objcopy", "-O", "binary", "-j", ".text", x, b])
        return open(b, "rb").read()


def with_gap(etype, v0, expect):
    e = std(etype, v0, asm(v0, expect))
    add_data(e, v0)
    return e


def good():
    return std(ET_DYN, 0, EXIT0)


# ---------------------------------------------------------------- positive files
cases = []   # (name, kind, build function result)  kind: OK / REJECT / FAULT


def ok(name, e):
    cases.append((name, "OK", e))


def bad(name, e, why):
    cases.append((name, "REJECT", (e, why)))


# gcc built files go first (build.sh makes them), names only here
gcc_ok = ["ok_exec", "ok_pie"]
gcc_fault = ["fault_exec_rodata", "fault_exec_text", "fault_exec_nx_data",
             "fault_exec_nx_bss", "fault_pie_rodata", "fault_pie_nx_data"]

ok("ok_exec_fixed", with_gap(ET_EXEC, 0x10000000, 0x10001000))        # no bias for ET_EXEC
ok("ok_pie_gap", with_gap(ET_DYN, 0, MAIN_BASE + PAGE))               # bias = MAIN_BASE, hole between segs
ok("ok_pie_low", with_gap(ET_DYN, 0x1000, MAIN_BASE + PAGE))          # lowAddr != 0
ok("ok_pie_high", with_gap(ET_DYN, 0x400000, MAIN_BASE + PAGE))       # big lowAddr

e = with_gap(ET_DYN, 0, MAIN_BASE + PAGE)                             # extra headers must be ignored ok
n = len(e.phdrs) + 5
e.phdrs = [ph(PT_PHDR, PF_R, 64, 64, 56 * n, 56 * n, 8)] + e.phdrs + [
    ph(PT_NOTE, PF_R, 0x1000, 0x1000, 0, 0, 4),
    ph(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 16),
    ph(PT_GNU_RELRO, PF_R, 0x2000, 0x200000, PAGE, PAGE, 1),
    ph(PT_LOAD, PF_R, 0, 0x5000, 0, 0)]                               # memsz 0 load is skipped
ok("ok_extras", e)

e = std(ET_DYN, 0, EXIT0)                                             # exactly MAX_LOADS (16) loads
for i in range(14):
    e.phdrs.append(ph(PT_LOAD, PF_R | PF_W, PAGE, 0x3000 + i * PAGE, 0, PAGE))
ok("ok_loads_16", e)

e = std(ET_DYN, 0, EXIT0)                                             # exactly MAX_PH (64) headers
e.phdrs += [ph(PT_NOTE, PF_R, 0, 0, 0, 0, 4) for _ in range(62)]
ok("ok_phnum_64", e)

# ---------------------------------------------------------------- negative files
def mut(fn):
    e = good()
    fn(e)
    return e

bad("bad_magic",        mut(lambda e: e.ident.__setitem__(0, 0x7E)), "magic")
bad("bad_class32",      mut(lambda e: e.ident.__setitem__(4, 1)), "class")
bad("bad_endian",       mut(lambda e: e.ident.__setitem__(5, 2)), "class")
bad("bad_type_rel",     mut(lambda e: setattr(e, "etype", 1)), "type")
bad("bad_type_core",    mut(lambda e: setattr(e, "etype", 4)), "type")
bad("bad_machine",      mut(lambda e: setattr(e, "machine", 183)), "machine")
bad("bad_phentsize",    mut(lambda e: setattr(e, "phentsize", 32)), "phentsize")
bad("bad_phnum_zero",   mut(lambda e: setattr(e, "phnum", 0)), "phnum")

e = std(ET_DYN, 0, EXIT0)
e.phdrs += [ph(PT_NOTE, PF_R, 0, 0, 0, 0, 4) for _ in range(63)]      # 65 real headers
bad("bad_phnum_65", e, "phnum")

bad("bad_phoff_past_eof",   mut(lambda e: setattr(e, "phoff", 0x100000)), "phoff")
bad("bad_phtable_past_eof", mut(lambda e: setattr(e, "phoff", PAGE + len(EXIT0) - 56)), "phtable")
bad("bad_short_file",   mut(lambda e: setattr(e, "size", 40)), "short")
bad("bad_empty",        mut(lambda e: setattr(e, "size", 0)), "short")

t = Elf(ET_DYN)                                                       # plain text, not an elf at all
t.blobs = [(0, b"this is not an elf file, just some text. " * 3)]
t.pack = lambda b=t.blobs[0][1]: b
bad("bad_text", t, "magic")

bad("bad_filesz_gt_memsz",  mut(lambda e: e.phdrs[1].update(filesz=0x20, memsz=0x10)), "filesz>memsz")
bad("bad_offset_past_eof",  mut(lambda e: e.phdrs[1].update(off=0x10000)), "offset")
bad("bad_data_past_eof",    mut(lambda e: e.phdrs[1].update(filesz=0x5000, memsz=0x5000)), "datapast")
bad("bad_misaligned",       mut(lambda e: e.phdrs[1].update(vaddr=0x1010)), "congruent")
bad("bad_vaddr_va_end",     mut(lambda e: e.phdrs[1].update(vaddr=VA_END)), "vaddr")
bad("bad_memsz_past_va_end", mut(lambda e: e.phdrs[1].update(vaddr=VA_END - PAGE, memsz=0x2000)), "memsz")
bad("bad_exec_low_vaddr",   std(ET_EXEC, 0, EXIT0), "lowexec")
bad("bad_overlap",          mut(lambda e: e.phdrs[0].update(memsz=0x2000)), "overlap")
bad("bad_order",            mut(lambda e: e.phdrs.reverse()), "overlap")
bad("bad_align_not_pow2",   mut(lambda e: e.phdrs[1].update(align=3)), "align")

e = std(ET_DYN, 0, EXIT0)                                             # 17 loads, 1 too many
for i in range(15):
    e.phdrs.append(ph(PT_LOAD, PF_R | PF_W, PAGE, 0x3000 + i * PAGE, 0, PAGE))
bad("bad_too_many_loads", e, "toomany")

bad("bad_entry_outside", mut(lambda e: setattr(e, "entry", 0x10000)), "entry")
bad("bad_entry_at_end",  mut(lambda e: setattr(e, "entry", 0x2000)), "entry")   # high end is exclusive

e = good(); e.phdrs = [ph(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 16), ph(PT_NOTE, PF_R, 0, 0, 0, 0, 4)]
bad("bad_no_load", e, "noload")
e = good(); e.phdrs = [ph(PT_LOAD, PF_R, 0, 0, 0, 0)]
bad("bad_empty_load", e, "noload")


def interp(name, s, why, filesz=None, off=0x1100, count=1, patch=None):
    e = good()
    e.blobs.append((off if off < 0x10000 else 0x1100, s))
    for _ in range(count):
        p = ph(PT_INTERP, PF_R, off, 0x1100, len(s) if filesz is None else filesz,
               len(s) if filesz is None else filesz, 1)
        e.phdrs.append(p)
    bad(name, e, why)

interp("bad_interp_no_nul",   b"/lib/ld-no-nul.so", "interpnul")
interp("bad_interp_too_long", b"/" + b"a" * 255 + b"\0", "interplen")
interp("bad_interp_empty",    b"\0", "interplen")
interp("bad_interp_two",      b"/lib/ld-a.so\0", "interptwo", count=2)
interp("bad_interp_past_eof", b"/lib/ld-b.so\0", "interpeof", off=0x100000)
interp("bad_interp_missing",  b"/lib/ld-does-not-exist.so\0", "interpmissing")   # valid, but no such file

# ---------------------------------------------------------------- python copy of ELF::parse
def model(data, verbose=False):
    """same rules as ELF::parse in elf.cc, returns None if ok or a short reason"""
    size = len(data)
    if size < 64: return "short"
    h = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    ident, typ, mach, _, entry, phoff, _, _, _, phentsize, phnum = h[:11]
    if ident[:4] != b"\x7fELF": return "magic"
    if ident[4] != 2 or ident[5] != 1: return "class"
    if typ not in (ET_EXEC, ET_DYN): return "type"
    if mach != 62: return "machine"
    if phentsize != 56: return "phentsize"
    if phnum == 0 or phnum > 64: return "phnum"
    if phoff > size: return "phoff"
    if phnum * phentsize > size - phoff: return "phtable"
    pie = typ == ET_DYN
    segs, interp_seen, low, high = [], False, ~0, 0
    for i in range(phnum):
        t, fl, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", data, phoff + 56 * i)
        if t == PT_LOAD:
            if msz == 0: continue
            if fsz > msz: return "filesz>memsz"
            if va >= VA_END: return "vaddr"
            if msz > VA_END - va: return "memsz"
            if off > size: return "offset"
            if fsz > size - off: return "datapast"
            if va % PAGE != off % PAGE: return "congruent"
            if not pie and va < PAGE: return "lowexec"
            if al > 1 and (al & (al - 1)): return "align"
            if len(segs) >= 16: return "toomany"
            if segs and va < segs[-1][0] + segs[-1][1]: return "overlap"
            segs.append((va, msz))
            low = min(low, va & ~(PAGE - 1))
            high = max(high, (va + msz + PAGE - 1) & ~(PAGE - 1))
        elif t == PT_INTERP:
            if interp_seen: return "interptwo"
            if fsz < 2 or fsz > 256: return "interplen"
            if off > size or fsz > size - off: return "interpeof"
            if data[off + fsz - 1] != 0: return "interpnul"
            interp_seen = True
    if not segs: return "noload"
    if entry < low or entry >= high: return "entry"
    return "interpmissing" if interp_seen else None


# ---------------------------------------------------------------- write everything
os.makedirs(OUT, exist_ok=True)
order = []
for name in gcc_ok:
    order.append((name, "OK"))
for name, kind, thing in cases:
    if kind == "OK":
        data = thing.pack()
        r = model(data)
        assert r is None, (name, r)
    else:
        e, why = thing
        data = e.pack()
        r = model(data)
        assert r == why, (name, "wanted", why, "model says", r)
    path = os.path.join(OUT, name)
    open(path, "wb").write(data)
    os.chmod(path, 0o755)
    order.append((name, kind))
for name in gcc_fault:
    order.append((name, "FAULT"))

# stable order for the test: ok first, then faults, then rejects
order.sort(key=lambda x: {"OK": 0, "FAULT": 1, "REJECT": 2}[x[1]])

# init.c from the template
tmpl = open(os.path.join(HERE, "init.c.in")).read()
rows = "".join('    {"%s", %s},\n' % (n, k) for n, k in order)
open(os.path.join(OUT, "src", "init.c"), "w").write(tmpl.replace("@@CASES@@", rows))

# expected output
with open(os.path.join(OUT, "..", "033.ok"), "w") as f:
    for n, k in order:
        f.write("PASS: %s\n" % n)
    f.write("*** PASS: elf parse and map (%d cases)\n" % len(order))
print("wrote", len(order), "cases")
