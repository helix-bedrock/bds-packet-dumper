"""Loads a stripped Linux bedrock_server ELF for static reading.

Gives raw memory reads by virtual address, resolved pointers (the binary is
PIE, so most pointers in data are R_X86_64_RELATIVE relocations whose real
value only exists in .rela.dyn), and a reverse map from pointer target to the
places that point at it, which is how vtables and typeinfo are found.

PRIVATE research tooling. Output is facts about the binary, never Mojang code.
"""
import bisect
import mmap
import re
import struct

from elftools.elf.elffile import ELFFile

R_X86_64_RELATIVE = 8


class Binary:
    def __init__(self, path):
        self._f = open(path, "rb")
        self.mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        self.elf = ELFFile(self._f)
        self.segs = []
        for seg in self.elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                self.segs.append((seg["p_vaddr"], seg["p_filesz"], seg["p_offset"]))
        self.sections = {s.name: (s["sh_addr"], s["sh_size"]) for s in self.elf.iter_sections()}
        self._load_relocs()
        self._load_func_starts()

    # --- memory -----------------------------------------------------------
    def off(self, addr):
        for va, sz, fo in self.segs:
            if va <= addr < va + sz:
                return fo + addr - va
        return None

    def read(self, addr, n):
        o = self.off(addr)
        if o is None:
            return None
        return self.mm[o:o + n]

    def u32(self, addr):
        b = self.read(addr, 4)
        return None if b is None else struct.unpack("<I", b)[0]

    def ptr(self, addr):
        v = self.rel.get(addr)
        if v is not None:
            return v
        b = self.read(addr, 8)
        return None if b is None else struct.unpack("<Q", b)[0]

    def cstr(self, addr, limit=512):
        b = self.read(addr, limit)
        if b is None:
            return None
        end = b.find(b"\0")
        return b[:end if end >= 0 else limit].decode("latin-1")

    def in_section(self, addr, name):
        start, size = self.sections.get(name, (0, 0))
        return start <= addr < start + size

    # --- relocations --------------------------------------------------------
    def _load_relocs(self):
        start, size = self.sections[".rela.dyn"]
        raw = self.read(start, size)
        self.rel = {}
        self.refs = {}
        for off, info, add in struct.iter_unpack("<QQq", raw):
            if info & 0xFFFFFFFF == R_X86_64_RELATIVE:
                self.rel[off] = add
                self.refs.setdefault(add, []).append(off)

    def refs_to(self, target):
        return self.refs.get(target, [])

    # --- functions ----------------------------------------------------------
    def _load_func_starts(self):
        # .eh_frame_hdr has a sorted table of every function start (FDE
        # initial location); it is the only complete function list in a
        # stripped binary.
        hdr, _ = self.sections[".eh_frame_hdr"]
        b = self.read(hdr, 12)
        version, ptr_enc, cnt_enc, tab_enc = b[0], b[1], b[2], b[3]
        assert version == 1 and cnt_enc == 0x03 and tab_enc == 0x3B, (ptr_enc, cnt_enc, tab_enc)
        count = struct.unpack("<I", b[8:12])[0]
        table = self.read(hdr + 12, count * 8)
        self.funcs = sorted(hdr + loc for loc, _ in struct.iter_unpack("<ii", table))

    def func_end(self, start):
        i = bisect.bisect_right(self.funcs, start)
        return self.funcs[i] if i < len(self.funcs) else start + 0x1000

    # --- strings ------------------------------------------------------------
    def find_strings(self, pattern):
        """Yields (addr, text) for NUL-terminated strings in .rodata matching
        a bytes regex anchored on both ends."""
        start, size = self.sections[".rodata"]
        data = self.read(start, size)
        for m in re.finditer(rb"(?<=\0)" + pattern + rb"(?=\0)", data):
            yield start + m.start(), m.group().decode("latin-1")

    def find_suffix_strings(self, pattern):
        """Like find_strings but also matches strings that are the tail of a
        longer string (the linker merges "XFoo" and "Foo" into one)."""
        start, size = self.sections[".rodata"]
        data = self.read(start, size)
        for m in re.finditer(pattern + rb"(?=\0)", data):
            yield start + m.start(), m.group().decode("latin-1")

    def find_string(self, text):
        for addr, _ in self.find_strings(re.escape(text.encode())):
            return addr
        return None
