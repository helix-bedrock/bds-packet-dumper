"""Fast code->data reference index for RIP-relative LEA/MOV in .text.

Scans raw bytes with numpy instead of disassembling 180 MB of code, so it is
approximate (a match can start mid-instruction), but false positives are
rare and every use re-checks the hit with the real disassembler."""
import os
import numpy as np


def build(b, cache):
    if os.path.exists(cache):
        z = np.load(cache)
        return z["tgt"], z["site"]
    start, size = b.sections[".text"]
    data = np.frombuffer(b.read(start, size), dtype=np.uint8)
    rex = (data[:-7] == 0x48) | (data[:-7] == 0x4C)
    op = (data[1:-6] == 0x8D) | (data[1:-6] == 0x8B)
    modrm = (data[2:-5] & 0xC7) == 0x05
    idx = np.nonzero(rex & op & modrm)[0]
    disp = (data[idx + 3].astype(np.int64) | (data[idx + 4].astype(np.int64) << 8)
            | (data[idx + 5].astype(np.int64) << 16) | (data[idx + 6].astype(np.int64) << 24))
    disp = np.where(disp >= 1 << 31, disp - (1 << 32), disp)
    site = idx.astype(np.int64) + start
    tgt = site + 7 + disp
    order = np.argsort(tgt, kind="stable")
    tgt, site = tgt[order], site[order]
    np.savez(cache, tgt=tgt, site=site)
    return tgt, site


class Xrefs:
    def __init__(self, b, cache):
        self.tgt, self.site = build(b, cache)

    def to(self, target):
        lo = np.searchsorted(self.tgt, target, "left")
        hi = np.searchsorted(self.tgt, target, "right")
        return [int(x) for x in self.site[lo:hi]]


def build_calls(b, cache):
    """Direct `call rel32` index: target -> call sites."""
    if os.path.exists(cache):
        z = np.load(cache)
        return z["tgt"], z["site"]
    start, size = b.sections[".text"]
    data = np.frombuffer(b.read(start, size), dtype=np.uint8)
    idx = np.nonzero(data[:-5] == 0xE8)[0]
    rel = (data[idx + 1].astype(np.int64) | (data[idx + 2].astype(np.int64) << 8)
           | (data[idx + 3].astype(np.int64) << 16) | (data[idx + 4].astype(np.int64) << 24))
    rel = np.where(rel >= 1 << 31, rel - (1 << 32), rel)
    site = idx.astype(np.int64) + start
    tgt = site + 5 + rel
    funcs = np.array(b.funcs, dtype=np.int64)
    pos = np.searchsorted(funcs, tgt)
    ok = (pos < len(funcs)) & (funcs[np.minimum(pos, len(funcs) - 1)] == tgt)
    tgt, site = tgt[ok], site[ok]
    order = np.argsort(tgt, kind="stable")
    tgt, site = tgt[order], site[order]
    np.savez(cache, tgt=tgt, site=site)
    return tgt, site


class Calls:
    def __init__(self, b, cache):
        self.tgt, self.site = build_calls(b, cache)

    def to(self, target):
        lo = np.searchsorted(self.tgt, target, "left")
        hi = np.searchsorted(self.tgt, target, "right")
        return [int(x) for x in self.site[lo:hi]]


def find_imm_stores(b, prefix, values):
    """Sites of `prefix imm32` in .text where imm32 is in `values`."""
    start, size = b.sections[".text"]
    data = np.frombuffer(b.read(start, size), dtype=np.uint8)
    n = len(prefix)
    m = np.ones(len(data) - n - 4, dtype=bool)
    for k, byte in enumerate(prefix):
        m &= data[k:len(data) - n - 4 + k] == byte
    idx = np.nonzero(m)[0]
    imm = (data[idx + n].astype(np.int64) | (data[idx + n + 1].astype(np.int64) << 8)
           | (data[idx + n + 2].astype(np.int64) << 16) | (data[idx + n + 3].astype(np.int64) << 24))
    keep = np.isin(imm, np.array(sorted(values), dtype=np.int64))
    return [(int(s) + start, int(v)) for s, v in zip(idx[keep], imm[keep])]
