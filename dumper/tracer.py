"""Static field tracer for hand-written packet writers.

Every BinaryStream write method takes (value, doc_field_name, doc_field_notes),
so a writer is a sequence of virtual calls on the stream with a name string in
rdx and an optional notes string in rcx. This walks a writer in address order,
tracks which registers hold the stream, follows helper calls that receive the
stream and the std::function lambdas used for arrays and conditional writes,
and returns a tree of fields.

It is a linear sweep, not an emulator: branches are all included in address
order and loops show once. Good enough to list fields and types; the result
should be checked against a real capture.

PRIVATE research tooling. Output is facts about the protocol, not code.
"""
from capstone.x86 import (X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RAX,
                          X86_REG_RBP, X86_REG_RBX, X86_REG_RCX, X86_REG_RDI,
                          X86_REG_RDX, X86_REG_RIP, X86_REG_RSI, X86_REG_R8,
                          X86_REG_R9, X86_REG_R12, X86_REG_R13, X86_REG_R14,
                          X86_REG_R15, X86_REG_RSP)

import asm
from streamvt import WRITE

ARGS = [X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX, X86_REG_R8, X86_REG_R9]
CALLEE_SAVED = {X86_REG_RBX, X86_REG_RBP, X86_REG_R12, X86_REG_R13, X86_REG_R14,
                X86_REG_R15, X86_REG_RSP}
STRUCTURAL = {"if", "conditional", "branch", "array"}
# Which argument registers carry (doc_field_name, doc_field_notes) for each
# BinaryStream method, from the signatures in Endstone's binary_stream.h:
# float values travel in xmm0, a string_view value takes rsi+rdx.
NAME_REGS = {
    "f32": ("rsi", "rdx"), "f64": ("rsi", "rdx"), "fixedfloat": ("rsi", "rdx"),
    "normfloat": ("rsi", "rdx"), "string": ("rcx", "r8"),
    "if": ("rdx", "rcx"), "conditional": ("rsi", "r8"),
    "typeBegin": ("rsi", "rdx"), "typeEnd": (None, None), "enum": ("rsi", "rdx"),
}
FUNC_CALL_SLOT = 6  # libc++ std::__function::__func vtable: operator() slot


def _full(cs_insn, reg):
    """Map any sub-register (esi, sil) to its 64-bit parent id."""
    name = cs_insn.reg_name(reg)
    fam = {
        "rax": "rax", "eax": "rax", "ax": "rax", "al": "rax",
        "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bl": "rbx",
        "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx",
        "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx",
        "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
        "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
        "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
        "rsp": "rsp", "esp": "rsp",
    }
    if name in fam:
        return fam[name]
    if name.startswith("r") and name[1:].rstrip("dwb").isdigit():
        return "r" + name[1:].rstrip("dwb")
    return name


ARG_NAMES = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
SAVED = {"rbx", "rbp", "r12", "r13", "r14", "r15", "rsp"}


class Tracer:
    def __init__(self, b, max_depth=5):
        self.b = b
        self.max_depth = max_depth
        self._cache = {}

    def _str(self, addr):
        if addr is None or not self.b.in_section(addr, ".rodata"):
            return None
        s = self.b.cstr(addr, 400)
        return s if s and s.isprintable() else None

    def _func_vtable_call(self, vt_addr):
        """If vt_addr is a libc++ std::function __func vtable address point,
        return its operator() function."""
        b = self.b
        if not (b.in_section(vt_addr, ".data.rel.ro")):
            return None
        ti = b.ptr(vt_addr - 8)
        if ti is None:
            return None
        name_ptr = b.ptr(ti + 8)
        name = b.cstr(name_ptr, 60) if name_ptr else None
        if not name or "__function6__func" not in name:
            return None
        f = b.ptr(vt_addr + 8 * FUNC_CALL_SLOT)
        return f if f and b.in_section(f, ".text") else None

    def _stream_node(self, kind, strs, lambdas, depth):
        nreg, treg = NAME_REGS.get(kind, ("rdx", "rcx"))
        node = {"op": kind,
                "name": self._str(strs.get(nreg)) if nreg else None,
                "notes": self._str(strs.get(treg)) if treg else None}
        if kind in STRUCTURAL:
            # array/branch take std::function objects first; their doc
            # strings come in later argument registers, so take any found.
            if not node["name"]:
                found = [self._str(strs[r]) for r in ARG_NAMES if r in strs]
                node["name"] = next((x for x in found if x), None)
            if lambdas:
                node["children"] = [self.trace(l, ("rsi",), depth + 1) for l in lambdas]
        return node

    def trace(self, f, stream_args=("rsi",), depth=0):
        key = (f, tuple(stream_args))
        if key in self._cache:
            return self._cache[key]
        self._cache[key] = []  # recursion guard
        out = []
        b = self.b
        stream = set(stream_args)   # registers holding the stream pointer
        vtab = set()                # registers holding the stream's vtable
        stack_stream = set()        # [rsp+off] slots holding the stream
        strs = {}                   # register -> string address
        meth = {}                   # register -> stream method kind
        lambdas = []                # lambda bodies set up since last struct call
        end = b.func_end(f)
        for i in asm.insns(b, f, end, limit=60000):
            mn = i.mnemonic
            ops = i.operands
            if mn in ("mov", "lea") and len(ops) == 2 and ops[0].type == X86_OP_REG:
                dst = _full(i, ops[0].reg)
                src = ops[1]
                # Work out what dst becomes from the source *before* clearing
                # dst: `mov rax, [rax+0x78]` reads rax first.
                new = {}
                if mn == "lea" and src.type == X86_OP_MEM and src.mem.base == X86_REG_RIP:
                    tgt = i.address + i.size + src.mem.disp
                    if self._str(tgt):
                        new["str"] = tgt
                    elif depth < self.max_depth:
                        body = self._func_vtable_call(tgt)
                        if body:
                            lambdas.append(body)
                elif mn == "mov" and src.type == X86_OP_REG:
                    s = _full(i, src.reg)
                    if s in stream:
                        new["stream"] = True
                    if s in vtab:
                        new["vtab"] = True
                    if s in strs:
                        new["str"] = strs[s]
                    if s in meth:
                        new["meth"] = meth[s]
                elif mn == "mov" and src.type == X86_OP_MEM:
                    base = _full(i, src.mem.base) if src.mem.base else None
                    if base in stream and src.mem.disp == 0 and src.mem.index == 0:
                        new["vtab"] = True
                    elif base in vtab and src.mem.disp in WRITE and src.mem.index == 0:
                        new["meth"] = WRITE[src.mem.disp]
                    elif base == "rsp" and src.mem.disp in stack_stream:
                        new["stream"] = True
                stream.discard(dst); vtab.discard(dst); strs.pop(dst, None)
                meth.pop(dst, None)
                if new.get("stream"):
                    stream.add(dst)
                if new.get("vtab"):
                    vtab.add(dst)
                if "str" in new:
                    strs[dst] = new["str"]
                if "meth" in new:
                    meth[dst] = new["meth"]
                continue
            if mn == "mov" and len(ops) == 2 and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG:
                if ops[0].mem.base == X86_REG_RSP and _full(i, ops[1].reg) in stream:
                    stack_stream.add(ops[0].mem.disp)
                continue
            if mn in ("call", "jmp") and ops:
                op = ops[0]
                if op.type == X86_OP_MEM and op.mem.base and _full(i, op.mem.base) in vtab \
                        and op.mem.disp in WRITE:
                    out.append(self._stream_node(WRITE[op.mem.disp], strs, lambdas, depth))
                    lambdas = []
                elif op.type == X86_OP_REG and _full(i, op.reg) in meth:
                    out.append(self._stream_node(meth[_full(i, op.reg)], strs, lambdas, depth))
                    lambdas = []
                elif op.type == X86_OP_IMM and depth < self.max_depth:
                    t = op.imm
                    passed = [a for a in ARG_NAMES if a in stream]
                    if passed and b.in_section(t, ".text") and t != f:
                        sub = self.trace(t, tuple(passed), depth + 1)
                        if sub:
                            if lambdas and not any(n["op"] in STRUCTURAL for n in sub):
                                pass
                            out.append({"op": "call", "target": "%x" % t, "children": sub}
                                       if len(sub) > 1 else sub[0])
                if mn == "call":
                    for r in list(stream):
                        if r not in SAVED:
                            stream.discard(r)
                    for r in list(vtab):
                        if r not in SAVED:
                            vtab.discard(r)
                    for r in list(strs):
                        if r not in SAVED:
                            strs.pop(r)
                    for r in list(meth):
                        if r not in SAVED:
                            meth.pop(r)
                continue
        self._cache[key] = out
        return out


def flatten(nodes, depth=0):
    """Pretty lines for a traced tree."""
    lines = []
    for n in nodes:
        if n["op"] == "call":
            lines += flatten(n["children"], depth)
            continue
        txt = "%s%-10s %s" % ("  " * depth, n["op"], n.get("name") or "")
        if n.get("notes"):
            txt += "   // " + n["notes"][:100]
        lines.append(txt)
        for ch in n.get("children", []):
            lines += flatten(ch, depth + 1)
    return lines
