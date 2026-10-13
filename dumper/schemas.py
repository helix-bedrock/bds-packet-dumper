"""Extracts Mojang's cereal reflection schemas (types, members, enums) from a
stripped bedrock_server.

How it works (no symbols needed):
- entt identifies every type by FNV-1a-32 of its pretty name. The binary is
  full of `[Type = X]` strings (asserts, pretty_function), so hashing them all
  gives a hash -> type name table.
- Each schema is registered by inlined BasicFactory code. In that code the
  member name string is loaded first, then pointers to small accessor
  functions. A member accessor mentions [Owner, Owner, FieldType, FieldType]
  as type hashes; an enum constant getter stores the enum's hash and the
  value into a meta_any.
- Walking the registration code in address order turns that into
  owner -> [(member name, type)] and enum -> [(value name, number)].

PRIVATE research tooling. Output is facts about the protocol, not code.
"""
import bisect
import re

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RDI


WIRE_OFF = [0xA8]  # set per binary by Extractor.detect_wire_offset


def wire_store(i):
    """Packet encoding flags: `mov byte [x+0xa8|0xa9], imm` on a member
    descriptor. PacketSchemaWriter ORs these two bytes and tests bit 0
    (varint), bit 1 (alternate int32 form) and bit 3 (fixed u32 sizes)."""
    if i.mnemonic != "mov" or len(i.operands) != 2:
        return None
    dst, src = i.operands
    if dst.type != X86_OP_MEM or src.type != X86_OP_IMM or dst.size != 1:
        return None
    if dst.mem.disp in (WIRE_OFF[0], WIRE_OFF[0] + 1) and dst.mem.index == 0:
        return src.imm & 0xFF
    return None


def flag_or(i):
    """Element flag bits set by `or byte [x+0x12], imm` (member descriptor) or
    `or dword [x+0x18], imm<<16` (type descriptor); None otherwise."""
    if i.mnemonic != "or" or len(i.operands) != 2:
        return None
    dst, src = i.operands
    if dst.type != X86_OP_MEM or src.type != X86_OP_IMM:
        return None
    if dst.mem.disp == 0x12 and dst.size == 1:
        return src.imm & 0xFF
    if dst.mem.disp == 0x18 and dst.size == 4 and src.imm & 0xFFFF == 0:
        return (src.imm >> 16) & 0xFF
    return None

import asm

TYPEDESC = "cereal::internal::BasicSchema::TypeDescriptor"
PRIMITIVES = [
    "bool", "char", "signed char", "unsigned char", "short", "unsigned short",
    "int", "unsigned int", "long", "unsigned long", "long long",
    "unsigned long long", "float", "double", "void", "std::string",
    "std::string_view", "std::nullptr_t",
]
NOISE = ("Member descriptors", "Base::", "entt::", "Internal ", "it != ", "/mnt/",
         "internal::", "Accessing", "!mControl", "T *Bedrock", "static ",
         "virtual ", "const char *", "bool cereal", "void cereal", "Factory<",
         "The load context", "loadContextAny", "BasicSchema", "cereal::",
         "It is not allowed")


def fnv1a(s):
    h = 0x811C9DC5
    for c in s.encode("latin-1"):
        h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    return h


def split_template_args(s):
    """'A, LoadContext = B' with nested <...> -> ['A', 'LoadContext = B']."""
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def type_names(b):
    names = set(PRIMITIVES)
    for _, s in b.find_strings(rb"[^\0]{0,2000}\[[A-Za-z]+ = [^\0]+\]"):
        m = re.search(r"\[([A-Za-z]+ = .+)\]$", s)
        if not m:
            continue
        for part in split_template_args(m.group(1)):
            if " = " in part:
                names.add(part.split(" = ", 1)[1])
    return {fnv1a(n): n for n in names}


class SSOTracker:
    """Rebuilds short strings that the compiler writes straight onto the stack
    (libc++ short-string layout: one size byte = len*2, then the bytes), e.g.
    `mov byte [rsp+0x40], 0x18; movabs rax, "Chunk Ra"; mov [rsp+0x41], rax;
    mov dword [rsp+0x49], "dius"` -> "Chunk Radius"."""

    def __init__(self):
        self.reg = {}     # register -> known immediate
        self.mem = {}     # rsp offset -> byte
        self.heads = {}   # rsp offset -> string length

    def step(self, i):
        """Feed one instruction; returns a completed string or None."""
        ops = i.operands
        if i.mnemonic in ("mov", "movabs") and len(ops) == 2:
            dst, src = ops
            if dst.type == X86_OP_REG:
                name = i.reg_name(dst.reg)
                if src.type == X86_OP_IMM:
                    self.reg[name] = (src.imm, dst.size)
                else:
                    self.reg.pop(name, None)
                return None
            if dst.type == X86_OP_MEM and i.reg_name(dst.mem.base) == "rsp" and dst.mem.index == 0:
                if src.type == X86_OP_IMM:
                    val, size = src.imm, dst.size
                elif src.type == X86_OP_REG and i.reg_name(src.reg) in self.reg:
                    val, size = self.reg[i.reg_name(src.reg)][0], dst.size
                else:
                    return None
                off = dst.mem.disp
                for k in range(size):
                    self.mem[off + k] = (val >> (8 * k)) & 0xFF
                if size == 1 and val % 2 == 0 and 2 <= val <= 44:
                    self.heads[off] = val // 2
                return self._complete()
        elif i.mnemonic == "call":
            self.reg.clear()
        return None

    def _complete(self):
        for off, n in list(self.heads.items()):
            bs = [self.mem.get(off + 1 + k) for k in range(n)]
            if None in bs:
                continue
            del self.heads[off]
            txt = bytes(bs).decode("latin-1")
            if txt.isprintable() and any(c.isalpha() for c in txt):
                return txt
        return None


class Extractor:
    def __init__(self, b, xr):
        self.b = b
        self.xr = xr
        self.H = type_names(b)
        self.noise = NOISE
        self._fcache = {}

    # --- small accessor function analysis ---------------------------------
    def _hashes(self, f, depth=1, seen=None):
        seen = seen if seen is not None else set()
        if f in seen:
            return []
        seen.add(f)
        out = []
        for i in asm.insns(self.b, f, limit=300):
            for op in i.operands:
                if op.type == X86_OP_IMM:
                    n = self.H.get(op.imm & 0xFFFFFFFF)
                    if n and n != TYPEDESC:
                        out.append(n)
            if depth > 0 and i.mnemonic == "call":
                t = asm.branch_target(i)
                if t and self.b.in_section(t, ".text"):
                    out += self._hashes(t, depth - 1, seen)
            if i.mnemonic == "ret":
                break
        return out

    def _const_getter(self, f):
        """meta_any built from a constant: returns (enum type, value, bytes)."""
        typ = val = size = None
        for k, i in enumerate(asm.insns(self.b, f, limit=40)):
            if i.mnemonic == "ret":
                break
            if i.mnemonic != "mov" or len(i.operands) != 2:
                continue
            dst, src = i.operands
            if dst.type != X86_OP_MEM or src.type != X86_OP_IMM or dst.mem.base != X86_REG_RDI:
                continue
            if dst.mem.disp == 0x20 and dst.size == 4:
                typ = self.H.get(src.imm & 0xFFFFFFFF)
            elif dst.mem.disp == 0 and k > 4:
                val, size = src.imm, dst.size
        if typ and val is not None:
            mask = (1 << (8 * size)) - 1
            v = val & mask
            if v >> (8 * size - 1):
                v -= 1 << (8 * size)
            return typ, v, size
        return None

    def classify(self, f):
        if f in self._fcache:
            return self._fcache[f]
        res = None
        c = self._const_getter(f)
        if c:
            res = ("const",) + c
        else:
            hs = self._hashes(f)
            if len(hs) >= 3 and hs[0] == hs[1] and hs[2] != hs[0]:
                res = ("member", hs[0], hs[2])
        self._fcache[f] = res
        return res

    # --- registration code walk ---------------------------------------------
    def detect_wire_offset(self, regs, sample=400):
        """The member descriptor's packet-flag byte moves between versions
        (0xa8 in 1.26.52, 0xb8 in 1.26.70 previews). It is the byte offset
        most often set to 1/4/5 (Compression / Enum-as-Value) in
        registration code."""
        import collections
        c = collections.Counter()
        for f in regs[:sample]:
            for i in asm.insns(self.b, f, limit=200000):
                if i.mnemonic != "mov" or len(i.operands) != 2:
                    continue
                d, s_ = i.operands
                if d.type == X86_OP_MEM and s_.type == X86_OP_IMM and d.size == 1                         and 0x80 <= d.mem.disp < 0x400 and d.mem.index == 0                         and s_.imm in (1, 4, 5) and i.reg_name(d.mem.base) not in ("rsp", "rbp"):
                    c[d.mem.disp] += 1
        if c:
            WIRE_OFF[0] = c.most_common(1)[0][0]
        return WIRE_OFF[0]

    def registration_functions(self):
        b = self.b
        fs = set()
        for addr, _ in b.find_strings(rb"[^\0]*cereal::BasicFactory<[^\0]*"):
            for site in self.xr.to(addr):
                fs.add(b.funcs[bisect.bisect_right(b.funcs, site) - 1])
        # Some registrations have no assert string; they still load the
        # type's display name, which is usually its C++ name.
        known = {n for n in self.H.values() if n not in PRIMITIVES}
        for addr, s in b.find_strings(rb"[A-Za-z_][A-Za-z0-9_:]{2,100}"):
            if s in known:
                for site in self.xr.to(addr):
                    fs.add(b.funcs[bisect.bisect_right(b.funcs, site) - 1])
        return sorted(fs)

    def _callee_event(self, f, depth=2):
        """First member/const accessor referenced inside an outlined
        registration helper (the name is passed in as an argument)."""
        key = ("callee", f, depth)
        if key in self._fcache:
            return self._fcache[key]
        self._fcache[key] = None  # recursion guard
        # A member helper can also reference a constant getter (a default
        # value), so a member anywhere in the helper wins over a constant.
        found = []
        for i in asm.insns(self.b, f, limit=3000):
            if i.mnemonic == "lea":
                r = asm.rip_target(i)
                if r is not None and self.b.in_section(r, ".text"):
                    c = self.classify(r)
                    if c:
                        found.append(c)
            elif i.mnemonic == "call" and depth > 0:
                # Only members are taken from nested helpers. An enumerator
                # helper references its constant getter directly; the enum's
                # scope/display-name setup only reaches one through a nested
                # call, and must not become a fake "= 0" value.
                t = asm.branch_target(i)
                if t and self.b.in_section(t, ".text"):
                    c = self._callee_event(t, depth - 1)
                    if c and c[0] == "member":
                        found.append(c)
            if any(c[0] == "member" for c in found):
                break
        res = next((c for c in found if c[0] == "member"), found[0] if found else None)
        self._fcache[key] = res
        return res

    def _helper_flags(self, f):
        key = ("flags", f)
        if key not in self._fcache:
            v = w = 0
            for i in asm.insns(self.b, f, limit=3000):
                fl = flag_or(i)
                if fl is not None:
                    v |= fl
                ws = wire_store(i)
                if ws is not None:
                    w |= ws
            self._fcache[key] = (v, w)
        return self._fcache[key]

    def walk(self, f, schema):
        b = self.b
        pending = []  # strings since the last member/const event
        last_str = -1 << 40
        self._last = None  # last member dict, collects following flag ORs
        sso = SSOTracker()
        for i in asm.insns(b, f, limit=400000):
            inline = sso.step(i)
            if inline:
                pending.append(inline)
                last_str = i.address
                continue
            fl = flag_or(i)
            if fl is not None and self._last is not None:
                self._last["flags"] |= fl
                continue
            w = wire_store(i)
            if w is not None and self._last is not None:
                self._last["wire"] |= w
                continue
            if i.mnemonic == "call" and pending and i.address - last_str < 40:
                # Outlined helper taking the member or enumerator name as an
                # argument. The enum's own scope setup also passes a name (the
                # enum's) and reaches a constant getter; that one is skipped.
                t = asm.branch_target(i)
                if t and b.in_section(t, ".text"):
                    c = self._callee_event(t)
                    if c and (c[0] == "member" or not self._is_scope_name(c[1], pending[-1])):
                        self._emit(c, pending, schema)
                        pending = []
                        if self._last is not None:
                            v, w = self._helper_flags(t)
                            self._last["flags"] |= v
                            self._last["wire"] |= w
                continue
            if i.mnemonic != "lea":
                continue
            r = asm.rip_target(i)
            if r is None:
                continue
            if b.in_section(r, ".rodata"):
                s = b.cstr(r, 300)
                if s and s.isprintable() and not s.startswith(NOISE):
                    pending.append(s)
                    last_str = i.address
            elif b.in_section(r, ".text"):
                c = self.classify(r)
                if not c:
                    continue
                self._emit(c, pending, schema)
                pending = []

    @staticmethod
    def _is_scope_name(typ, name):
        """True for names that are not enumerators: the enum's own name or
        display name (passed to its scope setup) and cereal tag strings."""
        last = typ.rsplit("::", 1)[-1]
        flat = typ.replace("::", "")
        return (name in (typ, last, flat) or name == "newlyCreated"
                or name.startswith("[") or "::" in name
                or (name.endswith(last) and len(name) > len(last)))

    def _emit(self, c, pending, schema):
        if not pending:
            return
        if c[0] == "member":
            self._last = schema.member(c[1], pending[-1], c[2], pending[:-1])
        elif c[0] == "const" and not self._is_scope_name(c[1], pending[-1]):
            schema.enumerator(c[1], pending[-1], c[2], c[3])
            self._last = None


class Schema:
    def __init__(self):
        self.types = {}   # owner -> list of (name, type), ordered, deduped
        self.enums = {}   # enum -> {"size": n, "values": [(name, value)]}

    def member(self, owner, name, typ, extra=()):
        # extra = strings seen between the previous member and this one:
        # the type's display name, a variant tag name ("Action"), notes.
        lst = self.types.setdefault(owner, [])
        for m in lst:
            if m["name"] == name and m["type"] == typ:
                return m
        m = {"name": name, "type": typ, "flags": 0, "wire": 0, "extra": list(extra)}
        lst.append(m)
        return m

    def finish(self):
        # A constant of a struct type is a member default value, not an enum.
        for t in list(self.enums):
            if t in self.types:
                del self.enums[t]

    def enumerator(self, typ, name, val, size):
        e = self.enums.setdefault(typ, {"size": size, "values": []})
        if (name, val) not in e["values"]:
            e["values"].append((name, val))
