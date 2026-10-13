"""Enum underlying types. cereal's TypeSchema<Enum> class mentions the
underlying integer type's entt hash in vtable slot 7 (checked on
GeneratorType/GameType = int, TextPacketType = unsigned char)."""
import asm
import rtti
from capstone.x86 import X86_OP_IMM

from schemas import fnv1a

PRIMS = ["bool", "char", "signed char", "unsigned char", "short", "unsigned short",
         "int", "unsigned int", "long", "unsigned long", "long long", "unsigned long long"]
PRIM_HASH = {fnv1a(p): p for p in PRIMS}
SLOT = 7


def _scan(b, f, depth, seen, out):
    if depth < 0 or f in seen:
        return
    seen.add(f)
    for i in asm.insns(b, f, limit=1500):
        for op in i.operands:
            if op.type == X86_OP_IMM and (op.imm & 0xFFFFFFFF) in PRIM_HASH:
                out.append(PRIM_HASH[op.imm & 0xFFFFFFFF])
        if i.mnemonic == "call":
            t = asm.branch_target(i)
            if t and b.in_section(t, ".text"):
                _scan(b, t, depth - 1, seen, out)
        if i.mnemonic == "ret":
            break


def mangle(name):
    parts = name.split("::")
    if len(parts) == 1:
        return "%d%s" % (len(name), name)
    return "N" + "".join("%d%s" % (len(p), p) for p in parts) + "E"


def underlying(b, enum_name):
    m = "N6cereal8internal10TypeSchemaI%sEE" % mangle(enum_name)
    for addr, _ in b.find_suffix_strings(m.encode()):
        ti = rtti.typeinfo_for_name(b, addr)
        vt = rtti.primary_vtable(b, ti) if ti else None
        if not vt:
            continue
        slots = rtti.vtable_slots(b, vt)
        if len(slots) <= SLOT:
            continue
        out = []
        _scan(b, slots[SLOT], 1, set(), out)
        if out:
            return out[0]
    return None
