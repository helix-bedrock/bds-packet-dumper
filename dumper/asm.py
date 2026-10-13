"""Disassembly helpers with call/string annotation."""
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

_md = Cs(CS_ARCH_X86, CS_MODE_64)
_md.detail = True


def insns(b, start, end=None, limit=4000):
    end = end or b.func_end(start)
    code = b.read(start, min(end - start, 0x20000))
    n = 0
    for i in _md.disasm(code, start):
        yield i
        n += 1
        if n >= limit:
            return


def rip_target(i):
    for op in i.operands:
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
            return i.address + i.size + op.mem.disp
    return None


def branch_target(i):
    if i.mnemonic in ("call", "jmp") and i.operands and i.operands[0].type == X86_OP_IMM:
        return i.operands[0].imm
    return None


def show(b, start, names=None, end=None):
    names = names or {}
    for i in insns(b, start, end):
        note = ""
        t = branch_target(i)
        if t is not None:
            note = names.get(t, "")
        r = rip_target(i)
        if r is not None and b.in_section(r, ".rodata"):
            s = b.cstr(r, 80)
            if s and s.isprintable() and len(s) > 1:
                note = repr(s)
        print("  %x  %-40s %s" % (i.address, i.mnemonic + " " + i.op_str, note))
