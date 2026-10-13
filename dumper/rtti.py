"""Itanium C++ ABI RTTI walking: class name -> typeinfo -> vtable."""
import re


def demangle_simple(mangled):
    """'14AddActorPacket' -> 'AddActorPacket'; nested 'N3Foo3BarE' -> 'Foo::Bar'."""
    s = mangled
    if s.startswith("N") and s.endswith("E"):
        s = s[1:-1]
    parts = []
    i = 0
    while i < len(s):
        m = re.match(r"\d+", s[i:])
        if not m:
            return None
        n = int(m.group())
        i += len(m.group())
        parts.append(s[i:i + n])
        i += n
    return "::".join(parts)


def typeinfo_for_name(b, name_addr):
    """A typeinfo object is {vptr, name ptr, ...}; the name pointer is at +8."""
    for ref in b.refs_to(name_addr):
        ti = ref - 8
        if b.ptr(ti) is not None and b.in_section(ti, ".data.rel.ro"):
            return ti
    return None


def primary_vtable(b, ti):
    """The address point of the primary vtable: the slot after the typeinfo
    pointer, where offset-to-top (the qword before the typeinfo ptr) is 0."""
    for ref in b.refs_to(ti):
        if b.ptr(ref - 8) != 0:
            continue
        first = b.ptr(ref + 8)
        if first is not None and b.in_section(first, ".text"):
            return ref + 8
    return None


def base_typeinfo(b, ti):
    """For a single-inheritance class (__si_class_type_info) the base typeinfo
    is at +16."""
    return b.ptr(ti + 16)


def vtable_slots(b, vt, max_slots=200):
    out = []
    for i in range(max_slots):
        p = b.ptr(vt + 8 * i)
        if p is None or not b.in_section(p, ".text"):
            # pure virtual / end of table
            if p is not None and p != 0 and b.in_section(p, ".plt"):
                out.append(p)
                continue
            break
        out.append(p)
    return out


def find_classes(b, pattern):
    """Yields (class name, typeinfo addr, vtable addr) for mangled names that
    match pattern."""
    seen = set()
    for addr, mangled in b.find_suffix_strings(pattern):
        # a regex hit inside a merged string can start at any digit of the
        # length prefix; try each start so "116Foo" also finds "16Foo"
        for k in range(len(mangled)):
            if not mangled[k].isdigit() and not (k == 0 and mangled[0] == "N"):
                break
            a, m = addr + k, mangled[k:]
            if a in seen or not b.refs_to(a):
                continue
            seen.add(a)
            yield from _class_at(b, a, m)


def _class_at(b, addr, mangled):
    name = demangle_simple(mangled)
    if not name:
        return
    ti = typeinfo_for_name(b, addr)
    if ti is None:
        return
    yield name, ti, primary_vtable(b, ti)
