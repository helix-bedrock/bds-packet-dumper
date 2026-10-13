"""Enum extraction v2: find every constant getter by its instruction pattern
(mov dword ptr [rdi+0x20], <enum type hash>), read its value, then name it
from the nearest string loaded before the getter is referenced (following
outlined helpers up to their call sites)."""
import bisect

import asm
from xrefs import Calls, find_imm_stores

NAME_WINDOW = 0x120  # bytes searched backwards for the enumerator name


class EnumFinder:
    def __init__(self, ex, calls_cache):
        self.ex = ex
        self.b = ex.b
        self.calls = Calls(self.b, calls_cache)
        self._scache = {}

    def _fn(self, a):
        return self.b.funcs[bisect.bisect_right(self.b.funcs, a) - 1]

    def _strings_in(self, f):
        """Sorted (addr, string) of every string lea in function f (cached)."""
        c = self._scache.get(f)
        if c is None:
            c = []
            for i in asm.insns(self.b, f, limit=400000):
                if i.mnemonic == "lea":
                    r = asm.rip_target(i)
                    if r is not None and self.b.in_section(r, ".rodata"):
                        s = self.b.cstr(r, 200)
                        if s and s.isprintable() and not s.startswith(self.ex.noise):
                            c.append((i.address, s))
            self._scache[f] = c
        return c

    def _name_before(self, site, typ):
        """Last usable string lea in [site-NAME_WINDOW, site)."""
        lst = self._strings_in(self._fn(site))
        k = bisect.bisect_left(lst, (site, ""))
        while k > 0:
            k -= 1
            a, s = lst[k]
            if a < site - NAME_WINDOW:
                return None
            if not self.ex._is_scope_name(typ, s):
                return s
        return None

    def run(self, schema, struct_types):
        """Adds enums that the registration walk did not find."""
        H = self.ex.H
        enum_hashes = {h for h, n in H.items()
                       if n not in struct_types and n not in schema.enums}
        getters = {}
        for site, h in find_imm_stores(self.b, b"\xC7\x47\x20", enum_hashes):
            f = self._fn(site)
            c = self.ex._const_getter(f)
            if c:
                getters[f] = c
        for f, (typ, val, size) in getters.items():
            name = None
            for ref in self.ex.xr.to(f):
                name = self._name_before(ref, typ)
                if name:
                    break
                # outlined enumerator helper: name is passed by its caller
                for call in self.calls.to(self._fn(ref)):
                    name = self._name_before(call, typ)
                    if name:
                        break
                if name:
                    break
            if name:
                schema.enumerator(typ, name, val, size)
        return len(getters)
