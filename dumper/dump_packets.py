"""Dump every Bedrock packet (id, name, fields, wire types) and every enum from
a stripped Linux bedrock_server.

    python dump_packets.py <bedrock_server> <out_dir>

Writes <out_dir>/packets.json, enums.json, types.json and a readable
packets.txt. Use diff_packets.py to compare two dumps.

Two kinds of packets exist in 1.26.x:
- schema packets: written by Mojang's generic cereal writer from a reflected
  payload struct. Fields, names and types come from the schema; the wire
  encoding of integers comes from per-member flag bit 0 (varint) / bit 1
  (big-endian int32) / bit 3 (fixed u32 sizes), checked against every
  hand-written packet that also has a schema (see validate.py).
- hand-written packets: traced from their write() with BinaryStream doc names.

PRIVATE research tooling. Output is facts about the protocol, not code.
"""
import json
import os
import re
import sys
import time

import rtti
from bdsbin import Binary
from enums2 import EnumFinder
from schemas import Extractor, Schema
from tracer import Tracer, flatten
from xrefs import Calls, Xrefs

GENERIC_WRITER_PROLOGUE = "415741564154534881ec8803"
SLOT_ID, SLOT_NAME, SLOT_WRITE = 2, 3, 6


def int_wire(cxx, wire, enum_size=None):
    """C++ integer type + member flags -> wire type."""
    var = wire & 1
    if cxx in ("bool",):
        return "bool"
    if cxx in ("signed char", "char"):
        return "i8"
    if cxx == "unsigned char":
        return "u8"
    if cxx == "short":
        return "i16"
    if cxx == "unsigned short":
        return "u16"
    if cxx == "int":
        return "varint32" if var else ("i32be" if wire & 2 else "i32")
    if cxx == "unsigned int":
        return "varuint32" if var else "u32"
    if cxx in ("long", "long long"):
        return "varint64" if var else "i64"
    if cxx in ("unsigned long", "unsigned long long"):
        return "varuint64" if var else "u64"
    if cxx == "float":
        return "f32"
    if cxx == "double":
        return "f64"
    if cxx in ("std::string", "std::string_view"):
        return "string"
    return None


def enum_wire(e, wire):
    if e.get("underlying"):
        return int_wire(e["underlying"], wire)
    size = e["size"]
    signed = any(v < 0 for _, v in e["values"])
    if size == 1:
        return "i8" if signed else "u8"
    if size == 2:
        return "i16" if signed else "u16"
    if size == 4:
        return int_wire("int" if signed else "unsigned int", wire)
    return int_wire("long" if signed else "unsigned long", wire)


def split_args(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


class Expander:
    """Turns a schema type into a wire-level field tree."""

    def __init__(self, schema):
        self.types = schema.types
        self.enums = schema.enums

    def expand(self, cxx, wire=0, depth=0, seen=()):
        if depth > 12:
            return {"type": cxx, "note": "depth limit"}
        w = int_wire(cxx, wire)
        if w:
            return {"type": w}
        if cxx in self.enums:
            e = self.enums[cxx]
            return {"type": enum_wire(e, wire), "enum": cxx}
        m = re.fullmatch(r"std::optional<(.+)>", cxx)
        if m:
            return {"type": "optional", "present": "bool",
                    "of": self.expand(m.group(1), wire, depth + 1, seen)}
        m = re.fullmatch(r"std::vector<(.+)>", cxx)
        if m:
            return {"type": "list", "count": "u32" if wire & 8 else "varuint32",
                    "of": self.expand(m.group(1), wire, depth + 1, seen)}
        m = re.fullmatch(r"std::variant<(.+)>", cxx)
        if m:
            alts = split_args(m.group(1))
            return {"type": "variant", "index": "varuint32" if wire & 1 else "u32",
                    "alternatives": [dict(name=a, **self.expand(a, 0, depth + 1, seen))
                                     for a in alts]}
        if cxx in ("void", "cereal::NullType", "std::monostate"):
            return {"type": "empty"}
        if cxx in self.types and cxx not in seen:
            return {"type": "struct", "struct": cxx,
                    "fields": [dict(name=f["name"], **self.expand(f["type"], f["wire"], depth + 1, seen + (cxx,)))
                               for f in self.types[cxx]]}
        return {"type": "custom", "struct": cxx}


def packet_list(b):
    out = []
    for name, ti, vt in rtti.find_classes(b, rb"\d+[A-Za-z0-9_]*Packet"):
        if not vt:
            continue
        vs = rtti.vtable_slots(b, vt)
        if len(vs) <= SLOT_WRITE:
            continue
        c = b.read(vs[SLOT_ID], 6)
        if not (c[0] == 0xB8 and c[5] == 0xC3):
            continue
        out.append({"id": int.from_bytes(c[1:5], "little"), "name": name,
                    "write": vs[SLOT_WRITE], "slots": vs})
    out.sort(key=lambda p: p["id"])
    return out


def packet_owners(b, calls, regs, plist, max_depth=8):
    """For each registration function, the packets whose vtable methods reach
    it through direct calls (searched upwards from the registration)."""
    import bisect
    root_owner = {}
    for p in plist:
        for f in p["slots"]:
            root_owner.setdefault(f, set()).add(p["name"])
    fn = lambda a: b.funcs[bisect.bisect_right(b.funcs, a) - 1]
    memo = {}

    def owners(f, depth):
        if f in root_owner:
            return root_owner[f]
        if depth == 0:
            return frozenset()
        key = (f, depth)
        if key in memo:
            return memo[key]
        memo[key] = frozenset()
        out = set()
        for site in calls.to(f):
            out |= owners(fn(site), depth - 1)
        memo[key] = frozenset(out)
        return memo[key]

    return {r: owners(r, max_depth) for r in regs}


def reachable_from_packets(b, plist, depth=3, max_size=0x40000):
    """Functions reached by direct calls from packet vtable methods (other
    than write). Some schema registrations have no assert string and an
    inline display name, so the string search alone misses them."""
    import asm
    seen = set()
    frontier = set()
    for p in plist:
        for k, f in enumerate(p["slots"]):
            if k > SLOT_WRITE:
                frontier.add(f)
    for _ in range(depth + 1):
        nxt = set()
        for f in frontier:
            if f in seen or b.func_end(f) - f > max_size:
                continue
            seen.add(f)
            for i in asm.insns(b, f, limit=60000):
                if i.mnemonic == "call":
                    t = asm.branch_target(i)
                    if t and b.in_section(t, ".text") and t not in seen:
                        nxt.add(t)
        frontier = nxt
    return seen


def merge_into(dst, src):
    """Add types/enums from src that dst does not have yet."""
    for t, members in src.types.items():
        dst.types.setdefault(t, members)
    for t, e in src.enums.items():
        dst.enums.setdefault(t, e)


def main():
    binpath, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    t0 = time.time()
    b = Binary(binpath)
    xr = Xrefs(b, binpath + ".xrefs.npz")
    ex = Extractor(b, xr)
    plist = packet_list(b)
    calls = Calls(b, binpath + ".calls.npz")
    regs = ex.registration_functions()
    print("packet flag byte offset: 0x%x" % ex.detect_wire_offset(regs))
    extra = reachable_from_packets(b, plist)
    regs = sorted(set(regs) | extra)
    owners = packet_owners(b, calls, regs, plist)
    # Walk every registration once into its own Schema. A type can be
    # registered more than once with different display names (the packet
    # form, a JSON data form, another packet's local form), so each packet is
    # expanded from the registrations its own vtable reaches first, then the
    # shared packet-side pool, then everything else.
    per_fn = {}
    for f in regs:
        per_fn[f] = Schema()
        ex.walk(f, per_fn[f])
    schema = Schema()
    for f in regs:
        if owners[f]:
            merge_into(schema, per_fn[f])
    for f in regs:
        if not owners[f]:
            merge_into(schema, per_fn[f])
    EnumFinder(ex, binpath + ".calls.npz").run(schema, set(schema.types))
    schema.finish()
    from enumtypes import underlying
    import re as _re
    factory = set()
    for _, txt in b.find_strings(rb"[^\0]*cereal::BasicFactory<[^\0]*"):
        m = _re.search(r"cereal::BasicFactory<(.+?)>::(viewFromScope|scope)\(", txt)
        if m:
            factory.add(m.group(1))
    for name in list(schema.enums):
        e = schema.enums[name]
        e["underlying"] = underlying(b, name)
        # A constant getter for a struct (a component's default instance)
        # looks like an enum value; real enums have an underlying integer
        # type or an enum factory.
        if not e["underlying"] and name not in factory:
            del schema.enums[name]
    by_packet = {}
    for f in regs:
        for name in owners[f]:
            by_packet.setdefault(name, []).append(f)
    print("registrations: %d, reached from packets: %d" % (len(regs), sum(1 for f in regs if owners[f])))
    print("schemas: %d types, %d enums (%.0fs)" % (len(schema.types), len(schema.enums), time.time() - t0))

    tr = Tracer(b)
    packets = []
    for p in plist:
        p.pop("slots")
        w = p.pop("write")
        generic = b.read(w, 12).hex() == GENERIC_WRITER_PROLOGUE
        # Mojang generates its protocol docs from the payload schema of
        # every packet, hand-written ones included, so the schema is the
        # primary description; the hand-written trace is kept as a check
        # of the actual wire order.
        payload = p["name"] + "Payload" if p["name"] + "Payload" in schema.types else None
        if payload is None and generic:
            hs = ex._hashes(w, depth=2)
            payload = next((h for h in hs if h in schema.types), None) or                 next((h for h in hs if h == p["name"] + "Payload"), None)
        p["writer"] = "generic" if generic else "handwritten"
        p["payload"] = payload
        if payload:
            local = Schema()
            for f in by_packet.get(p["name"], []):
                merge_into(local, per_fn[f])
            merge_into(local, schema)
            local.enums = schema.enums
            p["fields"] = Expander(local).expand(payload).get("fields", [])
            if not p["fields"]:
                p["note"] = "payload has no registered members (empty packet?)"
        else:
            p["fields"] = []
            p["note"] = "no payload schema found"
        if not generic:
            p["trace"] = tr.trace(w)
        packets.append(p)
    print("packets: %d (%d with schema, %d hand-written writers) (%.0fs)" % (
        len(packets), sum(bool(p["payload"]) for p in packets),
        sum(p["writer"] == "handwritten" for p in packets), time.time() - t0))

    json.dump(packets, open(os.path.join(outdir, "packets.json"), "w"), indent=1)
    json.dump(schema.enums, open(os.path.join(outdir, "enums.json"), "w"), indent=1)
    json.dump(schema.types, open(os.path.join(outdir, "types.json"), "w"), indent=1)
    with open(os.path.join(outdir, "packets.txt"), "w", encoding="utf-8") as fo:
        for p in packets:
            fo.write("%3d  %s  [%s writer%s]\n" % (p["id"], p["name"], p["writer"],
                                                 ", " + p["payload"] if p.get("payload") else ""))
            if p.get("note"):
                fo.write("  NOTE: %s\n" % p["note"])
            for line in schema_lines(p["fields"], 1, schema.enums):
                fo.write(line + "\n")
            if p.get("trace"):
                fo.write("  -- hand-written writer trace (wire order check):\n")
                for line in flatten(p["trace"], 2):
                    fo.write(line + "\n")
            fo.write("\n")
    print("done (%.0fs) -> %s" % (time.time() - t0, outdir))


def schema_lines(fields, depth, enums):
    lines = []
    for f in fields:
        lines += node_lines(f.get("name", ""), f, depth, enums)
    return lines


def node_lines(name, n, depth, enums):
    pad = "  " * depth
    t = n["type"]
    if t == "struct":
        lines = ["%s%-10s %s  (%s)" % (pad, "struct", name, n["struct"])]
        return lines + schema_lines(n["fields"], depth + 1, enums)
    if t == "optional":
        return ["%s%-10s %s" % (pad, "optional", name)] + node_lines("value", n["of"], depth + 1, enums)
    if t == "list":
        return ["%s%-10s %s  (count %s)" % (pad, "list", name, n["count"])] + node_lines("item", n["of"], depth + 1, enums)
    if t == "variant":
        lines = ["%s%-10s %s  (index %s)" % (pad, "variant", name, n["index"])]
        for k, a in enumerate(n["alternatives"]):
            lines += node_lines("[%d] %s" % (k, a["name"]), a, depth + 1, enums)
        return lines
    if t == "custom":
        return ["%s%-10s %s  (%s: custom serializer)" % (pad, "custom", name, n["struct"])]
    s = "%s%-10s %s" % (pad, t, name)
    if n.get("enum"):
        vals = enums.get(n["enum"], {}).get("values", [])
        s += "  enum %s {%s}" % (n["enum"], ", ".join("%s=%d" % (a, v) for a, v in vals[:40]))
    return [s]


if __name__ == "__main__":
    main()
