"""Per-packet exact comparison of a dump against Mojang's published JSON
schemas for the same version: both sides are flattened to the ordered list
of (field path, wire type) and compared.

    python compare_docs.py <dump_dir> <docs_json_dir>
"""
import json
import os
import sys

from validate_docs import options

UT_WIRE = {
    ("int8", False): "i8", ("uint8", False): "u8", ("int16", False): "i16",
    ("uint16", False): "u16", ("int32", False): "i32", ("int32", True): "varint32",
    ("uint32", False): "u32", ("uint32", True): "varuint32",
    ("int64", False): "i64", ("int64", True): "varint64",
    ("uint64", False): "u64", ("uint64", True): "varuint64",
    ("float", False): "f32", ("double", False): "f64",
}


class Docs:
    def __init__(self, folder):
        self.folder = folder
        self.cache = {}

    def load(self, ref):
        name = os.path.basename(ref)
        if name not in self.cache:
            p = os.path.join(self.folder, name)
            self.cache[name] = json.load(open(p, encoding="utf-8")) if os.path.exists(p) else None
        return self.cache[name]

    def flat(self, node, path, out, depth=0):
        if depth > 14 or node is None:
            return out
        if "$ref" in node and "properties" not in node:
            target = self.load(node["$ref"])
            merged = dict(target or {})
            merged.update({k: v for k, v in node.items() if k != "$ref"})
            return self.flat(merged, path, out, depth + 1)
        t = node.get("type")
        opts = node.get("x-serialization-options", [])
        if "properties" in node:
            props = sorted(node["properties"].items(), key=lambda kv: kv[1].get("x-ordinal-index", 0))
            for k, v in props:
                self.flat(v, path + [k], out, depth + 1)
        elif t == "array":
            out.append(("/".join(path), "list"))
            self.flat(node.get("items", {}), path + ["item"], out, depth + 1)
        elif "oneOf" in node and not all("const" in o for o in node["oneOf"]):
            out.append(("/".join(path), "variant"))
            for k, alt in enumerate(node["oneOf"]):
                self.flat(alt, path + ["[%d]" % k], out, depth + 1)
        elif t == "null":
            out.append(("/".join(path), "empty"))
        elif t == "boolean":
            out.append(("/".join(path), "bool"))
        elif t == "string" and "enum" not in node:
            out.append(("/".join(path), "string"))
        else:
            ut = node.get("x-underlying-type")
            # Compression only changes 32/64-bit integers
            comp = "Compression" in opts and ut in ("int32", "uint32", "int64", "uint64")
            w = UT_WIRE.get((ut, comp)) if ut else None
            out.append(("/".join(path), w or (ut or t or "?")))
        return out


def flat_dump(fields, path, out):
    for f in fields:
        node_flat(f, path + [f.get("name", "")], out)
    return out


def node_flat(n, path, out):
    t = n["type"]
    if t == "struct":
        flat_dump(n["fields"], path, out)
    elif t == "optional":
        # docs model optionals as a nullable value; compare the value only
        node_flat(n["of"], path, out)
    elif t == "list":
        out.append(("/".join(path), "list"))
        node_flat(n["of"], path + ["item"], out)
    elif t == "variant":
        out.append(("/".join(path), "variant"))
        for k, a in enumerate(n["alternatives"]):
            node_flat(a, path + ["[%d]" % k], out)
    else:
        out.append(("/".join(path), t))


def main():
    dump, folder = sys.argv[1], sys.argv[2]
    packets = json.load(open(os.path.join(dump, "packets.json")))
    docs = Docs(folder)
    exact = names_only = differ = nodoc = 0
    report = []
    for p in packets:
        d = docs.load(p["name"] + "Payload.json")
        if d is None or not p.get("payload"):
            nodoc += 1
            continue
        want = docs.flat(d, [], [])
        got = flat_dump(p["fields"], [], [])
        if want == got:
            exact += 1
            continue
        if [w[0] for w in want] == [g[0] for g in got]:
            names_only += 1
            kind = "TYPES"
        else:
            differ += 1
            kind = "LAYOUT"
        report.append("%s %s (id %d)" % (kind, p["name"], p["id"]))
        for k in range(max(len(want), len(got))):
            a = want[k] if k < len(want) else None
            b = got[k] if k < len(got) else None
            if a != b:
                report.append("    docs %-60s dump %s" % (a, b))
                if len(report) > 200000:
                    break
    print("packets compared: %d  exact: %d  same fields/different types: %d  different layout: %d  (no docs/payload: %d)"
          % (exact + names_only + differ, exact, names_only, differ, nodoc))
    with open(os.path.join(dump, "compare_docs.txt"), "w", encoding="utf-8") as fo:
        fo.write("\n".join(report))
    print("details:", os.path.join(dump, "compare_docs.txt"))


if __name__ == "__main__":
    main()
