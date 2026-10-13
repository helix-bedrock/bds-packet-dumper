"""Compare a dump's types/enums with Mojang's published JSON schemas for the
same version (github.com/Mojang/bedrock-protocol-docs, json/ folder).

    python validate_docs.py <dump_dir> <docs_json_dir>

Used to measure the extractor's accuracy on a version where docs exist, so it
can be trusted on a version where they do not exist yet.
"""
import glob
import json
import os
import sys

OPTION_BITS = [(0x01, "Compression"), (0x02, "Big Endian"), (0x04, "Enum-as-Value"),
               (0x08, "No size compression"), (0x20, "Allow unknown enum values")]

UNDERLYING = {
    "bool": "boolean", "signed char": "int8", "char": "int8", "unsigned char": "uint8",
    "short": "int16", "unsigned short": "uint16", "int": "int32",
    "unsigned int": "uint32", "long": "int64", "long long": "int64",
    "unsigned long": "uint64", "unsigned long long": "uint64",
    "float": "float", "double": "double",
}


def options(flags):
    return [n for bit, n in OPTION_BITS if flags & bit]


def doc_file_name(t):
    return t.replace("::", "__").replace(" ", "_") + ".json"


def main():
    dump, docs = sys.argv[1], sys.argv[2]
    types = json.load(open(os.path.join(dump, "types.json")))
    enums = json.load(open(os.path.join(dump, "enums.json")))
    # Docs title types by display name ("AuthorAndMessage"); the dump keys
    # them by C++ name ("TextPacketPayload::AuthorAndMessage"). The display
    # name is the extra string seen right before a type's first member.
    alias = {}
    for t, ms in types.items():
        alias.setdefault(t, t)
        alias.setdefault(t.rsplit("::", 1)[-1], t)
        if ms and ms[0].get("extra"):
            alias.setdefault(ms[0]["extra"][0], t)
    for t in enums:
        alias.setdefault(t, t)
        alias.setdefault(t.rsplit("::", 1)[-1], t)
    doc = {}
    for f in glob.glob(os.path.join(docs, "*.json")):
        d = json.load(open(f, encoding="utf-8"))
        doc[d.get("title", os.path.basename(f)[:-5])] = d
    stats = {"types_in_docs": 0, "types_missing_in_dump": 0, "name_order_ok": 0,
             "name_order_bad": 0, "opt_ok": 0, "opt_bad": 0, "utype_ok": 0, "utype_bad": 0,
             "enums_in_docs": 0, "enum_ok": 0, "enum_bad": 0, "enums_missing": 0}
    bad = []
    for title, d in doc.items():
        if d.get("type") == "object" and "properties" in d:
            stats["types_in_docs"] += 1
            title = alias.get(title, title)
            if title not in types:
                stats["types_missing_in_dump"] += 1
                bad.append("missing type " + title)
                continue
            props = sorted(d["properties"].items(), key=lambda kv: kv[1].get("x-ordinal-index", 0))
            want = [k for k, _ in props]
            got = [m["name"] for m in types[title]]
            if want == got:
                stats["name_order_ok"] += 1
            else:
                stats["name_order_bad"] += 1
                bad.append("names %s: docs=%s dump=%s" % (title, want, got))
            mine = {m["name"]: m for m in types[title]}
            for k, p in props:
                m = mine.get(k)
                if not m:
                    continue
                want_opts = sorted(p.get("x-serialization-options", []))
                got_opts = sorted(options(m.get("wire", 0)))
                if want_opts == got_opts:
                    stats["opt_ok"] += 1
                else:
                    stats["opt_bad"] += 1
                    bad.append("opts %s.%s: docs=%s dump=%s (%s)" % (title, k, want_opts, got_opts, m["type"]))
                ut = p.get("x-underlying-type")
                if ut and m["type"] in UNDERLYING:
                    if UNDERLYING[m["type"]] == ut:
                        stats["utype_ok"] += 1
                    else:
                        stats["utype_bad"] += 1
                        bad.append("utype %s.%s: docs=%s dump=%s" % (title, k, ut, m["type"]))
        elif "enum" in d or "oneOf" in d and all("const" in o for o in d.get("oneOf", [])):
            stats["enums_in_docs"] += 1
            title = alias.get(title, title)
            if title not in enums:
                stats["enums_missing"] += 1
                bad.append("missing enum " + title)
                continue
            if "oneOf" in d:
                want = sorted((o.get("title"), o.get("const")) for o in d["oneOf"])
            else:
                want = None
            got = sorted((n, v) for n, v in enums[title]["values"])
            if want is None or want == got:
                stats["enum_ok"] += 1
            else:
                stats["enum_bad"] += 1
                bad.append("enum %s: docs=%s dump=%s" % (title, want[:6], got[:6]))
    for k, v in stats.items():
        print("%-22s %d" % (k, v))
    with open(os.path.join(dump, "validate_docs.txt"), "w", encoding="utf-8") as fo:
        fo.write("\n".join(bad))
    print("details:", os.path.join(dump, "validate_docs.txt"))


if __name__ == "__main__":
    main()
