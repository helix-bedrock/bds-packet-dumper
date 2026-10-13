"""Diff two dump folders: new/removed/renumbered packets, field changes,
enum value changes.

    python diff_packets.py <old_dump> <new_dump> [out.txt]
"""
import json, os, sys
from compare_docs import flat_dump


def load(d):
    return (json.load(open(os.path.join(d, "packets.json"))),
            json.load(open(os.path.join(d, "enums.json"))))


def flat(p):
    if p.get("fields"):
        return flat_dump(p["fields"], [], [])
    out = []
    def walk(ns, path):
        for n in ns:
            if n["op"] == "call":
                walk(n["children"], path); continue
            out.append((path + (n.get("name") or ""), n["op"]))
            for ch in n.get("children", []):
                walk(ch, path + (n.get("name") or "") + "/")
    walk(p.get("trace", []), "")
    return out


def main():
    (op, oe), (np_, ne) = load(sys.argv[1]), load(sys.argv[2])
    o = {p["name"]: p for p in op}; n = {p["name"]: p for p in np_}
    L = []
    for k in sorted(set(n) - set(o)):
        L.append("NEW PACKET  %s (id %d)" % (k, n[k]["id"]))
        L += ["    + %-50s %s" % f for f in flat(n[k])]
    for k in sorted(set(o) - set(n)):
        L.append("REMOVED PACKET  %s (id %d)" % (k, o[k]["id"]))
    for k in sorted(set(o) & set(n)):
        a, b = o[k], n[k]
        head = []
        if a["id"] != b["id"]:
            head.append("    id %d -> %d" % (a["id"], b["id"]))
        fa, fb = flat(a), flat(b)
        if fa != fb:
            sa, sb = set(fa), set(fb)
            head += ["    - %-50s %s" % f for f in fa if f not in sb]
            head += ["    + %-50s %s" % f for f in fb if f not in sa]
            if sa == sb:
                head.append("    (same fields, order changed)")
        if head:
            L.append("CHANGED PACKET  %s (id %d)" % (k, b["id"]))
            L += head
    for k in sorted(set(ne) - set(oe)):
        L.append("NEW ENUM  %s: %s" % (k, ne[k]["values"]))
    for k in sorted(set(oe) & set(ne)):
        va = {tuple(x) for x in oe[k]["values"]}; vb = {tuple(x) for x in ne[k]["values"]}
        if va != vb or oe[k].get("underlying") != ne[k].get("underlying"):
            L.append("CHANGED ENUM  %s" % k)
            L += ["    - %s = %s" % v for v in sorted(va - vb, key=lambda x: x[1])]
            L += ["    + %s = %s" % v for v in sorted(vb - va, key=lambda x: x[1])]
            if oe[k].get("underlying") != ne[k].get("underlying"):
                L.append("    underlying %s -> %s" % (oe[k].get("underlying"), ne[k].get("underlying")))
    txt = "\n".join(L) or "no differences"
    if len(sys.argv) > 3:
        open(sys.argv[3], "w", encoding="utf-8").write(txt)
    print(txt[:6000])
    print("\n%d lines" % len(L))


if __name__ == "__main__":
    main()
