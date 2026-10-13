# AGENTS.md

Rules for AI coding agents working in this repo. Also read the org-wide rules
in `../.github/AGENT_RULES.md`. Where they disagree, this file wins for this
repo.

## What this repo is

A Python backup tool that dumps Bedrock packets and enums from the Linux BDS
binary and diffs versions. It is not part of the engine and does not depend
on the engine API, so the pre-design freeze does not apply here.

## Commands

```bash
pip install -r requirements.txt
python -m compileall -q dumper
python dumper/update.py [--preview] [--version X]
```

## Layout

| File | Role |
|---|---|
| `dumper/bdsbin.py` | ELF loading, relocations, function starts |
| `dumper/rtti.py` | Itanium RTTI: name to typeinfo to vtable |
| `dumper/xrefs.py` | numpy reference and call indexes |
| `dumper/asm.py` | capstone helpers |
| `dumper/schemas.py` | Walks cereal schema registration: types, members, flags |
| `dumper/enums2.py`, `dumper/enumtypes.py` | Enum values and underlying types |
| `dumper/tracer.py` | Traces hand-written `BinaryStream` writers |
| `dumper/dump_packets.py` | Main dump |
| `dumper/diff_packets.py` | Diff between two dumps |
| `dumper/compare_docs.py`, `dumper/validate_docs.py` | Accuracy against Mojang's docs |
| `dumper/update.py` | One-command pipeline |

## Invariants: do not break these

1. Never commit Mojang binaries, dumps, decompiled code or disassembly. `work/`
   stays git-ignored.
2. Never hard-code a version-specific address or offset. Detect it, as
   `detect_wire_offset` does.
3. Every accuracy claim comes from `compare_docs.py` on a version with
   published docs.

## Gotchas

- Short names are built inline on the stack (libc++ short strings). See
  `SSOTracker`.
- A type can be registered more than once: once for packets and once for JSON
  data, with different display names. Registrations reached from a packet's
  own vtable win.
- Strings can be tail-merged, so search with `find_suffix_strings`.
