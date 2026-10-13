# bds-packet-dumper

Backup tool: dumps every Minecraft: Bedrock packet (ID, field names, wire
types) and every protocol enum (names, numeric values, underlying type)
straight from the **Linux Bedrock Dedicated Server binary**, and diffs two
versions.

Mojang normally publishes the same information on release day in
[Mojang/bedrock-protocol-docs](https://github.com/Mojang/bedrock-protocol-docs).
Use this when the docs are late or missing, or when you need enum **numbers**,
which the docs do not list.

## Quick start

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt     # Windows: .venv\Scripts\pip
.venv/bin/python dumper/update.py             # latest release
.venv/bin/python dumper/update.py --preview   # latest preview
```

Output goes to `work/<version>/dump/` (git-ignored):

| File | Contents |
|---|---|
| `packets.txt` | Readable list: every packet, its fields and wire types, enum values inline |
| `packets.json`, `enums.json`, `types.json` | Machine-readable dumps |
| `diff-from-<old>.txt` | New/removed/renumbered packets, field changes, enum changes |
| `compare_docs.txt` | Mismatches against Mojang's docs, when docs exist |

Individual steps:

```bash
python dumper/dump_packets.py <bedrock_server> <out_dir>
python dumper/diff_packets.py <old_out_dir> <new_out_dir> [diff.txt]
python dumper/compare_docs.py <out_dir> <docs>/json     # exact per-packet comparison
python dumper/validate_docs.py <out_dir> <docs>/json    # per type / enum / flag
```

## How it works

No symbols and no disassembler GUI. About 2.5 minutes per version.

- **Packets:** C++ RTTI names (`14AddActorPacket`) lead to each packet's vtable.
  Slot 2 returns the packet ID.
- **Fields and enums:** BDS registers a reflection schema (Mojang's "cereal" on
  top of EnTT) for every packet payload. Types are identified by FNV-1a-32
  hashes of their names. The registration code is walked in order:
  - Each field is a name string followed by an accessor that names
    `[owner, owner, field type, field type]` by hash.
  - Each enum value is a name followed by a constant getter holding the enum
    hash and the value.
- **Wire encoding:** a per-field flag byte, with the same meanings as the docs'
  `x-serialization-options`:

  | Bit | Option |
  |---|---|
  | 1 | Compression (varint) |
  | 2 | Big Endian |
  | 4 | Enum-as-Value |
  | 8 | No size compression |
  | 0x20 | Allow unknown enum values |

  Its offset moves between versions and is detected automatically.
- **Hand-written writers:** every `BinaryStream` write passes a
  `doc_field_name`, so these are also traced as a wire-order check.

## Accuracy

Measured with `compare_docs.py` against Mojang's docs for the same build:

| Version | Packets exactly equal | Encoding flags | Enum values |
|---|---|---|---|
| 1.26.52 | 145 / 218 | 1552 / 1557 | 129 ok, 0 wrong |
| 1.26.70-preview.20 | 155 / 227 | 1656 / 1666 | 133 ok, 0 wrong |

Known gaps (why the rest are not exact):

- **Custom types:** types with hand-written serializers show as `custom`. These
  are NBT (`CompoundTag`), item stack descriptors, item stack request slot
  info, `SynchedActorData` and some `SharedTypes`. They rarely change; take
  them from gophertunnel or the docs.
- **Variants:** shown as an index plus alternatives. On the wire, each
  alternative is selected by a tag (an enum constant).
- **Names:** some single-field types use the type name as the field name.

## Rules

- Never commit Mojang binaries, dumps or anything derived from them. `work/`
  is git-ignored for that reason.
- The tool reads the binary; it contains no Mojang code.
- Output is facts needed for interoperability. Check anything important
  against a real client connection.

## Licence

MIT. See [LICENSE](LICENSE).
