---
name: update-packets
description: When Minecraft Bedrock updates (release or preview), dump every packet and enum from the new Linux BDS with bds-packet-dumper, diff against the previous version, check accuracy against Mojang's bedrock-protocol-docs, and report what changed for the protocol / gophertunnel update. Use when asked "Minecraft updated", "what packets changed", "dump the packets", "new protocol version", or "update the protocol".
---

# Update packets for a new Minecraft version

Repo: `bds-packet-dumper` (workspace folder `../bds-packet-dumper` from any
Helix repo). All output goes to `work/` and is never committed.

## 1. Setup (once)

```bash
cd bds-packet-dumper
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt   # Linux/macOS: .venv/bin/
```

## 2. Run

```bash
.venv/Scripts/python dumper/update.py            # latest release
.venv/Scripts/python dumper/update.py --preview  # latest preview
.venv/Scripts/python dumper/update.py --version 1.26.80.1   # a specific build
```

This one command:
1. Asks Mojang's download API for the newest Linux BDS and downloads it
   (about 100 MB).
2. Dumps packets, types and enums to `work/<version>/dump/` (about 2.5 min).
3. Diffs against the newest older dump in `work/` and writes
   `diff-from-<old>.txt`.
4. If Mojang has published docs for that build, downloads them and runs
   `compare_docs.py` and `validate_docs.py`.

The diff needs an older dump. On a fresh machine, first dump the previous
version with `--version`.

## 3. Check the run is healthy

Read the console output:

- `packet flag byte offset: 0x..` must be found. In 1.26.52 it was 0xa8; in
  1.26.70 previews it was 0xb8.
  - If almost every int in the diff flips between varint and fixed, the offset
    detection failed. Fix `Extractor.detect_wire_offset`.
- `packets: N`: N should be close to the previous count. A big drop means the
  RTTI or vtable layout changed. Check `SLOT_ID` / `SLOT_WRITE` in
  `dump_packets.py`.
- When docs exist, compare against the baseline (see the README's accuracy
  table):
  - The "exact" packet count should be about 145+ of 220.
  - `enum_bad` should be 0.
  - `opt_bad` should be under 1%.
  - A clear drop means the tool broke; fix it before trusting the diff.

## 4. Report to the user

From `diff-from-<old>.txt`, summarise:

- **New packets** (name + ID + fields), **removed packets**, and **renumbered
  IDs**.
- **Changed packets:** the field-level `-`/`+` lines.
  - Ignore pure `custom` noise.
  - Point out wire-type changes (varint vs fixed) explicitly, because they
    break decoding silently.
- **Enum changes:** new or removed values and changed numbers.
  - Skip `Editor::*` and data-driven `SharedTypes::*` unless asked; they are
    not packet-relevant.

Then say plainly:

- Which parts are reliable: packet list, IDs, field names, varint flags and enum
  values.
- Which need a human: anything shown as `custom` (NBT, item stacks, item stack
  requests, entity metadata) and variant layouts. Check these against
  gophertunnel or the docs once they exist.
- That nothing was tested against a real client. A human has to join with the
  new client to confirm.

## Rules

- Never commit binaries, dumps or diffs. Never paste them into Helix repos,
  issues or PRs as Mojang-derived text. Describe changes in your own words
  instead: field names, types and IDs are protocol facts.
- Do not change accuracy numbers in the README unless `compare_docs.py`
  produced them.
