"""One command for a new Minecraft version: download the Linux BDS, dump all
packets and enums, diff against the previous dump, and (if Mojang has
published docs for that version) measure accuracy against them.

    python dumper/update.py                   # latest release
    python dumper/update.py --preview         # latest preview
    python dumper/update.py --version 1.26.52.3 [--preview]
    python dumper/update.py --binary path/to/bedrock_server --version X

Everything is written under work/ (git-ignored): the server binary and every
dump are derived from Mojang's files and are never committed.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WORK = os.path.join(ROOT, "work")
LINKS = "https://net-secondary.web.minecraft-services.net/api/v1.0/download/links"
DOCS_REPO = "Mojang/bedrock-protocol-docs"
UA = {"User-Agent": "Mozilla/5.0"}


def latest(preview):
    data = json.load(urllib.request.urlopen(urllib.request.Request(LINKS, headers=UA)))
    want = "serverBedrockPreviewLinux" if preview else "serverBedrockLinux"
    for link in data["result"]["links"]:
        if link["downloadType"] == want:
            return re.search(r"bedrock-server-([\d.]+)\.zip", link["downloadUrl"]).group(1), link["downloadUrl"]
    sys.exit("no %s link in %s" % (want, LINKS))


def fetch_binary(version, preview, url=None):
    folder = os.path.join(WORK, version)
    binary = os.path.join(folder, "bedrock_server")
    if os.path.exists(binary):
        return binary
    os.makedirs(folder, exist_ok=True)
    url = url or "https://www.minecraft.net/bedrockdedicatedserver/%s/bedrock-server-%s.zip" % (
        "bin-linux-preview" if preview else "bin-linux", version)
    zpath = os.path.join(folder, "bds.zip")
    print("downloading", url)
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA)) as r, open(zpath, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
    with zipfile.ZipFile(zpath) as z:
        z.extract("bedrock_server", folder)
    os.remove(zpath)
    return binary


def previous_dump(version):
    """Newest other dump in work/, by version number."""
    key = lambda v: [int(x) for x in v.split(".") if x.isdigit()]
    others = [v for v in os.listdir(WORK) if v != version
              and os.path.exists(os.path.join(WORK, v, "dump", "packets.json"))]
    older = [v for v in others if key(v) < key(version)]
    pick = max(older or others, key=key, default=None)
    return pick


def docs_json(version, preview):
    """Download Mojang's published schemas for this version, if they exist."""
    short = ".".join(version.split(".")[:3]) if not preview else version
    candidates = ["automated/%s" % short, "v%s" % short]
    if preview:
        parts = version.split(".")
        candidates = ["v%s-preview.%s" % (".".join(parts[:3]), parts[3])]
    folder = os.path.join(WORK, "docs", version)
    if os.path.isdir(os.path.join(folder, "json")):
        return os.path.join(folder, "json")
    for ref in candidates:
        try:
            tar = subprocess.run(["gh", "api", "repos/%s/tarball/%s" % (DOCS_REPO, ref)],
                                 capture_output=True, check=True).stdout
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
        os.makedirs(folder, exist_ok=True)
        import io
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(tar)) as t:
            for m in t.getmembers():
                parts = m.name.split("/", 1)
                if len(parts) == 2 and parts[1].startswith("json/"):
                    m.name = parts[1]
                    t.extract(m, folder)
        print("docs:", ref)
        return os.path.join(folder, "json")
    print("no published docs for %s yet (that is when this tool matters)" % version)
    return None


def run(script, *args):
    subprocess.run([sys.executable, os.path.join(HERE, script), *args], check=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version")
    ap.add_argument("--preview", action="store_true")
    ap.add_argument("--binary")
    ap.add_argument("--no-docs", action="store_true")
    a = ap.parse_args()

    url = None
    version = a.version
    if not version:
        version, url = latest(a.preview)
    print("version", version, "(preview)" if a.preview else "")
    binary = a.binary or fetch_binary(version, a.preview, url)
    out = os.path.join(WORK, version, "dump")
    run("dump_packets.py", binary, out)

    prev = previous_dump(version)
    if prev:
        diff = os.path.join(out, "diff-from-%s.txt" % prev)
        run("diff_packets.py", os.path.join(WORK, prev, "dump"), out, diff)
        print("diff:", diff)
    else:
        print("no earlier dump in work/ to diff against")

    if not a.no_docs:
        docs = docs_json(version, a.preview)
        if docs:
            run("compare_docs.py", out, docs)
            run("validate_docs.py", out, docs)
    print("done:", out)


if __name__ == "__main__":
    main()
