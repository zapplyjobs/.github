#!/usr/bin/env python3
"""repo_guard_scan.py — server-side malware/config injection guard (NullReceiver campaign).

Runs in CI on every push/PR. Fails (exit 1) if any known payload shape is present
in the repository's HEAD tree. Zero dependencies beyond git + python3 stdlib.

IOC source of truth: .omp/skills/malware-scanning/scripts/iocs.json (workspace);
this file carries the campaign constants inline — update both when IOCs change.
"""
import subprocess
import sys
from pathlib import Path

# --- Campaign constants (NullReceiver, Aug 2026) ---
BAD_BLOB_SHAS = {
    "c1a9ec600e907276f454ab23fd3795bd021c2386": "fa-solid-400.woff2 payload (31,206B JS)",
    "5e226620d2e360205cc8634e3c581a008d382561": ".vscode/tasks.json folderOpen auto-run",
}
MARKERS = [b"A11--#", b"eth.blockscout.com", b"166.88.134.62"]
FONT_MAGICS = {b"wOFF": (0, 4, "woff"), b"true": (0, 4, "ttf"), b"OTTO": (0, 4, "otf"), b"wOF2": (0, 4, "woff2"), b"\x00\x01\x00\x00": (0, 4, "ttf-sfnt")}

findings = []


def sh(*args):
    return subprocess.run(args, capture_output=True, cwd=Path.cwd())


# 1. Exact known-bad blob SHAs anywhere in the HEAD tree
tree = sh("git", "ls-tree", "-r", "HEAD").stdout.decode(errors="replace")
for line in tree.splitlines():
    meta = line.split("\t")
    if len(meta) != 2:
        continue
    info, path = meta
    sha = info.split()[2]
    if sha in BAD_BLOB_SHAS:
        findings.append(f"KNOWN PAYLOAD BLOB at {path} ({BAD_BLOB_SHAS[sha]})")

# 2. Marker strings in tracked files (git grep over the whole tree)
for marker in MARKERS:
    r = sh("git", "grep", "-l", "-F", marker, "HEAD")
    if r.returncode == 0 and r.stdout.strip():
        for hit in r.stdout.decode(errors="replace").splitlines():
            findings.append(f"MARKER '{marker.decode()}' in {hit}")

# 3. JavaScript hiding in font/asset extensions (magic mismatch + printable ratio)
lines = sh("git", "ls-tree", "-r", "HEAD", "--format=%(objectname) %(path)").stdout.decode(errors="replace")
objs = []
for line in lines.splitlines():
    parts = line.split(" ", 1)
    if len(parts) == 2:
        objs.append(parts)
for sha, path in objs:
    if path.lower().endswith((".woff2", ".woff", ".ttf", ".otf")):
        blob = sh("git", "cat-file", "blob", sha).stdout[:16]
        if not any(blob[o:o + n] == m for m, (o, n, _) in FONT_MAGICS.items()):
            findings.append(f"SCRIPT-IN-ASSET: {path} lacks font magic (first bytes: {blob[:8]!r})")

# 4. VS Code auto-task persistence
tracked = {p for _, p in objs}
if ".vscode/tasks.json" in tracked:
    blob = sh("git", "show", "HEAD:.vscode/tasks.json").stdout.decode(errors="replace")
    if "folderOpen" in blob:
        findings.append(".vscode/tasks.json contains folderOpen auto-run task")
if ".vscode/settings.json" in tracked:
    blob = sh("git", "show", "HEAD:.vscode/settings.json").stdout.decode(errors="replace")
    if "allowAutomaticTasks" in blob and "true" in blob.split("allowAutomaticTasks", 1)[1][:30]:
        findings.append(".vscode/settings.json enables task.allowAutomaticTasks")

# 5. createRequire shim appended to config files (the E158 config-variant prep)
CONFIGS = ("eslint.config.mjs", "eslint.config.js", "babel.config.js", "astro.config.mjs",
           "next.config.mjs", "next.config.js", "vite.config.js", "eslint.config.ts")
for _, p in objs:
    if p in CONFIGS:
        blob = sh("git", "show", f"HEAD:{p}").stdout
        for hint in ATTACK_CONFIG_HINTS:
            if hint.encode() in blob:
                findings.append(f"{p} contains attacker createRequire shim")
        if len(blob) > 6000:
            findings.append(f"{p} is {len(blob)}B (config files are normally <6KB — inspect for appended payload)")

if findings:
    print("::error::repo-guard FAILED — known malware/injection shapes detected")
    for f in findings:
        print(f"::error::{f}")
    sys.exit(1)
print("repo-guard PASS: no known payload shapes in HEAD tree")
