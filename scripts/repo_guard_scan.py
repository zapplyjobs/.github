#!/usr/bin/env python3
"""repo_guard_scan.py — server-side malware/config injection guard (NullReceiver campaign).

Runs in CI on every push/PR. Fails (exit 1) if any known payload shape is present
in the repository's HEAD tree. Zero dependencies beyond git + python3 stdlib.

IOC source of truth: scripts/repo_guard_iocs.json NEXT TO THIS FILE (single source,
shared with the workspace weekly rescan inf-org-malware-rescan.sh). Update the JSON only.
"""
import json
import subprocess
import sys
from pathlib import Path

IOCS = json.loads((Path(__file__).parent / "repo_guard_iocs.json").read_text())
BAD_BLOB_SHAS = IOCS["bad_blob_shas"]
MARKERS = [m.encode() for m in IOCS["markers"]]
ATTACK_CONFIG_HINTS = IOCS["attack_config_hints"]
WEAK_CONFIG_HINTS = IOCS.get("weak_config_hints", [])
CONFIG_SIZE_LIMIT = IOCS["oversized_config_bytes"]
CONFIGS = set(IOCS["watched_configs"])
FONT_MAGICS = [bytes.fromhex(h) for h in IOCS["font_magics_hex"]]

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
        if not any(blob[:len(m)] == m for m in FONT_MAGICS):
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
                findings.append(f"{p} contains attacker config hint {hint!r}")
        # Weak hints (standard Node ESM createRequire idiom, which the E158 prep shim
        # also used) fire ONLY with corroboration — a campaign marker or an oversized
        # config. Live false-positive: zapply-chrome-extension vite.config.js (legit
        # since 2026-06). All observed campaign configs matched markers + oversize too.
        if any(m in blob for m in MARKERS) or len(blob) > CONFIG_SIZE_LIMIT:
            for hint in WEAK_CONFIG_HINTS:
                if hint.encode() in blob:
                    findings.append(f"{p} contains shim hint {hint!r} with corroboration (marker/oversize)")
        if len(blob) > CONFIG_SIZE_LIMIT:
            findings.append(f"{p} is {len(blob)}B (config files are normally <6KB — inspect for appended payload)")

if findings:
    print("::error::repo-guard FAILED — known malware/injection shapes detected")
    for f in findings:
        print(f"::error::{f}")
    sys.exit(1)
print("repo-guard PASS: no known payload shapes in HEAD tree")
