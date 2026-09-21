#!/usr/bin/env python3
"""Regression tests for the normal Node ESM require.resolve config allowance.

The allowance must be narrow: a large Vite config using only Node's documented
``createRequire``/``require.resolve`` bridge passes, but the same config still
fails when it contains a known marker or uses the bridge to load a module.
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "repo_guard_scan.py"
IOCS = Path(__file__).resolve().parent.parent / "scripts" / "repo_guard_iocs.json"
GATE = Path(__file__).resolve().parent.parent / "scripts" / "repo_content_gate.json"

passed, failed = 0, 0


def ok(name, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  ✓ {name}")
    else:
        failed += 1
        print(f"  ✗ {name}")


def run(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def scan(repo, scripts):
    return run(sys.executable, str(scripts / "repo_guard_scan.py"), cwd=repo)


def write_and_commit(repo, content):
    (repo / "vite.config.js").write_text(content)
    run("git", "add", "vite.config.js", cwd=repo)
    result = run("git", "commit", "-m", "fixture", cwd=repo)
    if result.returncode:
        raise RuntimeError(result.stderr)


def main():
    base = Path(tempfile.mkdtemp(prefix="guard-ems-require-test-"))
    scripts = base / "scripts"
    try:
        scripts.mkdir()
        shutil.copy(SCRIPT, scripts / "repo_guard_scan.py")
        shutil.copy(IOCS, scripts / "repo_guard_iocs.json")
        shutil.copy(GATE, scripts / "repo_content_gate.json")

        normal = """import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const pdfWorker = require.resolve('pdfjs-dist/build/pdf.worker.mjs');
""" + ("// ordinary Vite configuration\n" * 300)
        unsafe_use = normal.replace(
            "require.resolve('pdfjs-dist/build/pdf.worker.mjs')",
            "require('child_process')",
        )

        for name, content, should_pass, expected in (
            ("normal resolver", normal, True, ""),
            ("normal resolver with marker", normal + "\n// eth.blockscout.com\n", False, "MARKER"),
            ("non-resolve require use", unsafe_use, False, "shim hint"),
        ):
            repo = base / name.replace(" ", "-")
            repo.mkdir()
            run("git", "init", "-b", "main", cwd=repo)
            run("git", "config", "user.name", "z-apply", cwd=repo)
            run("git", "config", "user.email", "admin@zapply.jobs", cwd=repo)
            # Fixtures exist only to exercise the scanner; do not require the
            # developer's signing agent to be available for their throwaway commits.
            run("git", "config", "commit.gpgsign", "false", cwd=repo)
            run("git", "remote", "add", "origin", "https://github.com/zapplyjobs/unlisted-test.git", cwd=repo)
            write_and_commit(repo, content)
            result = scan(repo, scripts)
            ok(f"{name} has expected result", (result.returncode == 0) == should_pass)
            if expected:
                ok(f"{name} keeps the relevant detector", expected in result.stdout)
    finally:
        shutil.rmtree(base, ignore_errors=True)

    print(f"\n{passed} passed, {failed} failed")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
