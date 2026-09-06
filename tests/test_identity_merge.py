#!/usr/bin/env python3
"""
Unit test: identity-check merge-committer allowance (MERGECOMMIT-IDENTITY-GUARDFP-1).

Builds a throwaway git repo whose origin URL scopes it to an identity-checked repo,
fabricates the three commit shapes that matter, and runs the REAL scanner script
against the throwaway repo (IOCS copy re-scoped to the throwaway name):

  A. 2-parent merge commit, committer GitHub <noreply@github.com>  → PASS (the
     sanctioned merges-API promotion shape; was the false-positive class).
  B. 1-parent commit, committer GitHub <noreply@github.com>        → FAIL (spoof
     guard: only true merge commits get the allowance; author stays strict).
  C. 1-parent commit, outsider author+committer                    → FAIL (baseline).

Zero network; requires git + python3 on PATH.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "repo_guard_scan.py"
IOCS = Path(__file__).resolve().parent.parent / "scripts" / "repo_guard_iocs.json"

passed, failed = 0, 0


def ok(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✓ {name}")
    else:
        failed += 1
        print(f"  ✗ {name}")


def git(repo, *args, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run(["git", *args], cwd=repo, env=e, capture_output=True, text=True)


def commit_file(repo, path, content, env=None):
    p = Path(repo) / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    git(repo, "add", path)
    git(repo, "commit", "-m", f"add {path}", env=env)


def run_scanner(repo, harness_scripts):
    return subprocess.run(
        [sys.executable, str(harness_scripts / "repo_guard_scan.py")],
        cwd=repo, capture_output=True, text=True,
    )


def main():
    base = Path(tempfile.mkdtemp(prefix="guardfix-test-"))
    repo = base / "scratch-repo"
    harness_scripts = base / "scripts"
    try:
        # Harness copy of the scanner + re-scoped IOCS + empty content gate (the test
        # exercises the IDENTITY check only).
        harness_scripts.mkdir(parents=True)
        shutil.copy(SCRIPT, harness_scripts / "repo_guard_scan.py")
        iocs = json.loads(IOCS.read_text())
        iocs["identity_check"]["repos"] = ["job-board-processing"]
        (harness_scripts / "repo_guard_iocs.json").write_text(json.dumps(iocs))
        (harness_scripts / "repo_content_gate.json").write_text(json.dumps({"repos": {}}))

        ZA = {"GIT_AUTHOR_NAME": "z-apply", "GIT_AUTHOR_EMAIL": "admin@zapply.jobs",
              "GIT_COMMITTER_NAME": "z-apply", "GIT_COMMITTER_EMAIL": "admin@zapply.jobs"}
        GH = {"GIT_AUTHOR_NAME": "z-apply", "GIT_AUTHOR_EMAIL": "admin@zapply.jobs",
              "GIT_COMMITTER_NAME": "GitHub", "GIT_COMMITTER_EMAIL": "noreply@github.com"}

        # Scratch repo scoped by origin URL to an identity-checked repo.
        repo.mkdir(parents=True)
        git(repo, "init", "-b", "main")
        git(repo, "config", "user.name", "z-apply")
        git(repo, "config", "user.email", "admin@zapply.jobs")
        git(repo, "remote", "add", "origin", "https://github.com/zapplyjobs/job-board-processing.git")

        # Baseline allowlisted commit.
        commit_file(repo, "README.md", "scratch\n", env=ZA)

        # Case A: 2-parent merge commit with the GitHub machinery committer.
        git(repo, "checkout", "-b", "side", env=ZA)
        commit_file(repo, "side.txt", "side\n", env=ZA)
        git(repo, "checkout", "main", env=ZA)
        git(repo, "merge", "--no-ff", "side", "-m", "Merge branch 'side'", env=GH)
        r = run_scanner(repo, harness_scripts)
        ok("A: 2-parent GitHub-merge commit passes", r.returncode == 0)

        # Case B: 1-parent commit with the GitHub committer (spoof shape) → must fail.
        commit_file(repo, "spoof.txt", "spoof\n", env=GH)
        r = run_scanner(repo, harness_scripts)
        ok("B: 1-parent GitHub-committer commit fails", r.returncode == 1)
        ok("B: finding names IDENTITY", "IDENTITY" in r.stdout)

        # Reset to the merge state for case C.
        git(repo, "reset", "--hard", "HEAD~1")
        # Case C: outsider author+committer → fails (baseline guard intact).
        OUT = {"GIT_AUTHOR_NAME": "Stranger", "GIT_AUTHOR_EMAIL": "stranger@example.com",
               "GIT_COMMITTER_NAME": "Stranger", "GIT_COMMITTER_EMAIL": "stranger@example.com"}
        commit_file(repo, "out.txt", "out\n", env=OUT)
        r = run_scanner(repo, harness_scripts)
        ok("C: outsider commit fails", r.returncode == 1)
        ok("C: author finding present", "IDENTITY: author" in r.stdout)
    finally:
        shutil.rmtree(base, ignore_errors=True)

    print(f"\n{passed} passed, {failed} failed")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
