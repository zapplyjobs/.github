#!/usr/bin/env python3
"""
Unit test: identity-check merge-committer allowance (MERGECOMMIT-IDENTITY-GUARDFP-1).

Builds a throwaway git repo whose origin URL scopes it to an identity-checked repo,
fabricates the commit shapes that matter, and runs the REAL scanner script
against the throwaway repo (IOCS copy re-scoped to the throwaway name):

  A. 2-parent merge commit, committer GitHub <noreply@github.com>  → PASS (the
     sanctioned merges-API promotion shape; was the false-positive class).
  B. 1-parent commit, committer GitHub <noreply@github.com>        → PASS
     (INF-REPOGUARD-WEBMERGE-LANE-1: the registered web-flow lane is an exact
     (name,email) committer pair; squash/rebase web merges are 1-parent).
  B2. Same lane NAME with a foreign email                          → FAIL (the
     lane is a pair, never a name grant — the spoof tripwire).
  C. A documented exact-SHA 1-parent GitHub web edit               → PASS.
  D. 1-parent commit, outsider author+committer                    → FAIL (baseline).

  E. Registered lane identity (identity_check.lanes) on the org email -> PASS.
  F. Unregistered lane-style name on an allowlisted email            -> FAIL.
  G. Registered lane name with a foreign email                       -> FAIL (email is the boundary).
  H. Registered automation name (Aggregator Bot)                     -> PASS.

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
        # This throwaway fixture tests scanner behavior, not the developer's GPG
        # setup. Keep its synthetic commits independent of a local signing agent.
        git(repo, "config", "commit.gpgsign", "false")
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

        # Case B: 1-parent commit with the registered web-flow lane committer —
        # PASSES (INF-REPOGUARD-WEBMERGE-LANE-1: squash/rebase web merges are
        # 1-parent; the lane blesses the exact (name, email) committer pair and
        # the author stays strict).
        commit_file(repo, "spoof.txt", "spoof\n", env=GH)
        r = run_scanner(repo, harness_scripts)
        ok("B: 1-parent registered-lane committer passes", r.returncode == 0)

        # Case B2: spoof tripwire — same lane NAME, foreign email -> FAIL. A lane
        # is an exact (name, email) pair, never a name grant.
        EVILGH = {"GIT_AUTHOR_NAME": "z-apply", "GIT_AUTHOR_EMAIL": "admin@zapply.jobs",
                  "GIT_COMMITTER_NAME": "GitHub", "GIT_COMMITTER_EMAIL": "attacker@evil.com"}
        commit_file(repo, "spoof2.txt", "spoof2\n", env=EVILGH)
        r = run_scanner(repo, harness_scripts)
        ok("B2: GitHub name with foreign email fails", r.returncode == 1)
        ok("B2: finding names IDENTITY", "IDENTITY" in r.stdout)

        # Reset to the merge state, create a known web-edit shape, and allow only
        # its exact SHA. The lane path already passes this shape; the exact-SHA
        # exemption branch stays as the fallback if the lane is ever withdrawn.
        git(repo, "reset", "--hard", "HEAD~1")
        commit_file(repo, "known-web-edit.txt", "known web edit\n", env=GH)
        known_sha = git(repo, "rev-parse", "HEAD").stdout.strip()
        iocs["identity_check"]["github_single_parent_committer_exemptions"] = [
            {"commit": known_sha, "why": "test fixture"}
        ]
        (harness_scripts / "repo_guard_iocs.json").write_text(json.dumps(iocs))
        r = run_scanner(repo, harness_scripts)
        ok("C: exact-SHA GitHub web edit passes", r.returncode == 0)

        # Case D: outsider author+committer → fails (baseline guard intact).
        OUT = {"GIT_AUTHOR_NAME": "Stranger", "GIT_AUTHOR_EMAIL": "stranger@example.com",
               "GIT_COMMITTER_NAME": "Stranger", "GIT_COMMITTER_EMAIL": "stranger@example.com"}
        commit_file(repo, "out.txt", "out\n", env=OUT)
        r = run_scanner(repo, harness_scripts)
        ok("D: outsider commit fails", r.returncode == 1)
        ok("D: author finding present", "IDENTITY: author" in r.stdout)

        # Case E: registered lane identity on the org email -> passes (the 10-09
        # incident shape; identity_check.lanes makes lane attribution legal).
        LANE = {"GIT_AUTHOR_NAME": "AGG Lane", "GIT_AUTHOR_EMAIL": "admin@zapply.jobs",
                "GIT_COMMITTER_NAME": "AGG Lane", "GIT_COMMITTER_EMAIL": "admin@zapply.jobs"}
        git(repo, "reset", "--hard", "HEAD~1")
        commit_file(repo, "lane.txt", "lane\n", env=LANE)
        r = run_scanner(repo, harness_scripts)
        ok("E: registered lane identity passes", r.returncode == 0)

        # Case F: unknown lane-style name on the allowlisted email -> fails until
        # registered (attribution is validated against the registry, not free-text).
        UNK = {"GIT_AUTHOR_NAME": "Mystery Lane", "GIT_AUTHOR_EMAIL": "admin@zapply.jobs",
               "GIT_COMMITTER_NAME": "Mystery Lane", "GIT_COMMITTER_EMAIL": "admin@zapply.jobs"}
        git(repo, "reset", "--hard", "HEAD~1")
        commit_file(repo, "unknown-lane.txt", "unknown\n", env=UNK)
        r = run_scanner(repo, harness_scripts)
        ok("F: unregistered name on allowlisted email fails", r.returncode == 1)
        ok("F: finding names IDENTITY", "IDENTITY" in r.stdout)

        # Case G: registered lane NAME with a foreign email -> fails (the email is
        # the account boundary; a name never grants access).
        EVIL = {"GIT_AUTHOR_NAME": "AGG Lane", "GIT_AUTHOR_EMAIL": "attacker@evil.com",
                "GIT_COMMITTER_NAME": "AGG Lane", "GIT_COMMITTER_EMAIL": "attacker@evil.com"}
        git(repo, "reset", "--hard", "HEAD~1")
        commit_file(repo, "evil-email.txt", "evil\n", env=EVIL)
        r = run_scanner(repo, harness_scripts)
        ok("G: registered lane name with foreign email fails", r.returncode == 1)

        # Case H: registered automation name on its allowlisted email -> passes.
        AB = {"GIT_AUTHOR_NAME": "Aggregator Bot", "GIT_AUTHOR_EMAIL": "bot@zapplyjobs.com",
              "GIT_COMMITTER_NAME": "Aggregator Bot", "GIT_COMMITTER_EMAIL": "bot@zapplyjobs.com"}
        git(repo, "reset", "--hard", "HEAD~1")
        commit_file(repo, "bot.txt", "bot\n", env=AB)
        r = run_scanner(repo, harness_scripts)
        ok("H: registered automation name passes", r.returncode == 0)

        # Case I: [bot]-suffixed name on a NON-github email -> fails (closes the old
        # any-email [bot]-name bypass; platform bots ride noreply domains).
        SPOOFBOT = {"GIT_AUTHOR_NAME": "evil[bot]", "GIT_AUTHOR_EMAIL": "evil@example.com",
                    "GIT_COMMITTER_NAME": "evil[bot]", "GIT_COMMITTER_EMAIL": "evil@example.com"}
        commit_file(repo, "spoofbot.txt", "spoofbot\n", env=SPOOFBOT)
        r = run_scanner(repo, harness_scripts)
        ok("I: bot-name with foreign email fails", r.returncode == 1)
    finally:
        shutil.rmtree(base, ignore_errors=True)

    print(f"\n{passed} passed, {failed} failed")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
