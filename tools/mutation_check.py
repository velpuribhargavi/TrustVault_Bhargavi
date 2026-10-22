"""Prove the tests actually test the authorization checks.

The hackathon judges "take one authorisation check out of your code and run
your tests. If they still pass, they were not testing anything." This script
does exactly that, for *every* check, automatically:

1. Find every line tagged ``# AUTHZ-CHECK[name]`` or ``# AUTHZ-SQL[name]``.
2. For each one, copy the project to a temporary folder and remove that one
   check:
     - ``if <condition>:``  becomes ``if False:``   (the refusal never fires)
     - a SQL fragment string becomes ``" "``       (the filter disappears)
     - any other statement becomes ``pass``
3. Run the test suite against the mutant. It must FAIL ("mutant killed").

Usage (from the project folder):
    python tools/mutation_check.py              # all checks, 4 in parallel
    python tools/mutation_check.py --jobs 8
    python tools/mutation_check.py --list       # just show the checks found
    python tools/mutation_check.py --only csrf-token-required,session-expiry

Exit code 0 only if every mutant was killed.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TAG = re.compile(r"#\s*AUTHZ-(CHECK|SQL)\[([a-z0-9-]+)\]")
IGNORE = shutil.ignore_patterns("instance", ".venv", "venv", "__pycache__", ".git", ".pytest_cache", "*.pyc")


@dataclass
class Mutant:
    file: Path
    lineno: int
    kind: str
    name: str
    original: str

    def mutated_line(self) -> str:
        m = TAG.search(self.original)
        code = self.original[: m.start()].rstrip()
        indent = code[: len(code) - len(code.lstrip())]
        stripped = code.strip()
        if self.kind == "SQL":
            replaced, n = re.subn(r'"[^"]*"', '" "', stripped, count=1)
            if n != 1:
                raise ValueError(f"{self.file}:{self.lineno} AUTHZ-SQL line has no string literal")
            return f"{indent}{replaced}  # MUTATED"
        if stripped.startswith(("if ", "elif ")) and stripped.endswith(":"):
            keyword = stripped.split(" ", 1)[0]
            return f"{indent}{keyword} False:  # MUTATED (was: {stripped[:60]})"
        return f"{indent}pass  # MUTATED (was: {stripped[:60]})"


def find_mutants() -> list[Mutant]:
    mutants = []
    for path in sorted((ROOT / "trustvault").rglob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            m = TAG.search(line)
            if m:
                mutants.append(Mutant(path.relative_to(ROOT), lineno, m.group(1), m.group(2), line))
    names = [m.name for m in mutants]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise SystemExit(f"duplicate check names: {sorted(dupes)}")
    return mutants


def run_suite(project: Path, timeout: int, extra: list[str]) -> tuple[int, str]:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    for var in ("TRUSTVAULT_MASTER_KEY", "TRUSTVAULT_AUDIT_KEY", "TRUSTVAULT_INSTANCE_DIR"):
        env.pop(var, None)
    cmd = [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", "--no-header", *extra]
    try:
        proc = subprocess.run(cmd, cwd=project, env=env, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "timeout"


def check(mutant: Mutant, timeout: int, extra: list[str]) -> dict:
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="tv-mutant-") as tmp:
        project = Path(tmp) / "project"
        shutil.copytree(ROOT, project, ignore=IGNORE)
        target = project / mutant.file
        lines = target.read_text(encoding="utf-8").splitlines()
        if mutant.lineno > len(lines) or lines[mutant.lineno - 1] != mutant.original:
            # The file changed since the checks were listed: mutating "line N" now
            # would remove the wrong line and report a meaningless result.
            return {"mutant": mutant, "killed": False, "by": "SOURCE CHANGED DURING RUN - rerun",
                    "seconds": time.time() - started}
        lines[mutant.lineno - 1] = mutant.mutated_line()
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        code, output = run_suite(project, timeout, extra)
    failed = re.findall(r"^FAILED (\S+)", output, flags=re.MULTILINE)
    return {"mutant": mutant, "killed": code != 0, "by": failed[0] if failed else ("timeout" if code == -1 else ""),
            "seconds": time.time() - started}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--only", default="", help="comma-separated check names")
    ap.add_argument("--list", action="store_true")
    args, extra = ap.parse_known_args()

    mutants = find_mutants()
    if args.only:
        wanted = set(args.only.split(","))
        mutants = [m for m in mutants if m.name in wanted]
    if args.list:
        for m in mutants:
            print(f"{m.name:45} {m.file}:{m.lineno}\n    original: {m.original.strip()}\n    mutant:   {m.mutated_line().strip()}")
        print(f"\n{len(mutants)} authorization checks tagged")
        return 0

    print("Baseline: running the unmodified test suite ...", flush=True)
    code, output = run_suite(ROOT, args.timeout, extra)
    if code != 0:
        print(output[-3000:])
        print("Baseline FAILED - fix the tests before mutation testing.")
        return 2
    print(f"Baseline passed. Removing {len(mutants)} checks one at a time ({args.jobs} in parallel) ...\n", flush=True)

    results = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for r in pool.map(lambda m: check(m, args.timeout, extra), mutants):
            status = "KILLED  " if r["killed"] else "SURVIVED"
            print(f"  {status} {r['mutant'].name:45} {r['seconds']:5.1f}s  {r['by']}", flush=True)
            results.append(r)

    survivors = [r for r in results if not r["killed"]]
    print(f"\n{len(results) - len(survivors)}/{len(results)} mutants killed.")
    if survivors:
        print("These checks can be removed without any test failing:")
        for r in survivors:
            print(f"  - {r['mutant'].name} ({r['mutant'].file}:{r['mutant'].lineno})")
        return 1
    print("Every authorization check is covered by at least one failing test when removed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
