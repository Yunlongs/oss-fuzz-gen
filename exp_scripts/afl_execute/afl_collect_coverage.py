"""Run coverage execution and collect report for each generated target.

Workflow per target:
1) run coverage against AFL corpus queue
2) collect *.profraw into merge.profdata
3) generate coverage_report.txt

Per-target stdout/stderr is written to:
  exp_scripts/afl_coverage_logs/<project>/<entry>.log
"""

import argparse
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from common import (
    AFL_EXECUTE_DIR,
    COVERAGE_LOG_BASE,
    COVERAGE_OUTPUT_BASE,
    get_project_target_name,
    list_project_entries,
)

LOG_BASE = COVERAGE_LOG_BASE
SCRIPTS_BASE = AFL_EXECUTE_DIR

# RUN template adapted to actual local paths.
RUN_COMMAND_TEMPLATE = (
    "docker run --rm --platform linux/amd64 "
    "-v {out_dir}:/out "
    "-v {scripts_dir}:/src "
    "-v {coverage_save_dir}:/cov "
    "gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04 /bin/bash -lc "
    "\"timeout {run_timeout}s /src/execute_fuzzer_corpus.sh {corpus} /out/{fuzzer}\""
)

COLLECT_COMMAND_TEMPLATE = (
    "docker run --rm --platform linux/amd64 "
    "-v {out_dir}:/out "
    "-v {coverage_save_dir}:/cov "
    "gcr.io/oss-fuzz-base/base-clang:latest bash -lc "
    "\"cd /cov && "
    "ls *.profraw >/dev/null 2>&1 && "
    "llvm-profdata merge -sparse *.profraw -o merge.profdata && "
    "llvm-cov report /out/{fuzzer} -instr-profile=merge.profdata > coverage_report.txt\""
)


def get_fuzzer_corpus_dir(fuzzer: str) -> str:
    """Return corpus queue path relative to /out in the container."""
    return os.path.join("out", f"{fuzzer}_afl_address_out", "default", "queue")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run coverage and collect report for a given OSS-Fuzz project."
    )
    parser.add_argument(
        "project",
        help="OSS-Fuzz project name (e.g. cjson, ffmpeg). "
             "All out/ sub-directories whose name starts with "
             "'<project>-' will be processed.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without executing them.",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=50,
        help="Number of parallel worker threads (default: 50).",
    )
    parser.add_argument(
        "-r",
        "--round",
        type=int,
        default=0,
        help="Round number for coverage output directory (default: 0).",
    )
    parser.add_argument(
        "--run-timeout",
        type=int,
        default=24 * 3600,
        help="Coverage run timeout in seconds per target (default: 86400).",
    )
    return parser.parse_args()


def find_project_dirs(project: str) -> list[tuple[str, str]]:
    """Return list of (entry_name, out_dir) pairs for the project."""
    pairs = list_project_entries(project)
    if not pairs:
        print(f"[WARN] No directories starting with '{project}-' found under build/out")
    return [(entry, str(out_dir)) for entry, out_dir in pairs]


def run_one(
    entry: str,
    out_dir: str,
    fuzzer: str,
    project: str,
    log_dir: str,
    round_id: int,
    run_timeout: int,
    dry_run: bool,
) -> tuple[str, int]:
    """Run coverage then collect report for one target. Returns (entry, rc)."""
    coverage_save_dir = os.path.join(str(COVERAGE_OUTPUT_BASE), f"round_{round_id}", project, entry)
    os.makedirs(coverage_save_dir, exist_ok=True)

    corpus = get_fuzzer_corpus_dir(fuzzer)
    run_cmd = RUN_COMMAND_TEMPLATE.format(
        out_dir=out_dir,
        scripts_dir=SCRIPTS_BASE,
        coverage_save_dir=coverage_save_dir,
        corpus=corpus,
        fuzzer=fuzzer,
        run_timeout=run_timeout,
    )
    collect_cmd = COLLECT_COMMAND_TEMPLATE.format(
        out_dir=out_dir,
        coverage_save_dir=coverage_save_dir,
        fuzzer=fuzzer,
    )

    log_path = os.path.join(log_dir, f"{entry}.log")
    print(f"[START] {entry}  ->  {log_path}")

    if dry_run:
        with open(log_path, "w") as f:
            f.write(f"[DRY-RUN][RUN] {run_cmd}\n")
            f.write(f"[DRY-RUN][COLLECT] {collect_cmd}\n")
        return entry, 0

    with open(log_path, "w") as log_file:
        log_file.write(f"RUN CMD: {run_cmd}\n\n")
        log_file.flush()
        run_ret = subprocess.run(
            run_cmd,
            shell=True,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        if run_ret.returncode != 0:
            log_file.write(f"\n[RUN FAILED] exit={run_ret.returncode}\n")
            return entry, run_ret.returncode

        log_file.write(f"\nCOLLECT CMD: {collect_cmd}\n\n")
        log_file.flush()
        collect_ret = subprocess.run(
            collect_cmd,
            shell=True,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        return entry, collect_ret.returncode


def main() -> None:
    args = parse_args()

    # Get target_name from project's YAML
    target_name = get_project_target_name(args.project)
    if not target_name:
        print(f"Failed to load target_name for project '{args.project}' from YAML.", file=sys.stderr)
        sys.exit(1)

    pairs = find_project_dirs(args.project)
    if not pairs:
        print(f"No valid out directories found for project '{args.project}'.")
        sys.exit(1)

    helper_script = os.path.join(str(SCRIPTS_BASE), "execute_fuzzer_corpus.sh")
    if not os.path.isfile(helper_script):
        print(f"[ERROR] helper script not found: {helper_script}", file=sys.stderr)
        print("Please add exp_scripts/afl_execute/execute_fuzzer_corpus.sh first.", file=sys.stderr)
        sys.exit(1)

    log_dir = LOG_BASE / args.project
    log_dir.mkdir(parents=True, exist_ok=True)

    resolved: list[tuple[str, str]] = []
    for entry, out_dir in pairs:
        resolved.append((entry, out_dir))

    if not resolved:
        print("No targets were found.", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(resolved)} target(s) for project '{args.project}'.")
    print(f"Logs           -> {str(log_dir)}")
    print(f"Fuzzer         -> {target_name}")
    print(f"Coverage output-> {str(COVERAGE_OUTPUT_BASE)}/round_{args.round}/")
    print(f"Workflow       : run -> collect")
    print(f"Workers        : {args.workers}\n")

    failed: list[str] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                run_one,
                entry,
                out_dir,
                target_name,
                args.project,
                str(log_dir),
                args.round,
                args.run_timeout,
                args.dry_run,
            ): entry
            for entry, out_dir in resolved
        }
        for future in as_completed(futures):
            entry, rc = future.result()
            if rc == 0:
                print(f"[OK]    {entry}")
            else:
                print(f"[FAIL]  {entry}  (exit {rc})", file=sys.stderr)
                failed.append(entry)

    print(f"\nDone. {len(resolved) - len(failed)}/{len(resolved)} succeeded.")
    if failed:
        print("Failed targets:", file=sys.stderr)
        for name in sorted(failed):
            print(f"  {name}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

