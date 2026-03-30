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
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from common import (
    AFL_EXECUTE_DIR,
    COVERAGE_LOG_BASE,
    COVERAGE_OUTPUT_BASE,
    REPO_ROOT,
    OSS_FUZZ_GEN_OUTPUT_DIR,
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
    "-v {corpus_dir}:/corpus "
    "-v {coverage_save_dir}:/cov "
    "gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04 /bin/bash -lc "
    "\"timeout {run_timeout}s /src/execute_fuzzer_corpus.sh /out/{fuzzer}\""
)

COLLECT_COMMAND_TEMPLATE = (
    "docker run --rm --platform linux/amd64 "
    "-v {libs_dir}:/libs "
    "-v {coverage_project_dir}:/cov "
    "gcr.io/oss-fuzz-base/base-clang:latest bash -c "
    "'cd /cov && rm -f merge.profdata && "
    "prof_files=$(find . -type f -name \"*.profdata\") && "
    "llvm-profdata merge -sparse $prof_files -o merge.profdata && "
    "llvm-cov report /libs/{lib_name}.so -instr-profile=merge.profdata > coverage_report.txt'"
)


def get_fuzzer_corpus_dir(fuzzer: str, out_dir: str) -> str:
    """Return corpus queue path relative to /out in the container."""
    return os.path.join(out_dir, f"{fuzzer}_afl_address_out", "default", "queue")

def get_oss_fuzz_gen_corpus_dir(project:str, project_entry_dir: str) -> str:
    entry_name = os.path.basename(project_entry_dir)
    trial_id = entry_name[-1:]
    entry_dir = entry_name[:-2]
    return os.path.join(OSS_FUZZ_GEN_OUTPUT_DIR, project, f"output-{entry_dir}", "corpora", f"0{trial_id}.fuzz_target")

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
    parser.add_argument(
        "--libs-dir",
        type=str,
        default=str(REPO_ROOT / "exp_scripts" / "libs"),
        help="Directory containing shared libraries for llvm-cov (default: exp_scripts/libs).",
    )
    parser.add_argument(
        "--lib-name",
        type=str,
        default=None,
        help="Library basename without .so for llvm-cov report (auto-resolved by default).",
    )
    parser.add_argument(
        "--collect-only",
        action="store_true",
        help="Skip run stage and only merge/show coverage from existing *.profraw.",
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
    """Run coverage for one target. Returns (entry, rc)."""
    coverage_save_dir = os.path.join(str(COVERAGE_OUTPUT_BASE), f"round_{round_id}", project, entry)
    shutil.rmtree(coverage_save_dir, ignore_errors=True)
    os.makedirs(coverage_save_dir, exist_ok=True)

    corpus = get_fuzzer_corpus_dir(fuzzer, out_dir)
    #corpus = get_oss_fuzz_gen_corpus_dir(project, out_dir)
    if not os.path.isdir(corpus):
        print(f"[WARN] Corpus directory not found for {entry}: {corpus}")
        return entry, 1
    run_cmd = RUN_COMMAND_TEMPLATE.format(
        out_dir=out_dir,
        scripts_dir=SCRIPTS_BASE,
        coverage_save_dir=coverage_save_dir,
        corpus_dir=corpus,
        fuzzer=fuzzer,
        run_timeout=run_timeout,
    )
    log_path = os.path.join(log_dir, f"{entry}.log")
    print(f"[START] {entry}  ->  {log_path}")
    print(f"        CORPUS: {corpus}")

    if dry_run:
        with open(log_path, "w") as f:
            f.write(f"[DRY-RUN][RUN] {run_cmd}\n")
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
        return entry, 0


def collect_project_coverage(
    project: str,
    round_id: int,
    libs_dir: str,
    lib_name: str,
    log_dir: str,
    dry_run: bool,
) -> int:
    """Merge all profile files under project coverage dir and generate one report."""
    coverage_project_dir = os.path.join(str(COVERAGE_OUTPUT_BASE), f"round_{round_id}", project)
    os.makedirs(coverage_project_dir, exist_ok=True)

    collect_cmd = COLLECT_COMMAND_TEMPLATE.format(
        libs_dir=libs_dir,
        coverage_project_dir=coverage_project_dir,
        lib_name=lib_name,
    )

    collect_log_path = os.path.join(log_dir, f"{project}-collect.log")
    if dry_run:
        with open(collect_log_path, "w") as f:
            f.write(f"[DRY-RUN][COLLECT] {collect_cmd}\n")
        print(f"[OK]    {project}-collect")
        return 0

    with open(collect_log_path, "w") as log_file:
        log_file.write(f"COLLECT CMD: {collect_cmd}\n\n")
        log_file.flush()
        collect_ret = subprocess.run(
            collect_cmd,
            shell=True,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        return collect_ret.returncode


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

    if not args.collect_only:
        helper_script = os.path.join(str(SCRIPTS_BASE), "execute_fuzzer_corpus.sh")
        if not os.path.isfile(helper_script):
            print(f"[ERROR] helper script not found: {helper_script}", file=sys.stderr)
            print("Please add exp_scripts/afl_execute/execute_fuzzer_corpus.sh first.", file=sys.stderr)
            sys.exit(1)

    log_dir = LOG_BASE / args.project
    log_dir.mkdir(parents=True, exist_ok=True)

    libs_dir = args.libs_dir
    if not os.path.isdir(libs_dir):
        print(f"[ERROR] libs directory not found: {libs_dir}", file=sys.stderr)
        sys.exit(1)

    project_name = args.project.replace("-", "_")
    lib_name = args.lib_name or (
        project_name if project_name.startswith("lib") else f"lib{project_name}"
    )
    lib_so = os.path.join(libs_dir, f"{lib_name}.so")
    if not os.path.isfile(lib_so):
        print(f"[ERROR] shared library not found: {lib_so}", file=sys.stderr)
        print("Use --lib-name to specify the correct library basename.", file=sys.stderr)
        sys.exit(1)

    resolved: list[tuple[str, str]] = []
    for entry, out_dir in pairs:
        resolved.append((entry, out_dir))

    if not resolved:
        print("No targets were found.", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(resolved)} target(s) for project '{args.project}'.")
    print(f"Logs           -> {str(log_dir)}")
    print(f"Fuzzer         -> {target_name}")
    print(f"Library        -> {lib_name}.so")
    print(f"Coverage output-> {str(COVERAGE_OUTPUT_BASE)}/round_{args.round}/")
    workflow = "collect-only" if args.collect_only else "run -> collect"
    print(f"Workflow       : {workflow}")
    print(f"Workers        : {args.workers}\n")

    failed: list[str] = []

    if not args.collect_only:
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

    collect_rc = collect_project_coverage(
        project=args.project,
        round_id=args.round,
        libs_dir=libs_dir,
        lib_name=lib_name,
        log_dir=str(log_dir),
        dry_run=args.dry_run,
    )
    if collect_rc != 0:
        print(f"[FAIL]  {args.project}-collect  (exit {collect_rc})", file=sys.stderr)
        failed.append(f"{args.project}-collect")

    succeeded = len(resolved) - len([name for name in failed if name != f"{args.project}-collect"])
    if args.collect_only:
        print(f"\nDone. collect stage {'succeeded' if collect_rc == 0 else 'failed'}.")
    else:
        print(f"\nDone. {succeeded}/{len(resolved)} run targets succeeded.")
    if failed:
        print("Failed targets:", file=sys.stderr)
        for name in sorted(failed):
            print(f"  {name}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

