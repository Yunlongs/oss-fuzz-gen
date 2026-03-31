"""Build fuzzers for a given OSS-Fuzz project by iterating over pre-built
out/work directory pairs under the build output directory.

Targets are executed in parallel with a ThreadPoolExecutor.
Per-target stdout/stderr is written to:
  exp_scripts/build_fuzzers_logs/<project>/<entry>.log
"""

import argparse
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from common import BUILD_BASE, BUILD_LOG_BASE, list_project_entries

LOG_BASE = BUILD_LOG_BASE

COMMAND_TEMPLATE = (
    "docker run --privileged --shm-size=2g --platform linux/amd64 --rm "
    "-e FUZZING_ENGINE=afl "
    "-e SANITIZER=address "
    "-e ARCHITECTURE=x86_64 "
    "-e PROJECT_NAME={project} "
    "-e HELPER=True "
    "-e FUZZING_LANGUAGE=c++ "
    "-e SRC=/src "
    "-v {out_dir}:/out "
    "-v {work_dir}:/work "
    "-v {out_dir}/src:/src "
    "gcr.io/oss-fuzz/{project}"
)


COVERAGE_COMMAND_TEMPLATE = (
    "docker run --privileged --shm-size=2g --platform linux/amd64 --rm "
    "-e SANITIZER=coverage "
    "-e ARCHITECTURE=x86_64 "
    "-e PROJECT_NAME={project} "
    "-e HELPER=True "
    "-e FUZZING_LANGUAGE=c++ "
    "-e SRC=/src "
    "-v {out_dir}:/out "
    "-v {work_dir}:/work "
    "-v {out_dir}/src:/src "
    "gcr.io/oss-fuzz/{project}"
)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build fuzzers for a given OSS-Fuzz project."
    )
    parser.add_argument(
        "project",
        help="OSS-Fuzz project name (e.g. cjson, ffmpeg).  "
             "All out/work sub-directories whose name starts with "
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
        default=100,
        help="Number of parallel worker threads (default: 100).",
    )
    parser.add_argument(
        "-c",
        "--coverage",
        action="store_true",
        help="Use coverage build template (SANITIZER=coverage).",
    )
    return parser.parse_args()


def find_project_dirs(project: str):
    """Return list of (entry_name, out_dir, work_dir) triples for the project."""
    work_base = BUILD_BASE / "work"
    pairs = list_project_entries(project)
    if not pairs:
        print(f"[WARN] No directories starting with '{project}-' found under {BUILD_BASE / 'out'}")
        return []

    result = []
    for entry, out_dir in pairs:
        work_dir = work_base / entry
        if not work_dir.is_dir():
            print(f"[WARN] Matching work directory not found, skipping: {work_dir}")
            continue
        result.append((entry, str(out_dir), str(work_dir)))
    return result


def run_one(entry: str, out_dir: str, work_dir: str, project: str,
            log_dir: str, dry_run: bool, coverage: bool) -> tuple[str, int]:
    """Build a single target. Returns (entry, returncode)."""
    template = COVERAGE_COMMAND_TEMPLATE if coverage else COMMAND_TEMPLATE
    cmd = template.format(
        project=project,
        out_dir=out_dir,
        work_dir=work_dir,
    )
    log_path = os.path.join(log_dir, f"{entry}.log")
    print(f"[START] {entry}  ->  {log_path}")

    if dry_run:
        with open(log_path, "w") as f:
            f.write(f"[DRY-RUN] {cmd}\n")
        return entry, 0

    with open(log_path, "w") as log_file:
        log_file.write(f"CMD: {cmd}\n\n")
        log_file.flush()
        ret = subprocess.run(
            cmd,
            shell=True,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

    return entry, ret.returncode


def main():
    args = parse_args()
    project = args.project
    if args.coverage:
        print(f"=== Running in COVERAGE mode (SANITIZER=coverage) ===")

    triples = find_project_dirs(project)
    if not triples:
        print(f"No valid out/work pairs found for project '{project}'.")
        sys.exit(1)

    # Prepare log directory
    log_dir = LOG_BASE / project
    log_dir.mkdir(parents=True, exist_ok=True)

    print(f"Found {len(triples)} target(s) for project '{project}'.")
    print(f"Logs -> {str(log_dir)}")
    print(f"Mode: {'coverage' if args.coverage else 'afl'}")
    print(f"Workers: {args.workers}\n")

    failed = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(run_one, entry, out_dir, work_dir, project,
                        str(log_dir), args.dry_run, args.coverage): entry
            for entry, out_dir, work_dir in triples
        }
        for future in as_completed(futures):
            entry, rc = future.result()
            if rc == 0:
                print(f"[OK]    {entry}")
            else:
                print(f"[FAIL]  {entry}  (exit {rc})", file=sys.stderr)
                failed.append(entry)

    print(f"\nDone. {len(triples) - len(failed)}/{len(triples)} succeeded.")
    if failed:
        print("Failed targets:", file=sys.stderr)
        for name in sorted(failed):
            print(f"  {name}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

