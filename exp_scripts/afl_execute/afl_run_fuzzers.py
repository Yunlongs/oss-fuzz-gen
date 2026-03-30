"""Run AFL fuzzers for a given OSS-Fuzz project by iterating over pre-built
out directory entries under the build output directory.

Targets are executed in parallel with a ThreadPoolExecutor.
Each container is pinned to a dedicated CPU core via --cpuset-cpus.
Per-target stdout/stderr is written to:
  exp_scripts/afl_fuzzers_logs/<project>/<entry>.log
"""

import argparse
import os
import queue  # 用于管理 CPU 核心池
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from common import RUN_LOG_BASE, get_project_target_name, list_project_entries

LOG_BASE = RUN_LOG_BASE

WATCHDOG_INTERVAL = 10 * 60    # seconds between each scan
MAX_CONTAINER_AGE = 24 * 3600  # containers older than this are reaped
FUZZER_TIMEOUT    = 24 * 3600  # subprocess timeout (seconds)

# Global process registry so cleanup helpers can find live subprocesses
_processes: list[tuple[subprocess.Popen, str, str]] = []
_processes_lock = threading.Lock()

COMMAND_TEMPLATE = (
    "timeout 24h "
    "docker run --network none --cpuset-cpus={cpu} --privileged --shm-size=2g "
    "--platform linux/amd64 --rm -i "
    "-e FUZZING_ENGINE=afl "
    "-e SANITIZER=address "
    "-e RUN_FUZZER_MODE=interactive "
    "-e HELPER=True "
    "-e AFL_NO_UI=1 "
    "-v {out_dir}:/out "
    "-t gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04 "
    "run_fuzzer {fuzzer}"
)


# ---------------------------------------------------------------------------
# Watchdog: periodically kill containers that have exceeded the time limit
# ---------------------------------------------------------------------------

def _reap_stale_containers(fuzzer: str) -> None:
    """Kill every running docker container whose command contains `fuzzer`
    and that has been alive for more than MAX_CONTAINER_AGE seconds."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--no-trunc",
             "--format", "{{.ID}}\t{{.CreatedAt}}\t{{.Command}}"],
            capture_output=True, text=True, timeout=15,
        )
    except Exception as exc:
        print(f"[WATCHDOG] docker ps failed: {exc}", file=sys.stderr)
        return

    now = datetime.now(timezone.utc)
    for line in result.stdout.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        cid, created_at, command = parts
        if fuzzer not in command:
            continue
        # CreatedAt format: "2024-01-15 10:30:00 +0000 UTC"
        # Strip the redundant trailing timezone name before parsing.
        try:
            ts_str = created_at.rsplit(" ", 1)[0]  # "2024-01-15 10:30:00 +0000"
            created = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S %z")
        except ValueError:
            print(
                f"[WATCHDOG] Cannot parse CreatedAt '{created_at}' "
                f"for container {cid[:12]}",
                file=sys.stderr,
            )
            continue
        age_seconds = (now - created).total_seconds()
        if age_seconds > MAX_CONTAINER_AGE:
            print(
                f"[WATCHDOG] Removing stale container {cid[:12]} "
                f"(fuzzer={fuzzer}, age={age_seconds / 3600:.1f}h)"
            )
            try:
                subprocess.run(
                    ["docker", "rm", "-f", cid],
                    timeout=30, capture_output=True,
                )
            except Exception as exc:
                print(
                    f"[WATCHDOG] Failed to remove {cid[:12]}: {exc}",
                    file=sys.stderr,
                )


def _watchdog_loop(fuzzer: str, stop_event: threading.Event) -> None:
    """Daemon loop: wait WATCHDOG_INTERVAL seconds, then reap stale containers.
    Repeats until stop_event is set."""
    print(
        f"[WATCHDOG] Started – interval={WATCHDOG_INTERVAL // 60}min, "
        f"max_age={MAX_CONTAINER_AGE // 3600}h, fuzzer={fuzzer}"
    )
    while not stop_event.wait(WATCHDOG_INTERVAL):
        print("[WATCHDOG] Scanning for stale containers...")
        _reap_stale_containers(fuzzer)
    print("[WATCHDOG] Stopped.")


def start_watchdog(fuzzer: str) -> tuple[threading.Thread, threading.Event]:
    """Spawn the watchdog daemon thread and return (thread, stop_event)."""
    stop_event = threading.Event()
    t = threading.Thread(
        target=_watchdog_loop,
        args=(fuzzer, stop_event),
        name="watchdog",
        daemon=True,
    )
    t.start()
    return t, stop_event


# ---------------------------------------------------------------------------
# Legacy helpers (kept for reference)
# ---------------------------------------------------------------------------

def _find_docker_container(fuzzer):
    """Find running docker container ID for a given fuzzer name."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--no-trunc",
             "--filter", "ancestor=gcr.io/oss-fuzz-base/base-runner:latest",
             "--format", "{{.ID}} {{.Command}}"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if fuzzer in line:
                return line.split()[0]
    except Exception:
        pass
    return None

def _stop_docker_container(fuzzer):
    """Stop the docker container running a given fuzzer."""
    container_id = _find_docker_container(fuzzer)
    if container_id:
        print(f"Stopping docker container {container_id} for fuzzer {fuzzer}")
        try:
            subprocess.run(["docker", "stop", container_id], timeout=15)
        except Exception:
            try:
                subprocess.run(["docker", "rm", "-f", container_id], timeout=500)
            except Exception:
                pass

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run AFL fuzzers for a given OSS-Fuzz project."
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
        "--workers",
        type=int,
        default=100,
        help="Number of parallel worker threads / containers (default: 50).",
    )
    return parser.parse_args()


def _read_cpu_stats() -> dict[int, tuple[int, int]]:
    """Read per-core (idle, total) jiffies from /proc/stat."""
    stats: dict[int, tuple[int, int]] = {}
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            for line in f:
                if not line.startswith("cpu") or line.startswith("cpu "):
                    continue
                parts = line.split()
                label = parts[0]  # e.g. cpu0
                if not label[3:].isdigit():
                    continue
                values = [int(v) for v in parts[1:]]
                if len(values) < 5:
                    continue
                idle = values[3] + values[4]  # idle + iowait
                total = sum(values)
                stats[int(label[3:])] = (idle, total)
    except Exception:
        return {}
    return stats


def pick_idle_cores(max_count: int, sample_seconds: float = 0.25) -> list[str]:
    """Pick currently most idle CPU cores by sampling /proc/stat twice."""
    if max_count <= 0:
        return []

    first = _read_cpu_stats()
    if not first:
        cpu_count = os.cpu_count() or 1
        return [str(i) for i in range(min(max_count, cpu_count))]

    time.sleep(sample_seconds)
    second = _read_cpu_stats()
    if not second:
        cpu_count = os.cpu_count() or 1
        return [str(i) for i in range(min(max_count, cpu_count))]

    scored: list[tuple[float, int]] = []
    for core_id, (idle1, total1) in first.items():
        if core_id not in second:
            continue
        idle2, total2 = second[core_id]
        delta_total = total2 - total1
        delta_idle = idle2 - idle1
        idle_ratio = (delta_idle / delta_total) if delta_total > 0 else 0.0
        scored.append((idle_ratio, core_id))

    if not scored:
        cpu_count = os.cpu_count() or 1
        return [str(i) for i in range(min(max_count, cpu_count))]

    scored.sort(key=lambda item: (-item[0], item[1]))
    return [str(core_id) for _, core_id in scored[:max_count]]


def build_cpu_pool(cores: list[str]) -> queue.Queue:
    """Return a Queue pre-loaded with selected CPU core IDs."""
    cpu_pool: queue.Queue = queue.Queue()
    for c in cores:
        cpu_pool.put(c)
    return cpu_pool


def find_project_dirs(project: str) -> list[tuple[str, str]]:
    """Return list of (entry_name, out_dir) pairs for the given project."""
    pairs = list_project_entries(project)
    if not pairs:
        print(f"[WARN] No directories starting with '{project}-' found under build/out")
    return [(entry, str(out_dir)) for entry, out_dir in pairs]


def run_one(
    entry: str,
    out_dir: str,
    fuzzer: str,
    log_dir: str,
    cpu_pool: queue.Queue,
    dry_run: bool,
) -> tuple[str, int]:
    """Run a single fuzzer target. Returns (entry, returncode)."""
    cpu = cpu_pool.get()
    try:
        cmd = COMMAND_TEMPLATE.format(
            cpu=cpu,
            out_dir=out_dir,
            fuzzer=fuzzer,
        )
        log_path = os.path.join(log_dir, f"{entry}.log")
        print(f"[START] {entry}  cpu={cpu}  ->  {log_path}")

        if dry_run:
            with open(log_path, "w") as f:
                f.write(f"[DRY-RUN] {cmd}\n")
            return entry, 0

        # Use `script` to allocate a PTY so AFL/docker produce real output.
        wrapped_cmd = f"script -q -f {log_path} -c {repr(cmd)}"
        process = subprocess.Popen(
            wrapped_cmd,
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with _processes_lock:
            _processes.append((process, entry, fuzzer))

        timed_out = False
        try:
            process.wait(timeout=FUZZER_TIMEOUT)
        except subprocess.TimeoutExpired:
            timed_out = True
            print(f"[TIMEOUT] {entry} – stopping after {FUZZER_TIMEOUT // 3600}h")
            try:
                process.terminate()
            except Exception:
                pass
            _stop_docker_container(fuzzer)
            try:
                process.wait(timeout=10)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass

        with _processes_lock:
            try:
                _processes.remove((process, entry, fuzzer))
            except ValueError:
                pass

        rc = process.returncode if process.returncode is not None else (124 if timed_out else 1)
        return entry, rc
    finally:
        cpu_pool.put(cpu)


def main() -> None:
    args = parse_args()
    project = args.project

    # Get target_name from project's YAML
    target_name = get_project_target_name(project)
    if not target_name:
        print(f"Failed to load target_name for project '{project}' from YAML.", file=sys.stderr)
        sys.exit(1)

    pairs = find_project_dirs(project)
    if not pairs:
        print(f"No valid out/ directories found for project '{project}'.")
        sys.exit(1)

    # Prepare log directory
    log_dir = LOG_BASE / project
    log_dir.mkdir(parents=True, exist_ok=True)

    resolved: list[tuple[str, str]] = []
    for entry, out_dir in pairs:
        resolved.append((entry, out_dir))

    if not resolved:
        print("No targets were found.", file=sys.stderr)
        sys.exit(1)

    cores = pick_idle_cores(args.workers)
    if not cores:
        print("No CPU cores available.", file=sys.stderr)
        sys.exit(1)

    effective_workers = min(args.workers, len(cores))
    cpu_pool = build_cpu_pool(cores)

    # Start watchdog daemon with target_name to catch containers
    _watchdog_thread, _stop_event = start_watchdog(target_name)

    print(f"Found {len(resolved)} target(s) for project '{project}'.")
    print(f"Logs   -> {str(log_dir)}")
    print(f"Fuzzer -> {target_name}")
    print(f"Workers: {effective_workers} (requested={args.workers})")
    print(f"CPUs   : {','.join(cores)}\n")

    failed: list[str] = []
    with ThreadPoolExecutor(max_workers=effective_workers) as pool:
        futures = {
            pool.submit(run_one, entry, out_dir, target_name,
                        str(log_dir), cpu_pool, args.dry_run): entry
            for entry, out_dir in resolved
        }
        for future in as_completed(futures):
            entry, rc = future.result()
            if rc == 0:
                print(f"[OK]    {entry}")
            else:
                print(f"[FAIL]  {entry}  (exit {rc})", file=sys.stderr)
                failed.append(entry)

    # All futures done – shut down watchdog
    _stop_event.set()
    _watchdog_thread.join(timeout=5)

    print(f"\nDone. {len(resolved) - len(failed)}/{len(resolved)} succeeded.")
    if failed:
        print("Failed targets:", file=sys.stderr)
        for name in sorted(failed):
            print(f"  {name}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
