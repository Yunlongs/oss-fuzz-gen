"""Collect all .fuzz_target harnesses from an output directory,
renumber them sequentially, and copy them to harnesses_dir."""

import argparse
import os
import shutil

from common import BUILD_BASE, HARNESS_OUTPUT_BASE

harnesses_dir = str(HARNESS_OUTPUT_BASE)
out_root = str(BUILD_BASE / "out")


def get_build_name(fpath: str) -> str | None:
    """Derive the build directory name in *out_root* for a given .fuzz_target path.

    Path convention: .../output-{project}-{func}/*/NN.fuzz_target
    Build dir name:  {project}-{func}-{N}
    Returns None if the path does not match the expected structure.
    """
    fname = os.path.basename(fpath)           # e.g. "01.fuzz_target"
    stem = fname.replace(".fuzz_target", "")  # e.g. "01"
    try:
        variant = int(stem)
    except ValueError:
        return None

    # Go up two levels: .../experiment_dir/subdir/NN.fuzz_target
    experiment_dir = os.path.basename(os.path.dirname(os.path.dirname(fpath)))
    if not experiment_dir.startswith("output-"):
        return None

    base = experiment_dir[len("output-"):]    # e.g. "file-magic_list"
    return f"{base}-{variant}"                # e.g. "file-magic_list-1"


def has_profdata(build_dir: str) -> bool:
    """Return True if the dumps/ subdirectory of *build_dir* contains any .profdata file."""
    dumps_dir = os.path.join(build_dir, "dumps")
    if not os.path.isdir(dumps_dir):
        return False
    return any(f.endswith(".profdata") for f in os.listdir(dumps_dir))


def collect_harnesses(src_dir: str, dst_dir: str) -> None:
    """Find every *.fuzz_target file under *src_dir*, renumber them
    sequentially (01, 02, …) and write copies into *dst_dir*."""
    os.makedirs(dst_dir, exist_ok=True)

    harnesses = []
    for root, _dirs, files in os.walk(src_dir):
        for fname in sorted(files):
            if fname.endswith(".fuzz_target"):
                fpath = os.path.join(root, fname)
                if os.path.getsize(fpath) == 0:
                    print(f"[skip] empty file: {fpath}")
                    continue

                build_name = get_build_name(fpath)
                if build_name is None:
                    print(f"[skip] cannot derive build name: {fpath}")
                    continue

                build_dir = os.path.join(out_root, build_name)
                if not os.path.isdir(build_dir):
                    print(f"[skip] build dir not found ({build_name}): {fpath}")
                    continue

                if not has_profdata(build_dir):
                    print(f"[skip] no profdata in dumps/ ({build_name}): {fpath}")
                    continue

                harnesses.append(fpath)

    harnesses.sort()  # deterministic ordering by full path

    pad = len(str(len(harnesses))) if harnesses else 1
    for idx, src_path in enumerate(harnesses, start=1):
        ext = ".fuzz_target"
        new_name = f"{idx:0{pad}d}{ext}"
        dst_path = os.path.join(dst_dir, new_name)
        shutil.copy2(src_path, dst_path)
        print(f"[{idx:0{pad}d}/{len(harnesses)}] {src_path} -> {dst_path}")

    print(f"\nDone. {len(harnesses)} harness(es) collected into {dst_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Collect and renumber .fuzz_target harnesses from an output directory."
    )
    parser.add_argument(
        "src_dir",
        help="Root directory to search (e.g. /home/.../output/ffmpeg)",
    )
    args = parser.parse_args()
    base_name = os.path.basename(os.path.normpath(args.src_dir))
    save_dir = os.path.join(harnesses_dir, base_name)
    os.makedirs(save_dir, exist_ok=True)
    collect_harnesses(args.src_dir, save_dir)


#  docker ps --filter "status=running" --format "{{.ID}} {{.Command}} {{.RunningFor}}" | grep "run_fuzzer" | grep "25 hours ago" | awk '{print $1}' | xargs -r docker rm -f