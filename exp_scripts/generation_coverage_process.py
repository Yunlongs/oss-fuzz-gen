import os
import subprocess
import shutil
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Settings ---
OSS_FUZZ_DIR = "/home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz"
COVERAGE_DIR = "/home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/exp_scripts/generation_coverage"
COMMAND_TEMPLATE = "docker run --rm -v /home/lyuyunlong/work/source_code/oss-fuzz/experiments/libs:/libs -v /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/exp_scripts/generation_coverage/{project}:/cov gcr.io/oss-fuzz-base/base-clang:latest bash -c 'cd /cov && rm -f merge.profdata && llvm-profdata merge -sparse *.profdata -o merge.profdata && llvm-cov report /libs/{lib_name}.so -instr-profile=merge.profdata > coverage_report.txt'"

def get_project_fuzzers(project):
    """Find fuzzer directories for a project."""
    src_dir = os.path.join(OSS_FUZZ_DIR, "build", "out")
    fuzzers = []
    if not os.path.exists(src_dir):
        print(f"Directory {src_dir} does not exist.")
        return []
    
    for item in os.listdir(src_dir):
        if item.startswith(project + "-"):
            fuzzer_path = os.path.join(src_dir, item)
            fuzzers.append(fuzzer_path)
    return fuzzers

def copy_coverage_files(project):
    """Copy merged.profdata files from fuzzer directories to coverage dir."""
    dst_dir = os.path.join(COVERAGE_DIR, project)
    os.makedirs(dst_dir, exist_ok=True)
    
    fuzzers = get_project_fuzzers(project)
    print(f"[{project}] Found {len(fuzzers)} fuzzers.")
    
    copied = 0
    for fuzzer in fuzzers:
        profdata_file = os.path.join(fuzzer, "dumps", "merged.profdata")
        if not os.path.exists(profdata_file):
            continue
        
        dst_file = os.path.join(dst_dir, os.path.basename(fuzzer) + "_merged.profdata")
        shutil.copy(profdata_file, dst_file)
        copied += 1
    
    print(f"[{project}] Copied {copied} profdata files.")
    return copied > 0

def execute_coverage_command(project_name):
    """Execute docker command to merge and generate report."""
    lib_name = project_name if project_name.startswith("lib") else f"lib{project_name}"
    command = COMMAND_TEMPLATE.format(project=project_name, lib_name=lib_name)
    
    print(f"[Starting Show] {project_name}")
    print(f"Command: {command}")
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=1800)
        if result.returncode == 0:
            print(f"[Success Show] {project_name}")
            return {'project': project_name, 'status': 'success'}
        else:
            print(f"[Failed Show] {project_name} - Return Code: {result.returncode}\nStderr: {result.stderr}")
            return {'project': project_name, 'status': 'failed', 'error': result.stderr}
    except subprocess.TimeoutExpired:
        print(f"[Timeout Show] {project_name}")
        return {'project': project_name, 'status': 'timeout'}
    except Exception as e:
        print(f"[Error Show] {project_name} - {str(e)}")
        return {'project': project_name, 'status': 'error', 'error': str(e)}

def process_project(project):
    """Collect then show for one project."""
    print(f"\n--- Processing {project} ---")
    if copy_coverage_files(project):
        return execute_coverage_command(project)
    else:
        print(f"[{project}] No profdata to process.")
        return {'project': project, 'status': 'no_data'}

def main():
    parser = argparse.ArgumentParser(description="Collect and show generation coverage.")
    parser.add_argument("projects", nargs="+", help="List of projects to process")
    parser.add_argument("--workers", type=int, default=100, help="Number of concurrent workers")
    args = parser.parse_args()

    project_names = args.projects
    print(f"Starting to process {len(project_names)} projects: {', '.join(project_names)}")
    print(f"Using {args.workers} workers.")

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_project = {executor.submit(process_project, project): project for project in project_names}
        for future in as_completed(future_to_project):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"Exception processing project: {e}")
                results.append({'project': "Unknown", 'status': 'exception', 'error': str(e)})

    print("\n" + "="*60)
    print("Summary:")
    print("="*60)
    
    success = [r for r in results if r.get('status') == 'success']
    failed = [r for r in results if r.get('status') not in ('success', 'no_data')]
    no_data = [r for r in results if r.get('status') == 'no_data']
    
    print(f"Total: {len(results)}")
    print(f"Success: {len(success)}")
    print(f"No Data: {len(no_data)}")
    print(f"Failed/Error/Timeout: {len(failed)}")
    
    if failed:
        print("\nFailed Projects:")
        for r in failed:
            print(f"  - {r.get('project')}: {r.get('status')} {r.get('error', '')}")

if __name__ == "__main__":
    main()
