import os
import yaml
import shutil
import argparse

# Settings
OSS_FUZZ_OUT_DIR = "/home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz/build/out"
BENCHMARK_API_DIR = "/home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/benchmark-sets/all_api"
OUTPUT_BASE_DIR = "/home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/exp_scripts/afl_execute/harnesses"

def get_target_path(project_name):
    yaml_path = os.path.join(BENCHMARK_API_DIR, project_name, f"{project_name}.yaml")
    if not os.path.exists(yaml_path):
        print(f"[-] YAML not found for {project_name}: {yaml_path}")
        return None
        
    with open(yaml_path, 'r') as f:
        try:
            data = yaml.safe_load(f)
            return data.get('target_path')
        except yaml.YAMLError as e:
            print(f"[-] YAML parsing error for {yaml_path}: {e}")
            return None

def process_project(project_name, round_num):
    target_path = get_target_path(project_name)
    if not target_path:
        return

    # Extract relative path (e.g., from "/src/checksum_fuzzer.c" -> "checksum_fuzzer.c")
    if target_path.startswith('/src/'):
        rel_path = target_path[5:] # remove '/src/'
    else:
        rel_path = target_path.lstrip('/')
        
    ext = os.path.splitext(rel_path)[1]
    
    # 按照项目和 round 分类存放，避免同名文件在不同 round 之间被覆盖
    # 以满足把"harness文件重命名为对应的目录名"的精确需求：zlib-uncompress_z-1.c
    output_dir = os.path.join(OUTPUT_BASE_DIR, f"round-{round_num}", project_name)
    os.makedirs(output_dir, exist_ok=True)
    
    count = 0
    
    for item in os.listdir(OSS_FUZZ_OUT_DIR):
        if item.startswith(f"{project_name}-"):
            fuzzer_dir = os.path.join(OSS_FUZZ_OUT_DIR, item)
            if not os.path.isdir(fuzzer_dir):
                continue
                
            src_fuzzer_file = os.path.join(fuzzer_dir, "src", rel_path)
            
            if os.path.exists(src_fuzzer_file):
                # 重命名为对应的目录名
                new_filename = f"{item}{ext}"
                dst_path = os.path.join(output_dir, new_filename)
                
                shutil.copy2(src_fuzzer_file, dst_path)
                print(f"[+] Copied {src_fuzzer_file} to {dst_path}")
                count += 1
            else:
                print(f"[-] Harness not found: {src_fuzzer_file}")
                
    print(f"[*] Project {project_name} (Round {round_num}): collected {count} harness files into {output_dir}")

def main():
    parser = argparse.ArgumentParser(description="Collect generated harnesses")
    parser.add_argument("project", help="A single project to process (e.g., zlib)")
    parser.add_argument("--round", "-r", required=True, type=int, help="Round number (e.g., 1)")
    args = parser.parse_args()
    
    process_project(args.project, args.round)

if __name__ == "__main__":
    main()
