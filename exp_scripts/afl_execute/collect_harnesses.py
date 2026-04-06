import os
import yaml
import shutil
import argparse
import hashlib

# Settings
OSS_FUZZ_OUT_DIR = "//home/lyuyunlong/work/oss-fuzz-gen/output/oss-fuzz/build/out"
BENCHMARK_API_DIR = "//home/lyuyunlong/work/oss-fuzz-gen/benchmark-sets/all_api"
OUTPUT_BASE_DIR = "//home/lyuyunlong/work/oss-fuzz-gen/exp_scripts/afl_execute/harnesses"

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

def reverse_project(project_name, round_num):
    target_path = get_target_path(project_name)
    if not target_path:
        return

    # Extract relative path (e.g., from "/src/checksum_fuzzer.c" -> "checksum_fuzzer.c")
    if target_path.startswith('/src/'):
        rel_path = target_path[5:] # remove '/src/'
    else:
        rel_path = target_path.lstrip('/')
        
    ext = os.path.splitext(rel_path)[1]
    
    input_dir = os.path.join(OUTPUT_BASE_DIR, f"round-{round_num}", project_name)
    if not os.path.exists(input_dir):
        print(f"[-] Harness input directory not found: {input_dir}")
        return
        
    count = 0
    
    for item in os.listdir(input_dir):
        if item.startswith(f"{project_name}-") and item.endswith(ext):
            src_fuzzer_file = os.path.join(input_dir, item)
            
            # The item is formatted like zlib-compress-1.c
            # The corresponding out directory should be build/out/zlib-compress-1
            fuzzer_dir_name = item[:-len(ext)]
            fuzzer_dir = os.path.join(OSS_FUZZ_OUT_DIR, fuzzer_dir_name)
            
            if not os.path.isdir(fuzzer_dir):
                print(f"[-] Fuzzer output directory not found: {fuzzer_dir}, skipping")
                continue
                
            dst_path = os.path.join(fuzzer_dir, "src", rel_path)
            
            # Create src directory if it doesn't exist
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)
            
            shutil.copy2(src_fuzzer_file, dst_path)
            print(f"[+] Reversed {src_fuzzer_file} to {dst_path}")
            count += 1
            
    print(f"[*] Project {project_name} (Round {round_num}): reversed {count} harness files into their out directories.")

def check_project(project_name):
    target_path = get_target_path(project_name)
    if not target_path:
        return

    if target_path.startswith('/src/'):
        rel_path = target_path[5:]
    else:
        rel_path = target_path.lstrip('/')
        
    print(f"[*] Checking md5 of harnesses for {project_name}, expected file: {rel_path}\n")

    md5_dict = {}
    total_count = 0
    
    for item in os.listdir(OSS_FUZZ_OUT_DIR):
        if item.startswith(f"{project_name}-"):
            fuzzer_dir = os.path.join(OSS_FUZZ_OUT_DIR, item)
            if not os.path.isdir(fuzzer_dir):
                continue
                
            src_fuzzer_file = os.path.join(fuzzer_dir, "src", rel_path)
            
            if os.path.exists(src_fuzzer_file):
                with open(src_fuzzer_file, 'rb') as f:
                    file_hash = hashlib.md5(f.read()).hexdigest()
                
                print(f"{file_hash}  {item}")
                md5_dict[file_hash] = md5_dict.get(file_hash, 0) + 1
                total_count += 1
            else:
                print(f"[-] Missing: {item}")

    print(f"\n[*] Summary for {project_name}:")
    print(f"    Total files exactly equal to target_path: {total_count}")
    if len(md5_dict) == 0:
        print("    No files found.")
    elif len(md5_dict) == 1:
        print(f"    [!] WARNING! All {total_count} files have the EXACT SAME MD5 hash: {list(md5_dict.keys())[0]}")
    else:
        print(f"    Good. Found {len(md5_dict)} unique hashes across {total_count} files.")
        for h, count in md5_dict.items():
            print(f"      - Hash {h[:8]}... appears {count} times.")

def main():
    parser = argparse.ArgumentParser(description="Collect or reverse generated harnesses")
    parser.add_argument("project", help="A single project to process (e.g., zlib)")
    parser.add_argument("--round", "-r", type=int, help="Round number (e.g., 1)")
    parser.add_argument("--reverse", action="store_true", help="Reverse operation: copy gathered harnesses back to out directories")
    parser.add_argument("--check", action="store_true", help="Check MD5 sums of harnesses in out directories")
    args = parser.parse_args()
    
    if args.check:
        check_project(args.project)
    elif args.reverse:
        if args.round is None:
            parser.error("--round is required with --reverse")
        reverse_project(args.project, args.round)
    else:
        if args.round is None:
            parser.error("--round is required")
        process_project(args.project, args.round)

if __name__ == "__main__":
    main()
