
import os
import subprocess
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import shutil
import threading

# 切换到脚本所在目录
oss_fuzz_dir = "/home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz"
coverage_dir = "/home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/exp_scripts/coverage"
os.chdir(oss_fuzz_dir)

#project_names =  ["lcms", "libaom", "libjpeg-turbo", "libpcap", "libpng", "libtiff", "libvpx", "opencv", "protobuf-c", "sqlite3", "zlib", "file", "re2", "pugixml", "c-ares", "liblouis", "curl", "tinygltf"] # remove ffmpeg, openssl
project_names = ["zlib", "c-ares", "curl", "liblouis", "opencv", "openssl", "pugixml", "tinygltf"]
#project_names = ["ffmpeg", "lcms", "libaom", "libjpeg-turbo", "libpcap", "libpng", "libtiff", "libvpx", "opencv", "openssl", "protobuf-c", "sqlite3", "zlib", "file", "re2", "pugixml", "c-ares", "liblouis", "curl", "tinygltf"]
#build_fuzzer_command_template = "python infra/helper.py coverage --no-serve --corpus-dir {} {} --fuzz-target {}"



def get_project_fuzzers(project):
    src_dir = os.path.join(oss_fuzz_dir, "build", "out")
    fuzzers = []
    for item in os.listdir(src_dir):
        if item.startswith(project + "-"):
            print(f"Found fuzzer: {item}")
            fuzzer_path = os.path.join(src_dir, item)
            fuzzers.append(fuzzer_path)
    return fuzzers


def copy_coverage_files(project):
    dst_dir = os.path.join(coverage_dir, project)
    os.makedirs(dst_dir, exist_ok=True)
    for fuzzer in get_project_fuzzers(project):
        profdata_file = os.path.join(fuzzer, "dumps", "merged.profdata")
        if not os.path.exists(profdata_file):
            continue
        print(f"Copying {profdata_file} to {dst_dir}")
        dst_file = os.path.join(dst_dir, os.path.basename(fuzzer) + "_merged.profdata")
        shutil.copy(profdata_file, dst_file)

for project in project_names:
    copy_coverage_files(project)


# command_template = "docker run --rm  -v /home/lyuyunlong/work/source_code/oss-fuzz/experiments/libs:/libs -v /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/exp_scripts/coverage/file:/cov  gcr.io/oss-fuzz-base/base-clang:latest bash -c 'cd /cov && rm -f merge.profdata && llvm-profdata merge -sparse *.profdata -o merge.profdata && llvm-cov report /libs/file.so -instr-profile=merge.profdata > coverage_report.txt'"
