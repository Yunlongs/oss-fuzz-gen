import shutil
import os

output_dir = "/home/lyuyunlong/work/oss-fuzz-gen/output"
oss_fuzz_dir = "/home/lyuyunlong/work/oss-fuzz-gen/output/oss-fuzz/build/"

#project_names = ["ffmpeg", "lcms", "libaom", "libjpeg-turbo", "libpcap", "libpng", "libtiff", "libvpx", "opencv", "openssl", "protobuf-c", "sqlite3", "zlib", "file", "re2", "pugixml", "c-ares", "liblouis", "curl", "tinygltf"]
project_names = ["file", "cjson", "ffmpeg", "lcms", "libaom", "libjpeg-turbo", "libpcap", "libpng", "libtiff", "libvpx", "opencv", "openssl", "protobuf-c", "sqlite3", "zlib", "re2", "pugixml", "c-ares", "liblouis", "curl", "tinygltf"]
#project_names = ["sqlite3"]

for project in project_names:
    path = os.path.join(output_dir, project)
    shutil.rmtree(path, ignore_errors=True)
    print(f"Removed {path}")
    out_dir = os.path.join(oss_fuzz_dir, "out")
    if not os.path.exists(out_dir):
        continue
    work_dir = os.path.join(oss_fuzz_dir, "work")
    for entry in os.listdir(out_dir):
        if entry.startswith(project):
            shutil.rmtree(os.path.join(out_dir, entry), ignore_errors=True)
            print(f"Removed {os.path.join(out_dir, entry)}")
    for entry in os.listdir(work_dir):
        if entry.startswith(project):
            shutil.rmtree(os.path.join(work_dir, entry), ignore_errors=True)
            print(f"Removed {os.path.join(work_dir, entry)}")

    

# docker ps | grep "run_fuzzer ${fuzzer_name}" | grep -E "Up (2[4-9]|[3-9][0-9]|[0-9]{3,}) hours|days|weeks|months" | awk '{print $1}' | xargs -r docker rm -f
# docker ps | grep "run_fuzzer" | grep -E "Up (2[4-9]|[3-9][0-9]|[0-9]{3,}) hours|days|weeks|months" | awk '{print $1}' | xargs -r docker rm -f


# docker rm -f $(docker ps -a --format '{{.ID}}\t{{.Names}}\t{{.Status}}' | grep -v "promptfuzz" | awk -F'\t' '$3 ~ /hour|day|week/ {print $1}')