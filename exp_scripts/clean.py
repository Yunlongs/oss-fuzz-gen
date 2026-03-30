import shutil
import os

output_dir = "/home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output"

project_names = ["ffmpeg", "lcms", "libaom", "libjpeg-turbo", "libpcap", "libpng", "libtiff", "libvpx", "opencv", "openssl", "protobuf-c", "sqlite3", "zlib", "file", "re2", "pugixml", "c-ares", "liblouis", "curl", "tinygltf"]

for project in project_names:
    path = os.path.join(output_dir, project)
    shutil.rmtree(path, ignore_errors=True)