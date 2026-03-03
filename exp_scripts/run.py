project_names = ["ffmpeg", "lcms", "libaom", "libjpeg-turbo", "libpcap", "libpng", "libtiff", "libvpx", "opencv", "openssl", "protobuf-c", "sqlite3", "zlib", "file", "re2", "pugixml", "c-ares", "liblouis", "curl", "tinygltf"]

# ffmpeg, libaom, opencv, openssl

#  python -m data_prep.introspector lcms -m 1000 -o benchmark-sets/all_api/lcms
#  python -m data_prep.introspector re2 -m 1000 -o benchmark-sets/all_api/re2

# conda activate oss-fuzz-gen && source .env
# ./run_all_experiments.py -l DeepSeek-V3.2 -y ./benchmark-sets/all_api/libjpeg-turbo/libjpeg-turbo.yaml -ag -w ./output/libjpeg-turbo -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz