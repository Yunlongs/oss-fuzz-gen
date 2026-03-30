project_names = ["ffmpeg", "lcms", "libaom", "libjpeg-turbo", "libpcap", "libpng", "libtiff", "libvpx", "opencv", "openssl", "protobuf-c", "sqlite3", "zlib", "file", "re2", "pugixml", "c-ares", "liblouis", "curl", "tinygltf"]

# ffmpeg, libaom, opencv, openssl

#  python -m data_prep.introspector lcms -m 1000 -o benchmark-sets/all_api/lcms
#  python -m data_prep.introspector re2 -m 1000 -o benchmark-sets/all_api/re2

# conda activate oss-fuzz-gen && source .env
# timeout 24h ./run_all_experiments.py -l DeepSeek-V3.2 -y ./benchmark-sets/all_api/ffmpeg/ffmpeg.yaml -ag -w ./output/ffmpeg -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
# timeout 24h ./run_all_experiments.py -l DeepSeek-V3.2 -y ./benchmark-sets/all_api/file/file.yaml -ag -w ./output/file -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
# timeout 24h ./run_all_experiments.py -l DeepSeek-V3.2 -y ./benchmark-sets/all_api/lcms/lcms.yaml -ag -w ./output/lcms -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300


# timeout 24h ./run_all_experiments.py -l DeepSeek-V3.2 -y ./benchmark-sets/all_api/libaom/libaom.yaml -ag -w ./output/libaom -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
# timeout 24h ./run_all_experiments.py -l DeepSeek-V3.2 -y ./benchmark-sets/all_api/libjpeg-turbo/libjpeg-turbo.yaml -ag -w ./output/libjpeg-turbo -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300

# timeout 24h ./run_all_experiments.py -l DeepSeek-V3.2 -y ./benchmark-sets/all_api/libpcap/libpcap.yaml -ag -w ./output/libpcap -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
# timeout 24h ./run_all_experiments.py -l DeepSeek-V3.2 -y ./benchmark-sets/all_api/libpng/libpng.yaml -ag -w ./output/libpng -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
# timeout 24h ./run_all_experiments.py -l DeepSeek-V3.2 -y ./benchmark-sets/all_api/libtiff/libtiff.yaml -ag -w ./output/libtiff -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300

# timeout 24h ./run_all_experiments.py -l DeepSeek-V3.2 -y ./benchmark-sets/all_api/libvpx/libvpx.yaml -ag -w ./output/libvpx -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
# timeout 24h ./run_all_experiments.py -l DeepSeek-V3.2 -y ./benchmark-sets/all_api/protobuf-c/protobuf-c.yaml -ag -w ./output/protobuf-c -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
# timeout 24h ./run_all_experiments.py -l DeepSeek-V3.2 -y ./benchmark-sets/all_api/re2/re2.yaml -ag -w ./output/re2 -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300


# timeout 24h ./run_all_experiments.py -l DeepSeek-V3.2 -y ./benchmark-sets/all_api/sqlite3/sqlite3.yaml -ag -w ./output/sqlite3 -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
# timeout 24h ./run_all_experiments.py -l deepseek-reasoner -y ./benchmark-sets/all_api/zlib/zlib.yaml -ag -w ./output/zlib -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300


# timeout 24h ./run_all_experiments.py -l deepseek-reasoner -y ./benchmark-sets/all_api/c-ares/c-ares.yaml -ag -w ./output/c-ares -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
# timeout 24h ./run_all_experiments.py -l deepseek-reasoner -y ./benchmark-sets/all_api/curl/curl.yaml -ag -w ./output/curl -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
# timeout 24h ./run_all_experiments.py -l deepseek-reasoner -y ./benchmark-sets/all_api/liblouis/liblouis.yaml -ag -w ./output/liblouis -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
# timeout 24h ./run_all_experiments.py -l deepseek-reasoner -y ./benchmark-sets/all_api/opencv/opencv.yaml -ag -w ./output/opencv -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
# timeout 24h ./run_all_experiments.py -l deepseek-reasoner -y ./benchmark-sets/all_api/openssl/openssl.yaml -ag -w ./output/openssl -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
# timeout 24h ./run_all_experiments.py -l deepseek-reasoner -y ./benchmark-sets/all_api/pugixml/pugixml.yaml -ag -w ./output/pugixml -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
# timeout 24h ./run_all_experiments.py -l deepseek-reasoner -y ./benchmark-sets/all_api/tinygltf/tinygltf.yaml -ag -w ./output/tinygltf -of /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/output/oss-fuzz -to 300
