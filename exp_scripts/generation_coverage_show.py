import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


project_names = ["zlib", "c-ares", "curl", "liblouis", "opencv", "openssl", "pugixml", "tinygltf"]  # 需要处理的项目列表
#project_names =  ["openssl", "lcms", "libaom", "libjpeg-turbo", "libpcap", "libpng", "libtiff", "libvpx", "opencv", "protobuf-c", "sqlite3", "zlib", "file", "re2", "pugixml", "c-ares", "liblouis", "curl", "tinygltf"] # remove ffmpeg, openssl, lcms

command_template = "docker run --rm  -v /home/lyuyunlong/work/source_code/oss-fuzz/experiments/libs:/libs -v /home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/exp_scripts/coverage/{project}:/cov  gcr.io/oss-fuzz-base/base-clang:latest bash -c 'cd /cov && rm -f merge.profdata && llvm-profdata merge -sparse *.profdata -o merge.profdata && llvm-cov report /libs/{lib_name}.so -instr-profile=merge.profdata > coverage_report.txt'"


def execute_coverage_command(project_name):
    """执行单个项目的覆盖率收集命令"""
    # 处理特殊情况：如果项目名中有连字符，库文件名可能不同
    lib_name = project_name if project_name.startswith("lib") else f"lib{project_name}"
    
    # 填充命令模板
    command = command_template.format(project=project_name, lib_name=lib_name)
    
    print(f"[开始] {project_name}")
    print(f"命令: {command}")
    
    try:
        # 执行命令
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=1800  # 10分钟超时
        )
        
        if result.returncode == 0:
            print(f"[成功] {project_name}")
            return {
                'project': project_name,
                'status': 'success',
                'stdout': result.stdout,
                'stderr': result.stderr
            }
        else:
            print(f"[失败] {project_name} - 返回码: {result.returncode}")
            print(f"错误输出: {result.stderr}")
            return {
                'project': project_name,
                'status': 'failed',
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
    except subprocess.TimeoutExpired:
        print(f"[超时] {project_name}")
        return {
            'project': project_name,
            'status': 'timeout'
        }
    except Exception as e:
        print(f"[异常] {project_name} - {str(e)}")
        return {
            'project': project_name,
            'status': 'error',
            'error': str(e)
        }


def main():
    """使用多线程执行所有项目的覆盖率收集"""
    print(f"开始处理 {len(project_names)} 个项目...")
    print(f"使用多线程并发执行\n")
    
    results = []
    
    # 使用 ThreadPoolExecutor 进行多线程执行
    # max_workers=4 表示同时运行4个线程，可以根据需要调整
    with ThreadPoolExecutor(max_workers=4) as executor:
        # 提交所有任务
        future_to_project = {
            executor.submit(execute_coverage_command, project): project 
            for project in project_names
        }
        
        # 收集完成的任务结果
        for future in as_completed(future_to_project):
            project = future_to_project[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"处理 {project} 时发生异常: {e}")
                results.append({
                    'project': project,
                    'status': 'exception',
                    'error': str(e)
                })
    
    # 汇总结果
    print("\n" + "="*60)
    print("执行结果汇总:")
    print("="*60)
    
    success_count = sum(1 for r in results if r.get('status') == 'success')
    failed_count = sum(1 for r in results if r.get('status') == 'failed')
    timeout_count = sum(1 for r in results if r.get('status') == 'timeout')
    error_count = sum(1 for r in results if r.get('status') in ['error', 'exception'])
    
    print(f"总计: {len(results)} 个项目")
    print(f"成功: {success_count}")
    print(f"失败: {failed_count}")
    print(f"超时: {timeout_count}")
    print(f"异常: {error_count}")
    
    # 显示失败的项目
    if failed_count > 0 or error_count > 0 or timeout_count > 0:
        print("\n失败/异常的项目:")
        for result in results:
            if result.get('status') != 'success':
                print(f"  - {result['project']}: {result.get('status')}")
                if 'error' in result:
                    print(f"    错误: {result['error']}")


if __name__ == "__main__":
    main()

