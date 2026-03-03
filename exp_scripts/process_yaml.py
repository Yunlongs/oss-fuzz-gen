import re
import yaml

def filter_yaml_functions(input_file, output_file, target_functions):
    """
    读取 YAML 文件，仅保留 functions 列表中 name 等于 target_name 的项。
    """
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if 'functions' in data and isinstance(data['functions'], list):
            # 执行过滤逻辑：仅保留匹配特定名称的函数
            filtered_functions = [
                func for func in data['functions'] 
                if func.get('name') in target_functions
            ]
            
            # 更新数据结构
            data['functions'] = filtered_functions

        # 将处理后的数据写回文件
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, allow_unicode=True, sort_keys=False)
            
        print(f"处理完成！已将过滤后的内容保存至: {output_file}")
        print(f"保留项数量: {len(data['functions'])}")

    except Exception as e:
        print(f"处理出错: {e}")

def filter_yaml_tiff_functions(input_file, output_file):
    """
    读取 YAML 文件，仅保留 functions 列表中 name 等于 target_name 的项。
    """
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if 'functions' in data and isinstance(data['functions'], list):
            # 执行过滤逻辑：仅保留匹配特定名称的函数
            filtered_functions = [
                func for func in data['functions'] 
                if func.get('name', '').startswith('TIFF')
            ]
            
            # 更新数据结构
            data['functions'] = filtered_functions

        # 将处理后的数据写回文件
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, allow_unicode=True, sort_keys=False)
            
        print(f"处理完成！已将过滤后的内容保存至: {output_file}")
        print(f"保留项数量: {len(data['functions'])}")

    except Exception as e:
        print(f"处理出错: {e}")

def merge_yaml_function(prior_file, input_file, output_file):
    """
    以 prior_file 为模板，将 input_file 中 functions 里未出现在
    prior_file 中的项追加到末尾，保存到 output_file。
    判断重复的依据是 function_signature 字段（fallback 到 name）。
    """
    with open(prior_file, 'r', encoding='utf-8') as f:
        prior_data = yaml.safe_load(f)
    with open(input_file, 'r', encoding='utf-8') as f:
        input_data = yaml.safe_load(f)

    def get_key(func):
        return func.get('function_signature') or func.get('name', '')

    prior_functions = prior_data.get('functions', [])
    input_functions = input_data.get('functions', [])

    existing_keys = {get_key(f) for f in prior_functions}
    new_functions = [f for f in input_functions if get_key(f) not in existing_keys]

    # Merge top-level fields: input_data as base, prior_data takes precedence.
    merged_data = dict(prior_data)
    merged_data['functions'] = prior_functions + new_functions

    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(merged_data, f, allow_unicode=True, sort_keys=False)

    print(f"合并完成！已保存至: {output_file}")
    print(f"原有函数: {len(prior_functions)}，新增函数: {len(new_functions)}，合计: {len(merged_data['functions'])}")


def parse_funcs(func_file):
    """
    读取 .func 文件，提取每行函数签名中的函数名列表。
    函数名是 '(' 之前的最后一个标识符。
    跳过不含 '(' 的行（如注释、空行、标题行）。
    """
    funcs = []
    with open(func_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if '(' not in line:
                continue
            # 取 '(' 之前的部分，提取最后一个标识符作为函数名
            before_paren = line[:line.index('(')]
            match = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*$', before_paren)
            if match:
                funcs.append(match.group(1))
    return funcs


def _parse_signature(line: str) -> dict:
    """
    解析单行函数签名，返回包含 name/params/return_type/signature 的字典。
    格式: return_type func_name(type1 name1, type2 name2, ...)
    """
    line = line.strip()
    paren_start = line.index('(')
    paren_end = line.rindex(')')

    # 函数名及返回类型
    before_paren = line[:paren_start].strip()
    name_match = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*$', before_paren)
    if not name_match:
        return {}
    func_name = name_match.group(1)
    return_type = before_paren[:name_match.start()].strip() or 'void'

    # 参数列表
    params_str = line[paren_start + 1:paren_end].strip()
    params = []
    if params_str and params_str != 'void':
        for i, param in enumerate(params_str.split(',')):
            param = param.strip()
            if not param:
                continue
            # 最后一个标识符为参数名，其余为类型
            pm = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*$', param)
            if pm:
                pname = pm.group(1)
                ptype = param[:pm.start()].strip() or 'void'
            else:
                pname = f'arg{i}'
                ptype = param
            params.append({'name': pname, 'type': ptype})

    return {
        'name': func_name,
        'params': params,
        'return_type': return_type,
        'signature': line,
    }


def generate_from_func_file(func_file, output_file):
    """
    从 .func 文件生成 YAML 文件，格式与现有 benchmark YAML 一致。
    每条函数条目包含 name、params、return_type、signature 字段。
    """
    functions = []
    with open(func_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if '(' not in line or ')' not in line:
                continue
            parsed = _parse_signature(line)
            if parsed:
                functions.append(parsed)

    data = {'functions': functions}
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, allow_unicode=True, sort_keys=False)

    print(f"生成完成！已保存至: {output_file}")
    print(f"共生成 {len(functions)} 个函数条目")





# --- 配置参数 ---
INPUT_PATH = '/home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/benchmark-sets/all_api/zlib/zlib.yaml'       # 你的原始文件名

PRIOR_PATH = '/home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/benchmark-sets/all/zlib.yaml'

FUNC_FILE = "/home/lyuyunlong/work/FuzzWork/oss-fuzz-gen/exp_scripts/libvpx.func"

TARGET_FUNCTIONs = parse_funcs(FUNC_FILE)

if __name__ == "__main__":
    #filter_yaml_functions(INPUT_PATH, INPUT_PATH, TARGET_FUNCTIONs)
    #filter_yaml_tiff_functions(INPUT_PATH, INPUT_PATH)
    merge_yaml_function(PRIOR_PATH, INPUT_PATH, INPUT_PATH)
    #generate_from_func_file(FUNC_FILE, INPUT_PATH)