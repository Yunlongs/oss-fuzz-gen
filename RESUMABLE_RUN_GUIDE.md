# 断点续跑功能使用指南

## 概述

本文档说明如何使用新添加的**断点续跑（Resumable Run）** 功能。该功能允许您在LLM调用中断或其他错误时，恢复运行而无需重新執行已完成的基准测试。

## 功能特性

### 三种运行模式

#### 1. **fresh 模式**（默认）
- 清空之前的所有输出
- 从头开始运行所有实验
- 适用于全新的运行

```bash
python run_all_experiments.py \
  -b benchmark-sets/file \
  -w output/file_fresh \
  -l gpt-4o-mini
  # --resume-mode fresh 可显式指定，但已是默认
```

#### 2. **resume 模式**
- 扫描已完成的实验
- 跳过已完成的基准
- 继续运行未完成的任务
- **适用于中断后恢复**

```bash
# 原始运行中断后
python run_all_experiments.py \
  -b benchmark-sets/file \
  -w output/file \
  -l gpt-4o-mini \
  --resume-mode resume
```

#### 3. **resume-only 模式**
- 扫描并显示运行状态
- 不执行任何实验
- 仅用于状态查看

```bash
python run_all_experiments.py \
  -b benchmark-sets/file \
  -w output/file \
  -l gpt-4o-mini \
  --resume-mode resume-only
```

## 工作原理

### 状态跟踪机制

#### 1. **Checkpoint 注册表**
- 位置：`{output_dir}/.checkpoint_registry.json`
- 记录每个基准的执行状态
- 包含时间戳和错误信息

```json
{
  "file-buffer_apprentice": {
    "status": "completed",
    "timestamp": "2026-04-03 01:31:00",
    "output_dir": "output-file-buffer_apprentice"
  },
  "file-magic_open": {
    "status": "error",
    "timestamp": "2026-04-03 08:48:15",
    "error_message": "Error code: 429"
  }
}
```

#### 2. **实验输出识别**
- 扫描 `output-*` 格式的目录
- 检查 `status/*/result.json` 文件
- 验证文件有效性

#### 3. **WorkDirs 保留机制**
- resume 模式时，`WorkDirs` 使用 `keep=True`
- 已生成的 harness、编译文件等被保留
- 新增实验使用新的编号（status/02, status/03 等）

## 使用场景

### 场景1：LLM 超时中断

```bash
# 首次运行
$ python run_all_experiments.py \
    -b benchmark-sets/file \
    -w output/file \
    -l gpt-4o-mini \
    -n 2

# 执行到第8个基准时因 429 限流中断...

# 恢复运行（跳过前7个）
$ python run_all_experiments.py \
    -b benchmark-sets/file \
    -w output/file \
    -l gpt-4o-mini \
    -n 2 \
    --resume-mode resume
```

**输出示例：**
```
Resume mode: found 7 completed experiments
Skipping 7 completed experiments, continuing with 12 remaining.
Running 12 experiment(s) in parallels of 2.
```

### 场景2：检查运行进度

```bash
# 查看当前运行状态
$ python run_all_experiments.py \
    -b benchmark-sets/file \
    -w output/file \
    -l gpt-4o-mini \
    --resume-mode resume-only
```

**输出示例：**
```
================================================================================
Experiment Status Summary
================================================================================
Total experiments: 19
Completed: 15
Pending/Error: 4

Detailed Status:
✓ file-buffer_apprentice        completed    2026-04-03 01:31:00
✓ file-cdf_tole4                completed    2026-04-03 01:20:15
✓ file-cdf_tole8                completed    2026-04-03 02:05:30
⏳ file-magic_open               in_progress  2026-04-03 08:48:00
✗ file-magic_file               error        2026-04-03 08:45:00
  └─ Error: Error code: 429 - You have exceeded the 5-hour usage quota
- file-magic_list               pending      
...
```

### 场景3：调试特定基准

```bash
# 仅运行失败的基准
# 手动过滤或修改 benchmark YAML 后
$ python run_all_experiments.py \
    -b benchmark-sets/file_magic_open_only.yaml \
    -w output/file \
    -l gpt-4o-mini \
    --resume-mode resume
```

## 注意事项

### 1. **保存的输出内容**
Resume 模式时保留：
- ✓ 生成的 harness 代码
- ✓ 编译日志和编译产物
- ✓ 覆盖率报告
- ✓ 之前的状态文件

**不保留**（会被覆盖）：
- report.json - 会更新
- checkpoint registry - 会更新

### 2. **参数变化处理**
如果运行参数改变（如 `-n`、`-t`、`-l`），建议：
- 对于关键参数变化，使用 `fresh` 模式重新开始
- 对于次要参数（如 `--delay`），可继续 `resume` 模式

当前实现未在 checkpoint 中记录参数，这是未来改进的方向。

### 3. **并行执行考虑**
- `--resume-mode resume` 与多进程并行（`NUM_EXP > 1`）兼容
- 未完成的基准会被并行处理
- Checkpoint 保存是原子操作（底层文件操作）

### 4. **错误状态处理**
错误的基准会被标记为 `status: error`：
- Resume 模式会跳过显式错误的基准
- 使用 `resume-only` 查看具体错误信息
- 手动修复后可再次尝试运行

## 技术实现细节

### CheckpointManager 类

```python
class CheckpointManager:
  - scan_completed_experiments()    # 扫描已完成实验
  - get_completed_benchmark_ids()   # 获取已完成ID列表
  - is_completed(benchmark_id)      # 检查单个基准
  - save_checkpoint()               # 保存检查点
  - mark_started()                  # 标记为开始
  - mark_completed()                # 标记为完成
  - mark_error()                    # 标记为错误
  - print_status()                  # 显示状态
  - get_resume_info()               # 获取恢复信息
```

### 集成点

1. **run_all_experiments.py::main()**
   - 初始化 CheckpointManager
   - 处理不同的 resume_mode
   - 过滤已完成的基准

2. **run_all_experiments.py::run_experiments()**
   - 判断是否需要保留输出（keep参数）
   - 保存基准状态变化

3. **experiment/workdir.py::WorkDirs**
   - 支持 keep 参数（已有）
   - Resume 模式下保留目录结构

## 故障排查

### 问题1：Resume 模式不工作
**症状**：仍然清空了之前的输出

**排查：**
1. 检查输出目录是否真的存在
2. 验证 status/*/result.json 文件有效性
3. 查看 .checkpoint_registry.json 内容

```bash
# 查看注册表
cat output/file/.checkpoint_registry.json | python -m json.tool
```

### 问题2：感觉进度没有保存
**症状**：Resume 后仍然重复运行了某些任务

**原因**：
- Status 文件可能没有正确生成（程序在生成 harness 时中断）
- Need 检查 checkpoint 中的状态记录

**解决**：
```bash
# 手动检查状态
python -c "
from checkpoint_manager import CheckpointManager
cm = CheckpointManager('output/file')
resume_info = cm.get_resume_info()
print('Completed:', len(resume_info['completed']))
print('Pending:', len(resume_info['pending']))
"
```

### 问题3：Checkpoint 注册表损坏
**症状**：JSON 格式错误，无法加载

**解决**：
1. 备份文件
2. 手动修复 JSON 格式
3. 或删除注册表强制重新扫描

```bash
# 强制重新扫描（删除注册表）
rm output/file/.checkpoint_registry.json
# 再次运行 resume-only 重新生成
python run_all_experiments.py ... --resume-mode resume-only
```

## 最佳实践

### ✅ 推荐做法
1. 首次运行时使用默认的 fresh 模式
2. 中断后立即使用 resume 模式恢复
3. 定期使用 resume-only 检查进度
4. 在重要决定前使用 resume-only 确认状态

### ❌ 避免做法
1. 不要在 resume 运行中途改变基准列表
2. 不要手动删除 output-* 目录而不更新注册表
3. 不要在参数大幅改变时再用 resume（容易产生不一致）
4. 不要同时在两个进程中使用同一个输出目录

## 版本信息

- **实现日期**：2026-04-03
- **Python 版本**：3.10+
- **相关文件**：
  - checkpoint_manager.py - 新增
  - run_all_experiments.py - 已修改
  - experiment/workdir.py - 无需修改（已支持keep参数）

## 问题反馈

如遇到问题，请检查：
1. `/home/lyuyunlong/work/oss-fuzz-gen/RESUMABLE_RUN_ANALYSIS.md` - 详细技术文档
2. 日志文件：`output/{project}/run_all_experiments.log`
3. Checkpoint 注册表：`output/{project}/.checkpoint_registry.json`
