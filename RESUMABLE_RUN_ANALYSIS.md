# 断点续跑功能分析与实现方案

## 一、问题诊断

### 1.1 问题现象
- **症状**：程序运行中途因LLM网络超时中断，重新运行时完全从头开始
- **成本**：已完成的 harness 生成、代码编译、覆盖率测试等工作失效，需重复
- **日志证据**：`/home/lyuyunlong/work/oss-fuzz-gen/output/file/run_all_experiments.log` 中显示 429 LLM 配额超限错误导致程序异常退出

### 1.2 现状分析
当前项目输出结构（以 file 为例）：
```
output/file/
├── report.json                          # 总体报告（覆盖率统计）
├── run_all_experiments.log              # 主程序日志
└── output-file-<function_name>/         # 每个目标函数的输出目录
    ├── benchmark.yaml                   # 基准配置
    ├── status/01/                       # 状态保存目录
    │   ├── result.json                  # 试验结果
    │   └── log.txt                      # 试验日志
    ├── fuzz_targets/                    # 生成的 fuzz 目标
    ├── fixed_targets/                   # 修复后的目标
    ├── code-coverage-reports/           # 覆盖率报告
    ├── corpora/                         # 测试语料库
    ├── artifacts/                       # 工件（编译产物）
    └── raw_targets/                     # 原始生成的目标
```

### 1.3 当前状态保存机制的问题
1. ✓ 有状态文件保存（`status/01/result.json`）
2. ✗ **无全局状态注册表** - `run_all_experiments.py` 不知道哪些任务已完成
3. ✗ **无断点检查** - 每次启动都重新从完整的 benchmark 列表开始
4. ✗ **无恢复机制** - 中断后无法从中断点继续

## 二、执行流程分析

### 2.1 当前执行流程
```
main() 
├─ prepare_experiment_targets()  # 加载所有基准
├─ for each benchmark:
│  └─ run_experiments(benchmark) # 运行单个实验
│     ├─ WorkDirs(output-{id})  # 创建或清空工作目录
│     ├─ run_one_experiment.run()
│     │  ├─ _fuzzing_pipeline()  # 三阶段流程
│     │  │  ├─ Writing Stage    # LLM生成harness
│     │  │  ├─ Execution Stage  # 编译并运行fuzz
│     │  │  └─ Analysis Stage   # 分析结果
│     │  └─ return AggregatedResult
│     └─ return Result
└─ 输出汇总结果
```

### 2.2 关键问题点
1. **WorkDirs 初始化**：`WorkDirs(path, keep=False)` 默认会清空已存在的目录
   - 位置：`experiment/workdir.py` 第 34-36 行
   - 影响：即使目录存在已完成的输出，也会被删除

2. **无状态检查**：`run_all_experiments()` 直接创建 WorkDirs，没有检查
   - 位置：`run_all_experiments.py` 第 125-130 行
   - 缺失：应该检查输出目录是否已完成

3. **无恢复选项**：`run_all_experiments.py` 的 `parse_args()` 没有恢复相关参数

## 三、实现方案

### 3.1 核心设计

#### 新增组件：CheckpointManager
**文件**：`checkpoint_manager.py`

功能：
- ✓ 扫描输出目录，识别已完成的实验
- ✓ 维护全局状态注册表（JSON格式）
- ✓ 支持三种模式：
  1. **fresh** (默认)：清空输出，完全重新开始
  2. **resume**：跳过已完成任务，继续运行未完成的
  3. **resume-only**：仅查看状态，不运行

#### 状态定义
```python
{
  "benchmark_id": {
    "status": "completed|in_progress|pending",
    "timestamp": "2026-04-03 08:30:00",
    "output_dir": "output-file-xxx",
    "completion_info": {
      "writing_stage": true,
      "execution_stage": true, 
      "analysis_stage": true,
      "final_aggregated_result": {...}
    }
  }
}
```

### 3.2 修改点详解

#### 修改 1：添加 checkpoint_manager.py（新文件）
```python
class CheckpointManager:
  def __init__(self, work_dir):
    self.work_dir = work_dir
    self.registry_path = os.path.join(work_dir, '.checkpoint_registry.json')
  
  def scan_completed_experiments(self):
    """扫描已完成的实验"""
    # 逻辑：找所有 output-* 目录，检查是否有status/*/result.json
    
  def get_completed_benchmarks(self):
    """返回已完成的benchmark ID列表"""
    
  def save_checkpoint(self, benchmark_id, status, result=None):
    """保存一个benchmark的检查点"""
    
  def is_completed(self, benchmark_id):
    """检查某个benchmark是否已完成"""
```

#### 修改 2：run_all_experiments.py - parse_args()
添加参数：
```python
parser.add_argument(
    '--resume-mode',
    type=str,
    default='fresh',
    choices=['fresh', 'resume', 'resume-only'],
    help='Resumable run mode'
)
```

#### 修改 3：run_all_experiments.py - main()
```python
def main():
  global WORK_DIR
  args = parse_args()
  
  # 新增：初始化checkpoint管理
  checkpoint_manager = CheckpointManager(args.work_dir)
  
  if args.resume_mode == 'resume':
    # 扫描已完成的实验
    completed = checkpoint_manager.scan_completed_experiments()
    # 过滤掉已完成的 benchmark
    experiment_targets = [
      b for b in experiment_targets 
      if b.id not in completed
    ]
    logger.info(f"Resume mode: skipping {len(completed)} completed experiments")
  
  elif args.resume_mode == 'resume-only':
    # 仅显示状态，不运行
    checkpoint_manager.print_status()
    return 0
  
  # ... 继续运行
```

#### 修改 4：run_all_experiments.py - run_experiments()
```python
def run_experiments(benchmark: benchmarklib.Benchmark, args) -> Result:
  """Runs an experiment based on the |benchmark| config."""
  try:
    # ... 现有逻辑
    result = run_one_experiment.run(
        benchmark=benchmark,
        model=model,
        args=args,
        work_dirs=work_dirs
    )
    
    # 新增：保存检查点
    if checkpoint_manager and result.result != 'Error':
      checkpoint_manager.save_checkpoint(
          benchmark.id, 
          'completed',
          result.result
      )
    
    return Result(benchmark, result)
  except Exception as e:
    # 新增：保存失败状态
    if checkpoint_manager:
      checkpoint_manager.save_checkpoint(
          benchmark.id,
          'error',
          str(e)
      )
    # ...
```

#### 修改 5：experiment/workdir.py - WorkDirs.__init__()
```python
def __init__(self, base_dir, keep: bool = False):
  # ... 现有代码
  if os.path.exists(self._base_dir) and not keep:
    # 保留原有行为，但支持 keep=True 来保持已有文件
    rmtree(self._base_dir, ignore_errors=True)
  # ...
```

修改 run_experiments() 的调用：
```python
work_dirs = WorkDirs(
    os.path.join(args.work_dir, f'output-{benchmark.id}'),
    keep=(args.resume_mode == 'resume')  # 新增参数
)
```

### 3.3 实现步骤

| 步骤 | 任务 | 优先级 | 预计时间 |
|-----|------|--------|---------|
| 1 | 创建 checkpoint_manager.py | P0 | 20min |
| 2 | 修改 run_all_experiments.py 添加参数 | P0 | 10min |
| 3 | 修改 run_experiments() 的 WorkDirs 调用 | P0 | 10min |
| 4 | 在 run_experiments() 中保存检查点 | P0 | 10min |
| 5 | 在 main() 中集成状态扫描和过滤 | P0 | 15min |
| 6 | 修改 experiment/workdir.py 支持 keep 参数 | P1 | 5min |
| 7 | 测试和验证（基于file项目） | P0 | 30min |
| 8 | 文档编写 | P1 | 15min |

## 四、使用示例

### 场景1：首次运行
```bash
python run_all_experiments.py -b benchmark-sets/file -td output/file
# 或（显式指定）
python run_all_experiments.py -b benchmark-sets/file -td output/file --resume-mode fresh
```

### 场景2：运行中断后恢复
```bash
# 程序因网络超时中断...
# 恢复运行，跳过已完成的任务
python run_all_experiments.py -b benchmark-sets/file -td output/file --resume-mode resume
```

### 场景3：查看运行状态
```bash
python run_all_experiments.py -b benchmark-sets/file -td output/file --resume-mode resume-only
# 输出：
# ✓ output-file-buffer_apprentice: completed at 2026-04-03 01:31
# ✓ output-file-cdf_tole4: completed at 2026-04-03 01:20
# ✗ output-file-magic_open: error - RateLimitError at 2026-04-03 08:48
# ⏳ output-file-magic_file: pending
```

## 五、风险与缓解

| 风险 | 影响 | 缓解方案 |
|-----|------|---------|
| 输出目录损坏 | 无法判断完成状态 | 保存详细的状态信息，验证result.json有效性 |
| 部分完成状态不清 | 可能重复执行部分工作 | 记录每个阶段的完成情况 |
| 参数变化影响 | 参数变化时需要重新运行 | 在checkpoint中记录参数hash |

## 六、验证计划

### on file 项目验证
1. 完整运行一次 file benchmark
2. 模拟在第5个函数处中断（停止进程）
3. 使用 resume 模式继续运行，验证：
   - 前4个函数被跳过
   - 第5个及以后的函数继续运行
   - 最终结果的完整性

### 状态命令验证
```bash
# 检查状态
python run_all_experiments.py -b benchmark-sets/file -td output/file --resume-mode resume-only
```
