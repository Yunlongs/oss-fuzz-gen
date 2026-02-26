# agent/ — LLM Agent 模块说明

本目录包含 oss-fuzz-gen 系统中所有基于大语言模型（LLM）的 Agent 实现。每个 Agent 负责模糊测试（fuzzing）流水线中的一个特定阶段，彼此通过 `Result` 对象串联，共同完成从零生成可运行 fuzz target、分析运行结果、迭代优化的完整闭环。

---

## 模块总览

```
agent/
├── base_agent.py                # 所有 Agent 的抽象基类
├── analyzer.py                  # 分析类 Agent 的空壳基类
├── prototyper.py                # 交互式 fuzz target 生成（主力原型器）
├── one_prompt_prototyper.py     # 单轮提示的轻量级原型器
├── function_based_prototyper.py # 基于函数工具调用的原型器
├── enhancer.py                  # 交互式 fuzz target 增强优化器
├── one_prompt_enhancer.py       # 单轮提示的轻量级增强器
├── semantic_analyzer.py         # libFuzzer 日志解析与语义分析
├── coverage_analyzer.py         # 代码覆盖率分析与洞察生成
├── crash_analyzer.py            # 运行时 crash 分析（含 GDB 调试）
├── function_analyzer.py         # 目标函数隐式需求分析
└── context_analyzer.py          # crash 上下文分析（关联函数约束）
```

---

## 各模块详细说明

### `base_agent.py` — 抽象基类

**核心类：**

- **`BaseAgent`（ABC）**  
  所有 Agent 的顶层抽象基类，提供：
  - LLM 会话管理（`chat_llm`、`ask_llm`、`chat_llm_with_tools`）
  - LLM 响应解析（XML 标签提取 `_parse_tag`/`_parse_tags`、代码过滤 `_filter_code`）
  - 容器工具交互辅助（bash 命令执行与结果格式化）
  - 无效响应重试（`_container_handle_invalid_tool_usage`）
  - 云端 main 入口（`cloud_main`）

- **`ADKBaseAgent(BaseAgent)`**  
  基于 Google ADK（Agent Development Kit）库构建的 Agent 基类，仅支持 Vertex AI 模型。使用 `google.adk.runners.Runner` 异步驱动 LLM，支持工具调用（function calling），并通过 `InMemorySessionService` 维护多轮会话状态。

---

### `analyzer.py` — 分析器基类（空壳）

```python
class Analyzer(BaseAgent):
    pass
```

为所有"分析类"Agent 提供统一的类型标识，目前不含独立逻辑，作为分析阶段 Agent 的共同父类占位使用。

---

### `prototyper.py` — 交互式 Fuzz Target 原型器

**类：`Prototyper(BaseAgent)`**

从零开始生成能够编译通过的 fuzz target 原型，是系统的核心"写作"Agent。

**工作方式：**
1. 根据 benchmark 信息（目标函数、项目上下文、已有示例）构建初始 prompt。
2. 启动项目容器（`ProjectContainerTool`），通过**多轮交互**让 LLM 探索项目结构、逐步编写代码。
3. 每轮解析 LLM 返回的 `<fuzz target>` 和 `<build script>` 标签，调用容器编译，将编译结果反馈给 LLM。
4. 直到编译成功或达到最大轮数（`max_round`）为止。

**特性：**
- 支持 `--context` 参数引入项目上下文信息（`ContextRetriever`）。
- 支持函数需求文件（`function_requirements`）指导 LLM 生成更精准的代码。

---

### `one_prompt_prototyper.py` — 单轮提示原型器

**类：`OnePromptPrototyper(BaseAgent)`**

`Prototyper` 的轻量版，**不使用容器交互**，一次性生成 fuzz target 后通过编译验证。

**特性：**
- 支持多语言：C/C++、JVM（Java/Kotlin）、Python、Rust，自动选择对应的 `PromptBuilder`。
- 支持从测试文件生成 harness（`TestToHarnessConverter`）。
- 编译失败后通过内置的 `code_fixer` 自动修复，最多尝试 `max_round` 次。
- 相比 `Prototyper` 调用次数更少，适合资源受限场景。

---

### `function_based_prototyper.py` — 基于函数工具调用的原型器

**类：`FunctionBasedPrototyper(BaseAgent)`**

通过 LLM 的原生**函数调用（function calling）** 能力与项目进行交互，生成 fuzz harness。

**提供给 LLM 的工具（Tools）：**
| 工具名 | 功能 |
|---|---|
| `get_source_code_of_function` | 获取指定函数的源代码 |
| `run_commands_in_container` | 在项目容器中执行 bash 命令，探索构建环境 |
| `test_fuzz_harness_build` | 尝试编译指定的 fuzz harness 源码 |

LLM 自主决定调用哪些工具、以何种顺序探索项目，最终生成可编译的 harness。与 `Prototyper` 的区别在于使用 LLM 原生工具调用协议，而非基于标签解析的交互协议。

---

### `enhancer.py` — 交互式 Fuzz Target 增强器

**类：`Enhancer(Prototyper)`**

在已有可编译 fuzz target 的基础上，针对运行时问题进行优化，提升代码覆盖率或修复 crash。

**工作逻辑（根据上一轮 `AnalysisResult` 类型分支）：**
| 分析结果类型 | 使用的 PromptBuilder |
|---|---|
| `semantic_result`（语义错误） | `EnhancerTemplateBuilder` |
| `crash_result`（运行时 crash） | `CrashEnhancerTemplateBuilder` |
| `coverage_result`（低覆盖率） | `CoverageEnhancerTemplateBuilder` |
| JVM 项目 | `JvmFixingBuilder` |

增强逻辑继承自 `Prototyper`，同样通过容器多轮交互验证构建结果。

---

### `one_prompt_enhancer.py` — 单轮提示增强器

**类：`OnePromptEnhancer(OnePromptPrototyper)`**

`Enhancer` 的单轮版本，**不使用容器交互**，直接将分析结果（语义错误 / 覆盖率信息）注入 prompt，让 LLM 一次性修复 fuzz target。适合快速迭代场景。

---

### `semantic_analyzer.py` — 语义分析器

**类：`SemanticAnalyzer(BaseAgent)`**

**不调用 LLM**，通过规则（正则表达式）解析 libFuzzer 运行日志，判断 fuzz target 的运行质量。

**解析内容：**
- 代码覆盖点数（`cov_pcs`）与模块总点数（`total_pcs`）
- 是否发生 crash（排除 timeout/oom/leak 等非语义 crash）
- Crash 类型与调用栈信息
- `SemanticCheckResult`：汇总语义层面是否需要修复（如覆盖率过低、crash 在 fuzzer 内部等）

输出 `AnalysisResult`，交由后续 `Enhancer` 使用。

---

### `coverage_analyzer.py` — 覆盖率分析器

**类：`CoverageAnalyzer(BaseAgent)`**

当 fuzz target 覆盖率较低时，调用 LLM **分析低覆盖率原因**，并给出改进建议。

**工作方式：**
1. 以 `RunResult` 为输入，构建包含覆盖率数据的 prompt。
2. LLM 通过容器执行 bash 命令探索源码（如查看未覆盖代码路径）。
3. LLM 输出 `<conclusion>`、`<insights>`、`<suggestions>` 标签。
4. 将分析结果记录到 `CoverageResult`（`improve_required`、`insight`、`suggestions`）。

---

### `crash_analyzer.py` — Crash 分析器

**类：`CrashAnalyzer(BaseAgent)`**

分析 fuzz target 运行时 crash，借助 **GDB 调试工具** 进行深度根因分析。

**工作方式：**
1. 以 `RunResult`（含 crash 日志、fuzz target 源码）为输入构建初始 prompt。
2. 支持 LLM 通过 `<bash>` 标签调用容器命令，或通过 `<gdb>` 标签执行 GDB 调试命令（如查栈帧、打印变量）。
3. `GDBTool` 在 screen 会话中运行 GDB，支持交互式调试。
4. LLM 最终给出 `<conclusion>`，记录 crash 根因、是否为 fuzz target 自身问题，输出 `CrashResult`。

---

### `function_analyzer.py` — 函数需求分析器

**类：`FunctionAnalyzer(ADKBaseAgent)`**

在生成 fuzz target **之前**，对目标函数进行静态分析，识别其**隐式需求**（前置条件、参数约束、调用顺序等），为后续原型器提供更精准的指导。

**工作方式：**
1. 基于 ADK 框架，使用 Vertex AI 模型驱动。
2. 提供给 LLM 的工具：
   - `get_function_implementation`：获取函数实现代码
   - `search_project_files`：在项目中搜索相关文件
   - `return_final_result`：提交分析结论
3. 分析结果（`FunctionAnalysisResult`）序列化为 XML 写入需求文件，供 `Prototyper` 在构建 prompt 时读取。

---

### `context_analyzer.py` — Crash 上下文分析器

**类：`ContextAnalyzer(ADKBaseAgent)`**

在 crash 发生后，进一步分析**触发 crash 的函数调用上下文**，识别相关的隐式约束，辅助 `Enhancer` 生成更正确的修复代码。

**工作方式：**
1. 基于 ADK 框架，要求上一轮结果为含有 `crash_result` 的 `AnalysisResult`。
2. 提供给 LLM 的工具：
   - `get_function_implementation`：获取函数实现
   - `search_project_files`：搜索项目源文件
   - `report_final_result`：提交分析结果
3. 分析结果保存在 `AnalysisResult.crash_context_result` 中，供 `CrashEnhancerTemplateBuilder` 使用。

与 `FunctionAnalyzer` 的区别：前者在生成 harness 前分析目标函数的通用需求；后者在 crash 后聚焦于分析 crash 触发路径上的上下文约束。

---

## Agent 运行流水线

```
FunctionAnalyzer          ← 分析目标函数需求（可选）
       ↓
Prototyper / OnePromptPrototyper / FunctionBasedPrototyper
       ↓ (BuildResult)
SemanticAnalyzer          ← 解析 libFuzzer 日志
       ↓ (AnalysisResult)
CoverageAnalyzer          ← 分析低覆盖率原因（可选）
CrashAnalyzer             ← 分析运行时 crash（可选）
ContextAnalyzer           ← 分析 crash 上下文（可选）
       ↓
Enhancer / OnePromptEnhancer
       ↓ (BuildResult)
    [循环直到达标或超出轮数]
```

---

## 继承关系

```
BaseAgent (ABC)
├── Analyzer
├── Prototyper
│   └── Enhancer
├── OnePromptPrototyper
│   └── OnePromptEnhancer
├── FunctionBasedPrototyper
├── SemanticAnalyzer
├── CoverageAnalyzer
└── CrashAnalyzer
ADKBaseAgent (BaseAgent)
├── FunctionAnalyzer
└── ContextAnalyzer
```
