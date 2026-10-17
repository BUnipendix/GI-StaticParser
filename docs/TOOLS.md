# TOOLS — 本工作线维护的工具与资产清单（跨 session 复用入口）

> 目的：任何新 session 接到相关任务时，**先读这份文档**，不要重研。
> 状态截至 2026-10-17。所有「可用」结论都有实测证据（见 IMPLEMENTATION_LOG 对应节）。
> 需求事实源是 REQUIREMENTS.md；本文是工具/资产索引，不是需求。

## 0. 30 秒定位

**模块架构（R10）**：`mhydump derive` = 常数算法分析提取模块（一次性导出数据）；
`mhydump dump-gen --profile-in` = 解包模块（只读导出数据）；`dump-gen --profile-out`
可在一次运行里同时导出+解包（一次性做完）。导出数据是唯一接口。

| 你要做什么 | 用什么 |
|---|---|
| 一次性导出某版本的可推导数据（密码/表基址） | §1 `mhydump derive --out art.json` |
| 新版本 metadata 快速梳理（30 分钟） | §2 triage 组 + [version-matrix.md §4 SOP](re/version-matrix.md) |
| 相邻版本推导 profile（密码/表/列常数） | §1 `mhydump derive` + §2 colsolve 组 |
| 生成 Il2CppDumper 风格 dump.cs | §1 `mhydump dump-gen`（解包模块） |
| 查 7.1 加载流程/表结构知识 | [metadata-loading-flow-7.1.0.md](re/metadata-loading-flow-7.1.0.md) |
| 查跨版本矩阵/已知常数轮换结论 | [version-matrix.md](re/version-matrix.md) |
| 查与 Il2CppDumper 的差距 | [gap-inventory.md](re/gap-inventory.md) |
| 反编译大体量变异函数 | §4 kuna（注意 CWD=/tmp） |
| 去虚拟化 VTIL | §4 NoVmp |

## 1. mhydump（Rust 主工具）

- 仓库：`~/Documents/git-repo/GI-StaticParser`；构建：`cargo build --release`；
  产物：`target/release/mhydump`。
- 全部命令**无常数**（从代码/数据现场推导，禁止硬编码，求解失败显式报错）。

| 命令 | 用途 | 状态 |
|---|---|---|
| `derive --exe --metadata [--out art.json]` | **R10 分析提取模块**：一次性导出字符串密码+表槽锚点+表基址（含 stride）为 JSON 工件；内置 mscorlib 自检，失败拒绝导出 | 26 版实测：**20 版成功**（4.8.0–7.1.0），6 版失败（4.2.0–4.7.0 另一纪元）；6.x/7.1 常数与历史逐位一致（version-matrix §7） |
| `cipher --exe --metadata [--json]` | 无常数推导字符串密码（3/5 常数世代）+ strsec | 26 版验证；6.7.0 实测 ✓ |
| `anchors --exe --metadata [--json] [--site VA]` | 恢复头槽锚点 + 已解析表基址（含 stride） | 6.7.0 实测：354 锚点，typeDef 表直接给出 |
| `strings --exe --metadata [--out] [--head]` | 解密整个字符串堆并枚举 | ✓ |
| `tables --exe --metadata [--base] [--json]` | 纯结构定位元数据行表（无列名） | ✓ |
| `types-dump --exe --metadata --out` | 类型表四元组导出 | 26 版中 24 版可用 |
| `dump-gen --exe --metadata [--out] [--profile-in p.json] [--profile-out] [--no-cipher-check] [--images-out img.json] [--attributes-out attrs.json]` | **世代通用 dump 管线**（profile 驱动；内置 7.1 实测 profile） | 7.1.0 端到端 ✓ **88,902 类型 / 440,172 字段 / 733,442 方法**；script.json 的 ScriptMethod 已按 Il2CppDumper 兼容格式生成（679,867 条 + Addresses 460,313，见 §70）。**需与 global-metadata.dat 同目录的 `startup-metadata.dat`**（缺失则泛型回退为 System.Object 并 warn）；`--images-out` 输出 75 image 名 + 75 assembly 名；`--attributes-out` 输出全部 74,864 条属性实例（含含参属性，Recovered 70,693）。已对齐 oracle：类型名全限定、参数类型 88.54%、泛型渲染（`List<System.String>`）、方法修饰符 99.29%、字段修饰符 99.91%、字段类型 98.33%、基类 98.96%、接口 84.52%、`[CompilerGenerated]`/`[NonSerialized]` 特性行；Properties 为访问器合成（属性表未定位）。别名 `dump71` 过渡 |
| `dump` | 7.1 专用旧管线（里程碑 e/f） | ✓ |
| `pe-validate` / `decode-one` / `header-dump` / `il2cpp-fns` | PE 检查 / 单串解码 / 表基址打印 / il2cpp API 定位 | ✓ |

**profile**（`src/derive/profile.rs`）是唯一版本相关数据结构；`--profile-in` 吃 JSON，
`--profile-out` 可把生效 profile 落盘。layout71.rs 是 7.1 实测实例。

## 2. version-triage 工具组（Python，`tools/version-triage/`）

两阶段有界内存设计（字节扫 → 小窗），**禁止全量 capstone sweep**（曾 OOM 20+GB）。

| 脚本 | 用途 | 备注 |
|---|---|---|
| `triage.py <exe> <dat>` | 两阶段扫描 + blob 评分 + 多数哨兵 → 表槽常数 | 26 版全跑通 |
| `run_all.sh` | 批跑样本库（`-P2`、`ulimit -v 2500000`） | 结果在 `out/*.json` |
| `phase_c2.py` | typeDef 后处理（stride 池并集、逐列多数画像） | 8 版 typeDef 与历史逐位互证 |
| `matrix.py` | 生成跨版矩阵报告 | → `docs/re/version-matrix.md` |
| `colsolve2.py` | **非对齐堆锚点扫描**（numpy 滑动解密）+ 行 0 明文求解；`decrypt()/find_anchor()` 被其它脚本 import | 堆紧打包无对齐无终止符，8 对齐扫描会漏 |
| `colsolve4.py` | **相邻版本 typeDef 列全自动求解器**：name/ns/flags/bitfield/starts/counts/element/parent（明文锚点+单调性+fs/fc、ms/mc 全表链式判据） | 6.7.0 实测 5/9 列 |
| `colverify.py <hypo.json>` | 假设 JSON → 全表验证（分布/链/哨兵），产证据记录 | 6.7.0 五列 60k 行验证 |
| `densescan3.py <exe> <section> <out.jsonl>` | `.upx0` 全段列成语扫描：**双向变换**（常数先行/加载先行）+寄存器族归一+垃圾容忍+4KB 重同步 | 已用 7.1 已知常数校准（name/flags 双中）；v1/v2 已废弃 |
| `colscan.py` | 单变换常数站点窗数据流（单向，早期版） | 被 densescan3 取代，留档 |

`out/6.7.0.columns.json` 是「相邻版本推导结果」的记录格式样例（含证据、未解项、代码事件）。

## 3. 知识库（`docs/re/`）

- `metadata-loading-flow-7.1.0.md` — 加载流程全景（头=.rdata blob、body=文件+0x210、表槽成语、
  typeDef/方法行布局、mask2、运行时结构）。§0–§10 + 103 行机器生成槽表。
- `version-matrix.md` — 跨版矩阵 + SOP + 6.7.0 实测（§6）。
- `gap-inventory.md` — 对齐 Il2CppDumper 的差距清单（已关/待办）。
- `artifacts-7.1.0/` — 机器生成证据（slotrec4.json 702 站点、slotfn.json 256 函数、扫描器、kuna 反编译）。

## 4. 外部工具（本机维护状态）

| 工具 | 路径 | 用法要点 |
|---|---|---|
| kuna 反编译器 | `~/Documents/git-repo/kuna/decompiler/target/release/kuna` | **必须 CWD=/tmp**（否则静默 0 输出）；后台任务用绝对路径；**单实例**（4 并发打满内存）；大体量函数 Ghidra 超时的用它 |
| NoVmp | `~/Documents/git-repo/NoVmp-pub/build/NoVmp/NoVmp` | GI 26 版可用；交接文档 `VMP壳/交接-给下一个agent.md`；vmenter 清单 91 条在 `VMP壳/work/vmenters.txt`。注意：变异原生码（非 VM）它会正确拒绝，直接 capstone 读 |
| Ghidra GUI | 常驻（吃 ~10GB） | 函数边界批量用 getFunctionContaining（~2s）；`get-decompilation` 大函数超时 |
| 样本库 | `~/gire/sample/gi/<版本>/` | YuanShen.exe + YuanShen_Data/Managed/Metadata/{global,startup}-metadata.dat，4.2.0–7.1.0 共 26 版 |

## 5. 标准工作流

### A. 新版本到手（30 分钟 triage，[SOP 详版](re/version-matrix.md#4-相邻版本快速梳理-sop新版本到手-30-分钟)）

1. `bash tools/version-triage/run_all.sh`（或单跑 `triage.py`）→ `out/<ver>.json`
2. `python3 tools/version-triage/phase_c2.py out` → typeDef 候选 + 列画像
3. 与相邻版本 `out/*.json` 对照（槽迁移/多数列漂移）

### B. 相邻版本 profile 推导（6.7.0 实测流程）

1. `mhydump derive --exe … --metadata … --out derive.json` → 一次性导出（密码+锚点+表基址）
2. `python3 tools/version-triage/colsolve4.py <dat> <td_base> <stride> <strsec> <M1> <X1> <X2> <step>` → 自动解列
3. `colverify.py` 全表验证 → 落 `out/<ver>.columns.json`
4. 静态形态无解的列（疑似行级掩码）→ `densescan3.py` 定位站点 → 读变异码掩码链
5. 组 profile JSON → `mhydump dump-gen --profile-in p.json`

### C. 生成 dump

`mhydump dump-gen --exe <主模块> --metadata <dat> --out dump.cs [--profile-in p.json]`

一次性做完（R10.c）：`--profile-out p.json` 同场导出完整 profile（下次 `--profile-in` 免分析，
7.1 实测往返逐字节一致）；分析数据（derive 工件）+ profile 数据是仅有的两个跨模块工件。

## 6. 资源与坑（12 核 / 15GB RAM，Ghidra 常驻）

- **内存**：一切扫描有界（两阶段/分块/`ulimit -v`）；**永不全量 capstone sweep**。
- `/tmp` 会话内跨命令持久、**跨会话不持久**——产物要进仓（docs/re/artifacts-* 或 tools/*/out/）。
- capstone 寄存器枚举 ≠ x86 编码序（X86_REG_RDX=40 非 2）；REX.R 是 0x4 非 0x8。
- 变换双向：`op reg, imm` 与 `mov reg,K … op reg, [mem]` 都要扫。
- 变异码线性扫描会失步：4KB 重同步；垃圾指令写寄存器族要归一失效。
- 堆字符串：紧打包、无对齐、无终止符（长度在索引 byte3）。
- 锚点逐版本不同（6.7.0 Mono 类型无 `Mono.` 前缀）——从数据现找，不硬套旧表。
- Python `re.finditer` 不重叠 → 系统性欠计数，扫指令逐字节。

- [2026-10-17] dump-gen 的 Slot 列改由 src/vtable.rs 纯静态重算（接口槽前置 + final/显式实现不占类槽），245,235 个 virtual 方法；与 6.4 oracle 严格同构类型一致率 96.03%（tools/validate_slots.py）。

- [2026-10-17] DummyDll v1：`mhydump dump-gen --dummy-out x.jsonl` + `tools/dummygen`（net10.0, System.Reflection.Metadata）→ 单文件 DummyDll.dll（7.1：38MB，88,902 类型/733,442 方法/440,172 字段/548,400 参数/84,377 接口实现；dnfile 独立验证一致）。参考实现为 75 个程序集+自定义特性，v1 为单程序集、无 GenericParam/特性。

- [2026-10-17] 字符串字面量：tools/recover-literals.sh 包装外部工具 gi-stringliteral（版本无关，从 exe 抽常数+定位表）。7.1 实测 86,108 条字面量（table 0x1ebb8ec / data 0x1c6c828），产物 ~/gire/out/71/literals.json；前序 meta_string_literals.txt 覆盖 99.54%。6.4 样本因混淆代次不同失败（工具作者仅验证特定版本）。

- [2026-10-17] DummyDll v2：JSONL 新增 rva/token/slot/instance-offset；生成器追加 AddressAttribute/FieldOffsetAttribute 与 1,041,595 条 CustomAttribute（命名参数格式，内置解码校验通过），DummyDll.dll 77MB。剩余差异：75 程序集划分（依赖 image 映射）、GenericParam 表。
