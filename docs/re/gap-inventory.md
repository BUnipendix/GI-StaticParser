# 与 Il2CppDumper 的数据差距清单（2026-10-15 复测）

> 基准：Il2CppDumper 输出格式（本地 oracle：/tmp/giref/6.5Dump.cs，655,240 Token 行）。
> 我们的 dump：mhydump dump71 于 7.1.0（88,872 类型 / 440,061 字段 / 460,282 方法）。
> 参考比例按 6.4Dump.cs（77,260 类型）折算到 7.1 规模。

## 一、本轮已闭合（指令级解锁 + Rust 接线完成）

| 数据 | 修复前 | 修复后 | 参考期望 | 依据 |
|---|---|---|---|---|
| 类型种类 interface | 42,484 假阳性 | **1,580** | ~1,550 | 行+0x0C flags、行+0x32 bitfield（§28）|
| enum / struct / class 计数 | 4,508 / 1,963 / 39,917 | 8,123 / 4,797 / 74,372 | ~7,540 / ~3,790 / ~74,150 | 同上 |
| 可见性/静态/抽象/密封修饰符 | 全部 public | 全套（Il2CppDecompiler.cs else-if 规则）| — | flags 列 |
| 方法 Token | 0 | 顺序 0x06000001.. + 构造函数 0x00000000 | 与 oracle 编号规律逐位吻合 | 实测规则 |
| Constructors 段 | 无 | 拆分渲染 | — | 名称 .ctor/.cctor |
| Properties 段占位 | 无 | 恒有段头（空）+ 显式 warn 计数 | — | 诚实占位（R3/R4）|

验证锚点：行 0–4（<Module>/Locale/SR/Mono.Runtime…）与 oracle 逐字一致；
Token 前 3 个 = 0x06000001/2/3 与 oracle 完全一致。回归 17 passed / 0 failed。

## 二、仍缺（按解锁难度排序）

| # | 数据 | 参考量 | 阻塞点 / 解锁路径 |
|---|---|---|---|
| 1 | 字段偏移注释 | 440,061 | 运行时 fieldOffsets（静态注册结构 62A0 附近，§27.1 已定位入口）|
| 2 | 参数名/类型 | 361,974 | 参数表列变换未接线（param_stride 12 表已有；列常数需 .upx0 或统计求解）|
| 3 | Properties/Events 行 | 77,260 段 | 属性表槽位未定位（slot 清单单点槽待核）|
| 4 | 接口列表精确化 | 41,789 近似 | interfacesCount 列（行内 0x04 +0x89DE8E6E 候选待终判）|
| 5 | 方法 Slot 精确值 | REF 211,652 非零 | md_slot 已解码但大量 -1：掩码截断细节待数据级复核 |
| 6 | 属性 [Attribute] | 11,525 | attributeData 表未定位 |
| 7 | 枚举字面值 | — | fieldDefaultValues 表 |
| 8 | stringLiterals.json | 689,799 串 | 字符串字面量表（独立于用户串堆）|
| 9 | script.json ScriptString/Addresses/Signature | 689,799 / 239,153 | 依赖 #8 + 方法特征定位 |
| 10 | il2cpp.h / DummyDll | 整套 | 依赖以上全部 |

## 三、script.json 现状

ScriptMethod 460,282 已有（含全限定名）；ScriptString=0、Addresses=3、Signature 空 —— 待 #8/#9。

## 四、跨版本注意

flags/bitfield 常数是 7.1.0 专属（在 .upx0 变异函数逐版读取，0x159F63C4D 模式）；
其它版本接线前需先跑 version-triage + 该版 .upx0 常数读取（SOP 见 version-matrix.md §4）。
