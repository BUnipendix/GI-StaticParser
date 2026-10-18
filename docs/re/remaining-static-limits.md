# 剩余缺口的性质判定（静态 vs 运行时，2026-10-17）

> 目标要求区分「没有」与「困难」。本文件记录：哪些缺口是**元数据未保留/运行时才生成**（静态不可得），
> 哪些是**尚未定位但存在**（继续静态/模拟可攻），并附证据。

## A. 静态已证不可得（oracle 侧值来自运行时，或 GI 构建期丢弃）

| 项 | 证据 |
|---|---|
| 静态字段偏移（109,214 个字段）| oracle 首静态偏移 vs TypeDefIndex 单调性仅 50.2% ⇒ 偏移由运行时类初始化顺序决定；7.1 元数据无静态偏移表 |
| 补充（2026-10-18）| 用 6.4Dump 的 instance 偏移序列在 6.4 exe 全量搜索（tools/version-triage/check_field_offsets_cross.py）：只命中 0x70/0x78/0x80 通用平凡序列，无真实每类型数组 ⇒ 6.4 的值同样来自运行时辅助 dump，不是文件里的静态数组。|
| 方法 Slot 非零值 | 反汇编 0x1405155FC 构建器逐句核对：7.1 元数据几乎全 -1；oracle 6.4 非零 Slot 属 oracle 运行时语义 |
| interface 的基接口（oracle 270 行）| 7.1 元数据 interface 的 iface_start/count 全哨兵（0xFFFF/0）；且实现类接口列表**已扁平化**（7.1 ResourceReader 行含 IResourceReader+IEnumerable+IDisposable），运行时判定 0x140513260 只遍历 klass+0x20 接口数组、不递归基接口 ⇒ 构建期裁掉，运行时不需要（docs/re/71-generics-interface-origin.md）|
| ~~metadataUsage~~（script.json Addresses/ScriptMetadata 基础）| **已推翻（2026-10-18，R19）**：索引表 body+(hdr[0x19C]^0x159FBC84)、pair 表 body+(hdr[0x14C]^0x2F249C2F)，解析器 0x140524250；全量 311,730 usage / 788,057 pair（tools/inspect_usage_tables.py，见 docs/re/71-usage-tables.md）|
| ~~stringLiterals 数据~~ | **已推翻（2026-10-18，R19）**：offset 表 = body+(hdr[0x88]+0xF3C0B2FE)、数据 = body+(hdr[0x13C]^0x28B1D785)，解密器 0x140526BD0；86,108 条与 literals.json 逐条一致（tools/inspect_usage_tables.py）|
| ~~属性表本体（propertyDefs）~~ | **已推翻（2026-10-18，§83）**：不是标准 20B 行，而是 `hdr[0x158]−0x1D545CCC` 的 **10B 行**（name/getter/未知/setter），运行时 PropertyInfo 构建器 0x140515FC0 直接读它；全量解出 115,596 条属性（详见 gap-inventory #3、71-final-status）|
| ~~泛型参数名~~（genericParameters）| **已恢复（2026-10-18，R23）**：`body + (hdr[0x174] + 0xCED1EDB1)` = 0xDF8708，14B 行 × **5,796**，逐行 mask；名字为真实源码名（TKey 289 / TValue 305 / TResult 97 / TRest …），dump.cs 已接线（docs/re/71-generic-params.md）。**约束**仍未解（accessor 不读约束字段，标准约束表扫描 0 命中）|
| ~~属性参数~~（22,146 条含参属性）| **结论修订（R19）**：不是未定位，而是运行时设计上不存在——4 个属性查询 API（0x1404B2400/2710/2C90/5353DC）只返回 attribute klass（经 0x140526AF0），无对象构造/ctor 调用；成员→实例表 = slot 0x118、实例→类 = slot 0x1A8（body 0x9BACA4）。属性参数在构建期丢弃 |

> 这些项的 oracle 值要么来自运行时内存（Il2CppDumper 参考 dump 是运行时辅助产生的），要么 GI 构建期 strip。
> 继续静态攻的期望收益低；若将来允许运行时 dump，可一次性补齐。

## B. 尚未定位但可能存在的（继续静态/模拟可攻）

| 项 | 现状 | 下一步 |
|---|---|---|
| attribute 参数 blob | 数据层已解（类型+成员），参数值缺失 | 在 .upx0/变异函数里找 attribute reader；或用属性类 ctor 参数类型反推变长记录布局 |
| ~~属性表（若存在）~~ | **已解（2026-10-18）**：10B propertyDefs 行表 + typeDef propStart@0x24/propCount@0x43；115,596 条属性已进 dump.cs | 下一步把属性表接入 DummyDll PropertyDefinition 行 |
| `.upx0` 中其余 metadata 函数 | 206 个 `.text→.upx0` 入口中仅 3 个与 metadata 相关（flags/klass 解析器已解）| 扩大入口发现范围（`.upx0` 内部 27,139 个调用目标里可能有未被 .text 直接引用的 metadata 访问器）|

## C. 工程类（数据已有，只需产出格式）

| 项 | 说明 |
|---|---|
| DummyDll | 用现有类型/字段/方法数据生成 .NET 桩程序集（需写 PE+CLI 元数据，1–2k 行）|
| il2cpp.h | **未产出（有理由）**：GI 运行时结构经 VMP 改造（实测 klass+0x10=tdi、+0x38 events、+0x48 props、+0x58 methods、+0x60 typeDef 行等），与 Il2CppDumper 标准 V27/V29 模板不一致；标准模板会误导，而 GI 实测结构只覆盖 metadata-cache 部分，不足以生成完整头文件 |
| script.json 的 Signature/TypeSignature | 可从已解类型/参数渲染（仅格式约定待定）|
| 多版本通用化（R9）| 用 26 个样本跑 version-triage + .upx0 常数读取 SOP |

## D. 本轮模拟器进展（tools/emu_upx.py）

- 已验证可执行 flags/klass 解析器（entry 0x14051DB00，rcx=293 完整返回）；
- 增加故障记录（fault）与宽容模式（未映射执行地址补 `xor eax,eax; ret` 桩）；
- 批量跑 206 入口：11 个可完整执行、195 个因 VMP 运行时解析槽（文件里是 RVA 形占位，如 0x3b4d7a4）而失败 —— 说明这些入口依赖 VMP 初始化器，
  要跑通需先模拟 VMP 初始化（下一阶段工作）。
