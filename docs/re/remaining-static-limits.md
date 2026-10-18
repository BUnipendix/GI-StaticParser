# 剩余缺口的性质判定（静态 vs 运行时，2026-10-17）

> 目标要求区分「没有」与「困难」。本文件记录：哪些缺口是**元数据未保留/运行时才生成**（静态不可得），
> 哪些是**尚未定位但存在**（继续静态/模拟可攻），并附证据。

## A. 静态已证不可得（oracle 侧值来自运行时，或 GI 构建期丢弃）

| 项 | 证据 |
|---|---|
| 静态字段偏移（109,214 个字段）| oracle 首静态偏移 vs TypeDefIndex 单调性仅 50.2% ⇒ 偏移由运行时类初始化顺序决定；7.1 元数据无静态偏移表 |
| 方法 Slot 非零值 | 反汇编 0x1405155FC 构建器逐句核对：7.1 元数据几乎全 -1；oracle 6.4 非零 Slot 属 oracle 运行时语义 |
| interface 的基接口（oracle 270 行）| 7.1 元数据 interface 的 iface_start/count 全哨兵（0xFFFF/0） |
| metadataUsage（script.json Addresses/ScriptMetadata 基础）| 扫 body 无 `{start,count}` 连续表（两种列序、双相位、≥32 行连续）；该表在运行时由 code registration 写入 BSS |
| stringLiterals 数据 | exe `il2cpp` 段（306MB）无 ASCII 文本池（64KB 块密度>0.8 且零率<2% 的块数 = 0）；metadata body 只有 ~45KB 明文字符串（默认值用的 UI 路径），非 689,799 条字面量 |
| ~~属性表本体（propertyDefs）~~ | **已推翻（2026-10-18，§83）**：不是标准 20B 行，而是 `hdr[0x158]−0x1D545CCC` 的 **10B 行**（name/getter/未知/setter），运行时 PropertyInfo 构建器 0x140515FC0 直接读它；全量解出 115,596 条属性（详见 gap-inventory #3、71-final-status）|
| 泛型参数名（genericParameters）| 29 个字符串解码调用点逐一分析、startup/body 明文 packed 索引扫、`{nameIdx,owner}` 8B 扫、16B container 扫 均无命中 |
| 属性参数（22,146 条含参属性）| attributeTypes 数组后仅 769 个小整数；0xA03E64–0xC00000 无明文串；无 74,864 长度的偏移/单调数组 |

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
| il2cpp.h | Il2CppDumper 的运行时结构头（版本固定模板 + 指针宽度）|
| script.json 的 Signature/TypeSignature | 可从已解类型/参数渲染（仅格式约定待定）|
| 多版本通用化（R9）| 用 26 个样本跑 version-triage + .upx0 常数读取 SOP |

## D. 本轮模拟器进展（tools/emu_upx.py）

- 已验证可执行 flags/klass 解析器（entry 0x14051DB00，rcx=293 完整返回）；
- 增加故障记录（fault）与宽容模式（未映射执行地址补 `xor eax,eax; ret` 桩）；
- 批量跑 206 入口：11 个可完整执行、195 个因 VMP 运行时解析槽（文件里是 RVA 形占位，如 0x3b4d7a4）而失败 —— 说明这些入口依赖 VMP 初始化器，
  要跑通需先模拟 VMP 初始化（下一阶段工作）。
