# GI 7.1 静态解包完整性报告（il2cppdumper 等效数据）

日期：2026-10-18（最终版）。目标：静态补齐 7.1 版 Il2CppDumper 可解包数据，运行时快照仅作 oracle/验证。
**一键验证**：tools/final_verify.sh（重建全部工件并断言计数/大小；WITH_LITERALS=1 时一并重跑字面量工具）。

## 1. 结论

7.1 版**静态可解数据已全部恢复**。相对 2026-10-17 版本，本轮（§83–§89）又新增：
真实 propertyDefs 表（115,596）、eventDefs 表（628）、参数默认值表（25,374 行 / 15,592 个常量）、
DummyDll 的 Token/Attribute/Constant/MetadataOffset 全量接线，以及两个长期 DummyDll 结构 bug 的修复。
其余"未恢复"项均已定位为「GI 元数据/二进制未保留」或「需运行时数据」，并有可复现实验证据，不是"还没找到"。

## 2. 产物清单（~/gire/out/71/）

| 文件 | 大小 | 内容 |
|---|---|---|
| dump.cs | 127,769,231 B | 88,902 类型 / 440,172 字段 / 733,442 方法 / 115,596 真实属性（Slot 列已静态重算；**泛型参数名已渲染**，见 docs/re/71-generic-params.md） |
| script.json | 176,764,249 B | ScriptMethod 679,867 + **ScriptString 137,466** + **ScriptMetadataMethod 84,875** + **Addresses 483,496**（方法 460,313 + generic 12,827 + invoker 25,651；见 docs/re/71-usage-tables.md §3） |
| attributes.json | 10,025,050 B | 74,864 条属性实例，Recovered 70,693 |
| literals.json | 6,287,449 B | 86,108 条字符串字面量（静态解密） |
| images.json | 14,326 B | 75 images / 75 assemblies |
| DummyDll.dll | 146,724,352 B | 88,907 TypeDef / 733,447 Method / 440,182 Field / 115,596 Property / 628 Event / 133,270 MethodSemantics / 90,224 Constant（74,632 字段 + 15,592 参数）/ 2,491,946 CustomAttribute / **5,796 GenericParam（类型级 2,697 + 方法级 3,099，真实名字 TKey/TValue/TRest…）** |
| dummy.jsonl | 224,397,559 B | DummyDll 生成器输入（115,596 P + 628 E + 70,692 A；字段/参数 cv/mo；T/M 记录带 `gp` 泛型参数名） |

## 3. 逐项状态

### 3.1 已恢复（有全量验证）

| 项 | 状态 | 证据/说明 |
|---|---|---|
| 类型/命名空间/字段/方法/参数 | 已恢复 | 88,902 / 440,172 / 733,442；vs 6.4 oracle：全限定名、参数 88.54%、字段类型 98.33%、基类 98.96% |
| 方法 Slot | 已恢复（纯静态） | src/vtable.rs 重算 245,235 个 virtual 方法；严格同构类型 8,548/8,901 = 96.03%（tools/validate_slots.py） |
| instance 字段偏移 | 布局重建 | dump_gen::instance_offsets；类型级与 6.4 oracle 一致率 79.55%（跨版本差异 + 显式布局限制） |
| propertyDefs | 已恢复（§83） | hdr[0x158]−0x1D545CCC，10B 行：115,596 条 / 30,226 类型；getter 112,107 / setter 19,907 全部 < methodCount；全量铺瓦 0 不规则；名称经 cipher 解码；vs 6.4 oracle corelib 序列全等 1,272/1,318=96.5%（tools/validate_properties.py） |
| eventDefs | 已恢复（§85） | hdr[0x64]+0xE6130C67，14B 行：628 条 / 225 类型；铺瓦 0 不规则；type 全合法；未混淆类型 add/remove 命中 add_*/remove_*；raise 全 0xFFFF（未保留） |
| 泛型参数名 | 已恢复（R23） | `body+(hdr[0x174]+0xCED1EDB1)` = 0xDF8708，14B×5,796，逐行 mask；真实名字 TKey/TValue/TRest… 已进 dump.cs（docs/re/71-generic-params.md）|
| 参数默认值 | 已恢复（§88） | hdr[0x1D0]^0x07D0BBF9，12B 行：25,374 行（key=全局参数索引，升序）；15,595 有值 / 9,779 dataIndex=-1；对应参数 100% 带 Optional|HasDefault |
| DummyDll Constant | 已接入 | 90,224 = 74,632 字段 + 15,592 参数；不可表示 kind → MetadataOffsetAttribute（919 = 916 + 3） |
| 字符串字面量 | 已恢复 | gi-stringliteral（外部工具）：86,108 条；旧 meta_string_literals.txt 覆盖 99.54% |
| 自定义属性实例 | 已恢复（实例/成员身份） | attributes.json 74,864 实例；dump.cs 中 47,976 条渲染为 [Class] |
| DummyDll | 已生成 | 单程序集自包含；5 个标记类型与 bundled Il2CppDummyDll 一致；TokenAttribute 1,378,740；AttributeAttribute 70,692；参数归属 / SequenceNumber / HasDefault 均已修复（§84/§86/§88） |

### 3.2 未恢复（均带证据，属"元数据未保留 / 需运行时"）

| 项 | 证据 |
|---|---|
| 静态字段偏移（109,214） | 文件内无 fieldOffsets 数组（400 类型签名抽样 0 有效命中，长签名 0 命中，tools/check_field_offset_arrays.py §79）；oracle 首静态偏移 vs TypeDefIndex 单调仅 50.2% ⇒ 每程序集 arena，image.typeStart/typeCount 已被剥离，无法定位类型→程序集分组 |
| 属性构造参数（22,146 条含参属性） | 静态无 token/参数 blob（§75），且 **R19 确证运行时设计上不需要**：4 个属性查询 API 只返回 attribute klass，无对象构造（详见 docs/re/71-usage-tables.md §4）；DummyDll 用 AttributeAttribute(Name=类名) 标记 |
| interface 的基接口 | 7.1 metadata 1,580 个 interface 的基接口行 = 0（全量；6.4 oracle 有 270 个）；实现类列表已扁平化、运行时判定不递归基接口 ⇒ 构建期裁掉（docs/re/71-generics-interface-origin.md） |
| 泛型参数名 → **已恢复（R23）**；约束仍未解 | 参数表 body 0xDF8708，14B×5,796，逐行 mask；真实名字 TKey/TValue/TRest… 已进 dump.cs（docs/re/71-generic-params.md）。约束：accessor 0x14050EDF0 只读 +0/+0xC 两列，标准约束表扫描 0 命中 |
| ~~metadataUsage / ScriptString~~ | **已恢复（R19/R20）**：usage 索引/pair 表在 body（slot 0x19C / 0x14C），311,730 usage / 788,057 pair；`ScriptString` 137,466 已进 script.json（R20），`Addresses` 483,496（R21）。仅 Il2CppDumper 的 `ScriptMetadata`（kind1/kind7 归类未定）未接线——见 docs/re/71-usage-tables.md |
| DummyDll 75 程序集划分 | image 表解列后无 typeStart/typeCount（反汇编 loader，§78） |
| il2cpp.h | 未产出：GI 运行时结构经 VMP 修改（klass+0x10=tdi、+0x38 events、+0x48 props、+0x58 methods、+0x60 typeDef 行…），与 Il2CppDumper 标准 V27/V29 模板不一致；产出标准模板会误导。GI 实测结构目前只覆盖 metadata-cache 部分，不足以生成完整头文件 |

## 4. 复现与验证

    tools/final_verify.sh                    # 重建全部工件并断言计数/大小
    WITH_LITERALS=1 tools/final_verify.sh    # 额外重跑字面量工具
    python3 tools/validate_slots.py          # Slot vs 6.4 oracle
    python3 tools/validate_properties.py     # propertyDefs vs 6.4 oracle
    python3 tools/final_verify.py            # 仅校验现有工件

## 5. 版本适配（未来版本）

- 主流水线 profile 驱动（derive → dump-gen --profile-in），算法不变时零代码改动；
- Slot 重算、propertyDefs/eventDefs/参数默认值/字段默认值解码、DummyDll 生成均为版本无关代码；
- 已知每版需重导出的数据：profile（derive 流程）；字面量（gi-stringliteral 对新混淆代次可能需适配）；
- 运行时快照仅用于 oracle 校验，发布路径不依赖它。
