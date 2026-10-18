# GI 7.1 静态解包完整性报告（il2cppdumper 等效数据）

日期：2026-10-17。目标：静态补齐 7.1 版 Il2CppDumper 可解包数据，运行时快照仅作 oracle/验证。

## 1. 结论

7.1 版静态可解数据已全部恢复；所有"未恢复"项都已定位为「GI 元数据/二进制未保留」或「需运行时数据」，
并有可复现实验证据，不是"还没找到"。7.1 产物与 6.4 参考 dump 在可对照维度上逐项校验。

## 2. 产物清单（~/gire/out/71/）

| 文件 | 大小 | 内容 |
|---|---|---|
| dump.cs | 127,953,647 B | 88,902 类型 / 440,172 字段 / 733,442 方法（Slot 列已静态重算）+ **115,596 条真实属性**（propertyDefs 表，2026-10-18） |
| script.json | 160,118,677 B | ScriptMethod 679,867 + Addresses 460,313（Il2CppDumper 兼容格式） |
| attributes.json | 10,025,050 B | 74,864 条属性实例，Recovered 70,693 |
| literals.json | 6,287,449 B | 86,108 条字符串字面量（静态解密） |
| images.json | 14,326 B | 75 images / 75 assemblies |
| DummyDll.dll | 96,388,096 B | 88,904 TypeDef / 733,444 Method / 440,177 Field / **115,596 Property / 30,226 PropertyMap / 628 Event / 225 EventMap / 133,270 MethodSemantics** / 1,041,595 CustomAttribute / 1,195 GenericParam |
| dummy.jsonl | 186,550,006 B | DummyDll 生成器输入（结构化导出，含 115,596 条 P + 628 条 E 记录） |

## 3. 逐项状态

| 项 | 状态 | 证据/说明 |
|---|---|---|
| 类型/命名空间/字段/方法/参数 | 已恢复 | dump.cs 88,902 / 440,172 / 733,442；与 6.4 oracle 对齐全限定名、参数 88.54%、字段类型 98.33%、基类 98.96% |
| 方法 Slot | 已恢复（纯静态） | src/vtable.rs 重算 245,235 个 virtual 方法；与 oracle 严格同构类型 8,548/8,901 = 96.03%（tools/validate_slots.py） |
| instance 字段偏移 | 布局重建 | dump_gen::instance_offsets（布局规则）；类型级与 6.4 oracle 一致率 79.55%（跨版本差异+显式布局限制） |
| 静态字段偏移 | 不可得（有证据） | metadata/exe 均无 fieldOffsets 数组：400 类型签名抽样 28 命中全为同一通用误报，长签名 0 命中（tools/check_field_offset_arrays.py，日志 §79） |
| 字符串字面量 | 已恢复 | gi-stringliteral（外部工具，版本无关）：86,108 条；旧 meta_string_literals.txt 覆盖 99.54%（tools/recover-literals.sh） |
| 自定义属性实例 | 已恢复（实例/成员身份） | attributes.json 74,864 实例；dump.cs 中 47,976 条可渲染为 [Class] |
| 属性构造参数 | 未保留 | body 无属性构造 token 表/参数 blob（全 body 扫描最长 token 连续段 11，日志 §75） |
| 接口继承（interface 的基接口） | 未保留 | 7.1 metadata 1,580 个 interface 的基接口行 = 0（全量），6.4 oracle 有 270 个（日志 §75） |
| property 表 | **已恢复（真实表，2026-10-18）** | metadata body 的 10B 行表（hdr[0x158]−0x1D545CCC）即 propertyDefs：115,596 条 / 30,226 类型，getter 112,107 / setter 19,907 全部索引合法；属性名经字符串 cipher 解码；与 6.4 oracle corelib shared 类型属性序列全等 1,272/1,318=96.5%、名称 Jaccard 0.9899（tools/validate_properties.py；日志 §83）。dump.cs 由合成 63,117 换成真实 115,596 |
| metadataUsage / ScriptString / ScriptMetadata | 未解（需运行时/加密） | script.json 对应字段为空；metadataUsage 槽在运行时 BSS（历史轮次已证） |
| DummyDll | 已生成 | 单程序集自包含（96MB）；Address(RVA/Offset/VA)/FieldOffset 特性 1,041,595 条；GenericParam 1,195；**Property 115,596 + PropertyMap 30,226 + Event 628 + EventMap 225 + MethodSemantics 133,270（真实属性表/事件表，2026-10-18）** |
| DummyDll 75 程序集划分 | 不可得 | startup image 表解列后无 typeStart/typeCount（反汇编 loader，日志 §78） |
| 方法泛型参数 / 泛型约束 | 不可得 | method 泛型容器信息未从 metadata 解出；约束未保留 |

## 4. 复现

    cd ~/Documents/git-repo/GI-StaticParser && cargo build --release
    ./target/release/mhydump dump-gen --exe YuanShen.exe --metadata global-metadata.dat \
      --out ~/gire/out/71/dump.cs --attributes-out ~/gire/out/71/attributes.json \
      --images-out ~/gire/out/71/images.json --dummy-out ~/gire/out/71/dummy.jsonl
    tools/recover-literals.sh global-metadata.dat YuanShen.exe ~/gire/out/71/literals.json
    cd tools/dummygen && dotnet bin/Release/net10.0/dummygen.dll ~/gire/out/71/dummy.jsonl ~/gire/out/71/DummyDll.dll
    python3 tools/validate_slots.py            # Slot 与 oracle 校验
    python3 tools/check_field_offset_arrays.py # 静态偏移不可得证据

## 5. 版本适配（未来版本）

- 主流水线 profile 驱动（derive → dump-gen --profile-in），算法不变时零代码改动；
- Slot 重算、字面量表定位（外部工具）、DummyDll 生成均为版本无关代码；
- 已知每版需重导出的数据：profile（derive 流程）、字面量（若工具对新混淆代次失败需适配 extract_constants）；
- 运行时快照仅用于本次 oracle 校验，发布路径不依赖它。
