# 与 Il2CppDumper 的数据差距清单（2026-10-15 复测）

> 基准：Il2CppDumper 输出格式（本地 oracle：/tmp/giref/6.5Dump.cs，655,240 Token 行）。
> 我们的 dump：mhydump dump-gen 于 7.1.0（**88,902 类型 / 440,172 字段 / 733,442 方法**，2026-10-17 修复后）。
> 参考比例按 6.4Dump.cs（77,260 类型）折算到 7.1 规模。

## 〇、2026-10-17 新闭合：方法/类型表截断（此前静默漏 37% 方法）

两个**行数来源错误**导致大表被截断（不是提取难度问题，是计数取错）：

| 项 | 修复前 | 修复后（实测） | 根因 |
|---|---|---|---|
| 方法行数 | 460,282 | **733,442** | `md_count()` 用了「方法指针数组长度」当上限；该数组只覆盖有直接代码指针的方法。真值 = hdr[0x134]+0x8EEFDB56=19,070,516 ÷0x1A = 733,481 行（实测最后有效行 733,480）|
| 类型行数 | 88,872 | **88,902** | 链式铺瓦 walk 在第一个不规则处提前停止；真值 = hdr[0x60]^0x15335474=6,223,280 ÷0x46 = 88,904 行，尾部 2 行全哨兵填充|
| 无名类型 | 静默跳过（-30）| 保留输出（空名，同 oracle `class  : Object`）| `if td.name.is_empty() { continue; }`；oracle 6.4 实测保留无名类型 |
| 字段数 | 440,061 | **440,172** | 随类型尾部 30 行补回（其 fieldStart 达 440,170）|

验证：类型标记 88,902 个、索引 0–88,901 无缺口；方法/Token 行 733,442；回归 17 passed。
profile 新增 `td_size`/`md_size`（大小槽，非偏移）。

> 旧的「460,282 方法」曾与 oracle 655,240 Token 行对面而未察觉——教训：**行数必须由表大小槽推出，
> 链式/数组长度只能作下界**（已写入 IMPLEMENTATION_LOG §33）。

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

> **2026-10-17 重大发现（§50/§51）**：Metadata 目录另有 **startup-metadata.dat（4.06MB）**，是 **附加表容器**。
> **§51 纠正**：同一个加载函数里混用两种基址——startup 指针 B=0x145AD62C8、global body 指针 A=0x145AD62C0。
> 例：槽 0x15C/0x78 用 B（0x380DFC / 0x0）、槽 0x1A4/0x10/0x1C 用 A（0xCD026C 12B 行 / 0x1F0F850 u16 / 0x1F5E9C4 10B 行）= **泛型实例数据链**。
> 泛型渲染下一步：解析 12B 行 `{u32, u32 packed, u32}` 语义（field1 形如 `0x8000000|低字节`），用已知 `List<GameObject>` 验证后接入。

| # | 数据 | 参考量 | 阻塞点 / 解锁路径 |
|---|---|---|---|
| 1 | 字段偏移注释 | 440,061 | **已接线（2026-10-17）**：磁盘无偏移表 ⇒ dump_gen 新增顺序布局复算（97.9% 核心规则验证），显式布局（flags&0x18==0x10）排除。7.1 实测：**321,796 字段已计算**（73%）/ 9,162 未解 / 109,214 静态字段（模块静态区不可推）。交叉验证 92.71%。待：精度提升（失配簇分析）+ 静态字段偏移来源 |
| 2 | 参数名/类型 | 361,974 | **已关闭（2026-10-17）**：参数定义表 = `hdr[0x68]^0x146BE503`，**8B 行**：`name=(raw@+4 ^ 0x6B95F108) − mask(i)`、`type=(raw@+0 ^ 0x76621606) − mask(i)`（−1=无类型），mask 为参数索引链 `((((i*0x4A23)^0x5F268FCF)*0x2B0352A0)>>9 ^0x1028EA75 +0x68B376F1) ^0x4F86A723`（反汇编 0x1405297EE）。全 548,400 参数可解；vs 6.4 oracle：**参数名 91.37%**（失配为混淆名跨版本改名）、类型 81.7%（余差=泛型 object 2,792 + 嵌套类型短名 1,490 + 混淆改名 + 比较器重载配对） |
| 3 | Properties/Events 行 | 77,260 段 | 属性表仍未定位（本轮验证候选行结构均不符）。**临时方案已实现**：从 `get_`/`set_` 访问器方法**合成** Properties（62,879 条/10,102 类型，warn 明示 SYNTHESIZED；类型签名真实，setter 可见性对齐 `{ get; private set; }` 形式）。局限：GI 属性名与访问器方法名独立混淆 ⇒ 覆盖主要是未混淆库；属性表本体需运行时路径。Events：6.4 参考 dump 无 Events 段（Il2CppDumper 该配置未开），暂不产出 |
| 3b | 嵌套类型全名 | **已关闭（2026-10-17）** | typeDef `nestedTypesStart`=u16@0x36^0xC87C、`nestedTypesCount`=u8@0x45^0xAB，表 base=hdr[0x1B8]^0x586ABAF1（u32 child tdi）；验证 Selectable→[Transition, SelectionState]。dump.cs 头部现为全限定名、基类短名、接口全限定、嵌套链（对齐 Il2CppDumper）|
| 4 | 接口列表精确化 | **已关闭（2026-10-17）** | **own-count 列解出**：`interfacesCount = (u8@0x42 + 0xA2) & 0xFF`（86,587/88,902 类型 count==run 长度，sum 108,758 ≈ 109,607；Selectable 8 个接口与 oracle 完全一致）。dump 不再用 run-length 近似。剩余：泛型接口（GENERICINST，24,529 条）因 gap #11 跳过并计数 |
| 5 | 方法 Slot 精确值 | REF 211,652 非零 | **已结论（2026-10-17）**：反汇编 0x1405155FC 构建器确认 slot=(i16)((u16@0x0C^0x1E2A)−mask2)，与引擎逐句一致；GI 7.1 元数据本身几乎全 -1。oracle 6.4 的非零 Slot 属 oracle 侧语义，不再视为缺陷 |
| 5b | 类型名格式 | — | **已对齐（2026-10-17）**：全部原始类型/类名改全限定（`System.Void`/`System.Int32`/`System.String`/`System.Object`），数组 `System.Int32[]`、byref `&`；与 oracle 逐字一致（参数类型精确率 88.54%，余差泛型/混淆改名/重载配对）|
| 5d | 方法 Token | 733,442 | **已修正（2026-10-17，§53）**：旧实现把 ctor Token 硬编码为 0（未验证假设，导致 82,004 个 Token 0）。修正为 `0x06000001 + 方法表行号`（构造器同样有 token）；vs 6.4 oracle 结构验证：同类型相邻方法 delta 100% 恒定（65,422/65,422），85.77% 共享类型 delta 全程恒定，差异来自版本插入。 |
| 5c | 方法修饰符 | — | **已对齐（2026-10-17）**按 oracle 120 种 (flags, mods) 配对反推规则——private virtual 只输出可见性；final→`sealed override`、newslot→`virtual`、reuse→`override`；实测 sampled 一致率 **96.75%**（旧规则 72.69%，根因是把 0x80 hidebysig 当 newslot 代理）|
| 6 | 属性 [Attribute] | 11,525 | **判读修正（2026-10-17）**：hdr[0x1D0] 的表是 **ParameterDefaultValue**（按类型解码默认值），不是特性表；参数默认值侧已定位（25,374 条）。字段默认值（枚举字面值）应有同构表待找 |
| 7 | 枚举字面值 | **已解（2026-10-17）** | **已关闭**：字段默认值表 base = `hdr[0x164]^0x03893506`，12B 行 `{valueOff, fieldIndex, typeIdx}`，行数 `(hdr[0x144]+0xD1F800F2)/12`（75,548 行）；值区 `body+(hdr[0x128]^0x371354A2)+valueOff`，按 kind 解码；字符串 = `{u32 len, UTF-8}`。dump 已渲染 74,614 个 const 值；vs 6.4 oracle 枚举值 99.83%、全 const 99.26% |
| 8 | stringLiterals.json | 689,799 串 | 字符串字面量表（独立于用户串堆）|
| 9 | script.json ScriptString/Addresses/Signature | 689,799 / 239,153 | 依赖 #8 + 方法特征定位 |
| 10 | il2cpp.h / DummyDll | 整套 | 依赖以上全部 |
| 11 | **泛型类型渲染**（新发现，2026-10-17）| 42,313 字段 | **已关闭（2026-10-17，§52）**：`GENERICINST.data`=g → startup-metadata 8B 行表（`hdr[0x120]^0x1C3F68EA`，行=`{defTdi, genericInstIdx}`）→ `Il2CppMetadataRegistration+0x28` 的 16B `Il2CppGenericInst{argc,pad,argv}` → argv 的 `Il2CppType*`。实测 `List`1<GameObject>`/`IComparer`1<Level2Map>`/`ReadOnlyCollection`1<MoleMole…>` 全对；字段类型 vs 6.4 oracle **98.33%**（泛型字段 95.23%）。遗留：kind 0x13/0x1E 泛型参数引用仍是占位（需 genericParameters 表） |

## 三、script.json 现状

ScriptMethod 733,442 已有（含全限定名，2026-10-17 方法数修复后）；ScriptString=0、Addresses=3、Signature 空 —— 待 #8/#9。

## 四、跨版本注意

flags/bitfield 常数是 7.1.0 专属（在 .upx0 变异函数逐版读取，0x159F63C4D 模式）；
其它版本接线前需先跑 version-triage + 该版 .upx0 常数读取（SOP 见 version-matrix.md §4）。
