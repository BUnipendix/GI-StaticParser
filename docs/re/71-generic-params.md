# 7.1 泛型参数表（R23 新发现，已接线）

> 2026-10-18。证据记录。此前 R18/R22 的"泛型参数名已剥离"结论**作废**：表存在，只是逐行加密。

## 0. 结论

- 泛型参数表：`body + (hdr[0x174] + 0xCED1EDB1)` = body **0xDF8708**，14B 行，**5,796 行**。
- 每行用与行号相关的 32 位 mask 加密；解出 `nameIndex` 与 `ownerContainerIndex`，nameIndex 经共享字符串密码解出
  **真实源码名**：TKey/TValue/TResult/TSource/TRest/TInput/TOutput/TEventArgs/TStateMachine…（distinct 47；
  5708 个可打印标识符 + 81 个单控制字符混淆名 + 7 个混合）。
- 计数不是 header 字段：typearr 中 VAR/MVAR 的最大 `data` 索引 = 5,795 ⇒ 表长 5,796，与连续可解区间完全一致。
- 已接线：dump.cs 中 `object/*k0x13*/` 占位改为真实泛型参数名（157 处无法打印的混淆名保留占位）。

## 1. 定位过程（指令级）

`0x14050E7A0` = `Class::FromIl2CppType`，30 项 type-kind 跳表（`[type+0xA]`，1..0x1E）：

```
case VAR(0x13)/MVAR(0x1E) @0x14050E897/0x14050E986:
  base = body + (i32(hdr[0x174]) + 0xCED1EDB1)        ; 0xDF8708
  mask = ((gpi*0x6F1C0337A0897415 + 0x31061C4212D60D89) >> 22) & 0xFFFFFFFF
  row  = base + 14*gpi
  nameIndex = (u32[row+0] + 0x9E5299B1) ^ mask        -> GetStringFromIndex
  ownerTI   = ((u16[row+0xC] + 0xA8E2) ^ (mask & 0xFFFF))  ; 指向 Il2CppType（owner 的 typearr 索引）
  call 0x14050EDF0  ; Class::FromGenericParameter：建 klass、设 kind 0x13/0x1E、gpi=klass+0x68
```

`0x14050EDF0`（kuna 反编译确认）只读取行内 **+0 与 +0xC** 两个字段；其余 9 字节是填充/噪声。

## 2. 全量验证

| 项 | 实测 |
|---|---|
| 行数 | **5,796**（连续可解区间；第 5,796 行 nameIndex 越界）|
| owner 分组 | 4,425 个 owner 值（u16），每组 arity 递增 |
| 名称可打印 | 5,708 |
| 混淆名（单控制字符） | 81（dump.cs 保留 `*k0x13*` 占位，避免控制字符污染文本）|
| 关键名 | TKey 289 / TValue 305 / TResult 97 / T 2,835 / TRest 1 |
| dump.cs 变化 | 127,953,647 → **127,769,231 B**；`Dictionary`2` 字段/接口现为 `TKey,TValue`；`ValueTuple`8` 为 `TRest` |

## 3. 剩余（不在本轮范围）

- 泛型**约束**：**未发现任何读取路径（强负结果，R26 复核）**：
  - 读取泛型参数表锚点（hdr[0x174]）的全部 8 个不同函数都已反编译：`Class::FromIl2CppType`(0x14050E7A0)、
    `Class::FromGenericParameter`(0x14050EDF0)、类型名构建(0x1404B8990/0x1404C7E90)、类型对象解析(0x1404E4A90)、
    接口变体判定(0x140512880/0x14051A330)、泛型定义解析(0x1405472D0/0x140547410)；
  - `FromGenericParameter` 只读行内 `+0`（name）与 `+0xC`（owner container）；变体判定只读 `+6` 的低 2 位（variance）；
    类型对象解析只读 `+0xA`（参数位置索引）；无任何函数读 `+4/+8` 作为约束 start/count；
  - 标准布局 genericParameterConstraints 表在 body/startup 结构扫描 0 命中。
  ⇒ 判断：7.1 构建期丢弃了约束（与接口基接口同类），运行时不做泛型约束校验。仍保留很小不确定性：
    若存在尚未发现的独立校验路径，结论可能被推翻（需运行时 oracle）。
- **容器行字段（R26 补全，供方法级参数校验用）**：容器表行 16B = `{+0 ownerKind/data, +4 paramStart, +8 argc, +0xC ownerAttrs}`，
  mask 用 `container_mask2(V)`：`start = u32[+4] ^ m2 ^ 0x2BAD4D8C`、`argc = u32[+8] ^ m2 ^ 0x07F8A45C`
  （反编译 0x1404B8990/0x1404E4A90 确认）；与参数行 +0xC 的分组结果一致（5,796 参数 = 类型级 2,697 + 方法级 3,099）。
- ~~owner 容器语义未映射~~ **已解（R24）**：参数行 +0xC 即 genericContainerIndex；容器表 = body+(hdr[0xC8]^0x8D701A3)
  的 16B 加密行（4,425 行）。`data == mask2(V)+0xE276AF5D` ⇒ VAR（owner=typeDefIndex），否则 MVAR（owner=methodIndex）；
  `owner = attrs ^ (mask2(V)+0x71555646) ^ 0x5C56350B`。已验证 `ValueTuple`1..`8`→T1..T7/TRest、
  `Dictionary`2`→TKey/TValue、`List`1`→T。
- DummyDll 的 GenericParam **全部接线（R24/R25）**：T 与 M 记录都新增 `"gp"`（按参数槽对齐，控制字符名→空串），
  dummygen 用真实名字 `AddGenericParameter`；需要按 ECMA 排序（TypeOrMethodDef 编码索引 = `(row<<1)|tag`，
  TypeDef/MethodDef 按 row 交错），且泛型类型**嵌套类型**（名字无 `` `N `` 后缀）以 `gp` 长度为准。
  Verify 断言：ValueTuple`8 第 8 个参数=TRest、Dictionary`2=TKey/TValue、存在 2 个泛型参数名为 T1/T2 的方法。
  **GenericParam 总行数 = 5,796**（类型级 2,697 + 方法级 3,099，含嵌套泛型类型），与 metadata 参数表完全一致。
- 工件变化（相对 R23）：dummy.jsonl 217,786,835 → **224,397,559 B**；DummyDll.dll 146,666,496 → **146,724,352 B**；
  dump.cs/script.json 不变；final_verify 全 PASS。

## 4. 复现

```
# Rust 侧：Meta::load 计算 gp_base/gp_count；Meta::generic_param_name(i)
MHY_SAMPLE_EXE=… MHY_SAMPLE_DAT=… cargo test --release generic_param_names_sample -- --ignored
# Python 侧（本文件数据）：见 IMPLEMENTATION_LOG §94 的公式
```
