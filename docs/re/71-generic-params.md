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

- 泛型**约束**：该 accessor 不读取约束字段；标准布局 genericParameterConstraints 表在 body/startup 扫描 0 命中，
  约束仍是未解项（且运行时可能同样不使用）。
- owner 的容器语义：u16 owner 值 = 4,425 个分组，尚未映射回 typeDef/method 的 genericContainer 表。
- DummyDll 的 GenericParam 行仍由类型名 arity 合成（未接真实名字）。

## 4. 复现

```
# Rust 侧：Meta::load 计算 gp_base/gp_count；Meta::generic_param_name(i)
MHY_SAMPLE_EXE=… MHY_SAMPLE_DAT=… cargo test --release generic_param_names_sample -- --ignored
# Python 侧（本文件数据）：见 IMPLEMENTATION_LOG §94 的公式
```
