# 7.1 custom-attribute 数据层（已解开，待实现渲染）

> 2026-10-17 第 25 轮发现并验证。不是需求，是证据记录。

## 1. 结构

GI 7.1 的自定义属性数据由两部分（都是**明文**）组成：

### (a) 属性实例类型数组

- 位置：**global-metadata body 0x9BACA4**，连续 **74,864** 个 u32。
- 每一项 = **typearr 索引**（Il2CppType 索引，范围实测 873..574,958，全部 < 683,568 ✓）。
- 该 Il2CppType 的 `kind=0x12 (CLASS)`、`data=typeDefIndex` ⇒ 属性类（全部继承 `System.Attribute`）。

### (b) 属性实例 → 成员映射表

- 形态：8B 行 `{成员 token (u32), 0x01000000 + 实例号 (u32)}`，实例号 0..74,863（与 (a) 的长度一致 ✓）。
- 分布在 body 约 **0x1C00000–0x1C70000** 的多个连续块（按 token 排序后分块，共约 216 块；块内实例号连续）。
- 稳健读法：扫全 body 的 8B 行，取 `val - 0x01000000 ∈ [0, 74864)` 的行 ⇒ 得 `实例号 → 成员 token`。
  7.1 实测：匹配 **76,288** 行（含 4,066 行重复/假阳性），覆盖 **72,222** 个实例号（96.5%）；2,642 个实例号未出现（缺行，可能被逐行掩码/哨兵）。

## 2. 验证（对 6.4 oracle 语义交叉核对）

属性类频次（按实例号映射后统计）：

| 属性类 | 次数 | 成员 token 种类分布 |
|---|---|---|
| `UnityEngine.SerializeField` | 44,971 | 0x04 字段 44,209（其余 token=0 哨兵 746）|
| `IFix.Core.IDTagAttribute` | 16,286 | 0x06 方法 16,217 |
| `XLua.MonoPInvokeCallbackAttribute` | 4,283 | 0x06 方法 4,282 |
| `IFix.PreserveAttribute` | 1,465 | 0x06 方法 1,451 |
| `System.Runtime.InteropServices.ComVisibleAttribute` | 607 | 0x02 类型 338 / 0x06 方法 137 / 0x17 属性 60 |
| `MiHoYo.SDK.PreserveAttribute` | 508 | 0x06 方法 484 |
| **`System.ParamArrayAttribute`** | 469 | **0x08 参数 447**（该属性只能用于参数 ✓）|
| `FullInspector.ShowInInspectorAttribute` | 367 | 0x04 字段 326 / 0x17 属性 29 |

成员种类总分布：field 45,213 / method 23,271 / type 1,699 / 参数 448 / 属性 123 / 其它极少。
**有属性的不同成员数 = 72,151**。

成员 token 编码与 dump 里的 token 一致：`0x02`=TypeDef、`0x04`=Field、`0x06`=Method、`0x08`=Param、`0x17`=Property。

## 3. 重要结论：5 种「系统属性」不在这张表里

6.4 oracle 渲染的 5 种属性（CompilerGenerated 8,538 / DllImport 1,296 / FixedAddressValueType 893 / NonSerialized 750 / MarshalAs 48）**在 7.1 的属性表里出现 0 次**：
`CompilerGeneratedAttribute(tdi 1106)`、`NonSerializedAttribute(tdi 266)`、`DllImportAttribute(tdi 1129)`、`MarshalAsAttribute(tdi 1141)` 的 typearr 索引在 74,864 项中都不存在 ⇒ GI 把这几类编码进**标志位**
（FieldAttributes.NotSerialized / PInvokeImpl、k__BackingField 命名、`<PrivateImplementationDetails>` 类型），我们现有的启发式渲染与之一致。

## 4. 待办（下轮实现）

1. profile：`attribute_types` 表锚点（body 0x9BACA4）+ `attribute_count`（74,864）+ 实例标签 `0x01000000`；
2. engine：全 body 扫描建 `实例号 → token`（Rust 下 10M 行毫秒级）；解析 `实例号 → 属性类 tdi → 全限定名`；
3. dump_gen：成员行前输出 `[AttrClass]`（参数未恢复 ⇒ 先只输出类名；无参构造的属性可安全渲染，含参属性需注明或跳过——实现时按构造参数数决定）；
4. 已知缺口：2,642 个实例号缺行；属性**参数值**（attribute data blob）仍未定位。
