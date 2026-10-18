# 7.1 泛型参数名 / 接口基接口：运行时来源追查（R22）

> 2026-10-18。证据记录。目标第二轮：沿用「反汇编解析器→表锚点」方法追查这两项的运行时来源。

## 0. 结论

- **泛型参数名**：不是"藏在某张加密表里"。identifier 字符串堆（解密后）与 86,108 条 literal 表都 0 命中
  `TKey/TValue/TResult`；标准布局的 genericContainers（16B）与 genericParameters（14B）表在
  body(82,725,540B) 与 startup-metadata(4,060,728B) 的结构扫描均为 **0 个非退化候选**（§1b）。
- **接口基接口**：7.1 的 interface 类型 `iface_start/count` 全哨兵；但实现类的接口列表是**预先扁平化**的
  （7.1 自身 `System.Resources.ResourceReader : IResourceReader, IEnumerable, IDisposable`；6.4 oracle 同），
  运行时类型/接口判定函数 `0x140513260` 直接遍历 `klass+0x20` 的接口指针数组，不做基接口递归（§1d）
  ⇒ 基接口边对运行时无必要，构建期被裁掉，不是解析未遂。
- 结论与 R18/R19 的负结果一致；若要补，只能跨版本推断（6.4 oracle：泛型名 ~85% 可回填、接口基接口 131 条 ≈ 8%，见 R19 前测量）。

## 1. 证据

### 1a. 字符串侧（复述 R18/R19，补充 literal 检查）

- identifier 字符串堆：全池无 `TKey/TValue/TResult`（R18）；
- literal 表（86,108 条，R19 解密）：`TKey/TValue/TResult/T1/TSource/TElement/TItem` 各 0 条，
  仅 151 条 `T` 开头的普通单词（Type/Text/Toggle/True…）。

### 1b. 标准布局结构扫描（新工具 `tools/scan_generic_tables.c`）

扫描条件：

```
genericContainers : 16B 行 {owner i32, type_argc i32, is_method i32, param_start i32}
                    连续 64 行；is_method∈{0,1}、1<=argc<=16、param_start 逐行累加、owner 递增
genericParameters : 14B 行 {nameIndex u32, constraintsStart u16, constraintsCount u16, owner u32, flags u16}
                    连续 48 行；nameIndex 为 packed 串索引（高字节=长度<=31、低24位<0x1300000）、
                    constraintsStart 非降、owner<733,481、flags<=0x100
```

结果（body / startup）：containers **0 / 0**；genericParameters **11 个候选全部是 0xB9C98C 附近的全零退化行 / 0**。
⇒ 标准形式的这两张表不存在（若 GI 有自己的编码，只能是逐行加密/自定义布局，且没有任何 header 槽锚点命中）。

### 1c. 接口列表扁平化（直接证据）

| 来源 | ResourceReader 的接口列表 |
|---|---|
| 7.1 我们自己的 dump.cs | `IResourceReader, IEnumerable, IDisposable` |
| 6.4 oracle | `IResourceReader, IEnumerable, IDisposable` |
| 7.1 接口类型 `IResourceReader` 本身 | 无基接口（哨兵）|

标准 il2cpp 在构建期为实现类展开接口继承；7.1 只保留展开后的类侧列表，省掉接口→基接口的边。

### 1d. 运行时判定函数 `0x140513260`

反汇编显示它是 klass/接口可赋值判定：

```
14051330d  movsx ecx, byte ptr [rsi + 0x72]     ; klass 的类型种类
140513311  cmp   ecx, 0x1e / 0x13              ; 泛型参数/泛型实例特判
140513380  cmp   qword ptr [rax + rdx*8], rsi   ; 遍历 [klass+0x20] 的接口指针数组
1405133ab  movzx eax, byte ptr [rsi + 0xc5]     ; 接口数量
1405133ba  mov   rcx, qword ptr [rdi + 0x40]    ; 父类/接口父链
```

它只做"在已展开的接口数组里找指针"，没有"对接口再取基接口"的递归（也没有任何 14B/16B 表访问）。

## 2. 唯一尚未证明的点

GI 运行时的 genericParameter 结构（owner/constraints/nameIndex）是否存在：类型系统处理 VAR/MVAR 时
必须知道参数归属，但这可以完全由 genericContainers/typeDef 列表达，无需名字。下一步：定位
`Class::FromGenericParameter` / Il2CppType kind 0x13/0x1E 的分派入口（从 0x14050E7A0 与 type-kind
跳表继续），若其读取某张表则顺藤解码；若无表则该结构也是构建期合成。

## 3. 复现

```
gcc -O2 -o /tmp/scan_generic_tables tools/scan_generic_tables.c
python3 -c "import sys;open('/tmp/body.bin','wb').write(open('$HOME/gire/global-metadata.dat','rb').read()[0x210:])"
/tmp/scan_generic_tables /tmp/body.bin                 # containers=0, genericparams=11 个退化行
/tmp/scan_generic_tables $HOME/gire/sample/gi/7.1.0/YuanShen_Data/Managed/Metadata/startup-metadata.dat
python3 - <<'PY'   # literal 表负结果
import json; lits=[e['value'] for e in json.load(open('$HOME/gire/out/71/literals.json'))]
print(sum(1 for v in lits if v in ('TKey','TValue','TResult')))
PY
```
