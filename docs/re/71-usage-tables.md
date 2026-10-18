# 7.1 metadataUsage / stringLiterals 表解码（R19 新发现）

> 2026-10-18。证据记录，不是需求。触发：用户要求顺着"未解密内容"找可疑函数与关键解密点。

## 0. 结论（先看这里）

- **metadataUsage 不在运行时 BSS**：usage 索引表与 pair 表都在 global-metadata body，
  由运行时解析器 `0x140524250` 读取；全量解出 **311,730 条 usage / 788,057 个 pair**。
- **stringLiterals 表 + 数据 + cipher 全部解开**：86,108 条，与旧工件 `literals.json` 逐条一致（0 mismatch）。
- 这推翻了 `docs/re/remaining-static-limits.md` A 类里"metadataUsage / stringLiterals 运行时 BSS"的旧判定。
- **属性构造参数** 由"未定位"升级为"运行时设计上不存在"（§4）：运行时只查"成员是否有某属性类"，从不构造实例。

## 1. 定位过程（指令级证据）

`0x140524250` 是 Il2CppType/metadata-usage 的惰性解析器（8 分支 jump table，按 handle 高 3 位分派）：

```
usage 索引表 base = body + (i32(hdr[0x19C]) ^ 0x159FBC84)
maskA(i) = (((i*0x6536) ^ 0x138D67F3) * 0x44B1AAD4 + 0x1F9EA55AD057D0) >> 0x15
           * 0xD0DC29D5                       ; 32-bit
range(i) = { maskA(i)   + (raw[i]   ^ 0x15A6F604) + 0xE6495E3D,
             maskA(i+1) + (raw[i+1] ^ 0x15A6F604) + 0xE6495E3D }   ; raw = u32 @ table+4*i
pair 表 base = body + (i32(hdr[0x14C]) ^ 0x2F249C2F)
maskB(j) = (((j*0x3C5F6DC3F5D0) >> 0x14) ^ 0x615EB706) + 0x63D46A21
handle(j) = u32[pair+8*j+4] ^ maskB(j) ^ 0x5CD30101
kind = handle >> 29 ; index = handle & 0x1FFFFFFF
```

字符串字面量分支（`0x140524547`，kind 5）：

```
offset 表 base = body + (hdr[0x88] + 0xF3C0B2FE)     ; u32 前缀和
数据 blob base = body + (hdr[0x13C] ^ 0x28B1D785)
maskL(i) 同 0x9825/0x76C8023D/0x5E626528/0x3483F478/0xA0D4507F 链
start = maskL(i)+raw[i]+0x81555D04 ; end = maskL(i+1)+raw[i+1]+0x81555D04
解密器 0x140526BD0（全程序唯一 caller 就在该分支）：
  key = ((((seed*0x34044C3B94B40C) ^ 0x2C165A1E0D09C29E)
          * 0x4D613E5575A12594) ^ 0x1B34FA773FEE107E) * 0x29140A6156B9041E
  per 8-byte qword: out = data ^ key ; key += 0x70BA8080760AC800
```

## 2. 全量结果与验证（`tools/inspect_usage_tables.py`，2.8s，输出 OK）

| 项 | 实测 | 校验 |
|---|---|---|
| stringLiterals | **86,108** | 与 `~/gire/out/71/literals.json` 逐条相同（参考工件保留内嵌 NUL，本工具同样保留）|
| metadata usage | **311,730** | 范围连续：start(i+1)==end(i)，0 gap；pair 总数 788,057 |
| kind 分布 | 1:376,243 / 3:84,875 / 6:185,864 / 5:137,466 / 7:2,564 / 4:1,035 / 0:10 | kind 5 index 上界 = 0x1505B = 86,107 = literals-1；kind 1 上界 0xA6E2F ≈ typearr 683k；kind 3 上界 0xB30EF ≈ 方法数 733k |

kind 语义（与 il2cpp 一致的 3 位分类）：1=Il2CppType，3=MethodInfo，5=stringLiteral，
6=TypeInfo/方法引用类，4/7 少量；0 的 10 条为解码边界噪声（index 越界）。

## 3. 流水线接线（R20 已完成）

- Rust 模块 `src/usage_tables.rs`；样本测试：`MHY_SAMPLE_EXE=… MHY_SAMPLE_DAT=… cargo test --release usage_tables -- --ignored`
  断言 311,730 groups / 788,057 pairs / kind5=137,466，且 literal(0..) = i,m,s,u,x,evt,"",navMeshData。
- `script.json` 新增（全 PASS，final_verify.py 断言）：
  - `ScriptString` **137,466** 条（kind5；Value=解密字面量，逐条 ∈ literals.json 值集，max len 837）；
  - `ScriptMetadataMethod` **84,875** 条（kind3；Name=`Method$<类型>.<方法>()`，MethodAddress=方法 RVA；977 条无代码指针故为 0）；
  - `Addresses` = **483,496**（参考语义的合并：460,313 方法指针 + 12,827 genericMethodPointers + 25,651 invokerPointers，
    排序去重；数组锚点 = codeRegistration `0x1422DF450` 的 +0x08 / +0x78，计数分别由 hdr[0x110]/hdr[0x74] 行数
    与 hdr[0x200] 表最大值+1 推导，见 `src/code_addresses.rs`；reversePInvokeWrappers / unresolvedVirtualCallPointers
    两张数组尚未定位，已在运行时日志中显式报告）。
- **`Address` 字段写 0**：Il2CppDumper 的 "usage slot 地址" 在 GI 7.1 不存在——生成代码以立即数 usage 索引调用
  `0x140524250`，解析结果缓存在运行时解码的 registration 数组；exe 内搜不到编码 token（已实测）。
  这是与参考实现的语义偏差，`script_json.rs` 与本节均已标注；payload 字段是精确的。
- 未接线：kind6 185,864（MethodRef，需 methodSpecs）、kind1 376,243（Il2CppType → `ScriptMetadata "_var"`）、
  kind7 2,564、kind4 1,035。下一步继续。
- 对比：script.json 160,118,677 → **176,764,249 B**；dump.cs / DummyDll / dummy.jsonl 均未变。

## 4. 属性参数：确证为"运行时不需要"

- 成员→属性实例表：slot `0x118`（xor 0x4009A6BF），8B 行 `{member token, count<<24 | instance}`，26 个读点。
- 实例→属性类：slot `0x1A8` add `0xA8B3BA59` = body **0x9BACA4**（74,864 个 typearr 索引）。
- 取属性 API：`0x1404B2400`（type）/`0x1404B2710`（field）/`0x1404B2C90`（method）/`0x1405353DC`（property）
  都是 lower_bound 成员 token 后调 `0x140526AF0`，**返回值只有 attribute klass**；全程序无属性对象构造/ctor 调用。
- ⇒ GI 7.1 运行时只做 `IsDefined` 类判定，metadata 无需 ctor token/参数 blob；属性参数属于构建期即丢弃，
  不是"还没解开"。

## 5. 一处旧记录修正

body `0xA03E64` 起（attributeTypes 数组之后）不是属性数据，而是**每方法 invoker 索引表**：
slot `0x200` add `0xB43E0EB1`，733,481×u32，方法表构建器 `0x1405153F0` 用 `hdr[0x200]` 索引它（-1=无）。

## 6. 复现

```
python3 tools/inspect_usage_tables.py                     # 校验（OK / 2.8s）
python3 tools/inspect_usage_tables.py --literals-out /tmp/l.json
python3 tools/inspect_usage_tables.py --usages-out /tmp/u.jsonl
```
