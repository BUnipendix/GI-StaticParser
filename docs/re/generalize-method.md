# 跨版本通用解法：算法/常数分离 + 形态迁移 + 数据验收（2026-10-18）

> 目标（用户 2026-10-18 明确）：**不是逐版本堆常数，而是找出一个通用方法解出常数和关键算法，
> 用于未来版本自动 dump**。本文是方法设计与本轮实测；结论都附证据，未验证处显式标注。

## 0. 结论

1. **算法与常数可以分离，且已经分离成功**：metadata 访问器/builder 是同一批源码函数，逐版本编译后
   **去常数后的代码形态稳定**；所有版本相关的内容（表槽位、槽内偏移、列变换常数、逐行掩码链、
   stride）都是代码里的**立即数/位移**，或可由数据判据反解。
2. 因此通用解法 = **形态匹配定位算法 → 从匹配位置读常数 → 用版本无关的数据判据验收 → 失败显式报错**。
3. 本轮覆盖面：26 个样本中 **25 版可自动推导**（20 版头在 `YuanShen.exe`，5 版在
   `YuanShen_Data/Native/UserAssembly.dll`）；**typeDef 表 25/25 自动解出**；语义迁移在
   7.0/6.7/6.4/6.0/5.4 上对 typeDef **5/5 逐位正确**，4.8 失败（形态差异，见 §4）。
4. **尚未闭环的是行内列常数/掩码的自动提取**：本轮把「怎么通用地拿到它们」的路径打通到可实施，
   但还没有把 7.1 的 builder 常数映射做成通用提取器。这是下一步的主要工作量（§4.2）。

## 1. 为什么必须算法/常数分离（证据）

### 1.1 头结构逐版随机化：槽位语义不能硬编码

typeDef 表在每版的头槽位、运算、常数都不同（`derive` 实测，26 版）：

| 版本 | 槽 | op | imm | stride | base |
|---|---|---|---|---|---|
| 6.0.0 | 0xB8 | Xor | 0x5F815D53 | 70 | 0x1D6BD4 |
| 6.4.0 | 0xE0 | Xor | 0x584D480A | 70 | 0xE7579C |
| 6.7.0 | 0x1E0 | Xor | 0x4E66A4F6 | 70 | 0x21F77B0 |
| 7.0.0 | 0xC4 | Add | 0xC42E5C8F | 70 | 0x10B5E18 |
| 7.1.0 | 0xDC | Xor | 0x5278CA3B | 70 | 0x48F3FD8 |
| 5.4.0 | 0x1E8 | Add | 0xCF853FAA | 70 | 0x213921C |
| 4.8.0 | 0x60 | Add | 0xAA4E3A42 | 74 | 0xDF01C |

槽位在 0x18–0x200 之间漂移，op 在 Add/Xor 间翻转 ⇒ **不能把「槽 0xDC = typeDef」写进代码**。

### 1.2 body 内表布局逐版打乱：偏移不能平移

7.1 的 typeDef 基址是 body+0x48F3FD8，7.0 是 body+0x10B5E18，6.7 是 body+0x21F77B0。
⇒ 相邻版本表的相对顺序也不保持，**不能用「上一版偏移 ± 差值」外推**。

### 1.3 但访问器代码形态稳定（实测）

7.1 typeDef 访问器函数（0x1404B2405 起）与 7.0/6.7/6.4 的同一函数只差槽位与立即数：

```text
7.1: 48 8b 15 .. ; 48 63 b2 dc 00 00 00 ; 48 81 f6 3b ca 78 52 ; 48 01 c6
7.0: 48 8b 15 .. ; be 8f 5c 2e c4       ; 03 b2 c4 00 00 00    ; 48 63 f6 ; 48 01 c6
6.7: 48 8b 15 .. ; 48 63 b2 e0 01 00 00 ; 48 81 f6 f6 a4 66 4e ; 48 01 c6
6.4: 48 8b 15 .. ; 48 63 b2 e0 00 00 00 ; 48 81 f6 0a 48 4d 58 ; 48 01 c6
```

去常数指令骨架（助记符 + 操作数形态，数字全替换为 #）的 Jaccard 相似度：

| 目标版本 | 7.1 typeDef 函数匹配分 | 第二名 | 迁移出的 (槽,op,imm) | 与 derive 对照 |
|---|---|---|---|---|
| 7.0.0 | 0.49 | 0.26 | (0xC4, add, 0xC42E5C8F) | 逐位一致 |
| 6.7.0 | 0.69 | — | (0x1E0, xor, 0x4E66A4F6) | 逐位一致 |
| 6.4.0 | 0.57 | — | (0xE0, xor, 0x584D480A) | 逐位一致 |
| 6.0.0 | 0.62 | — | (0xB8, xor, 0x5F815D53) | 逐位一致 |
| 5.4.0 | 0.44 | — | (0x1E8, add, 0xCF853FAA) | 逐位一致 |
| 4.8.0 | **0.25** | — | (0x188, xor, 0x73611CF5) | **不一致** |

（匹配算法：每个 `mov reg,[rip+hdr_global]` 加载点取 0x180 字节前向窗口，capstone 反汇编，
数字替换为 # 后做 3-gram 倒排 + Jaccard；见 `tools/version-triage/shape_transfer.py`。）

### 1.4 常数确实在代码里：7.1 builder 反汇编直接可读

- 方法表 builder 0x1405155AD：
  `movsxd rbp,[r13+0x1E0]; xor rbp,0x2EE480FB; add rbp,r10`（method_defs 槽/常数）
  随后 `imul rcx,rax,0x4E94; xor rcx,0x62D8B7B8; imul r12,rcx,0x7572748A; add r12,0x1F4D9EEA;
  xor r12,0x6E8931D6` —— **正是 7.1 profile 的 md_pmask 链常数**；stride 26 以
  `lea rcx,[rax+rax*4]; lea r11,[rcx+rcx*4]; add r11,rax`（5×5+1）编码。
- 事件表 builder 0x140515E42：事件基址槽 0x64/0xE6130C67、mask 链 0x9C54/0x1F0DA79F/
  0x1BF89D8B64959BB7/0x295EE0EBA6CAFAEA/shr 0xF、name xor 0x05C273ED、type add 0x979C7DA9。
- 字段/属性 builder 0x1405162A9：字段基址槽 0x158/0xE2ABA334、property name_add 0xEE8895EA、
  get_sub 0x238F、set_xor 0xDB1、共享 mask 链 0xA593/0x3CA3FFA0/0x5CD0B62E/0x63A341E6/0x2411ED71。
- 7.1 typeDef builder 0x1405162A9 附近还能直接读到 td_name AddC 0xE811F779、td_ns XorC 0x666769B5。

⇒ **「关键算法 = 函数形态，常数 = 形态里的立即数/位移」在 7.1 上被逐条证实**；跨版本只要形态匹配成立，
这些常数都能从对应位置读出，不需要逐版人工反编译。

## 2. 通用流水线（分层，版本无关）

| 层 | 内容 | 现状 |
|---|---|---|
| L0 模块定位 | 在 exe 与同目录 Native/*.dll 中找唯一 `MHY\0` blob；验证 hdr_global 的 lea/mov 初始化 + 字符串堆 mscorlib 自检 | 已跑通：exe 20 版 + UserAssembly.dll 5 版（4.3–4.7）；4.2.0 未找到 blob |
| L1 字符串密码 | 3–7 ops 的 schedule + step + strsec，全部从代码现场推导 | 已自动：25/26 版 |
| L2 头/锚点 | MHY blob → hdr_global → 全部 `hdr[slot] op imm` 锚点（每版 291–485 条去重） | 已自动：25/26 版 |
| L3 表基址 + stride | 7.1 语义种子 + 函数形态匹配 → 从目标版本读 (slot,op,imm) 与 stride | 原型 24/25 语义产出候选；typeDef 5/5 正确、4.8 失败 |
| L4 行内列常数/掩码 | (a) builder 函数「常数单元」模板迁移；(b) 数据自解（已知明文 + 合法索引集 + tiling/单调/上界，反解列常数与逐行掩码再拟合链） | 7.1 人工已解；通用化未实现 |
| L5 验收器 | 每张表版本无关判据：size=行数×stride、tiling 0 违例、名字索引全部可解码为可打印标识符、索引上界、行 0 已知锚点；失败显式报错 | 部分已有（derive::tables、colsolve/colverify）；需统一 |
| L6 回归 | oracle：6.1–6.5 dump（~/Documents/git-repo/Genshin-Impact-Dump-collection，rar+6.4Dump.cs）、7.1 自检；逐版本比对 | 7.1 已有 final_verify；6.x 待接 |

**L3 的关键点**：不是「扫描 + 阈值」，而是「7.1 已解出的语义函数 → 目标版本同形态函数 → 读常数」。
7.1 是唯一需要人工 RE 的版本；之后所有版本的常数都从形态匹配后的位置读取（符合 R8「以实际执行代码
逻辑为基础」、R24「禁止硬编码版本常数」）。种子本身是**数据文件**（`docs/re/artifacts-7.1.0/shape-seed.json`），
不在代码里（R10）。

## 3. 本轮实测：批量结果

### 3.1 L0 模块定位（新增能力）

| 版本 | 头所在模块 | derive 结果 |
|---|---|---|
| 4.8.0–7.1.0（20 版） | YuanShen.exe | 全部成功 |
| 4.3.0/4.4.0/4.5.0/4.6.0/4.7.0 | YuanShen_Data/Native/UserAssembly.dll | 传入 DLL 后全部成功（cipher + typeDef 表） |
| 4.2.0 | 未找到（exe/DLL 无 MHY\0；metadata 首 0x210 含 MHY 但与 7.x 的明文头不同） | 失败，待专项 |

⇒ 覆盖从 20/26 提升到 **25/26**。时代差异（4.2–4.7）不是「另一套算法」，而是**代码模块位置不同**。
`derive` 后续应把「在候选模块中找 blob」内置（本轮用命令行手动传 DLL 验证）。

### 3.2 L2/L3/L5：每版 typeDef 表、语义迁移与验收

- typeDef 表：25/25 版由 derive 自动解出（4.x–5.0 为 stride 74，5.1+ 为 70）。
- 语义迁移（7.1 种子 → 目标）：24/25 语义在 6 个目标版本上都产出了候选值；其中 **typeDef 5/5 与 derive
  独立结果逐位一致**（7.0/6.7/6.4/6.0/5.4），4.8 因形态差异失败。
- **L5 验收器已接入并给出独立验证**：size 语义必须 = 行数 × stride（整除判据），候选里唯一的通过者被选中：

| 版本 | td_size/70（行） | 减尾行 = 类型数 | oracle | md_size/26（行） | 减尾行 = 方法数 | oracle |
|---|---|---|---|---|---|---|
| 6.4.0 | 77,262 | 77,260 | **77,260**（6.4Dump.cs 逐行统计） | 631,108 | 631,107 | **631,107** |
| 7.0.0 | 86,932 | 86,930 | 无 oracle；7.1=88,902（+1,972） | 713,956 | 713,955 | 无 oracle；7.1=733,442（+19,487） |

  ⇒ 6.4.0 的两个核心计数与社区 oracle **完全吻合**（只差已知的尾部 padding 行），说明
  「形态迁移拿基址/size + 整除验收」这条链是可靠的，不是拟合。
- 尚未通过验收的语义（显式标记，不当作结论）：6.7/6.0/5.4 的 td_size/md_size 候选未收集到唯一整除者
  （扫描器对部分版本的 size 读取形态覆盖不足，或函数匹配歧义）；4.8 全链条因形态差异失败。
  下一步：把「在整版锚点集合里按 size 判据搜索」作为 L5 的兜底（不依赖单一函数候选）。
- **typeDef 行布局不走代码迁移**：见 §3.2b，已由数据自动解出（含 oracle 验证）。

### 3.2b L4b 数据自解：typeDef 行布局已自动闭环（2026-10-18）

typeDef 行布局不再依赖 7.1 代码迁移，直接由数据判据求出（工具 = 现有 mhydump tables --base 类型表基址）：

- **两套铺瓦（IndexTable 谓词）**：fs/fc（fieldStart/fieldCount）与 ms/mc（methodStart/methodCount）
  两套链都满足“解码后的 start 单调铺满 [0, 行数)”。全表无违例者即为该表的行区间定义；
  max_index+1 同时给出字段表/方法表的行数。
- **字符串列**：对每个列偏移求常数 C，使 97% 的抽样行解码为合法字符串；本轮修了三处才把
  namespace 列也解出来（此前只有 name 列）：
  1. StringColumn 现在携带 transform family（Add/Xor）——同一列两种族都可能，旧输出只有 C，无法判断；
  2. 采样改为按列去重 raw（空 namespace 的哨兵 raw 在 typeDef 上重复约 25%，旧采样 24 行几乎全同值，
     常数交集不收敛，namespace 列 survivor 数万）；
  3. 允许 len == 0（空名）为合法，并在选择长度键 h 时把空名投票计入；同时要求非空行 >= 8，
     排除“h = m 全空”的平凡解。
- 判定语义：name 列 = 256/256 行非空且 99.9% 为标识符；ns 列 = 非空行 40–65/256（其余为空），
  两者自动区分，不需要外部常数。

实测（全表解码；6.4 用社区 6.4Dump.cs 逐行统计做 oracle）：

| 版本 | 行数 | name 列 | ns 列 | fs / fc | ms / mc | 字段行 | 方法行 |
|---|---|---|---|---|---|---|---|
| 7.1.0 | 88,904 | 0x14 Add 0xE811F779 | 0x18 Xor 0x666769B5（与 profile 逐位一致） | 0x00 Add 0x72628007 / 0x30 Xor 0x9A6B | 0x08 Add 0x0478AF59 / 0x3C Xor 0x8811 | 440,172 | 733,442（dump.cs 统计） |
| 7.0.0 | 86,932 | 0x10 Xor 0x616B619D | 0x18 Xor 0x7351490A | 0x00 Add 0x20749BC2 / 0x32 Xor 0x6B9B | 0x20 Add 0x33AB5AF8 / 0x3C Xor 0x37E5 | 430,288 | 713,953 |
| 6.7.0 | 83,775 | 0x18 Xor 0x17FB1577 | 0x2C Xor 0x4AAC4BAB | 0x14 Xor 0x1D37F888 / 0x38 Xor 0xEB4C | 0x0C Xor 0x4DFA3BEC / 0x30 Xor 0x8EED | 413,630 | 687,452 |
| 6.4.0 | 77,262 | 0x18 Add 0xE169AC15 | 0x20 Xor 0x468CB988 | 0x3E Xor 0x6FE9B568 / 0x78 Xor 0xD846 | 0x14 Add 0x7589193B / 0x28 Xor 0xE8D4 | 384,410 | 631,104 |
| 6.0.0 | 59,631 | 0x08 Add 0x85A69E32 | 0x0C Add 0x9FA88537 | 0x04 Add 0x6635464F / 0x28 Xor 0x787B | 0x14 Add 0x0BA968F3 / 0x32 Xor 0x1D76 | 304,855 | 475,153 |
| 5.4.0 | 58,938 | 0x3E Add 0xD13BCB2F | 0x42 Add 0xA1316236 | 0x08 Xor 0x5CB2D477 / 0x1A Xor 0xED8D | 0x36 Xor 0x6C8996BE / 0x56 Xor 0xF755 | 285,057 | 515,379 |

验证（证据）：
- **6.4 名字**：全表 77,232 条解码，99.94% 是合法标识符；与 6.4Dump.cs 的交集 60,312（其余差异是
  混淆名逐版随机化 + dump 只打印 public 子集）。
- **6.4 namespace**：解出 376 个，oracle 377 个（差 1 个空串），Jaccard **0.9973**。
- **6.4 计数**：方法行 631,104 与 md_size/26 = 631,108 差 4 行（尾部 padding）；类型行 77,262 − 2 = 77,260
  与 6.4Dump.cs 逐行统计的 77,260 完全一致。
- 六个版本解出的 namespace 集合样本完全相同（含同一混淆 GUID），说明列语义判定正确。
- 7.1 的 ns 列与 profile 的 0x18 XorC 0x666769B5 逐位一致（自洽校验）。

结论：**typeDef 的表基址/stride/行数/name/ns/fs/fc/ms/mc 已全部可自动求出**；代码迁移只需表基址与
size 槽（L3），行布局交给数据（L4b）。

### 3.2c 跨版本类型清单已能直接从数据产出（2026-10-18）

新增 tools/version-triage/type_defs_dump.py：给定 版本目录 + derive 工件 + tables --base 结果，
输出 JSONL {i, ns, name, fieldStart, fieldCount, methodStart, methodCount}，按 IndexTable 语义解码
（Add: raw = plain + C；Xor: raw = plain ^ C；raw == sentinel 表示该行无字段/方法；行号超过该模型
拟合行数的尾部 padding 不读列）。六个版本全部产出，且每版的 field/method 链 0 断裂：

| 版本 | 行数 | 解出名字 | sum(fieldCount) | 字段表行 | sum(methodCount) | 方法表行 |
|---|---|---|---|---|---|---|
| 7.1.0 | 88,904 | 88,872 | 440,172 | 440,171 | 733,442 | 733,431（dump.cs 733,442） |
| 7.0.0 | 86,932 | 86,900 | 430,290 | 430,288 | 713,956 | 713,953（md_size/26 713,956） |
| 6.7.0 | 83,775 | 83,743 | 413,644 | 413,630 | 687,467 | 687,452 |
| 6.4.0 | 77,262 | 77,230 | 384,411 | 384,410 | 631,108 | 631,104（md_size/26 631,108） |
| 6.0.0 | 59,631 | 59,601 | 304,855 | 304,855 | 475,157 | 475,153 |
| 5.4.0 | 58,938 | 58,910 | 285,058 | 285,057 | 515,399 | 515,379 |

验证（证据）：
- **7.1 自检**：本工具产出的 (namespace, name) 与既有 dump.cs 完全一致（85,709/85,709，
  Jaccard 1.0）；field/method 链结尾正好 440,172 / 733,442。
- **6.4 oracle**：type pairs 74,483 vs 74,555，Jaccard 0.961；全部差异是编译器生成泛型类的显示格式
  （metadata 里是 <>c__0 + 反引号 arity，6.4Dump.cs 用 GenericParam 表重建为 <>c<T> 形式），
  不是解码错误。字段行数 sum = 384,411 与 6.4Dump.cs 的字段行完全一致；
  方法 sum 631,108 vs oracle 631,107（1 行 padding）。
- 各版本解出的 namespace 数 376 / 373 / 376 / 376 / 376 / 363（同一份源码，数量级一致）。

意义：这是第一条跨版本的数据产物（此前只有 7.1 有完整输出），且不依赖任何版本常数——
布局来自 L4b 数据自解，基址来自 L3 形态迁移/derive。仍缺：typeDef 的 flags/bitfield/parent/接口/
property/event/nested 范围列，以及方法/字段/参数表的行布局与掩码，所以还不到完整 dump.cs。

### 3.2d 数据自解：typeDef 范围列（方法/字段/属性/事件）自动发现（2026-10-18）

新增 tools/version-triage/find_type_ranges.py：不依赖代码，纯数据找出 typeDef 行里的
「起始列 + 计数列」对（每种范围表一对）。常量 pin 方法：
- 计数列：多数类型没有成员 ⇒ 该列 raw 的众数就是 plain 0 的编码（xor: C=raw；add: C=-raw）；
  再以第 0 行（<Module>，无成员）作为第二候选；
- 起始列：任取一个计数为 0 的行，其起始列 raw 就是全 1 哨兵的编码（xor: C=raw^mask；add: C=mask-raw）；
- 全表铺瓦验证：start 非减、不与上一段重叠；数组有洞时只计 gap 数，重叠超过阈值即拒绝。

实测（6 版本；均与上一轮 R29 用 typeDef 计数字段求出的 sum 独立吻合）：

| 版本 | 方法对 (start/count → end) | 字段对 | 属性对 | 事件对 | 其它 |
|---|---|---|---|---|---|
| 7.1.0 | 0x08/0x3C → 733,442 | 0x00/0x30 → 440,172 | 0x24 Add 0xCE2141CC / 0x43 Xor 0x86 → 115,596 | 0x38 Add / 0x44 Xor 0xB5 → 628 | — |
| 7.0.0 | 0x20/0x3C → 713,956 | 0x00/0x32 → 430,290 | 0x1C Add 0xF6929062 / 0x45 Add 0xDB → 112,949 | 0x3E Xor 0x66AD / 0x44 Add 0x3A → 625 | — |
| 6.7.0 | 0x0C/0x30 → 687,467 | 0x14/0x38 → 413,644 | 0x00 Add 0xF43F5BDC / 0x44 Add 0x7C → 108,747 | 0x34 Add 0xFD33 / 0x40 Xor 0x10 → 617 | — |
| 6.4.0 | 0x14/0x28 → 631,108 | 未发现（count 偏移 0x78 越过行宽，IndexTable 模型特殊） | 0x1C Xor 0x1AF4F14C / 0x3A Add 0x6D → 99,320 | 0x2A Add 0xE909 / 0x3B Xor 0x52 → 596 | — |
| 6.0.0 | 0x14/0x32 → 475,157 | 0x04/0x28 → 304,855 | 0x18 Xor 0x08B87A48 / 0x38 Xor 0xFC → 77,319 | 0x2C Xor 0xBA4E / 0x3D Xor 0xC0 → 508 | — |
| 5.4.0 | 未发现 | 0x08/0x1A → 285,058 | 未发现 | 0x18 Add 0x1255 / 0x20 Xor 0x33 → 486 | 0x32 Add 0x20A5 / 0x68 Add 0x6 → 35,864（疑似嵌套表，gap=0） |

验证（证据）：
- 7.1 四对与 profile 逐位一致：字段 start 0x00 Xor 0x72628007、属性 start 0x24 Add 0xCE2141CC /
  count 0x43 Xor 0x86、事件 start 0x38 Add 0xFFFFD6AB / count 0x44 Xor 0xB5。
- 各版本 end 与 R29 用 typeDef 计数字段独立算出的 sum **完全一致**（方法 733,442/713,956/687,467/
  631,108/475,157；字段 440,172/430,290/413,644/304,855/285,058）。
- 7.0 / 6.4 的方法 end 恰等于 md_size/26（713,956 / 631,108），与 size 槽独立互证。
- 事件 end 6 版本 628/625/617/596/508/486，同源码量级一致。

已知缺口：6.4 字段对（count 偏移 0x78 越过行宽 0x46，属 IndexTable 的跨行模型，本扫描未覆盖）；
5.4 方法/属性对；嵌套/接口对在多数版本未发现（嵌套数组可跨类型乱序、接口 offsets 含继承项，
需要不同的链判据）。下一步：把该发现器接入 tables 子命令，并入 profile 草稿。

### 3.2e 类型清单扩展到属性/事件范围，并做逐类型 oracle 校验（2026-10-18）

范围对发现器收紧判据：start 必须完全非减（bad == 0），无缝（gaps == 0）时还要求
end == sum(count)，否则视为多段/重叠数组而拒绝（例如 5.4.0 的 35,864 行对就是这种）。
type_defs_dump.py 现在接受 ranges JSON，把属性/事件的 (start,count) 并入每个类型行：
{propStart, propCount, eventStart, eventCount}；属性对用 chain_rows>10k 且 end>5k 识别，
事件对用 chain_rows>=50 且 end<=5k 识别，选中后用 sum == end 复核，失败则显式拒绝。

逐类型 oracle 校验（把 dump.cs 的 "// Namespace" + 类型声明 + 属性行按类型聚合，与我们的
propCount 比较；同名类型占多数差异）：

| 版本 | 比较类型数 | 属性数一致 | 一致率 |
|---|---|---|---|
| 7.1.0 | 88,872 | 88,304 | **99.36%** |
| 6.4.0 | 75,764 | 75,179 | **99.23%** |

差异全部集中在同名类型/嵌套类型（dump 的类型块名与 metadata 短名不完全对应）以及 99 行
区间边界，不是属性列解码错误；属性总数与发现器 end 完全一致（115,596 / 99,320 …）。

当前六版本的类型行已含：ns/name/fieldStart/fieldCount/methodStart/methodCount/propStart/
propCount/eventStart/eventCount。5.4.0 的属性对因数组重叠被拒绝（显式报告），事件对保留。

### 3.2f 方法/参数表行布局：7.0 已从代码提取并数据验证（2026-10-18）

7.0 的方法表行布局从代码里直接读出（三个函数共享同一条方法行掩码链）：

- 0x1404E5560 运行时方法缓存 builder、0x1404E59E0 方法指针解析器、0x1404F9750 方法元数据
  decoder（参数解析）。署名依据：这三处都出现同一组 64 位掩码常量
  0x3639B538F896 / 0xCC49CF2E948F28F / shr 13 / 0x3209B9A2 / 0x066E3EE5EEBB7B78。
- 方法表基址 = hdr[0x138] + 0xD37E9675；stride 26 由 lea rcx,[rdx+rdx*4]; lea rcx,[rcx+rcx*4];
  add rcx,rdx 直接给出（5*5+1）。
- 列变换（从指令逐条读出，写入 docs/re/artifacts-7.0.0/method-layout.json，纯数据）：
  paramStart = raw[+4] + 0xAC706A39 - mask；paramCount = (raw8[+0x18] ^ 0x5B) - mask8；
  flags = raw16[+0x0E] - mask + 0x13；decl = raw[+8] - mask + 0x997E86CD。
- 参数表：基址 = hdr[0x1FC] + 0xFC3EC0CE，stride 8；参数行掩码链
  mul 0x2F64C993DFFE / add 0xAB42C68E0D4A / shr 17 / mul 0x272E941C / xor 0x705880A8；
  name = (raw[+4] + 0xDA14EDA6) ^ mask，type = (raw[+0] + 0x8FE5701B) ^ mask。

数据验证（tools/version-triage/method_rows.py，7.0.0）：

| 检查 | 结果 |
|---|---|
| 方法行数 / stride | 713,956 / 26（= md_size/26） |
| paramStart 哨兵行（0xFFFFFFFF） | 401,636，全部 paramCount = 0 |
| paramStart 链（非哨兵行）| 0 处违例（start_i 恰等于已累计参数数） |
| sum(paramCount) | 532,361 = 参数表行数 |
| 参数表 name/type 解码 | 532,361/532,361 全部成功（0 失败）；样本 msg/fmt/args/resourceFormat/p1/exception |
| flags | 66 种取值，static(0x10) 83,868，max 0xFA36 |
| decl | 989 个 0xFFFFFFFF 哨兵；非哨兵语义未定（值域待确认） |

结论：7.0 的方法表（paramStart/paramCount/flags/decl）与参数表（name/type/掩码）已经可解码，
且被参数表全量解码独立验证。尚未定位：方法 name 与 returnType 列（怀疑使用 mask2 或另一条
掩码链，7.0 行内其余偏移用当前掩码族均未通过全量验证），以及 decl 的语义（token/container）。

### 3.3 代码形态匹配的适用范围与边界

- 适用：同一编译器/同一代源码结构（6.x–7.1 实测）；函数窗口 0x180 字节足够。
- 不适用：4.8（匹配分 0.25，函数形态差异明显）；以及 .upx0 里的 VMP 变异码（逐版重写，形态不保持）。
- 因此 .upx0 内的常数（如 7.1 的 td_flags 0xDFA09F90、bitfield 0x8BA4）不能靠形态迁移，需
  「模式找链 + 数据验收」或接受为「运行时/构建期」不可得。

## 4. 未解决问题与下一步（按优先级）

1. **L5 验收器全面接入 L3 候选选择**：size 语义已做（整除判据，6.4 与 oracle 吻合）；其余待做：
   表基址必须落在 body 内且不与其它表重叠、rows 与 typeDef chain 一致、事件/属性 size 同样整除、
   名字列可解码。并加兜底：候选不足时在整版锚点集合里按判据搜索（不依赖单一函数候选）。
2. **L4a：builder 常数模板迁移（主要工作量）**：把 7.1 的 5 个 builder 函数（typeDef 0x1405162A9、
   method 0x1405155AD、event 0x140515E42、usage/literal 0x14052426D、generic 0x1404B8D4A）做成
   「常数单元」数据：记录 (指令序号/数据流位置 → profile 字段)。目标版本匹配函数后按同一映射读常数，
   产出完整 Profile → dump-gen。**先在 7.0 上闭环**：自动 profile → dump.cs → 与 7.1 dump 做计数/名称
   Jaccard 比对，再补 6.7/6.4。
3. **L4b：数据自解兜底**（不依赖代码）：把已知明文（<Module>/Locale/SR/…）+ 合法字符串索引集 +
   跨行约束做成通用求解器；对列常数与逐行掩码先按行反解候选、再拟合链，用 L5 验收。
   6.7 的 typeDef 列曾用 colsolve4 解出 5/9，可作为起点；需先把 colsolve2/4 的 3 常数解密换成
   schedule 形式以支持 5–7 ops 世代。
4. **4.8 形态差异**：指纹加长/改为函数级对齐，或允许 4.8 单独种子（数据文件，不是代码分支）。
5. **4.2.0**：定位其头/加载器（可能在 UnityPlayer.dll 或 metadata 自带头）。
6. **L6 回归**：7.0 dump 与 7.1 结构比对；6.1–6.5 与 oracle 比对；把结果写回 version-matrix。

## 5. 本轮工具与数据

| 文件 | 作用 |
|---|---|
| `tools/version-triage/loadsites.py` | 为某模块缓存全部 `hdr_global` 加载点 + 去常数函数指纹（JSON）；7.1 约 72 s/版本 |
| `tools/version-triage/shape_transfer.py` | 语义种子 + 目标指纹 → 语义映射（slot/op/imm/resolved + 匹配分 + 候选）；不做验收 |
| `docs/re/artifacts-7.1.0/shape-seed.json` | 25 条 7.1 语义种子（槽/op/imm/stride），纯数据 |
| `~/gire/out/cross/{v}.derive.json` | 各版本 derive 工件（本轮 25 版） |
| `~/gire/out/cross/sites/{v}.json` | 各版本加载点指纹缓存（本轮 7 版） |
| `~/gire/out/cross/shape/{v}.json` | 语义迁移原始结果（本轮 6 版，未验收） |

## 6. 边界声明

- 本文的「通用」指**算法/常数分离的推导管线**，不是「一个二进制通杀所有版本」：L0 的模块位置、
  L5 的验收判据仍需按代际设计；4.2.0 与 4.8 是已定位的边界。
- 所有「已解」的表述都有实测证据；7.0 的 td_size 等未过验收的候选明确标注为「原始候选，未定案」。
