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

### 3.2g 7.0 方法表 name/returnType 补齐（2026-10-18）

上一轮把 +0x08 当成 decl，实际它是**方法名**列：解析器 0x1404E59E0 把该列传给 0x1404E0110
（名字解析），且全表按 (raw[+8] + 0x997E86CD) - mask 解码后 99.8% 是可打印标识符。returnType
列没有已知明文，改用**窗口性质**在数据上钉常数：真实值 in [0, B) 且 value = (raw - mask) + C，
对 200k 行求 A = raw - mask 后 A 落在长度 < B 的环形窗口内，由此唯一解出
C = 0xDF812A65，解码值 0..0x15390（86,928）、76,000 种不同取值。

更新后的 7.0 方法行布局（docs/re/artifacts-7.0.0/method-layout.json v2）：

| 字段 | 偏移 | 变换 | 常数 |
|---|---|---|---|
| paramStart | +0x04 | (raw + C) - mask | 0xAC706A39 |
| name | +0x08 | (raw + C) - mask | 0x997E86CD |
| flags | +0x0E | raw16 - mask + C | 0x13 |
| returnType | +0x10 | (raw + C) - mask | 0xDF812A65 |
| paramCount | +0x18 | (raw8 ^ C) - mask8 | 0x5B |

全表验收（713,956 行）：

| 检查 | 结果 |
|---|---|
| name | 712,680 标识符 + 989 个 0xFFFFFFFF 哨兵 + 287 其它 = 99.82% 有效 |
| returnType | max 0x15390（86,928），76,000 种取值，分布合理（无越界） |
| paramStart 链 / 哨兵 | 0 违例 / 401,636 哨兵且 paramCount=0 |
| paramCount 总和 | 532,361 = 参数表行数 |
| 参数表 name/type | 532,361/532,361 全部解码成功 |

仍未定位：**slot 列**（候选 +0x16 i16 公式 (raw-mask-0x3EBD)，但 slot 与 virtual(0x40) 的相关性
不符：10,288 个 virtual 方法里 10,278 个解成 -1，说明候选不对或 flags 列语义另有映射），
以及 flags 位映射（当前 66 种取值，static 位 0x10 可信）。

### 3.2h 7.0 属性表行布局：代码提取 + 数据验证（2026-10-18）

缓存构建器 0x1404E6180 读属性表：基址 = hdr[0x15C] ^ 0x368C9997，stride 10
（lea rax,[rax+rax*4] 两次 = 10）。逐行掩码链：
mul 0xE0F8 / xor 0x22F6DA00 / mul 0x3AA8EE62 / add 0x49880E3C / xor 0x3E17E98E / add 0x7EC31F32。

列变换（写入 docs/re/artifacts-7.0.0/property-layout.json，纯数据）：
name = (raw[+0] ^ 0x5DC2119E) - mask；
getter = raw16[+8] - mask + 0xFFFF945B（0xFFFF = 无）；
setter = (raw16[+6] ^ 0xFFFFC45A) - mask（0xFFFF = 无）。
访问器索引是 **每类型相对的方法索引**（与 typeDef methodStart 相加得到全局方法索引）。

全表验收（tools/version-triage/property_rows.py，7.0.0）：

| 检查 | 结果 |
|---|---|
| 属性行数 | 112,949（与范围发现 end 一致） |
| 属性名 | 112,663 标识符 + 65 其它 = 99.94% 有效 |
| 访问器索引范围 | 128,776 个非空访问器，越出所属类型方法区间 **0 个（0.00%）** |
| 列语义 | +8 列 61,967 个方法名以 get_ 开头、0 个 set_ ⇒ getter；+6 列 8,781 个 set_、0 个 get_ ⇒ setter |
| 名称配对 | 未混淆子集里 getter 17,153 / setter 5,761 与属性名严格配对；GI 对属性名与访问器名独立混淆，故仅作参考 |

**更正**：之前 shape-transfer 语义里的 fields（槽 0x15C）其实是**属性表**，不是字段表；7.0 的字段表
（stride 10，name/type/attrs）仍未定位。

### 3.2i 7.0 profile 草稿与跨版本名字对照（2026-10-18）

新增 tools/version-triage/profile_draft.py：把已解出的各块（derive 密码、typeDef 布局 +
区间、方法/参数/属性布局）合成**单一 profile 草稿 JSON**；缺块不会被静默忽略，而是写进
unresolved 列表。7.0.0 草稿（docs/re/artifacts-7.0.0/profile-draft.json）计数：

| 项 | 值 |
|---|---|
| 类型行 / 有名字类型 | 86,932 / 86,900 |
| 字段行（sum fieldCount） | 430,290 |
| 方法行（sum methodCount） | 713,956（= md_size/26） |
| 属性行 / 事件行 | 112,949 / 625 |

**跨版本名字对照（独立 oracle 性质）**：7.0 解码出的前 200 个方法名与 7.1 dump.cs 的前 200 个
方法名**逐位相同 170/200**（差异主要是 dump 把 ".ctor" 写成 "ctor"、以及少量方法顺序差异）。
corelib 方法序列在两个相邻版本间一致，说明方法表的 name 列、行序与掩码解码正确。

仍未解（草稿里显式列出）：字段表（name/type/attrs）、方法 slot 列、typeDef flags/bitfield/parent/
nested 区间、泛型表、参数默认值表、usage/literal 表。

### 3.2j 7.0 字段表：调用图定位 + 掩码解码（2026-10-18）

字段表没有 start/count 对，IndexTable 谓词找不到；先用新增的 mhydump str-cols 子命令在
105 个候选基址 × stride 10 上做无掩码字符串列扫描，**0 命中**（字段列是逐行掩码的）。
改用调用图：名字解析器 0x1404E0110 有 52 个调用者，其中 0x1404EDB50 是一个惰性字段名访问器：

- 字段表基址 = hdr[0x1D0] + 0xB98BE77F（7.0：0x17A2444），stride 8；
- 逐行掩码（行号是**绝对字段索引** = typeDef fieldStart + 局部序号）：
  mask = (((i * 0x1147E475DFA9) >> 0x12) * 0x2CD0F4EE + 0xC16316113B52) >> 0x10；
- name = (raw32[+4] ^ 0x6040B64C) - mask；
- 访问器里 row = fieldStart_encoded + local + 0xDF8B643E，与 R30 纯数据解出的 fieldStart 列
  常数 0xDF8B643E 完全一致（互相印证）。

全表验收（tools/version-triage/field_rows.py，7.0.0）：

| 检查 | 结果 |
|---|---|
| 字段行数 | 430,290（与 typeDef sum fieldCount 一致） |
| 字段名 | 429,297 标识符 + 793 其它 + 200 哨兵 = **99.77% 标识符** |
| typeDef 字段区间覆盖 | 429,297 行可解码；993 行不可解码（恰为 793 其它 + 200 哨兵），区间与表行数完全对齐 |

### 3.2k 7.0 字段表 type 列（窗口性质求解）与参数 type 列的未决点（2026-10-18）

字段表 8 字节行的 +0 列没有已知明文，用窗口性质解：value = (raw - mask) + C 且所有值落在
一个连续窗口内。对 430,290 行求 A = raw - mask，环形窗口大小 = 232,881 ⇒ C 唯一
（C = -min(A) = 0xA90E9923），解码后字段 type 索引：**0..232,880，68,305 种不同取值**，
25% 的行 < 1000（常见基础类型集中在索引空间前部，最大 10 个取值各覆盖 7k–20k 字段）。
字段表现在 {type, name} 两列都可解码（field_rows.py 同步输���）。

参数表的 type 列（同一行掩码 + 参数行掩码链）用同样方法检查：三族窗口分别为
add 4.29e9 / sub 1.32e6 / xor 2.41e9 —— 没有一族收敛到可解释的 type 索引范围。结论：
参数 type 列可能还叠加了 mask2/打包位（或需要另一条掩码链），**本轮不定案**，显式记录。

### 3.2l 7.0 端到端验证脚本与两个待确认点（2026-10-18）

新增 tools/version-triage/verify_70.py：把 R28–R37 解出的 7.0 布局汇成一个**回归门禁**，逐表抽样
重解码并断言结构不变量（失败即非零退出）。当前 **12 项全部 PASS**：

- typeDef 行数 86,932 / 有名字 86,900；字段区间和 430,290、方法 713,956、属性 112,949、事件 625；
- 方法 name 抽样（20k）：19,237 标识符 / 723 个 0xFFFFFFFF 无名字 / 40 其它 / **0 个非哨兵失败**；
- paramStart 链抽样 20k：**0 违例**；
- 参数表 name/type 抽样 20k：全部可解；
- 属性名抽样 20k：19,779 标识符；
- 字段名抽样 20k：19,415 标识符 / 90 哨兵；
- 字段 type 抽样 20k：max 索引 13,504（< 300k）。

跨版本字段名对照：7.0 与 7.1 dump 的前 20 个字段名**顺序完全一致**，之后出现同名不同序
（GI 每版构建期重排字段，与 §60 的既有结论一致）⇒ 字段 name 解码正确，**字段顺序是构建期属性**。

两个显式标记的未决点（不当作已解）：

1. **方法 returnType 索引分布可疑**：713,956 个方法里最高频返回值只有 16,567 次，且 top 值在
   50k–83k 区间——与“void/int 占大头”的预期不符，可能 ret 列仍有 mask2 或我们解错了列。
2. **参数 type 索引空间不一致**：参数 type max 662,533，而字段 type max 232,880、方法 ret max 86,928；
   三者是否同一 typearr 索引空间、参数列是否叠加打包位，需要 typearr 本体（base + Il2CppType 布局）
   才能定案。

### 3.2m Il2CppType 数组定位 + 方法 returnType 列纠正（2026-10-18）

决定性一步：在 7.0 模块里结构扫描定位了 Il2CppType 数组——16 字节记录
{u64 data, u16 attrs, u8 type, u8 flags, 4B padding=0}，连续 662,534 条，
文件偏移 0x2D3C7F0（VA 0x142D3DFF0）。判定依据（互证）：

| 证据 | 结果 |
|---|---|
| 参数 type 列最大值 | 662,533 = count−1（全在界内） |
| 字段 type 列最大值 | 232,880 < count |
| 方法 return 列最大值 | 全部 < count |
| 记录语义 | type 枚举合法（class=0x12/valuetype=0x11 data=typeDefIndex；Void/Bool/Int32/String 等按枚举直接命名；genericinst=0x15 data=泛型实例索引） |

据此纠正 R33 的 returnType 列：不在 +0x10，而在 +0x00，
value = (raw ^ 0x215FCCB1) − mask。验证：

- 713,956 个方法值全部在 [0, 662,534)；
- 437,167 个解析为 System.Void（61.2%）；distinct 32,246；
- 前 12 个方法依次为 Void / String / String / String / Void…，与 <Module> 的
  .ctor、GetText、mono_runtime_install_handlers 等完全对应；
- 高频返回类型：Void 437,167、Boolean 66,823、Int32 30,854、String 13,880、UInt32 9,619。

原先放在 +0x10 的列不是返回值（分布不符合 void 占多数），已从布局里移除并标注未知。

新增 docs/re/artifacts-7.0.0/typearr.json；tools/version-triage/method_rows.py 输出
return_type 的解析样本/void 比例/越界数；verify_70.py 增加到 13 项检查，全部 PASS。

### 3.2n Il2CppType 渲染 + 与 7.1 dump 的方法级对照（2026-10-18）

Il2CppType data 语义已确认（7.0）：VALUETYPE/CLASS 的 data = typeDefIndex；VAR/MVAR 的 data =
泛型参数位置；PTR/SZARRAY/ARRAY 的 data = 元素类型在 typearr 里的 VA（可换算成索引后递归）；
GENERICINST 的 data 是尚未定位的泛型实例表索引（暂渲染为 genericinst#N）。

新增 tools/version-triage/type_render.py，用 7.0 布局输出全部 713,956 个方法行：
声明类型 + 方法名 + 渲染后的返回类型（例：Locale.GetText : System.String、
Runtime.mono_runtime_install_handlers : System.Void、Runtime.LoadBinData : System.Byte[]）。

与 7.1 dump.cs 的逐类型对照（corelib 60 个类型；方法名按类型对齐）：

| 指标 | 结果 |
|---|---|
| 方法名交集 | 5,166 |
| 返回类型逐项一致 | **5,164 / 5,166 = 99.96%** |
| 不一致项 | 2 个，均为泛型方法的 MVAR 返回（我们显示 !!1895，dump 显示 public T）⇒ 需要泛型参数名映射 |

这说明方法表的声明类型归属、方法名、返回类型在这个版本上已经端到端可用；剩余工作是把
GENERICINST 表定位、VAR/MVAR 映射成真实泛型参数名，然后同样渲染字段/参数/属性类型并生成
dump.cs。

### 3.2o 7.0 字段表 type 列定案（已知明文 + kind 分布）（2026-10-18）

R37 用窗口性质得到的字段 type 常数 0xA90E9923 是错的（解码后 top 值全是 genericinst）。
本轮用已知明文重钉：字段 0（Mono.RuntimeClassHandle.value）类型是 MonoClass*，在 typearr 里
对 PTR(0x0F) 条目解析元素类型，找到三处 MonoClass 指针条目 429,796 / 429,798 / 429,829；
以 field0 = 429,796 反解常数，在 15 种族 × 偏移 0..4 中只有 value = (raw + C) - mask
（C = 0xA9152807）同时满足“0 越界且值集合可解释”。

定案后的 type kind 分布（430,290 字段）：

| kind | 行数 |
|---|---|
| CLASS (0x12) | 111,845 |
| VALUETYPE (0x11) | 111,199 |
| GENERICINST (0x15) | 41,875 |
| Boolean | 36,449 |
| Int32 | 35,523 |
| UInt32 | 27,565 |
| Single | 23,481 |
| String | 19,554 |
| SZARRAY (0x1D) | 12,484 |

前几个字段解析为 MonoClass* / RemoteClass* / GenericParamInfo* / IntPtr / IntPtr / GPtrArray*，
与 corelib 结构体定义吻合。全表 430,290 行中只有 64 行落在 typearr 之外（尾部行），
其余全部可解析。verify_70.py 的字段 type 检查更新为：primitive-kind 行 >= 100k 且越界 <= 100
（实测 149,852 / 64），13 项检查全部 PASS。

### 3.2p 方法签名端到端渲染 + 逐参数对照（2026-10-18）

type_render.py 输出升级为完整签名：声明类型 + 方法名 + 渲染返回类型 + 每个参数的
(名字:类型)；Il2CppType 的 flags 字节 bit6 = byref，渲染时在该类型后加 &。样例：

- Locale.GetText : System.String (fmt:System.String, args:System.Object[])
- SR.Format : System.String (resourceFormat:System.String, p1:System.Object)
- Mono.Runtime.GetNativeStackTrace : System.String (exception:System.Exception)

与 7.1 dump.cs 的逐类型逐参数对照（corelib 60 类型）：

| 指标 | 结果 |
|---|---|
| 返回类型 | 990 / 994 = 99.6% |
| 参数类型（按位置） | **1,457 / 1,485 = 98.11%** |
| 剩余不一致 | genericinst#N 占位（泛型表未定位）+ 少量跨版本混淆改名（JAAJEOLDNPH vs FPBCFBKKCFG） |

即：参数名的 name 列、参数 type 列、参数顺序（paramStart 链）、byref 标志在 7.0 上都已验证；
现在只差泛型实例表就能把签名渲染完整。

### 3.2q 字段/属性类型渲染 + 7.1 dump 对照（2026-10-18）

用 typearr 渲染器把字段表 type 列、属性 getter 的返回类型都渲染成名字，与 7.1 dump.cs 的
corelib 前 60 个类型对照（字段按名字匹配，属性按名字匹配）：

| 指标 | 结果 |
|---|---|
| 字段类型（205 个同名匹配） | **205 / 207 = 99.03%** |
| 属性类型（34 个同名匹配） | **34 / 37 = 91.89%** |
| 属性访问器存在性（get/set 有无） | 35 / 37 = 94.6% |

属性类型残余差异与字段一样，来自泛型类型（genericinst 占位）与跨版本混淆改名。

附带负结果：为 GENERICINST 找泛型实例表，试了三种结构扫描都没命中——
16 字节 {argc, pad, argv_ptr}、24/32 字节 generic-class 记录（typeDefIndex, 0, 指针）、
以及 metadata body 内的 generic class 表（stride 8/12/16/20/24，首列 <86,932 的行占比 >0.9）
——0 个候选。GI 泛型实例表要么指针被加密，要么行布局不同，需另找入口（如运行时构建函数）。

### 3.2q.1 属性访问器解码参数

属性行 16 位列需要按列 kind 正确解释：getter 是 SubMaskAddC16（raw − mask_low16 + 0xFFFF945B），
setter 是 XorCSubMask16（(raw ^ 0xFFFFC45A) − mask_low16），最后都 &0xFFFF；用错成 32 位 xor
会解出 5 万级“索引”，与“访问器是每类型相对方法索引”矛盾。method_rows.col_value 已补此 kind。

### 3.2r 7.0 第一份端到端类型清单（dump70-partial）（2026-10-18）

新增 tools/version-triage/dump70_partial.py，用已解布局输出 7.0 全量类型清单
（~/gire/out/cross/dump70-partial.txt，63.8 MB）：

- 类型 86,932；字段 430,290；属性 112,949；方法 713,956；
- 每个类型带 TypeDefIndex 与字段/方法/属性计数；字段/属性/方法都渲染了真实类型名
  （类/值类型/基础类型/指针/数组/byref），泛型仍是 genericinst#N、!n、!!n 占位。

样例（与 7.1 dump 的 corelib 开头一致）：

    type Locale
    {
      System.Void .ctor()
      System.String GetText(System.String msg)
      System.String GetText(System.String fmt, System.Object[] args)
    }

这份清单还不是可编译的 dump.cs：typeDef flags（class/struct/interface/enum）、属性、
RVA/Token/Slot、泛型实例名都还没有；但“表 → 名字/类型”的端到端通路已经打通，后续
每补一个表（flags、slot、泛型）就可以直接注入。

### 3.2r.1 GENERICINST 表的负结果（2026-10-18）

为定位泛型实例表又做了三轮扫描，全部 0 候选：

1. exe 内 16 字节 {argc, pad, argv_ptr} 记录（argv 需指向 typearr 内 VA 数组）；
2. exe 内 24/32 字节 generic-class 记录（首列 typeDefIndex，第二列 0）；
3. metadata body 内任意列 <86,932 的规则表（stride 8/12/16/20/24/32/40/48/64，命中率 >0.97）。

结论：泛型实例表很可能在加密指针区域（7.0 的 .data 全局指针是密文，如 0x35125d183ea8b34e），
需要找到运行时全局指针解密例程才能静态还原；这条线索下一轮再挖。

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
