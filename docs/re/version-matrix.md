# 跨版本 triage 矩阵与通用常数确定方法（2026-10-15）

> 工具：tools/version-triage/（triage.py 全自动推导 / run_all.sh 批跑 / phase_c2.py typeDef 后处理 / matrix.py 矩阵）。
> 原则：零硬编码 VA/常数/stride，全部从指令与数据现场推导。输出在 out/*.json。

## 1. 核心结论

1. **常数逐版本全轮换**：相邻版本 (槽,OP,常数) 集合 Jaccard ≈ 0.00–0.25。
   连 typeDef 表的槽位号都在漂移（6.1.0=0x12C、6.3.0=0xE4、6.4.0=0xE0、6.6.0=0xE8、6.7.0=0x1E0、7.1.0=0xDC）。
   ⇒ 「常数库跨版本复用」不可行；**代码推导管线本身就是唯一通用方法**（这正是本工具的价值）。
2. **triage 方法已验证**：6.0.0/6.1.0/6.3.0/6.4.0/6.5.0/6.6.0/6.7.0/7.1.0 共 8 个版本的 typeDef 基址
   与历史独立推导结果**逐位一致**（见 §3 表）。注意 6.5.0 base=0x20A0 曾被旧日志判为「不合理」——本次以
   50 站点 + 多数判据复核为**正确**，旧判定撤回。
3. **行 stride 稳定区**：6.0.0+ 的 typeDef 行长恒为 70（0x46）；5.4.0/5.7.0/5.8.0 出现 stride=88 候选
   （n=3，需列级复核——可能是该纪元行长不同，也可能命中了别的表）。
4. **哨兵列位置也在漂移**：各版本 typeDef 行内「-1 多数列」的偏移不同（7.1.0=+0x1C 占 0.824；
   6.3.0/6.4.0 的 0x1C 列占 0.736；6.0.0/6.5.0/6.6.0/6.7.0 的 0x1C 无多数，多数列在 0x18/0x24/0x28/0x2C）。
   ⇒ 跨版本列语义判定也必须逐版本做（0x1C=elementTypeIndex 只是 7.1.0 的事实）。

## 2. 覆盖率（26 版）

| 分类 | 版本 | 说明 |
|---|---|---|
| 常数全推导 + typeDef 验证 | 6.0.0 6.1.0 6.3.0 6.4.0 6.5.0 6.6.0 6.7.0 7.1.0 | 槽 30–49 个、typeDef 基址多数判据通过 |
| 常数推导、typeDef 待补 | 4.8.0 5.0.0 5.1.0 5.2.0 5.3.0 5.5.0 5.6.0 6.2.0 7.0.0 | 7.0.0 已定位缺口：槽 0xC4 记录 op=None（常数以寄存器预装形式存在，超出当前回看窗口）；6.2.0 同类 |
| stride=88 候选（需列级复核） | 5.4.0 5.7.0 5.8.0 | n=3 站点 |
| 成语形态不同（另一纪元） | 4.2.0–4.7.0 | 每版仅 1 条记录，与旧结论「该纪元 0 表恢复」一致，需要另一套识别器 |

## 3. typeDef 表逐版本推导结果（stride=70 组）

| 版本 | 槽 | OP | 常数 | base | 站点 | 多数列 | 与历史结果对照 |
|---|---|---|---|---|---|---|---|
| 6.0.0 | 0xB8 | xor | 0x5F815D53 | 0x1D6BD4 | 48 | +0x2C | 一致 |
| 6.1.0 | 0x12C | xor | 0x46A23FE6 | 0x10050B8 | 50 | +0x14 | 一致 |
| 6.3.0 | 0xE4 | xor | 0x40F8965A | 0x76387C | 50 | +0x0 | 一致 |
| 6.4.0 | 0xE0 | xor | 0x584D480A | 0xE7579C | 47 | +0xC | 一致 |
| 6.5.0 | 0xB8 | xor | 0x65DDFF7C | 0x20A0 | 50 | +0x18 | 一致（旧「不合理」判定撤回）|
| 6.6.0 | 0xE8 | xor | 0x786B40A8 | 0x3E7AD7C | 51 | +0x24 | 一致 |
| 6.7.0 | 0x1E0 | xor | 0x4E66A4F6 | 0x21F77B0 | 49 | +0x28 | 一致 |
| 7.1.0 | 0xDC | xor | 0x5278CA3B | 0x48F3FD8 | 48 | +0x1C | 一致 |

## 4. 相邻版本快速梳理 SOP（新版本到手 30 分钟内）

1. bash tools/version-triage/run_all.sh（或单跑 triage.py <exe> <dat>）→ out/<ver>.json
2. python3 tools/version-triage/phase_c2.py out → typeDef 候选 + 每列多数画像
3. 用相邻版本的 out/*.json 对照：槽集合差异、typeDef 槽位迁移、多数列漂移
4. 列级常数（name/flags/bitfield/mask2）：
   - flags/bitfield 在 .upx0 变异函数里读（7.1.0 = 0x159F63C4D；其它版本先找 sub_14051db00 等价 thunk）
   - name 列走既有 find/solve 统计求解（6.2.0 缺名列表仍有待解）
5. 验证锚点：rows 0–4 应为 <Module>/Locale/SR/Mono.Runtime/Mono.RuntimeClassHandle（§25）

## 5. 已知缺口与下一步

1. triage 窗口对「常数寄存器预装」形态覆盖不足（7.0.0/6.2.0 的 op=None 记录）——
   扩展：回看窗口 0x30→0x80、支持 movabs imm64、跨基本块追一次 def-use。
2. 5.4/5.7/5.8 的 stride=88 候选需列级复核（行内多数列分布完全不同）。
3. 4.2–4.7.0：该纪元取表成语形态不同（无 HDR/BODY 全局对？），需单独逆向一个版本确定新形态。
4. 列语义（elementTypeIndex/flags/bitfield 的列位置）逐版本漂移，需要用 .upx0 读码逐版确认，
   或发展「已知明文锚点」（<Module> 行 flags=0、Mono.RuntimeClassHandle=sealed|vt）做列定位。

## 6. 相邻版本 profile 推导实测：6.7.0（2026-10-16）

按 §4 SOP 首次全流程跑通一个非 7.1 版本的**列级**推导。产物：`out/6.7.0.columns.json`。

### 6.1 自动层（零新工具，全部复用）

- `mhydump cipher`：3 常数世代，strsec=0x4126798，score=15119，堆首条 mscorlib ✓。
- `mhydump anchors`：354 个槽锚点；typeDef = hdr[0x1E0]^0x4E66A4F6，stride 70，base=0x21F77B0（与 triage 互证）。

### 6.2 数据驱动层（新工具 colsolve2/colsolve4/colverify）

**方法**：行 0–8 是已知明文（`<Module>`/`Locale`/`SR`/`Runtime`/`RuntimeClassHandle`…），
密码已解 → 直接在数据上解每列常数，再用全表统计/链式判据验证。**不需要读任何代码**。

已定案（60k 行验证）：

| 列 | disp | op | K | 证据 |
|---|---|---|---|---|
| name | 0x18 | xor | 0x17FB1577 | 行 0–9 解密全对，32/32 可打印 |
| flags | 0x04(u16) | xor | 0xFD91 | row0=0、Locale=0x100、SR=0x180、句柄=0x108；可见性分布 sane |
| fieldStart | 0x14 | xor | 0x1D37F888 | 哨兵 raw=0xE2C80777→0xFFFFFFFF |
| fieldCount | 0x38(u16) | xor | 0xEB4C | fs/fc 铺瓦链 **60000/60000，0 坏行**，总字段 290,507，max=859 |
| parent | 0x0C | xor | 0x4DFA3BEC | 哨兵 12.8%，值跨度 232,434 |

未解（下一轮）：ns、methodStart/Count、elementType、bitfield —— 静态 xor/add 形态全部不匹配，
疑似**行级掩码**（7.1 只在方法表见过掩码；6.7.0 可能扩展到了 typeDef 的 ns/start 列）。

### 6.3 关键新事实（比 7.1 认知更进一步）

1. **行锚点逐版本不同**：6.7.0 的 Mono 类型名**无前缀**（`Runtime` 而非 `Mono.Runtime`）——
   跨版本锚点必须从数据里现找（colsolve2 的 `<Module>` 全堆扫描），不能拿 7.1 的锚点表硬套。
2. **堆字符串无对齐、无终止符、紧打包**（长度在索引 byte3）：8 对齐扫描找不到 `<Module>`（在 0x14）。
   colsolve2 的 numpy 非对齐滑动解密是正确姿势。
3. **列位置逐版本重排**：name 0x14→0x18、fieldStart 0x00→0x14、flags 0x0C→0x04。
   「7.1 布局 + 轮换常数」假设不成立；每列语义必须独立求解+验证。
4. **变换方向双向**：`.upx0` 变异码里常数先行（`mov edx,K; add edx,[r15+disp]`）与加载先行两种
   都有；densescan3（双向+寄存器族归一+垃圾容忍）已用 7.1 已知常数校准过（name/flags 双中）。
5. flags u16 化：6.7.0 flags 是 u16（7.1 是 u32 列）。

### 6.4 新工具链（tools/version-triage/）

- `colsolve2.py`：非对齐堆锚点扫描 + 行 0 明文求解（`<Module>` 唯一命中）。
- `colsolve4.py`：**相邻版本 typeDef 列求解器**——name/ns/flags/bitfield/start/count/element/parent
  全自动（明文锚点 + 单调性 + fs/fc、ms/mc 全表链式判据）。6.7.0 实测解出 5/9。
- `colverify.py`：假设 JSON → 全表验证（分布/链/哨兵），产出证据记录。
- `densescan3.py`：`.upx0` 全段列成语扫描（4KB 重同步、双向变换、垃圾容忍），找行消费函数。

## 7. derive 分析层 26 版全量实测（2026-10-17，R10 模块）

`mhydump derive`（字符串密码 + 槽锚点 + 表基址，含 mscorlib 自检）对样本库 26 版逐一跑：

- **20 版 exit=0**（4.8.0 5.0.0 5.1.0 5.2.0 5.3.0 5.4.0 5.5.0 5.6.0 5.7.0 5.8.0 6.0.0 6.1.0 6.2.0 6.3.0 6.4.0 6.5.0 6.6.0 6.7.0 7.0.0 7.1.0）；
- **6 版 exit=1**（4.2.0–4.7.0，已知另一纪元形态，需扩识别器）。
  **2026-10-18 更正**：4.3.0–4.7.0 的 MHY 头在 YuanShen_Data/Native/UserAssembly.dll（不在 exe）；
  以 DLL 作为 --exe 传给 derive 后 5 版全部成功（cipher + typeDef 表，stride 74）。只有 4.2.0 的
  exe 与 DLL 都没有 MHY 魔数，仍待专项定位。derive 覆盖面因此为 **25/26**。

交叉验证：6.0.0/6.1.0/6.3.0/6.4.0/6.5.0/6.6.0/6.7.0/7.1.0 的 typeDef 表常数与 §3 历史独立推导**逐位一致**
（0x5F815D53/0x46A23FE6/0x40F8965A/0x584D480A/0x65DDFF7C/0x786B40A8/0x4E66A4F6/0x5278CA3B）。

新增实测事实：
1. 6.2.0 / 7.0.0（triage 曾报 op=None 寄存器常数缺口）**derive 能恢复 typeDef 表**（0x99E75364 / 0xC42E5C8F）。
2. 5.4.0/5.7.0/5.8.0（triage 报 stride=88 候选）derive 给出 stride 70 的表——候选表非 typeDef 的可能性上升，需列级复核。
3. 4.8.0/5.0.0 的首表 stride=74（5.1.0+ 回到 70）——stride 纪元边界新线索。
4. 表列表首项在 6.x/7.1 组与历史逐位互证，可认定为 typeDef 表；5.x 组的首表身份**未独立验证**（仅知 derive 能出表）。

**该覆盖是机器层（解密+定位表）的能力边界，不代表端到端 dump 覆盖**：列常数/profile 层目前仅 7.1.0 完整（见 §6 的 6.7.0 进度）。
