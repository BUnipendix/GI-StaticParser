# 零接触提取战役报告（R68–R70，2026-10-25）

目标（用户 R12 的延续）：未来版本**零或轻微调查**即可解析。本轮把「人工读汇编提常数」升级为
自动化管线，并用 5 个从未处理过的版本测了真实零接触率。

## 1. 新管线组件（全部无常数、可复用）

| 组件 | 作用 | 状态 |
|---|---|---|
| `symwalk.py` | builder 函数窗口**线性符号执行**：自动提取 hdr 锚点 (slot,op,imm)、行索引掩码链（含 mask2 派生）、行列公式（表达式树 JSON） | 回归 12 目标：掩码链 11/12 组全常数；7.1 方法链+mask2、7.1 事件 movabs 链、7.0 参数/属性表全过 |
| `exprvm.py` | 表达式树 → numpy 向量化求值（含 ext/lo 截断语义） | ✓ |
| `rowtable_solve.py` | 数据侧语义求解器：name 列（堆已知明文反解 C + 堆命中率/标识符率验收）、count 列（u8 众数）、start 列（哨兵钉 C + 非哨兵=累计数全表校验）、flags 列 | **6.7 方法表端到端回归：四列常数与人工逆向全部一致**（name off8 XorCSubMask 0x6bbf48d / count off24 +0xA8 / start off0 0xd62b555 链 0 违例 哨兵 385952/385952 / flags off20） |
| `chain_hunt.py` | 向量化 imul-imm32 簇扫描（形态转移失败时的兜底链发现） | 全 .text 23,807 簇头 / 3s；walk 环节是瓶颈，留优化 |
| `auto_tables.py` | mini-编排器：6.7 多表种子 shape_transfer → symwalk 匹配函数 → 链/列/基址落盘 | 5 版 × 5 表全跑通 |

种子即数据：`auto_tables.py` 内 SEED_67 表 = docs/re/artifacts-6.7.0 已验收常数，不在求解代码里。

## 2. 零接触战役结果（6.1/6.2/6.3/6.5/6.6 从未处理过）

| 版本 | param 表 | method 表 | 备注 |
|---|---|---|---|
| 6.6.0 | **✓ 零接触全解**：base slot 0x1CC^0x7706e77e=0x2E85D00、链 r12*0x7b3d+0x144e21a0^0x789842eb*0x19beb26f>>0xf（+派生）、name 0x37c37ea、type 0x4539395f；解码验证 resourceFormat/exception/out_ptr…，标识符率 98/98 | 链未定位（open） | 形态转移 5/5 语义命中 |
| 6.5.0 | **✓ 零接触全解**：base 0x19D8E6C，name/type 列公式直接解码（resourceFormat/exception/freeStruct/parser/attrs，572 行命中） | open | |
| 6.3.0 | 链已提取（fn 0x140467bc8 同时含 26i stride 与链 ((0x3770bdb16890*i)>>0xf)^0x43b7ca2c)+0x2e937253）；name 列公式未捕获 | open（基址候选未验证） | |
| 6.2.0 | 链+8 列已提取，解码未过验收 | open | |
| 6.1.0 | 链+9 列已提取，解码未过验收 | open | |

全部产物在 `~/gire/out/zero-touch/<ver>.json` + `<ver>.<table>.walk.json`。

## 3. 已定位的边界（下轮工作面）

1. **方法表链发现**是最大缺口：6.6 方法链函数不在锚点密集区（0x1404A0000–0x140500000 密扫无
   stride-26+链共存窗口）；解码器调用点定向（52 个 call 站点）只覆盖惰性访问器外围。
   → 需要把 chain_hunt 的簇 walk 做成有界并 ranking（按簇内 imul 密度+shr 共现打分，top-N），
   或用 6.5→6.6 相邻版本种子重试形态转移。
2. **列公式捕获不全**：6.3 方法 walk 只有裸 raw 列（变换在窗口外/别的函数）；需要把
   rowtable_solve 的数据侧 name/count/start 求解与 symwalk 列表达式合并消费（现在是两条路）。
3. **oracle 对比未做**：6.1–6.5 有官方 dump（~/gire/out/oracle/），本轮只做了堆解码自洽验证；
   oracle 逐名比对留作下一步。
4. symwalk 已知漏项：16 位访问器列（getter/setter 0x945b/0xc45a 类）在部分版本未捕获——
   由数据侧 brute（2^16 空间）可补。

## 4. 结论

- 「算法=函数形态，常数=形态内立即数 + 数据判据验收」这条通用路线在本轮被 6.7 回归与
  6.6/6.5 零接触解再次证实；
- 对**相邻已知版本**（如 7.1→7.2），预期路径 = derive（已 25/26 版）+ auto_tables（形态转移）
  + rowtable_solve（数据验收）三条全自动化链；残余人工点集中在「方法表链函数定位」一处。
- 6.4 遗留（方法 name/paramStart）未动，工具已具备再攻条件（oracle_column_bf + 本轮求解器）。
