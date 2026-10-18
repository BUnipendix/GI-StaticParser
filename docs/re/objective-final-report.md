# 目标完成度报告：泛化 GI il2cpp dumper 到历史版本

生成时间：2026-10-18（第 40 轮，goal 计时上限）。本报告如实记录证据、完成度与剩余工作。

## 1. 结论（先说结论）

- **已达成「通用方法 + 跨版本差异 + oracle 端到端验证」的完整样例：7.0.0 与 6.7.0 两个版本。**
  两个版本的 profile 都是纯数据 JSON（表基址/stride/掩码链/列常数/列掩码），工具零硬编码版本常数，
  并分别用 7.1 dump 做 corelib 逐类型对照。
- **6.4.0 部分完成**：typeDef 全验收；方法表 base/stride/掩码与 paramCount 已用 6.4Dump 逐条验证
  （60/60）；paramStart/name 与字段/属性表仍只是候选（未验证）。
- **6.0.0 / 5.4.0 / 7.1.0 只到 typeDef 级**；5.x、6.1–6.3、6.5–6.6 只有 derive 产物；
  **4.2–4.7 纪元尚未开始**（按目标最后处理）。
- 因此目标**尚未全部完成**，goal 保持 active（未标记 complete）。

## 2. 已完成证据

| 版本 | 内容 | 验证 |
|---|---|---|
| 7.0.0 | typeDef/方法/参数/属性/字段/typearr/类型分类（class/struct/interface/enum 114/114） | verify_70.py 13 项 PASS；与 7.1 dump：返回 99.6%、参数 98.1%、字段 99.0%、属性 91.9%；dump70-partial 全量清单 |
| 6.7.0 | typeDef/方法(name/flags/returnType/paramStart/paramCount)/参数/typearr/事件/字段/属性 | 与 7.1 dump：字段 100%、返回 100%、参数 100%、属性 96.3%；dump67-partial 全量清单 |
| 6.4.0 | typeDef 全验收；方法表 base/stride/mask；paramCount 列 | 6.4Dump 前 60 方法参数个数 60/60；typeDef 清单 Jaccard 0.961 |
| 7.1/6.0/5.4 | typeDef 表、区间、类型清单 | R28–R31 的链式/清单验证 |

## 3. 可自动化的 profile 管线（已成型组件）

| 组件 | 作用 |
|---|---|
| mhydump derive | 每版自解密码 + hdr 锚点（cipher 无法跨版搬运） |
| tools/version-triage/loadsites.py | hdr 载入点 + 常量无关指纹 |
| shape_transfer.py | 用语义种子函数指纹跨版定位同源函数（7.0→6.7 已验证） |
| decode_params.py | 用数据 JSON 解码方法/参数（7.0/6.7） |
| oracle_column_bf.py | 有 dump 时自动穷举列偏移×变换族×常数（6.4 paramCount 自动复现） |
| diff_profiles.py | 两版 profile 差异报告（结构可继承 vs 常数逐版重导） |
| status_matrix.py | 26 版本覆盖矩阵（version-status.md） |
| verify_70.py / validate67.py | 回归门禁 / oracle 对照 |

## 4. 剩余工作（按优先级）

1. **6.4**：方法 name/paramStart、字段/属性/事件表——目前常数已读出但数据验收未过（行索引或表身份
   语义仍错）；建议用 6.4Dump 做更强的 oracle 约束搜索（已知名字→列/常数），或继续追 cipher 解码
   调用者找惰性 name 访问器。
2. **6.0 / 5.4**：按 6.7 流程（形态转移 + 代码读常数 + oracle 列暴力）补方法/参数/字段/属性表；
   两版都有 dump 可做 oracle。
3. **5.x / 6.1–6.3 / 6.5–6.6**：先 derive→sites→shape，再按同流程补表。
4. **4.2–4.7 纪元**：代码在主 exe 外（UserAssembly.dll），需要单独的模块发现与加载流程；
   4.2.0 无 MHY 头，4.3–4.7 在 UserAssembly.dll 内。
5. 收尾：把 7.0/6.7 已验证的 profile 接回 dump.cs 生成器，跑通端到端产物并与 oracle 全量 diff。

## 5. 经验与教训（已固化在 constants-index.md）

- 结构（stride/列语义/行数）可跨版继承；**常数（slot/imm/掩码/列常数）必须逐版重导**；
- 同一族构建器指纹相似，**行数是判别表身份的第一依据**（属性 108,747 / 事件 617 / 字段 413,644 / 方法 687,467）；
- 无已知明文用窗口性质、有明文用 oracle 反解；7.0 字段 type 窗口解曾经错过，必须用已知明文复核；
- 8/16/32/64 位截断、掩码链乘法次序都是易错点（已踩坑记录在各节）；
- 泛型实例表在加密指针区域，多轮结构扫描 0 候选，需先解全局指针解密例程。
