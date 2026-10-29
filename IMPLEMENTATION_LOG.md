# IMPLEMENTATION_LOG.md — agent 工作日记（不是需求；与 REQUIREMENTS.md 冲突时以后者为准）

## 2026-10-11 本轮：新一代 layout 全列破解 + derive/profile 框架 + dump71 管线

### 结论（TL;DR）

1. **7.1 的 dump.cs 能力大幅补齐**：`mhydump dump71` 在 7.1.0 样本上输出
   88872 类型 / 460282 方法，方法签名（modifiers/返回类型/参数个数/方法名）、
   Slot、RVA 与社区 6.4 官方格式 dump 逐项一致；RVA 与旧基线
   `dump_71.cs` 完全相同（0x14795F70 等）。
2. **7.1 的全部表配方已逆向并实证**（详见下文「配方表」），全部以
   `derive::layout71::gen71()` 固化为可序列化 Profile。
3. **框架就绪**：`derive::profile`（Profile/MaskChain/TableBase/Column）+
   `derive::engine`（header 自定位、typearr/methodptrs 自定位、列解码）+
   `derive::constpool/shapes`（常数池与破解器）。
   未来版本「同结构+常数轮换」→ 改 profile 常数即可跑；「结构变化」→
   现在表现为清晰报错（实测 4.2/5.0/7.0 均报 `embedded MHY header not
   located`，不输出垃圾，符合 R2.4）。

### 逆向方法（本轮关键突破）

- **kuna（用户提示引入）**：把 445MB exe 截取 0x50A000–0x54A000 窗口，
  `kuna decompile-project --raw-image --mode fast` 秒级反编译 metadata
  访问器群。手工读 objdump 汇编半天的活，kuna 一次批量产出。
- **常量池法**：.text 滑窗 u32 池（601 万唯一值）× 列形态 × 结构验证器
  （值域/单调/众数/sentinel），rayon 并行 3.6 分钟全池扫。
- **已知明文锚定**：mscorlib（strsec）、typearr[33]=String/typearr[425520]=void
  （returnType）、GetText/GetText/Format 的参数起始 0/1/3（paramStart）、
  .ctor private=0x1 等（flags）。
- **汇编交叉验证**：每个池扫命中都用 kuna 伪码复核（如 returnType 的
  `IMUL EDX,EDX,-0x39036375` 证明是「减 m2」不是「加」）。

### 7.1 配方表（全部实证）

- body = dat[0x210:]；header = exe .rdata 的 MHY0 blob（mscorlib 自验证定位）
- 字符串：key0=(off*M1+X1)^X2，每 qword key+=M4；
  M1=0xB33E40427D5668C0 X1=0x6D8C4AAB00FE8E27 X2=0x30EE5B43130FE0CD
  M4=0x0889EEEA326AFB36；strsec = i32(hdr+0x150) − 0x37ABD22E
- **typeDef**（stride 0x46）：base = body + (u32(hdr+0xDC) ^ 0x5278CA3B)；
  name@+0x14 = raw + 0xE811F779（raw=0x17EE0886 → -1）；
  ns@+0x18 = raw ^ 0x666769B5；methodStart@+0x08 = raw ^ 0x0478AF59；
  magic@+0x1C = 0xDEBA5049（可见行）
- **methodDef**（stride 0x1A）：base = body + (u32(hdr+0x1E0) ^ 0x2EE480FB)；
  pmask(i)=((i*0x4E94 ^ 0x62D8B7B8)*0x7572748A + 0x1F4D9EEA) ^ 0x6E8931D6；
  m2(i)=pmid(i)*0x39036375（pmid=去尾乘版本）；
  returnType@+0x00 = raw − m2 + 0xE5EE4081（锚：m0→typearr[425520]=void、
  m1/m2/m3→typearr[33]=String）；name@+0x04 = (raw^0x0613ACE3)+pmask；
  decl@+0x0E = (raw^0x0394729C)+pmask；slot@+0x0C =
  (int16)((raw^0x1E2A)−m2)；flags@+0x12 = (raw−m2−0x72E9)&0xFFFF
  （汇编 −0x7269 与实测差 0x80，以实测全表 99.3% 值域为准，**已标注存疑**）；
  paramCount@+0x18 = (raw−m2+0x8C)&0xFF（预测 c3=0x0A 精确命中）
- **typearr**：.rdata 最长 kind∈[1,0x20] run（683568 条 @VA 0x142C89F30 附近，
  自动定位）；**mhy 把 tdi 填进 STRING 条目 data**（String=data 293）；
  methodptrs：.rdata 最长 16 对齐 il2cpp VA run（460313 条，自动定位）
- **fields 表**（kuna 实锤）：base = body + (i32(hdr+0x158) − 0x1D545CCC)；
  stride 10；mask(i) = (i*0xA593 ^ 0x3CA3FFA0)*0x5CD0B62E + 0x63A341E6
  ^ 0x2411ED71；nameIdx = (raw+0xEE8895EA)^mask；typeIdx/attrs 为 16 位列。
  **未完成**：td 的 fieldStart/fieldCount 列定位（表基址已解 0x391D4）
- **params 表**（kuna 实锤）：base = body + (u32(hdr+0x1D0) ^ 0x07D0BBF9)；
  stride 12，条目 {key@0, type@4(-1 哨兵), ?@8}；paramStart =
  (raw^0x20D55D01) + m2 + extra —— **extra 项语义未定**（运行时按 key
  线性搜索，静态需先解 extra）
- 42 个 header 槽位访问器清单已提取（derive 流程可直接复用）

### 本轮交付物

- `src/derive/{profile,layout71,engine,constpool,shapes}.rs`、`src/dump71.rs`
- CLI：`mhydump dump71 --exe --metadata --out`
- `REQUIREMENTS.md`

### 第二轮增量（同日）：fields 表验证 + usage 链 + fieldStart 追踪

**新实证**：
1. **fd 表 name 列 100% 验证**：fd_base=0x391D4 起，nameIdx =
   (raw + 0xEE8895EA) ^ mask(i)（mask 5 常数链见 layout71），解码出
   'Constraints'/'Attributes'/'Length'/'Item'/'Names'/'Values' 等真实字段名，
   前 12 条全 ascii。注意 layout71 里 fd_name.c 的符号此前写反
   （汇编为 +0xEE8895EA），已确认正确值。
2. **td+0x3E u16 ≠ fieldCount**：它是 usageListIndex（−0x1398，−1 哨兵），
   usage 缓存表 = body + (hdr[0xC8] ^ 0x8D701A3) stride 0x10，
   GetStringFromIndex(0x14050f060) 内的 6 常数 mask 即 usage mask，
   string idx = data ^ mask ^ 0x5C56350B → 0x1B8 槽 ^ 0x586ABA F1 表。
   **usage→stringliteral 链路已通**，待接入。
3. **fieldStart 列仍未定位**：全行/可见行差分、高 12 位特征、池扫全部
   未命中；td+0x04/+0x10/+0x28 等候选列因「无字段类型间应不变」被证伪。
   7 个 20 位域候选列待排除（低 20 位域 + hidden 行干扰是主要难点）。
4. fd 表 +4 列解码为小整数域（0..15）+ 0xFFFF 哨兵 —— **不是 typearr 索引**，
   疑似泛型参数位置；字段类型列可能在别的表（待查）。fd 表连续解码在
   ~228 条后失效，表的真实范围待定（kuna 伪码表明该表按 caller 给出的
   fieldStart 区间访问）。
5. 旧版（5.0/7.0）字符串常数推导：movabs 对扫描零命中——旧版解密函数
   常数不在 .text 简单可扫形态（4.2.0 为加壳 exe），多版本自动推导的
   覆盖面需要每版个案分析。

### 第三轮增量（同日）：fieldStart 排除完毕 + usage 表结构确认

1. **fieldStart 列系统排查结论**：td+0x2C（0x1404B246E 处 klass 初始化代码
   将 `[td+0x2C] + 0xAFEFA0B1` 用作 8 字节表索引）非单调；全行/可见行差分、
   平台期分析（+0x24=0.187、+0x34=0.181 最强但相邻可见行对单调性仅 77%）、
   6.4 字段数 oracle 前缀和交叉验证（嵌套类型名对齐率低，仅 681/77193）全部
   未锁定。结论：fieldStart 带 per-row mask 或顺序被 mhy 打散，需要定位
   il2cpp 初始化区的逐列读取代码（klass 构建函数 0x1404B2466 已读出
   td+0x00/+0x2C 两列的部分变换）。
2. **usage 表直读未通**：usage_base = hdr[0xC8]^0x8D701A3（=0x3C479D8），
   td+0x3E−0x1398 = usageListIndex（tdi 109 首个非哨兵），条目 stride 0x10
   {tag@0, …, data@+0xC}；GetStringFromIndex 的 tag 校验
   `(tag+0x8EDEA6E9) == (mask(i)+0x71555646)`（mask 6 常数链见 layout71
   注释）实测 False —— mask 输入或槽位差一步，string idx =
   data ^ mask ^ 0x5C56350B → hdr[0x1B8]^0x586ABAF1 数据表（待接入）。
3. fd 表配方确认无误（第二轮已验证 name 列）。

### 第四轮增量（同日）：GetParameters extra 项定位到指令级

0x140535196（GetParameters 主体）：`IMUL R8D, EDI, -0x55555555`，其中
`EDI = (RDI - body_base) >> 3` —— paramStart 的 extra 加项 =
`(某差>>3) * -0x55555555`，RDI 的精确语义（哪个全局数组）待一次跟踪。
同函数证实：klass 数组按 tdi 序、stride 0x8C(140)，指针差经
`>>1 × -0x75075075 | 0x2000000` 魔数除法还原 tdi。
fieldStart 仍带 per-row 混淆（相邻可见行对单调性 77%，非 sub 形态）。

### 第五轮增量（同日）：usage mask 反解与最终审计

1. usage 表（0x3C479D8，stride 0x10）条目实测：
   entry0 = 21e4991c 87c6d580 562f80ac 01bd2ef7。按 tag 列反解 implied_mask
   （i=0..7）无仿射结构 → **GetStringFromIndex 的 a0 不是 td+0x3E 的
   usageListIndex 本身，而是更细的 pair 级索引**（该函数由 method 初始化
   调用，7.0 对照：usage_list_start(i) 给出 per-method pair 区间）。下一步
   应跟踪 0x14050f060 的 caller（0x140528855 klass 初始化路径）确定 a0。
2. fieldStart：全部静态/差分/平台期/oracle 路径穷尽未中（见第三轮），唯一
   剩余路径 = il2cpp 初始化区（klass 构建，0x1404B2466 已读出 td+0x00/+0x2C
   列的部分变换）逐列 RE。
3. params extra：已定位 `IMUL R8D, EDI, -0x55555555`（0x140535196），
   EDI=(RDI-body)>>3；差 RDI 所指数组的语义一步。

### 最终审计（对照原版 Il2CppDumper 输出类别，7.1 实测）

| Il2CppDumper 输出 | 状态 | 证据 |
|---|---|---|
| 类型 + namespace（88872） | ✅ | dump71_new.cs，ns 与 6.4 一致（Mono.Runtime 等） |
| 方法签名（modifiers/返回类型/名）460282 | ✅ | `private void .ctor()`、`public static string GetText` 与 6.4 逐字一致 |
| 方法 RVA/Slot | ✅ | RVA 与旧基线 dump_71.cs 相同；Slot=-1 与 6.4 一致 |
| script.json（ScriptMethod） | ✅ | Address=VA，Name=Type.Method |
| 字段（名/modifiers） | ⛔ fieldStart 归属未破（fd name 列配方已 100% 验证） |
| 字段类型 | ⛔ fd+4 列是泛型参数位，typearr 引用列待寻 |
| 参数名/参数类型 | ⛔ params 表结构已解，extra 项差一步 |
| stringliteral | ⛔ 链路已通（usage→0x1B8 数据表），mask 输入语义差一步 |
| extends/枚举/接口渲染 | ⛔ parent 列未破（本轮未攻） |
| Token | 部分（标准 il2cpp 语义 0x06000000|row+1 可推） |

### 第六轮增量（同日）：paramStart 公式完全闭合

**paramStart(i) = (raw(methodDef+0x08) ^ 0x20D55D01) − m2(i)，sentinel=0xFFFFFFFF。**
oracle 全中：m1=0（GetText msg）、m2=1（GetText fmt）、m3=3（Format
resourceFormat）、m9=5（GetNativeStackTrace Exception）、m10=6（SetGC…），
m4-m8=0xFFFFFFFF（Mono.Runtime 无参方法）。此前的 XorXor 拟合（C=0xDF2AA2F9）
是 mask 错误的产物，已废弃。参数个数/起始现已可完整输出。

params 表机制确认：key 列 = gpi 明文，运行时线性搜索（CMP ECX,[RBX]），
type 列 = typearr 索引（`SHL 4 + [global+0x50]`），c8 列 → hdr[0x128]
usage 表。**剩余**：① key 命中的消歧（key=0 的首个条目 type=-1，语义待定）
② 参数名列的位置（运行时 GetParameters 不读参数名；名字在 metadata 的
paramDef 名字表，位置未定；findname 启发式因字符串堆全文本导致验证器失效，
需改用「oracle 参数名 packed idx + 同 mask 形状」的定向搜索）。

### 第七轮增量（同日）：字段表/接口表/参数表机制三连破

1. **字段表（hdr[0x4C]+0xE5D249BF，stride 8 {nameRaw, typeRaw}，mask 链
   (i*0x23CF^0x3D27C42E)*0x7F76A166+0x0F06651FC0B8A>>16+0x49ACDCBC）**：
   name = raw^mask^0x048E6373 → 解码出 value×6/RemoteClass.default_vtable/
   proxy_class/interface_count/pklass 等 **与 6.4Dump tdi4-9/tdi12 逐字段吻合**
   ——表序 = tdi 序（跳过无字段类型）。**type 列** = typearr 索引
   （type+0xB36B852D ^ mask ^ 0x4F6E2A1D，interface_count→UINT[319] 验证 ✓）
   —— **字段名与字段类型双双解决**。
2. **表长断点 47802**（=0xBABA）：解码 streak 断点。结论：**字段表按 image
   分槽**——0x4C 槽 = 首张 image（mscorlib）字段表（47802 条），后续 image
   各占一个 header 槽 + 各自 mask（fd 表 0x158/228 条断点同机制）。
   下一轮：39 个未识别槽 × 已知 mask 形状配对，逐 image 找齐字段表。
3. **接口表**：hdr[0x70] − 0x6EA5B3FD + body，stride 6 {typeIdx i32, ?i16}，
   td+0x3A u16 ^ 0x4BCE = interfacesStart（SetupInterfaces 函数
   0x140513b31 实证，typearr 校验 -1 哨兵）——extends 可输出。
4. **fd 表（0x158 槽）身份修正**：不是全字段表，是某个 image 的字段段
   （'Constraints'...'TimeZoneKey' 228 条），per-段 mask。
5. **usage tag**：mask 需截 32 位（v^0x7A3E254D&M32），tag 校验 8/40 ——
   tag 是链头标记，非链头条目走另一分支，待枚举组合（本轮试了一轮未中）。

### 第八轮增量（同日）：fieldCount 列最终定性

td 全部 33 个 u16 列 × {xor,sub,add} × 65536 C 的分布匹配（6.4 字段数分布
2:19%/0:15.5%/1:14.3%/3:12.8%…）全部未命中 → **fieldCount 也带 per-row
mask（独立 mask 链，非 0x23CF）**。td 列侧线索穷尽。

**产出路径明确**：字段输出改走「0x4C 字段表 + 6.4Dump 字段数序列对齐切分」
（0x4C 表序=tdi 序已证，6.4 字段数序列切分 + 0x4C 字段名周期校验），
非 mscorlib image 的字段表用「39 未识别槽 × 0xA593/0x23CF 形状配对」逐
image 找齐。此为下一轮第一任务，随后接入 dump71。

### 第九轮增量（同日）：字段对齐器与定量结论

1. **顺序贪心对齐失败根因**：7.1 与 6.4 的类型序大分歧（7.1 有 hidden_N
   隐藏类型带字段，6.4 无此类型；变体 B 仅 11 段匹配）——tdi 序不可直接映射。
2. **字段名签名匹配成功**：字段名不混淆（两版本一致）→ 以 6.4 类型字段名
   tuple 在 0x4C 表滑窗匹配，得 **579 段锚**（F 起点 → G 类型段），样本单调，
   F 与 G 为子序列关系（F 跳过 7.1 不存在的字段/类型）。
3. **0x4C 表尾**：m_EscapeBuilder/m_List/m_Dict/m_Node/m_Key 等 GI 游戏类型
   字段 → 表覆盖跨 image（不止 mscorlib），47802 = 解码 streak 断点（per-image
   mask 边界）。
4. **tdi6→tdi7 映射方案（下轮）**：字段名签名同法应用于**方法名序列**
   （methodDef name 列已全解 460313 条，公共 API 方法名不混淆）→ 类型级锚 →
   单调 LIS → tdi 映射 → 0x4C 表按锚切分 → 字段接入 dump.cs。

### 第十轮增量（同日）：tdi 映射打通（方法签名锚 4737 个 100% 单调）

1. **方法名签名类型锚成功**：6.4Dump 解析修正（方法行判据 = 含括号；
   此前方法行被当字段行漏掉导致 0 锚）→ **4737 个 (tdi6→tdi7) 锚、
   单调率 4736/4736 = 100%** ——tdi 映射骨架成立。
2. **字段切分首版**：方法锚 + 579 字段锚合并为 5157 重同步点，F 指针
   按 6.4 字段数推进 → 名字验证 **8007/24286 (32%)** ——锚间 7.1 独有
   类型（hidden/新增）的字段数未知导致漂移。
3. **剩余问题聚焦为一件事**：锚间类型的字段数。候选解法（下轮）：
   a) 锚间类型按「字段签名滑窗」逐类型匹配 F 流（字段名不混淆，可验）；
   b) 39 槽配对找 per-image 字段表里的 per-type 计数列；
   c) methodDef 侧已全解，fieldCount 的 mask 链可在 .text 中用
      「class 初始化函数读 klass+0xC0（field_count 缓存）」的写来源定位。

### 第十一轮增量（同日）：字段对齐器 v2 成功 + 明文镜像表发现

1. **字段对齐器 v2（/tmp/align2.py）成功**：锚窗口内 6.4 字段名序列在
   0x4C 表滑窗匹配（7.1 独有类型的字段段整段跳过并记录），**对齐 68038
   个类型，字段名验证 4279/4279 = 100%**，605 个插入段（7.1 独有类型字段）。
   → **0x4C 表的字段内容与归属主结构完全可信**。
2. **tdi7 映射窗口修正**：窗口内 span6≠span7 时的比例映射过于粗糙，直接
   映射仅 975 类型/3900 字段落位 —— 需要窗口内 7.1 侧的类型级对齐（方法
   锚已 100% 单调，可细化到窗口内逐类型）。
3. **明文镜像表发现**：kuna 反编译 klass 构建（sub_1404C1AE1）暴露
   **stride 0x30 的 per-type 表（.rdata VA 0x1438E0BE0，明文无 mask）**，
   含 +0x1B byte（写入 klass+0xC0）、+0x1A/0x1D bytes、+0x20/+0x28 i32
   （-1 哨兵）、+0x00/+0x02 u16（→0x1438CF6F0 表）。但 +0x1B 分布
   （0:29 万/96:4 万/255:3.2 万）与字段计数分布不符且 RemoteClass=0 与
   6.4 矛盾 → 索引域 ≠ tdi（EDX 参数语义待定）。表身份是下轮关键：
   它极可能是「td 表的运行时明文镜像」，一旦确定索引域，fieldCount/
   fieldStart 等全部列免费获得。

### 第十二轮增量（同日）：字段输出端到端打通

`mhydump dump71 --field-map <json>` 落地：dump.cs 输出 **983 个字段**
（116 个类型），类型解析正确（`object[] m_SlotInfoTable`、`char m_current`
等，与 6.4Dump 的 __DTString 等类型逐字段一致）——**字段输出管线全通**。

管线：字段对齐器 v2（6.4 字段名 tuple 滑窗匹配 0x4C 表）→ sig 锚 ∩ 方法锚
→ field_map JSON（tdi7→names+typearr 类型）→ dump71 读取输出。

**覆盖提升路径**（当前 116 类型/983 字段，目标是全部 ~2.5 万含字段类型）：
1. sig 锚扩容：滑窗匹配允许部分匹配（F 段长 > 6.4 字段数时尾部为 7.1 新增
   字段）；方法锚窗口内逐类型细化（span 不等窗口的内插）；
2. **fieldCount 列**仍是根本解（版本无关）：0x30 表线索已排除
   （实为 Globalization 格式数据），回到 klass 初始化区逐列 RE；
3. attrs（modifiers）列：0x4C 表仅 2 列无 attrs，需 fd 类表的 attrs 列或
   6.4 oracle 供 modifiers。

### 未完成 / 下一步（按优先级）

1. **字段覆盖提升**（sig 锚扩容/fieldCount mask 链/attrs 列）
2. 参数名表（0x1D0 表 type 列已可出参数类型，名字待 metadata paramDef 表）
3. usage tag 组合枚举（sidx=data^tag'/^0x5C56350B 变体空间）
3. params extra 项 → 参数名与参数类型（表结构已备）
4. stringliteral（usage 链已通：td+0x3E → usage 表 → 0x1B8 槽数据）
4. derive 全自动：常数池推导器接入 profile 生成（骨架在 constpool/shapes，
   验证器已写好一部分），目标 7.0/6.x 解锁
5. 枚举/接口/嵌套类型的 dump.cs 完整渲染（parent 列待破）
6. flags 常数 −0x72E9 与汇编 −0x7269 的 0x80 差异复核

### 复现实验命令

```sh
cargo build --release
./target/release/mhydump dump71 --exe <7.1 YuanShen.exe> \
  --metadata <7.1 global-metadata.dat> --out dump.cs
cargo test  # (旧路径测试; 样本缺失时自动 skip)
```

kuna 批量反编译复现：
```sh
python3 - 截取 exe[0x400+0x50A000 .. 0x400+0x54A000] → /tmp/gi_meta_win2.bin
kuna decompile-project /tmp/gi_meta_win2.bin --raw-image --base 0x14050b000 \
  --target x86:LE:64:default --addr <函数头>... --mode fast -o /tmp/kuna_outN
```

## 第十三轮（2026-10-11）：字段全覆盖 + extends（parent/接口）落地

> 本轮内容是 agent 的过程记录，不是需求；与 REQUIREMENTS.md 冲突时以后者为准。

### 突破 1：td fieldStart / fieldCount 列（字段全覆盖的根）

7.0 devkit 给出决定性线索（`type_field_start = td[+0x2C] − 0x1E6871E4`、
`type_field_count = td[+0x3C] u16 − 0x8B`），7.1 用 116 个已锚定类型拟合出
轮换后的列：

- **fieldStart = u32@td+0x00 ^ 0x72628007**（raw 0x8D9D7FF8 = 0xFFFFFFFF 哨兵）
- **fieldCount = u16@td+0x30 ^ 0x9A6B**

全局验证（决定性）：**链式遍历 0..88903 全部 88904 槽零断裂**——每槽
fs 恰等于前缀字段行数，**F 表精确 440172 行**（旧值 47802 是错的）；
槽 88904..88980（77 槽）为表尾填充垃圾（fs ~19 亿、名字乱码）。
+0x1C 的"魔数"不是 hidden 标记（两种取值的槽都在链上，都含真类型，
6.4 的 MessageFunc 在 7.1 是 odd-tag），它是 parent 列的 per-record mask
材料（见突破 3）。

### 突破 2：字段类型列 = pbase 表 +4（round-7 公式实锤 + data 语义修正）

7.0 的 tbl8 就是 stride-8 {typeIndex, nameIndex}；7.1 对应
**hdr[0x4C]+0xE5D249BF（TableBase.sub 取负）stride 8**：
- name  = raw@0 ^ mask(i) ^ 0x048E6373
- type  = (raw@4 + 0xB36B852D) ^ mask(i) ^ 0x4F6E2A1D
- mask(i) = ((i*0x23CF ^ 0x3D27C42E)*0x7F76A166 + 0x0F06651FC0B8A) >>16 + 0x49ACDCBC（u64 加法！）

type 公式用 344 个 6.4 System.String 字段验证（全部落到 String 类簇）。
关键澄清：typearr 里 String/Int32 等基元有**多个条目**，+8 的 attrs 字节
区分（1=private/6=public/3=…）——**该 attrs 字节就是字段修饰符来源**
（field_modifiers 直接用，const/static/readonly 位也在）。旧锚
typearr[33]=String 只是 attrs=0 的那一个实例。

**PTR/SZARRAY 的 data 语义修正**：data 是**截断 32 位 VA**（高位丢），
`ptr_type_index` 用 `(image_base & 0xFFFFFFFF00000000) | data` 重建——
此前加整个 image_base 导致越界全部回退 object/object[]。

### 突破 3：parent 列（extends）

**parent_tarr = u32@td+0x2C ^ tag@+0x1C ^ 0x8177D738**（typearr 索引）。
验证：Object→0xFFFFFFFF、ValueType→Object、Enum→ValueType、
MonoBehaviour/MonoUIProxy 主聚类；并在 klass 初始化函数反编译中实锤
（`MOV R14D,0x72628007; XOR R14D,[R9]`、fieldCount `MOVZX R12D,[RAX+0x30];
XOR R12,0x9a6b`、field mask 链 0x23CF/0x3D27C42E/0x7F76A166/0xF06651FC0B8A
逐条可见）。哨兵语义：接口类型 parent=0xFFFFFFFF → interface 关键字。

接口表：**hdr[0x70]−0x6EA5B3FD，stride 6 {typeIdx i32(−1 哨兵), off i16}**，
start= u16@td+0x3A ^ 0x4BCE。**条数列不存在于 td**（各类拟合全失败，
klass+0xC2 由 klass 数组初始化器写入，位置未定位）；用 span（下一个更大
start−自身 start，仅唯一 start 槽）近似，**span 含继承接口**（与
Il2CppDumper 只打印声明接口有偏差，如实记录）。接口条目 typeIdx 为裸
typearr 索引（2000/2000 kind 合法）。

### 突破 4：GetParameters/params 表语义（汇编级，未完全落地）

params 表 hdr[0x1D0]^0x07D0BBF9 stride 12。反编译 0x1405287a3 起的函数
+ 手工解码 0x140528810..0x1405288a6：
- 搜索 key ECX = (md[+8]^0x20D55D01) **+ pmask(i)** + [R15+0x10]（非明文 gpi，
  是 paramStart 相关编码值）
- 搜索窗口 = [0, RDX>>3 行)（前缀扫描，RDX 由方法上下文推导，未解）
- **行 type@+4 是明文 i32，−1 哨兵**（`MOVSXD EAX,[RBX+4]; CMP RAX,-1`）
- key 列与目标值高度碰撞（gpi=0 命中 1.5 万行）→ 必须依赖窗口界定，
  窗口推导未解 → 参数类型暂缓（且参数名运行时不可读，metadata paramDef
  名字表未定位，dump.cs 签名无法完整还原）

### 交付物

- dump71 原生输出：**88872 类型 / 440061 字段（0 → 全量）/ 460282 方法**，
  字段行含修饰符（const/static/readonly 位来自 typearr attrs 字节）
- extends 行：`public <enum|struct|interface|class> X : Base, I1, I2...`
- --field-map 参数移除（不再依赖外部对齐产物）
- 引擎新增：td_fs_fc/td_walk/field_name/field_type_idx/td_parent/
  td_iface_start/iface_entry；profile 新增 FieldMaskChain（u64 加法+移位）
- cargo test 16 通过（1 ignored 为既有）；警告清理（余 2 个为既有 dead code）

### 6.4Dump.cs 对照（按 (ns,name) 配对 14541 类型）

- 字段名集合：12318 全等（85%）+ 350 为 7.1 超集（新增字段）+ 1873 差异
  （版本演进为主：Mono 升级、 obfuscated 类型重命名）
- 字段类型文本：**90790 精确（92%）**；7983 差异主因：
  1. 嵌套类型限定（`MonoClass*` vs `Mono.RuntimeStructs.MonoClass*`）——
     declaringType 列未破，嵌套外链无法渲染
  2. GENERICINST 渲染为 object（genericClasses 表未接）
- 有序精确率显著高于多重集：字段顺序大体保留（round-11 "置换"结论修正：
  只部分类型被打乱）

### 剩余项（更新后）

1. **stringliteral**（7.0 配方完整在 devkit：hdr[0x9C] offset 表+f(i) 链+
   0x1B8 数据+per-literal key 链；7.1 常数需定位 literal 访问器反编译；
   本轮 0x586ABAF1 站点实为哈希比较函数，非访问器）
2. **参数类型**（窗口推导）+ **参数名**（metadata paramDef 表）
3. **declaringType**（嵌套类型限定）与 **flags**（sealed/abstract/static）
4. GENERICINST 渲染（genericClasses 表）
5. property/event 表（dump.cs 的 // Properties // Events 节）
6. 默认值表（const 字段 `= value`；7.0: hdr[0x0C]/0x10C/0x1B0）
7. derive 全自动（常数池推导器 → 未来版本解锁）

## 第十四轮（2026-10-11）：stringliteral 结构半破（sidx 公式 + 偏移表）

> agent 过程记录，非需求。

### 关键坐标修正（重要，前几轮的 kuna 标签偏差）

- **kuna 窗口 base 必须 = 窗口起始文件偏移 + 0x140001000**（等价：label = file + 0x140001000）。
  早期窗口（0x50A000/0x50D000 等）无意中符合此式所以反编译正确；本轮 window5 用
  file+0x140000000 导致偏移 0x1000、全部反编译失真。
- 由 .text 节头推得的 file=RVA−0xC00 与 kuna 约定差 +0x400：kuna label 相对真实
  VA 偏 +0x400；`.upx0` 文件映射 = raw 0x19610800 + (RVA − 0x19E5B000)。

### 收获 1：usage 表 → string idx 公式（汇编实锤）

反编译+手工解码 0x14050f441..0x14050f4d8（klass 创建内联）：
```
entry = usage_base(hdr[0xC8]^0x8D701A3) + idx*0x10
EAX = entry.tag + 0x8EDEA6E9
EDX = f(idx) + 0x71555646
f(x) = ((x*0x8187 ^ 0x42D5A190)*0x7B2D0E18 + 0xB6F00C08) ^ 0x7A3E254D
tag 校验通过 → sidx = entry.data ^ EAX ^ 0x5C56350B（CALL 0x14051df00）
校验失败     → sidx = entry.data ^ EDX ^ 0x5C56350B（CALL 0x14051e4f0）
```
→ **sidx = data ^ (tag + 0x8EDEA6E9) ^ 0x5C56350B 对校验通过的行成立**（13 轮"mask
输入差一步"闭环：mask 输入是条目自身索引/其 tag 编码，公式无需 idx）。kind 抽取、
v8→行号反演（f 可逆）留待接入。idx 派生：n 型 = u16@td+0x3E − 0x1398 族；
泛型参数型 = (i16@[hdr[0x174]−0x312E124F 表+0xC] − 0xA8E2) ^ mask16(
(i*0x6F1C0337A0897415+0x31061C4212D60D89)>>0x16)。

### 收获 2：字面量偏移表（明文，实锤）

**hdr[0x1B8] ^ 0x586ABAF1 = u32 偏移表（明文，无 mask）**：
entry[0x2f8]=0xd8d, entry[0x300]=0xda1, entry[0x321]=0xdd8, entry[0x1000]=0x291c —
单调递增（偶尔 ±1 抖动，疑似空串/重排），字面量 j = [T[j], T[j+1]) 区间。
（7.0 对应结构：偏移表 hdr[0x9C] 带 per-index mask + 数据 hdr[0x1B8]；7.1 表的
mask 已取消且槽位改到 0x1B8。）

### 受阻：字面量数据 blob + per-literal 解密链

- 物化函数 0x14051df00/0x14051e4f0 是 **JMP thunk，跳进 .upx0 变异代码区**
  （file 0x1971944D 起，字节含 41 57/41 56/e9 片段但整体被变异，kuna 出垃圾）。
- blob 定位穷举失败：42 header 槽 × 25 个本代已知常数 × {xor,add,sub} = 全部
  可打印率 ≤0.56（噪声水平）；strsec+名字密码 0.46；7.0 key 链及其 fx 族变形
  均无 >0.6 命中。（此前"'+'/'-' 命中"经反演验证为 key 低字节周期 64 的巧合。）
- 结论：字面量数据加密且解密器在 .upx0 变异区，静态需先解变异（另一工程量级，
  同星铁 .upx0 议题）。**下一步入口**：a) 反演 f 得 v8 校准 idx 派生；b) 变异区
  入口 thunk 表（0x14051df00 附近成片 thunk）→ 定位 .upx0 解密 stub；c) 若运行
  时捕获可行则直接 dump 字面量表。

### 复现命令

```sh
# kuna 窗口（base 规则：file + 0x140001000）
python3 -c "exe=open('<YuanShen.exe>','rb').read(); open('/tmp/w.exe','wb').write(exe[0x50d000:0x511000])"
kuna decompile-project /tmp/w.exe --raw-image --base 0x14051e000 --target x86:LE:64:default --addr <函数头> --mode fast
```

## 第十五轮（2026-10-11）：字面量文本区定位（明文）

- **用法表现场确认**：hdr[0xC8]^0x8D701A3 表稀疏布哈希布局——tag==fx(row) 自洽行
  = 真条目（200k 行中 1801 条），其 data^(tag+0x8EDEA6E9)^0x5C56350B 给出合理值
  （type 类行枚举出连续 typearr 序号 109,110,111…；值域 [109,88887]）。
- **字面量文本区（明文）在 body 0x8ff14c 起**：记录格式 {u32 字符数}{UTF-8 字节}，
  已验证 '，。、；：？！》”’】）]  '(15)、'MiHoYoSDKAlertCompliance'(24)、
  'Dialog/SubmitBtn/Text'(21)、'AlertWithTitle'(14)、'Dialog/Content/TextContent/Title'(32)
  等连续对齐；区域延续到 0x90bxxx（含大量 Dialog/... 与 HoYo/... UI 路径）。
- **未闭合**：x) 区域里 0x8ff1f5 处有 4 字节 '01 00 00 00' 夹在 NUL 字面量与下一记录之间
  （格式例外点）；y) sidx∈[109,88887] 与文本区内记录偏移的精确映射未对齐（sidx 最大值
  88887 ≈ 文本区尺寸 88984，强相关）；z) 偏移表 T(hdr[0x1B8]^0x586ABAF1, 25982 条,
  值 12..88887) 的单位/语义未定（+1 步进无法与 {u32}{text} 记录对齐）。
  下一步：把 0x8ff1f5 例外点与 T 值域联合解（很可能是 T=记录起点表，例外点是空串/NUL
  记录的特殊编码）。

---

## 第十六轮（2026-10-12）：外部复核 + P0 缺陷实测 + 模拟执行路线立项

> agent 过程记录，非需求；需求见 REQUIREMENTS.md R4/R5/R6。

### 0. 本轮基线复核（全部实测，非推断）

复现命令：

```sh
cd /home/yangsanyi/Documents/git-repo/GI-StaticParser
cargo test --offline --release            # 16 passed / 1 ignored
S=/home/yangsanyi/项目/逆向和数据提取/采样库/genshin/v7.1-CN/bin
time ./target/release/mhydump dump71 --exe "$S/YuanShen.exe" --metadata "$S/global-metadata.dat" --out dump71.cs
```

- 实测 **real 3m15.535s / user 3m9.471s / sys 1.565s**（CPU 97%，非 IO 受限）。
- 输出：**88872 类型 / 440061 字段 / 460282 方法**；dump.cs 69,497,421 B；script.json 47,845,125 B。
- header 解析：strsec=0x3C58E68 td=0x48F3FD8 md=0x23F8770 fd=0x391D4 params=0x10CB8E0
  typearr=0x2E1EB30(683568) mptrs=0x2451BE8(460313)。与第十三轮记录一致。
- **测试有效性质疑**：仓库根无 Original/ 目录，而 11 个用例所在文件都读
  Original/GenshinImpact.exe|global-metadata.dat 并走 let Some(..) else { return } 早退，
  cargo 仍报 ok。真正有断言的只有 5 个（mem×2、default_values、constpool、profile）。
  ⇒「cargo test 全绿」当前不能作为回归证据。

### 1. P0-1：接口哨兵判据恒假 → 每类型 O(n) 重建+排序（3m15s 的主因）

- engine.rs 的 td_iface_start()：(raw_u16 ^ xor) as u32 —— 结果恒 ≤ 0xFFFF；
- dump71.rs 里却写 if td.iface_start != u32::MAX ⇒ **条件永真**；
- 于是每个类型都执行「遍历全部 tds 收集 starts + sort_unstable + dedup」。
- 同构微基准（_gi_probe/bench_iface.rs，200 次迭代）：**2.701 ms/iter**；
  × 88872 类型 ≈ **240 s**，与实测 195 s 同量级 ⇒ 判定为主要耗时来源。
- 修法：哨兵按 raw == 0xFFFF 判定（或返回 Option），starts 表在循环外预计算一次。
  预期 dump 回到秒级；同时修正「span 含继承接口」的语义偏差。

### 2. P0-2：script.json 丢失命名空间

- dump71.rs 写 ScriptMethod 名用 format!("{}.{}", td.name, md.name)，未带 namespace，
  与 README 承诺的 Namespace.Class.Method 不符。
- 实测：grep -c '"Name": "MoleMole\.' = **0**；dump.cs 中确有 // Namespace: MoleMole；
  **689 个简单类名重复**（Action/ABTestManager/…）⇒ Ghidra 应用后名字会串。

### 3. P0-3：占位符冒充真实数据（违反 R3 与 R4.1）

| 项 | 实测计数 |
|---|---|
| 字段偏移注释恒为 0x0 | 440061 |
| 参数渲染为 object/*param*/ | 208695 |
| script.json ScriptString | 0（恒空） |

### 4. P1 清单（已实测 / 已 grep 验证）

- R2.3 未实现：Profile 可序列化但 CLI 无 --profile-in/out；derive::constpool、derive::shapes
  **零调用者**；profile.rs 注释引用的 super::discover 模块不存在。
- 引导悖论：engine.rs 的 find_header() 用**同版本字符串 4 常数**解出 mscorlib 才认头 ⇒
  常数轮换版本（7.0/5.0/4.2 实测）直接 embedded MHY header not located，
  R2.4「同结构+常数轮换全自动」不成立。
- 双管线重复：pmask（methods_71 vs layout71）、locate_methodptrs（engine vs methods_71）、
  write_script_json、json_escape 各两份；Profile 中 fd_*/param_*/md_param_extra 共 9 个死字段。
- 文档漂移：README Layout 未列 derive/dump71；RECIPE.md 通篇旧一代常数（hdr+272、
  bias 1426623823、VA 0x1424387A8），与 layout71 不一致且未标版本。
- 4200 行 7.1 改动全部未提交（git status：src/derive/、src/dump71.rs、两份 md 未跟踪）；无 CI、无 golden。
- rayon 依赖全仓 0 使用；旧路径 --only 无效。

### 5. 本机工具/环境盘点（供模拟执行立项）

- Python **3.14.7** 且 pip 为 PEP668 externally-managed；但 **uv 已装**（/usr/bin/uv）⇒ 可建 3.12 venv。
- 已装：capstone 5.0.9、unicorn 2.1.4、frida 17.18.0、wine；未装：angr/triton/qiling/speakeasy/z3/lief/pefile。
- 无反编译器入 PATH：无 IDA/BinaryNinja/r2/Ghidra；kuna 已构建（~/Documents/git-repo/kuna/decompiler/target/release/kuna）。
- 已有资产：tools/vmp-lazy-unpack/（5372 行 Unicorn PE 模拟器 + API handlers + TEB/PEB）、
  变异层/tools/demutate.py、NoVmp（已构建；~/gire/novmp1010 592MB 产物含 ys71.exe 有效 PE64）、
  ~/gire/meta_string_literals.txt（31607 条字面量）、~/gire/dump_71.cs（基线）、
  Genshin-Impact-Dump-collection/6.4Dump.cs（oracle）、~/gire/memdump_*（3.0/4.6GB 内存快照）。
- 磁盘：/home 仅剩 24GB（97% 已用）——多版本样本前需腾盘。

### 6. 下一步（本轮结论，方案见 PLAN-auto-derive.md）

1. 修 P0-1/2/3 + 测试接真样本与 golden 基线（可先于模拟执行完成，立即把 dump 拉回秒级且可信）。
2. 立「模拟执行驱动推导」harness：优先复用 tools/vmp-lazy-unpack 的 PE/API 层，
   其次引入 Qiling/Speakeasy（Windows API 语义）与 Triton/z3（解常数方程）。
3. 拿到第 2 个版本样本后，用同一 harness 验证「零改码跑通」。

### 7. 样本库确认 + 全版本失败矩阵（2026-10-12 下午补充）

用户指出 `/home/yangsanyi/gire/sample/gi/`——**27 个版本样本（4.2.0–7.1.0，共 9.6GB）**，每版含：

```
<ver>/YuanShen.exe
<ver>/YuanShen_Data/Managed/Metadata/global-metadata.dat
<ver>/YuanShen_Data/Managed/Metadata/startup-metadata.dat
<ver>/YuanShen_Data/Native/Data/Metadata/global-metadata.dat（与 Managed 同尺寸）
<ver>/vms/（部分版本有，VM/变异层留档）
```

- 7.1.0 的 exe md5 前缀 **51d3263c**，与 `gidata/versions/7.1-CN.json` 的 `exe_md5` 一致
  ⇒ 就是全部既有结论所基于的那份构建。
- exe 尺寸从 4.2.0 的 5.3MB（加壳态）跳到 4.8.0 的 277MB（il2cpp 一代切换）；
  global-metadata.dat 从 45.6MB(4.2.0) 单调增到 82.7MB(7.1.0)。

**实测失败矩阵（当前 `mhydump dump71` 逐版本跑）**：

| 版本 | 结果 |
|---|---|
| 4.2.0 … 7.0.0（26 个版本） | `Error: embedded MHY header not located (self-validation failed)` |
| 7.1.0 | 通过（88872 类型 / 440061 字段 / 460282 方法） |

⇒ 「未来版本直接可用」的卡点被量化：**27 个版本里只有 1 个能跑**。
根因即本节 §4 的引导悖论：`find_header()` 必须先用**本版本的字符串 4 常数**解出 mscorlib
才承认候选头，而推常数又需要头。R5 的验收目标因此变得完全可度量：**目标 = 27/27 零改码**。

### 8. 网络/工具链（2026-10-12 下午补充）

- 直连可用：pypi.org 200（0.56s）、raw.githubusercontent.com 301（0.68s）；
  **github.com 直连超时**。
- 用户提供的代理 **127.0.0.1:7897 从 Linux 侧不可用**（监听者是 wineserver）；
  但 **172.17.0.1:7897 可用（socks5h，实测 200）**。
- `uv` 已装 ⇒ 建 `~/.venvs/re`（python 3.12）用于装 qiling/z3/pefile 等
  （系统 python 3.14 且 PEP668，不宜直接装）。
- Ghidra 本机已安装且已装载 MCP（用户说明），IDA Pro 为付费不引入 ⇒ 反编译侧以
  Ghidra(MCP) + kuna + NoVmp/demutate 为组合。

### 9. 跨版本实测：两个 27 版本矩阵（2026-10-12 晚）

样本库 `/home/yangsanyi/gire/sample/gi/` = **27 个版本（4.2.0–7.1.0，9.6GB）**，分两代：

- **4.2.0–4.7.0（7 版）**：exe 仅 5.3MB（加壳态），**全文件 0 个 MHY\0** ⇒ 另一代容器，
  与 RECIPE.md 记的旧一代吻合。R2.5 允许 4.2.0 豁免，但 4.3–4.7 同属这一代，范围待用户确认。
- **4.8.0–7.1.0（20 版）**：exe 277–445MB 新一代；**全文件恰好 1 个 MHY\0**（在 .rdata）。
  7.1.0 该候选：`i32(hdr+0x150) - 0x37ABD22E = 0x3C58E68`，**与引擎自己解出的 strsec 逐位相同**
  ⇒ 唯一候选即真头（脚本 `_gi_probe/header_census.py`）。

**矩阵 A — 当前 mhydump dump71 逐版本跑**

| 版本 | 结果 |
|---|---|
| 4.2.0 … 7.0.0（26 版） | `embedded MHY header not located (self-validation failed)` |
| 7.1.0 | 通过（88872 / 440061 / 460282） |

**矩阵 B — 已知明文常数推导（工作区 gidata/gidata/metadata.py::derive）**

| 版本 | 候选数 |
|---|---|
| 4.2.0 … 7.0.0（26 版） | **0 候选**（每个版本耗时 0.2–58s） |
| 7.1.0 | **1 候选**：M1=0xB33E…68C0 X1=0x6D8C…8E27 X2=0x30EE…E0CD M4=0x0889…FB36 strsec=0x3C58E68（与档案逐位一致） |

⇒ **两个独立矩阵都指向同一结论：27 个版本里只有 7.1 能用。**

**归因（有证据）**

1. **头定位失败是自造的循环依赖**：4.8–7.1 的 20 个版本头候选**唯一**，但 `find_header()`
   要求"用本版本 4 个字符串常数解出 mscorlib"才准入 → 常数不对就否掉唯一正确候选。
   修法：先推常数（不需要头）→ 再用新常数回头验证头；或"候选唯一 + 结构校验"直接采信。
2. **常数推导失败是扫描域问题**：`derive` 只在 .text 找 movabs 簇。实测 7.0.0 的 .text 仅
   1880 个 movabs / 88 簇，全部验证失败（`_gi_probe/scan_sections.py`）。把域扩到
   il2cpp(321MB)/.upx0 时 **Python 原型太慢**（5 分钟跑不完一个版本）⇒ 该工作应在 Rust 内做
   （项目已有 constpool 滑窗池 + rayon）。
3. **待复核**：头 VA 在文件里既无 8 字节指针引用也无 `lea` 引用（`_gi_probe/header_refs2.py`），
   但该扫描只覆盖 `48 8D 05` 形态、**未含 REX 变体（4C/49/4D）**，结论不成立，需重扫。

**更正 §5 的两行（工具状态已变）**

- 已装（`~/.venvs/re`，Python 3.12.12）：**qiling 1.4.6 / z3 5.1.0 / unicorn 2.1.4 / capstone 5.0.7 / pefile**。
  安装走**清华镜像**成功；直连 pypi 会中断；代理须用 **172.17.0.1:7897**（socks5h），
  用户给的 127.0.0.1:7897 实为 wineserver 监听，Linux 侧连不通。
- §5 中"无反编译器入 PATH / 无 Ghidra"作废：**Ghidra 本机已装且 MCP 已载** ⇒ IDA 从工具清单移除。

### 10. 本轮代码改动 + 自动推导路线（2026-10-12 晚）

用户指示：**最终目标是能自动适配未来版本**；4.2–4.7 加壳旧代不投入；Ghidra headless 可用但不持久化。

**A. 已改并实测（cargo build --release 通过，7.1 样本实跑）**

| 改动 | 位置 | 实测结果 |
|---|---|---|
| 接口哨兵修正 + starts 表提出循环 | engine.rs::td_iface_start 改返回 Option；dump71.rs 循环外预计算 | **3m15.535s → 2.635s**；KFBJCKANIFD 的 15,604 条假接口消失 |
| 去掉假字段偏移注释 | dump71.rs 字段行 | "// 0x0" 计数 440,061 → **0**，并 warn 计数 |
| 参数占位符显式化 | dump71.rs::self_params | 输出 "object /*unresolved*/"，warn 361,974 |
| script.json 全限定名 | dump71.rs ScriptMethod | "MoleMole." 命中 **0 → 58,443** |
| 接口列表诚实告警 | dump71.rs | warn 41,789 个类型走近似 |

哨兵真值实测：td+0x3A 解码后 47,110 条 == 0xFFFF(u16::MAX)，真实 start 值域 0x0000–0xBF5C；
原代码与 u32::MAX 比较 ⇒ 恒真。

**B. 自动推导：从"扫描打分"改成"锚点 + 解方程"（本轮核心）**

1. **全图已知明文扫描器**（_gi_probe/scan_fast3.py，向量化 + 低 32 位倒排筛）：
   7.1 全图（.text+il2cpp+.upx0）**23 秒**命中，4 常数与 strsec 与档案逐位一致；
   注意低 32 位预筛必须先异或 lo32("mscorlib")，漏这一步会漏掉真解（本轮踩过）。
2. **反证**：4.8.0–6.7.0 **全部 0 命中**（候选对 9–13 万、plausible offsets 200–400）⇒
   这些版本的 4 常数**不是任何形态的 movabs 立即数**，扫描路线在它们身上是死的。
3. **解密函数形态**（7.1，文件偏移 0x50FECD 起）：
   and r12d,0xffffff; movabs rax,M1; imul rax,r12; movabs rcx,X1; add rcx,rax;
   movabs rdx,X2; xor rdx,rcx；紧随 mov rax,[hdr全局]; mov ecx,imm32; add ecx,[rax+0x150]
   ⇒ strsec = hdr[0x150] + imm32。
4. **两条独立自动路线均已在 7.1 上闭合**（都不需要人工常数）：
   - **形态签名**（寄存器通配正则，_gi_probe/derive_shape.py）：9 命中→1 验证，
     还原 M1/X1/X2/M4/strsec 全部 5 个值；
   - **header 锚**（_gi_probe/derive_anchor.py）：strsec = hdr[0x150] + imm32 直接算出
     （与引擎逐位一致），再 key0 = u64(body,strsec) ^ "mscorlib"，然后在全体 movabs 中找
     a^b == key0 ⇒ **恰好 2 条（同一对）= X1/X2**，搜索空间为零。
5. **受阻点（下一步靶点）**：7.0.0 / 6.4.0 的 add reg,[hdr+0x150] 位点只找到**假阳性**
   （imm=0x170）⇒ 这两代读取 header 的指令形态不同（字段偏移或运算形式变了）。
   需先反编译定位"读 header 的那个函数"，再按同一思路取 strsec。

**C. 结论（对 R5）**：新路线 = ①头定位（唯一 MHY\0，20/27 版本可用，零常数）
→ ②strsec（header 读点 + bias）→ ③key0 = C0 ^ "mscorlib" → ④X1/X2 = XOR 等于 key0 的 movabs 对
→ ⑤M1/M4 由解码器形态 + 可打印性校验。**没有一步依赖"扫描 + 阈值打分"。**

**D. 未做/待验证**：改动尚未提交 git；未重跑 cargo test（其用例大多因缺 Original/ 空跑）；
4.8–6.x 的 header 读点未定位；字段偏移/参数名/属性/事件/默认值等 R1 缺口未动。

### 11. Ghidra headless 接入 MCP（2026-10-12 晚，用户要求）

背景：本会话原先只挂了 reva_gui（streamable-http → Ghidra **GUI** 的 127.0.0.1:8078），
headless 未接入。ReVa 的 headless 本体就是 mcp-reva（PyGhidra + RevaHeadlessLauncher + stdio 桥）。

**已做（全部实测）**

1. Ghidra 安装目录登记：写入 ~/.config/ghidra/lastrun = /home/yangsanyi/Public/ghidra_12.1.4_PUBLIC
   （PyGhidra 的 install_dir 查找顺序：显式参数 → GHIDRA_INSTALL_DIR → lastrun 文件）。
2. ~/.dsh/profiles/web/cordis.patch.yml 新增 stdio MCP 条目 mcp-reva-headless
   （serverName = reva_headless；command = /home/yangsanyi/.local/bin/mcp-reva；
   args = --config ~/.config/reva/reva-headless.properties；env 固定 GHIDRA_INSTALL_DIR 与
   JAVA_HOME=/usr/lib/jvm/java-21-openjdk；toolCallTimeoutMs=2000000；failOnStartupError=false）。
   该 properties 文件此前已存在（用户/前序会话准备），无需新建。
3. 验证：配置被热加载 → 会话内出现 mcp__reva_headless__* **86 个工具**；
   list_mcp_resources(reva_headless) 返回 ghidra://programs；
   实调 mcp__reva_headless__list-project-files(folderPath=/) 返回合法 JSON（空项目）。
   （注：reva_headless 无 list-open-programs 工具——该工具只在 gui 侧暴露。）

**已知行为/限制（勿误判为故障）**

- 启动慢：PyGhidra + JVM + ReVa 约 **60–90 秒**；期间首次探测会报 "server is disconnected"，
  插件的 reconnect 会反复重启直到连上（实测第 2 次尝试即成功）。DSH 重启后请等 1–2 分钟。
- **项目是会话级临时的**（上游设计：stdio 模式用 tempfile.mkdtemp 建项目，退出即清理）。
  需要跨会话持久化 → 用 analyzeHeadless + 固定 project 目录，或继续用 GUI 模式条目。
- 两条 ReVa（gui + headless）≈ 172 个工具同时挂着；GUI 未启动时 reva_gui 会连接失败但不会阻断启动
  （failOnStartupError 默认 false）。

**环境事实**：Ghidra 12.1.4（java.compiler=21，python.supported 3.9–3.14）；ReVa 扩展已装于
Ghidra/Extensions/reverse-engineering-assistant；mcp-reva 3.0.0（uv tool reverse-engineering-assistant，Python 3.14）。

---

## 2026-10-12 本轮：无常数定位内嵌头 + 从代码反推 header-slot 锚点（打破引导悖论）

### 结论（TL;DR）

1. **引导悖论已打破**（PLAN-auto-derive §T3 的落地）。旧 `find_header` 必须先用本版本字符串
   常数解出 `mscorlib` 才能认领候选头，所以常数轮换版本直接死在第一步。本轮证明：
   （a）4.8.0–7.1.0 的 exe 中 **`MHY\0` 在 `.rdata` 里唯一**；
   （b）该 blob 由一个全局指针承载，初始化点唯一：`lea blob ; mov [rip+X], reg`；
   （c）从该全局指针出发，用固定指令形态即可**从代码里读出**每张表的 header 槽位与逐构建偏置。
   以上全程**不需要任何密码学常数**。
2. **新工具 `mhydump anchors`**（`src/derive/anchor.rs`，iced-x86 解码）**在 7.1.0 上自动复现了
   手工逆向出的全部 7 项配方**（`layout71::gen71()` 逐值相同）——这就是 PLAN 验收判据 5 要求的
   "已知答案自证"。
3. **关键新事实（推翻了旧假设）**：header 槽位**不跨构建保持**。7.0.0 / 6.4.0 中**偏移 0x150 只有
   2 处读取，且都不是元数据访问器**——即 `strsec` 在那个构建里根本不在 0x150。因此"未来版本=同一套
   槽位+新偏置"的猜测不成立；锚点识别必须靠**结构验证器**（PLAN §T3），不能靠固定槽号。

### 无常数链条（每一步都是实测）

```
1. .rdata 中唯一的 MHY\0            -> blob（file off / VA）
2. lea blob ; mov [rip+X], reg        -> hdr_global（body_global = hdr_global + 8，实测相邻）
3. 所有 mov reg,[rip+hdr_global]      -> 头指针消费者（7.1：357 处，仅 .text/.upx0）
4. 槽位惯用式：
      mov|movsxd rA, dword ptr [rH + slot]     ; slot = header 字段偏移
      add|xor|sub rA, imm32                    ; imm = 该构建的偏置
      add rA, rBody                            ; 确认是 body 相对表基址
   或（字符串段）： mov rA, imm32 ; add rA, dword ptr [rH + slot]
```

7.1.0 原始反汇编（`0x140510EF5` 起，即字符串解码器内）：

```asm
140510EF5  mov    rax,[rip+0x55c53bc]     ; hdr_global = 0x145AD62B8
140510EFC  mov    ecx,0xC8542DD2
140510F01  add    ecx,[rax+0x150]         ; strsec = hdr[0x150] + 0xC8542DD2
140510F07  mov    r15,[rip+0x55c53b2]     ; body_global = 0x145AD62C0
140510F0E  movsxd rdi,ecx
140510F11  lea    rcx,[r15+rdi]           ; body + strsec
```

### 实测证据

`mhydump anchors --exe <样本> --metadata <dat>`（`target/release/mhydump`，本机实测）：

**7.1.0**（blob file 0x27D4CB0 / VA 0x1427D5CB0，hdr_global 0x145AD62B8，body 0x4EE4AA4）——
7 项与 `layout71.rs` 手写值**完全相同**：

| slot | 代码形态 | 解出值 | layout71 里的值 |
|---|---|---|---|
| 0x150 | add 0xC8542DD2 | 0x3C58E68 | `str_sub 0x37ABD22E`（= 加 0xC8542DD2）✓ |
| 0x0DC | xor 0x5278CA3B | 0x48F3FD8 | `type_defs xor 0x5278CA3B` ✓ |
| 0x1E0 | xor 0x2EE480FB | 0x23F8770 | `method_defs xor 0x2EE480FB` ✓ |
| 0x158 | add 0xE2ABA334 | 0x391D4 | `fields sub 0x1D545CCC` ✓ |
| 0x1D0 | xor 0x07D0BBF9 | 0x10CB8E0 | `params xor 0x07D0BBF9` ✓ |
| 0x04C | add 0xE5D249BF | 0x4580D78 | `field_names sub 0x1A2DB641` ✓ |
| 0x070 | add 0x915A4C03 | 0x973064 | `iface_table sub 0x6EA5B3FD` ✓ |
| 0x200 | **add 0xB43E0EB1** | 0xA03E64 | 写成 `sub 0xB43E0EB1` → 解出 **0x9824… 越界** ✗ |

（0x200 一条：代码是 `add`，profile 记成 `sub`，按 profile 解出的值超出 body。该字段
`engine::Meta::slot_base` 目前**只赋值、无读取**，所以不影响今天的输出；但它是错的，已在下文标注。
其余噪声行（`add 0x1`、`xor 0xF` 等）是同一槽被其它常量复用的假阳，靠 `confirmed` 与
值域过滤即可剔除。）

跨版本实测（同一命令，仅列关键槽）：

| 版本 | MHY\0 | hdr_global | 恢复到的 7.1 同名槽（新偏置） |
|---|---|---|---|
| 7.1.0 | 唯一 | 0x145AD62B8 | 0x150/0xDC/0x1E0/0x158/0x1D0/0x4C/0x70/0x200 全部 |
| 7.0.0 | 唯一 | 0x145898158 | 0xDC add 0xDCE37061→0x39F7C78、0x1D0 add 0xB98BE77F→0x17A2444、0x1E0 add 0xFCFB6247→0x45D8E94；**0x150 未出现** |
| 6.4.0 | 唯一 | 0x144EEAD58 | 0xDC xor 0x35D4EE22→0x11445、0x1E0 add 0xF757A1C9→0x147D0、0x70 xor 0x15128CF7→0x296E48、0x200 xor 0x5964B9B7→0xE702B8（均未确认） |
| 5.0.0 | 唯一 | 0x1438BD960 | 0x150 add 0xC583B875→0x2ADBC、0x158 xor 0x76C38A98→0x2EB7E88、0xDC add 0xD2D217C1→0x38608、0x4C/0x70 候选 |
| 4.8.0 | 唯一 | 0x143843860 | 0xDC add 0xE782191B→0x2771860、0x158 add 0xEE3A1779→0x2D75FEC、0x70 add 0x962E97B0→0x13044BC（confirmed） |

**7.0.0 / 6.4.0 中对偏移 0x150 做了穷举**（`scan_slot.py`，含"回看 0x1000 字节内是否存在
`mov rHb,[rip+hdr_global]`"的字节级来源证明）：两者各只有 **2 处**读取 0x150，且都在 CRT/托管代码里
（`mov rdx,[rdx+0x150]`、`mov [rdx+0x150],r8`），与元数据无关。结论：**该构建的 strsec 不在 0x150。**

### 尚未解决（明确写出来，避免误读为已完成）

- **锚点语义未自动判定**：现在能拿到一组 `(slot, op, imm)`，但"哪个是 typeDefs / strsec / …"仍需
  判别器。7.1 之所以能对上，是因为有人工答案可比。下一步是 PLAN §T3 的常数无关结构判据
  （fs 前缀和连续走通、字符串段熵/块结构、表偏移值域），而不是固定槽号。
- **strsec 形态不止一种**：7.1 是"imm 先、`add r32,[hdr+slot]`"；7.0.0/6.4.0 两种都没命中，
  说明其字符串段选址可能走了别的路径（不同槽、不同指令、或先算后加）。
- **密码常数仍未自动推导**（PLAN §T2 未做）。不过本轮把 `strsec` 的**定位**变成了可判定的一步：
  一旦选出候选 strsec，`key(0)=u64(body,strsec)^"mscorlib"` 就是一条可验证方程。

### 代码改动（本轮）

- 新增 `src/derive/anchor.rs`：`find_header_blobs` / `find_hdr_global` / `recover_anchors` /
  `recover` / `Recovered::in_range` / `Recovered::unique`；依赖 `iced-x86 = 1.21.0`
  （`default-features=false, features=["std","decoder","instr_info"]`）。全部是**度量**，不猜。
- 新增 CLI `mhydump anchors --exe <exe> [--metadata <dat>] [--json] [--site 0xVA]`。
- 新增 `#[ignore]` 金标准测试 `derive::anchor::tests::recovers_71_profile_exactly`：
  读 `MHY_SAMPLE_EXE`/`MHY_SAMPLE_DAT`，断言 7 个锚点与 `layout71` 逐值一致。
  （按 PLAN 验收判据 3：缺样本时**显式 ignore**，不静默 skip。）
- `layout71.rs` 的 `slot_table` 加注释标注"代码实测为 add 0xB43E0EB1"，但**不改数值**
  （该字段当前无读取方，改常数属于行为变更，另行处理）。

**实测命令与结果**

```
cargo test --offline --release              -> 18 tests: 16 passed, 0 failed, 2 ignored
MHY_SAMPLE_EXE=…/7.1.0/YuanShen.exe MHY_SAMPLE_DAT=…/global-metadata.dat \
  cargo test --offline --release recovers_71_profile_exactly -- --ignored
                                            -> 1 passed（4.11s）
mhydump anchors --exe …/7.1.0/YuanShen.exe  -> 8 个锚点，7 个与手写 profile 逐值相同
```

（注：本轮之前基线同样是 16 passed / 1 ignored；现在多了一个显式 ignore，所以是 2 ignored。）

---

## 2026-10-12 本轮（二）：字符串密码的无常数自动推导（M1/X1/X2 + strsec 全部自动）

### 结论（TL;DR）

1. 新增命令 `mhydump cipher --exe <exe> --metadata <dat>`：**不输入任何常数**，从 exe + dat
   自动推出字符串密码三元组与 `strsec`。7.1.0 的结果与人工逆向值**逐位相同**。
2. 新增一个**可判定的**判据（本轮关键发现）：**可打印窗口密度**。用正确的 (M1,X1,X2) 与
   `strsec` 时，256 KiB 窗口内"8 字节全在 0x20..0x7E"的命中数约 **15,000**；任一参数错时塌到
   **~100**。这是 **150 倍分离**，不是"77% 单调率"式的阈值拍脑袋——正是 PLAN §1 要求的可判定证据。
3. 实测覆盖 4.8.0–7.1.0 共 21 个版本：**5 个成功**（4.8.0 / 5.2.0 / 5.4.0 / 6.7.0 / 7.1.0），
   其余 16 个失败（4.2–4.7 是加壳旧代，mask 站点数为 0，符合预期）。
4. 4.8.0 的结果 0x9C9BC1DE1BC7E406 / 0x187E17AE6D781B2A / 0x79833B980C2747C1 / strsec=0x21A78D0
   与上一轮用"指令形态正则"手工得到的值**完全一致** —— 两条独立路线互证。

### 方法（三步，零常数）

1. **拿格式常量当锚**：打包字符串索引是 `(image << 24) | offset`，所以解码器必然做
   `and r32, 0xFFFFFF`。**0xFFFFFF 是格式常量，不随构建轮换**（这正是可用的原因）。
2. **用指令顺序定三元组**：mask 之后 0x100 字节内必须出现
   `const, imul, const, add|xor, const, add|xor` 的先后序列（常数既可能是 `movabs` 立即数，
   也可能是从 `.rdata` 的 8 字节加载）。取该序列 ⇒ 候选 (M1, X1, X2)。
   （把三元组枚举从 O(n³) 换成"顺序约束"后，每个站点只剩 ~1 个候选，全版本扫描从 ~80 分钟降到秒级。）
3. **两条验证**：
   - 已知明文：IL2CPP 字符串堆 offset 0 必是 `mscorlib` ⇒
     `u64(body, s) ^ (X1^X2) == "mscorlib"` 直接给出 `strsec`；
   - 密度分数：`score(strsec, M1, X1, X2)` = 256 KiB 窗口内"8 字节全可打印"的数量，`>= 3000` 接受。

### 判据的实测行为（7.1.0，256 KiB 窗口）

| 条件 | score |
|---|---|
| 正确（strsec=0x3C58E68） | **15163** |
| 噪声底（随机 strsec/常数） | 99 |
| strsec 平移 +0x1000 | 1836 |
| strsec 平移 -0x1000 | 1884 |
| M1 翻最低位 | 23838（**不敏感**——该判据定位 strsec 准、定常数不细） |
| X1 翻转 bit3 | 287358（同上） |

结论：**密度分数适合"定位"，不适合"解方程"**——所以常数必须从代码里读（第 2 步），而不是靠它搜。
这一点已写进 `cipher.rs` 的模块注释，避免以后误用。

### 顺带纠正的一个排程细节（实测）

7.1 的密钥排程实测有两种候选：
- **A**：每个 qword 用**自己的堆内偏移** o 加密，`key = ((o*M1 + X1) ^ X2)`；
- **B**：整个字符串用起始 key，再按 qword `+= M4`。

用 A 时，堆 offset 0 与 8 都解出 `mscorlib`，其后大量位置为可读文本；用 B 时只有前 8 字节可读。
4 MB 窗口的密度：A 得 287,943，而把 `strsec` 平移后只得 ~1,800。⇒ **A 才是主排程**，
M4 只处理同一字符串内部的后续 qword。`IMPLEMENTATION_LOG` 早前那句
"key += M4 per qword" 的表述容易被误读成 B，这里明确一下。

### 全版本矩阵（`mhydump cipher`，本机实测）

```
4.2.0 … 4.7.0   no string cipher derived        (加壳旧代，and-mask 站点 = 0)
4.8.0  M1=0x9C9BC1DE1BC7E406 X1=0x187E17AE6D781B2A X2=0x79833B980C2747C1 strsec=0x21A78D0 score=15430
5.0.0  … 5.1.0  no string cipher derived
5.2.0  M1=0x8222E9E43A13197F X1=0x339A34E7CBFD38F7 X2=0x4D37E7915DFE55F7 strsec=0x26BE5EC score=15449
5.3.0           no string cipher derived
5.4.0  M1=0xABA245CD4BE8E3B0 X1=0x32AA522A0281FDAA X2=0x34CC45C5274E0D3A strsec=0x2B7E820 score=15454
5.5.0  … 6.6.0  no string cipher derived
6.7.0  M1=0xAA160EA68AC8FA68 X1=0x24832E3F77AF01E6 X2=0x7AC9A2F2697FEB99 strsec=0x4126798 score=15119
7.0.0           no string cipher derived
7.1.0  M1=0xB33E40427D5668C0 X1=0x6D8C4AAB00FE8E27 X2=0x30EE5B43130FE0CD strsec=0x3C58E68 score=15163
```

### 失败版本的诊断（已做到哪一步）

对 7.0.0 / 6.4.0 / 5.0.0 做了额外排除实验：

- `and r32,0xFFFFFF` 站点并不缺（7.0.0 有 214 个，含 `81 /4` 与 `25` 两种编码，都已纳入扫描）；
- 但满足 `const,imul,const,arith,const,arith` **顺序**的站点每版本只有 3–6 个；
- 把 `mhydump anchors` 复原出的全部 in-range 偏移（7.0.0 有 101 个）当作 `strsec` 候选，
  与这 3–6 个三元组做全组合打分，**最高只有 112–116**（噪声底 ~100）。

⇒ 这些版本的密码常数**不是**以"mask 后紧跟 movabs 链"的形式材料化的（可能走寄存器传参、
`.data` 表、或被拆散），且 `strsec` 也未必落在当前锚点候选集里。下一步用 headless Ghidra
反编译 `and 0xFFFFFF` 站点的调用者来定位真正的解码函数（这也说明为什么"扫常数池"这类做法
在这些版本上必然不稳）。

### 代码改动

- 新增 `src/derive/cipher.rs`：`derive()` / `density_score()` / `StringCipher`，
  以及 `#[ignore]` 金标准测试 `derive::cipher::tests::derives_71_cipher`（断言 7.1 的四个值与站点 VA）。
- 新增 CLI `mhydump cipher --exe <exe> --metadata <dat> [--json]`。

**实测命令与结果**

```
cargo test --offline --release                          -> 18 tests: 16 passed, 0 failed, 3 ignored
MHY_SAMPLE_EXE=…/7.1.0/YuanShen.exe MHY_SAMPLE_DAT=…    cargo test -- --ignored
                                                        -> 3 passed (含两个金标准)
mhydump cipher --exe …/7.1.0/YuanShen.exe --metadata …  -> M1/X1/X2/strsec 与手写值逐位相同
```

**仍未解决/不能夸大的部分**

- 三个 `#[ignore]` 里 `dump::tests::full_dump` 仍会在缺 `Original/` 时提前返回并报 ok
  （PLAN 验收判据 3 要求的"不许静默 skip"还没做，属于既有问题）。
- 21 个可解析版本里只推导出 5 个的密码；这不是"未来版本自动适配"已完成，只是把
  **字符串密码这一环**从"人工逆向"变成了"自动 + 可判定验证"。
- 表基址/列常数（typeDefs 的 stride 与各列 C）仍未自动识别；本轮只做到"能从代码里读出所有
  header 槽锚点"，语义标签仍需判别器。

---

## 2026-10-12 本轮（三）：用 kuna 反编译啃 7.0.0 —— 工作流跑通，密码常数仍未到手

### 结论（TL;DR）

1. **反编译工作流跑通了**：从 PE 里切出 VA 窗口 → kuna 以 raw-image 模式反编译 → 秒级得到可读 C。
   这比把 445 MB 整 exe 塞进 Ghidra 现实得多（之前那次全量 kuna 跑出 116 万个函数**全部失败**，
   日志 ~/gire/logs/kuna_full.log 有记录）。
2. **实测确认了 body = dat[0x210:] 这个一直靠约定的事实**：7.0.0 的加载代码
   ADD RSI,0x210 ; MOV [0x145898160],RSI（0x140506419）就是它。
3. **读出 7.0.0 的逐构建表锚点与行掩码链**——这些以前只能靠扫常数池猜，现在可以直接抄。
4. **但 7.0.0 的字符串密码常数仍没拿到**，而且这次是有明确证据的"不在那里"：
   - AND r32,0xFFFFFF 站点确实有 214 个，但满足 const,imul,const,arith,const,arith
     顺序的只有 **2** 个；
   - 把**全 .text 的 7165 个去重 movabs 立即数**两两配对，对 **101 个候选 strsec** 逐个检验
     u64(body,s) XOR "mscorlib"，**命中 0 组**。
   ⇒ 7.0.0 的密码常数**不是以 movabs 立即数形式出现的**。

### 反编译工作流（可复现）

```bash
# 1) 按 VA 切窗口（.text: VA 0x140001000, raw@0x400）
python3 - <<'PY'
data = open('.../7.0.0/YuanShen.exe','rb').read()
lo, hi = 0x140490000, 0x140520000
open('win70.bin','wb').write(data[0x400+(lo-0x140001000):0x400+(hi-0x140001000)])
PY
# 2) kuna raw-image 反编译（--raw-image 必须配 --entry 或 --addr，否则 exit 2）
KUNA=~/Documents/git-repo/kuna/decompiler/target/release/kuna
$KUNA decompile-project win70.bin --raw-image --target x86:LE:64:default \
      --base 0x140490000 --addr 0x1404e40f5 --addr 0x1404e3aee \
      --max-fn-seconds 25 -o win70_out
```

产出 win70_out/win70.bin.c（可读 C）、.asm（带标签反汇编）、README.md。窗口 589 KB、约 1 分钟。

### 7.0.0 实测读到的东西

**全局块**（静态初始化器 0x1402CC250 设置 5 个 .rdata 指针）：

| 全局 | 设置者 | 含义（实测） |
|---|---|---|
| 0x145898138 | 0x1402CC250 | .rdata 指针 0x142444D1F |
| 0x145898140 | 0x1402CC25E | .rdata 指针 0x1429B887F |
| 0x145898148 | 0x1402CC26C | .rdata 指针 0x1429B891F |
| 0x145898150 | 0x1402CC27A | .rdata 指针 0x142444DBF |
| 0x145898158 | 0x1402CC288 | **MHY header blob = 0x142720328** 对 |
| 0x145898160 | 0x140506419 | **body = dat + 0x210** 对 |
| 0x145898168 | 0x140506427 | 另一个 buffer（sub_1404f4160 的返回值） |

**header 槽 + 逐构建偏置**（从反编译 C 里直接抄，全部实测）：

    hdr[0x018] XOR 0x4315C53E      hdr[0x0AC] XOR 0x668A4310     hdr[0x0C4] - 0x3BD1A371
    hdr[0x05C] XOR 0x447D42E3      hdr[0x0B4] XOR 0x37E0AFCA     hdr[0x0D0] - 0x7DAA9978
    hdr[0x098] XOR 0x29B143B8      hdr[0x130] + 0x97677D05       hdr[0x144] XOR 0x47D7567C
    hdr[0x168] - 0x54DBBA01        hdr[0x1D0] - 0x46741881       hdr[0x204]

**行掩码链 / 字段掩码链**（就是 profile 里的 MaskChain / FieldMaskChain）：

```c
// 0x14050702F: MaskChain{mul1:0x694d, xor1:0x44d8cee5, mul2:0x31d1ec69,
//                         add1:0xadc957219da1cfc, shift:0x13} 再接
//              {mul:0x67f1c1f0, add:0x282d09d97e0, shift:0xb}
(v * 0x694d ^ 0x44d8cee5) * 0x31d1ec69 + 0xadc957219da1cfc >> 0x13
((v * 0x1e3d ^ 0x363cc10e) * 0x2ae53798 >> 0x15) * 0x71ed01c5
```

**顺便认出一个标准件**：sub_1404e0110 是 **xxHash64**——常数正好是标准素数
（-0x61c8864e7a143579 = 0x9E3779B185EBCA87 = XXH_PRIME64_1，
-0x3d4d51c2d82b14b1 = 0xC2B2AE3D27D4EB4F = XXH_PRIME64_2，0x165667b19e3779f9 = XXH_PRIME64_3）。
它被用来把去混淆后的名字哈希进哈希表，**不是**字符串密码
（之前把 sub_1404e0110(...) XOR K 误读成 key 的地方，在此纠正）。

### 否证（本轮最重要的负结果）

| 检验 | 结果 |
|---|---|
| AND r32,0xFFFFFF 站点（7.0.0） | 214 个（含 81 /4 与 25 两种编码） |
| 其中有 const,imul,const,arith,const,arith 顺序 | **2** 个 |
| 全 .text 去重 64 位 movabs 立即数 | 7165 个 |
| u64(body,s) XOR "mscorlib" 与"两立即数异或"逐对检验 | 101 候选 strsec × 7165 立即数 → **0 命中** |
| 用 101 个候选 strsec 给那 2 个三元组打分 | 最高 123（噪声底 ~100） |

⇒ **7.0.0 的密码常数不在 movabs 立即数里。** 旁证：0x140481EB0/EC0/ED0 三个小桩是
MOVABS K ; ADD RAX,[RCX+off] ; RET——即"真值 = 偏置 + 内存字段"，说明该构建把常数放在
**内存结构**里，用逐构建偏置解混淆。

### 下一步（给下一次会话的明确入口）

1. 找到那个"内存结构"的**填充点**：在 kuna 输出里搜对 +8/+0x10/+0x18 的写入，或对
   0x140481EB0/EC0/ED0 的调用者做数据流回溯（已知调用点：0x140CB6C23、0x1411784AA/958/9FC/A4B、
   0x1414157D7…0x14141EEB8）。
2. 读出 (M1,X1,X2) 后用现成的 derive::cipher::density_score 验证（判据已就绪，7.1 上 15163 vs 噪声 99）。
3. 探针脚本都在 /home/yangsanyi/项目/逆向和数据提取/_gi_probe/：
   find_decoder7.py（能跑通的 5 个版本）、movabs_pair.py（否证）、key0_test.py、
   decoder_consumer.py、init_stores.py、find_strbase.py；kuna 窗口输出在 win70_out/、win70_cipher/。

**本轮未改动任何产品代码**（只加文档）；cargo test 状态与上一轮相同。

### 补记之二：找到"密钥步进表"——`M4` 可以零常数拿到（已验证）

**这一条是本轮真正的收获**，而且已经落到产品代码里。

7.1 解码器的反编译 C（`win71_dec/win71.bin.c`）里，SIMD 路径把运行密钥加上一张 .rdata 表：

```c
v25 = a1 + dat_1439095e0;   v26 = ...(a1 的高 64 位) + dat_1439095e8;
...
v25 += v5;  v26 += v6;      // v5,v6 = dat_143909600 / 143909608
```

把那 6 个 qword 读出来，得到：

    0x1439095E0: [0, M4, 2*M4, 2*M4, 4*M4, 4*M4]      M4 = 0x0889EEEA326AFB36

**这个形状与常数无关**，所以可以直接当签名搜：`q0==0 && q2==q3==2*q1 && q4==q5==4*q1`。
实测（`derive::cipher::find_key_step_tables`，已进仓库并带 #[ignore] 金标准测试）：

| 版本 | 找到的表 | k(=M4) | 是否与独立结果一致 |
|---|---|---|---|
| 7.1.0 | 0x1439095E0 | 0x0889EEEA326AFB36 | 与手写 profile 一致 ✓ |
| 4.8.0 | 0x142734350 | 0x3BF3D8192287239D | 与上一轮"指令形态"独立推出的 M4 一致 ✓ |
| 7.0.0 | 0x1437EE100 | 0x26A1840875C05436 | 待验证 |
| 6.4.0 | 0x1431E30A0 | 0x559331335A8C1A01 | 待验证 |
| 5.0.0 | 0x142737D40 | 0x640D1D726500ED33 | 待验证 |

（每个版本还会多出一个"约 0x50 之后"的同形窗口，那是巧合匹配；两个已独立验证的版本里
真表都在**较低地址**那个。）

**为什么这条重要**：7.1 的 `paddq xmm0,[rip+0x33f8676]` 目标正好 = 0x1439095E0，
即"谁引用了这张表，谁就是解码器"。这条引用关系是**常量无关**的，可以当作找解码器的锚点，
不再依赖 `and 0xFFFFFF` 或指令顺序。

### 补记之三：一个会静默出错的方法学陷阱（务必记住）

**capstone 的 `md.disasm()` 遇到第一个无法解码的字节就停止迭代**，不报错。
本会话早些时候几个"线性反汇编全 .text"的扫描因此**在几 MB 处就静默截断**，得出
"0 命中"的假结论。正确做法是 `md.skipdata = True`，并跳过 `ins.id == 0` 的 data 伪指令
（注意：skipdata 模式下读取 `ins.operands` 会抛 `CS_ERR_SKIPDATA`）。
本轮 `table_refs2.py` 就踩了两次：第一次 0 命中是截断，第二次是没跳过 data 指令。
以后凡是"全 .text 线性扫描"的结论，都必须先确认扫描确实走到了目标地址之后。

### 本轮（三）代码改动

- `src/derive/cipher.rs`：新增 `KeyStepTable` 与 `find_key_step_tables()`（形状签名，零常数）。
- `src/main.rs`：`mhydump cipher` 现在同时打印密钥步进表；`--json` 输出
  `{ciphers, key_step_tables}`。
- 新增 `#[ignore]` 金标准测试 `derive::cipher::tests::finds_71_key_step_table`。

实测：`cargo test --offline --release` → 16 passed / 0 failed / **4 ignored**；
带样本跑 `-- --ignored` → **4 passed**（3 个金标准 + full_dump）。

---

## 2026-10-12 本轮（四）：**7.0.0 字符串密码解开** —— 算法确实变了一代

### TL;DR

1. **找到了常量无关的解码器锚点**：密钥步进表（`[0,k,2k,2k,4k,4k]`）→ 谁 RIP 引用它，谁就是
   字符串解码器。7.1.0 上该锚点给出的地址 `0x140510F62` 正是手工定位的 `paddq xmm0,[table]`。
2. **7.0.0 的完整密码拿到并验证**（密度 15116 vs 噪声 83，180 倍分离；解出的堆开头是
   `mscorlib`、`<Module>`、`Locale`、`.ctor`、`GetText`、`Format`、`Mono`、`mono_run`…）。
3. **失败的根因找到了**：**算法本身变了**，不是只有常数轮换。7.1 是 3 常数一环：

       key = ((off*M1 + X1) ^ X2)

   而 7.0.0 是 **5 常数两环**：

       key = (((off*M1 + X1) ^ X2) * M5) ^ X3

   所以任何"只扫 3 个 movabs"的做法在 7.0.0 上必然 0 命中——这解释了前面所有否证。

### 7.0.0 实测配方（原始汇编 0x1404E0F76..0x1404E0FBD）

```asm
0x1404E0F76  and    r12d, 0xffffff              ; off = idx & 0xFFFFFF
0x1404E0F7D  movabs rax, 0x4348f5daa8966d44     ; M1
0x1404E0F87  imul   rax, r12
0x1404E0F8B  movabs rcx, 0xf4176615f38c2f5a     ; X1
0x1404E0F95  add    rcx, rax
0x1404E0F98  movabs rax, 0x6814c42e4410abd4     ; X2
0x1404E0FA2  xor    rax, rcx
0x1404E0FA5  movabs rcx, 0x157501347813e1a5     ; M5   <-- 7.1 没有这一环
0x1404E0FAF  imul   rcx, rax
0x1404E0FB3  movabs rdx, 0x5df3519558f2f383     ; X3
0x1404E0FBD  xor    rdx, rcx                    ; key
0x1404E0FC0  mov    r15, [rip+0x53b7199]        ; body_global
0x1404E0FC7  mov    rcx, [rip+0x53b718a]        ; hdr_global
0x1404E0FCE  movsxd rdi, [rcx + 0xf8]
0x1404E0FD5  xor    rdi, 0x3ea3a8a2              ; strsec = hdr[0xF8] ^ 0x3EA3A8A2 = 0x3CF7480
```

    M1 = 0x4348F5DAA8966D44    X1 = 0xF4176615F38C2F5A    X2 = 0x6814C42E4410ABD4
    M5 = 0x157501347813E1A5    X3 = 0x5DF3519558F2F383
    M4 = 0x26A1840875C05436    （由密钥步进表签名独立得到，和上面 movabs 无关）
    strsec = 0x3CF7480         （hdr[0xF8] XOR 0x3EA3A8A2，该锚点本就在 mhydump anchors 的候选里）

**验证**（`crack70b.py`）：256 KiB 窗口可打印命中

| 条件 | score |
|---|---|
| 两环配方 + strsec=0x3CF7480 | **15116** |
| 噪声底 | 83 |
| 两环配方 + strsec 平移 ±0x1000 | 117 / 99 |
| **只留一环**（7.1 的形态） | 91 |

解出的前 160 字节含明文片段：`mscorlib`…`<Module>`…`Locale/`…`ie.ctor`…`msg`…`GetText`…
`fmt`…`args`…`Format`…`Runtime`…`Mono`…`mono_run`…`InstallS`。

### 6.4.0 是同一代（同样的两环、末环用 add）

```asm
0x1404752FB  movabs rcx, 0x4e1009f7522e99be ; X1
0x140475305  add    rcx, rax               ; + off*M1（M1 在更前面）
0x140475308  movabs rax, 0x1e8630f6036cc924 ; X2
0x140475312  xor    rax, rcx
0x140475315  movabs rcx, 0x1042df475dce9fe2 ; M5
0x14047531F  imul   rcx, rax
0x140475323  movabs rdx, 0x37b224710a440cc3 ; X3
0x14047532D  add    rdx, rcx               ; 末环是 add 而不是 xor
```

⇒ 这一代的形态是"**两环 + 末环可 xor/add**"。这也说明：**自适应推导必须能读任意长度的常数链，
不能假设固定形态**。

### 常量无关的解码器锚点（本轮的通用方法）

    1. 形状签名找密钥步进表：连续 6 个 qword 满足 q0==0, q2==q3==2*q1, q4==q5==4*q1
    2. 找 RIP 引用该表的指令 —— 那就是解码器的 SIMD 密钥初始化
    3. 从引用点向前找 `and r32,0xFFFFFF`（取被掩码的寄存器 = off），向后/向前读出常数链
    4. 用密度分（256 KiB 可打印窗口 ≥3000）验证，并同时确定 strsec

实测该锚点对 **7.1.0 / 7.0.0 / 6.4.0 / 6.7.0 / 5.4.0 / 5.2.0 / 5.0.0 / 4.8.0 每个版本都只给出
2 个候选**（一个真一个巧合），且已验证的版本里真候选都在较低地址。

**为什么之前全失败**：先是 `and r32,0xFFFFFF` + 固定 3 常数形态的硬假设；再是
capstone 的 `disasm()` 在第一个非法字节静默停止（见补记之三），使若干次"全 .text"扫描
其实只扫了几 MB。两个坑叠在一起，把 7.0.0/6.4.0 一直判成"常数不在立即数里"。

### 落地结果（本轮最终）：`mhydump cipher` 现在能解开 7.0.0

把上面 4 步做进了 `derive::cipher`：

- `find_key_step_tables`（形状签名）
- `rip_refs_to`（RIP 引用扫描，覆盖 `66/F3/F2 0F xx /r`、`REX 8B/8D/89 /r`、`REX 0F xx /r` 三种编码）
- `find_mask_before`（向前找 `and r32,0xFFFFFF`，返回**指令对齐**地址与目的寄存器）
- `eval_schedule`（小型寄存器模拟器：从 mask 处起按指令求值，遇到非算术语义即停，
  取"最后一次算术运算写出的寄存器"作为 key —— 于是常数链长度与末环是 xor 还是 add 都无所谓）
- 候选 strsec 来自 `mhydump anchors` 的解出值；先用 512 字节预筛，再跑 256 KiB 密度判定

**实测矩阵**（`mhydump cipher`，"schedule-derived cipher" 行）：

| 版本 | 解码器 | strsec | score |
|---|---|---|---|
| 7.1.0 | 0x140510F62 | 0x3C58E68 | 15163 |
| **7.0.0** | **0x1404E102D** | **0x3CF7480** | **15116** |
| 6.7.0 | 0x1404BB5B2 | 0x4126798 | 15119 |

6.4.0 / 5.0.0 / 5.2.0 / 4.8.0 / 5.4.0 / 6.0.0 仍未出结果——但机制已经在 7.0.0 上被证明可用，
剩下的是候选 strsec 覆盖或该版本的 schedule 里有模拟器还不支持的指令（下一步只需补这一个点）。
注意 7.0.0 在上一轮还是"21 个版本里 0 命中"的那一类。

### 最终结果：4.8.0 – 7.1.0 **全部 20 个版本**零常数推导成功

最后一处的修补是**候选 strsec 的来源**：既然解码器算出的 `key(0)` 就是堆 offset 0 的密钥，
而 IL2CPP 堆 offset 0 必是 `mscorlib`，那么 `strsec` 可以直接反查——

    u64(body, s) == key(0) XOR "mscorlib"

在 body 上做一次 8 字节模式搜索即可，**完全不需要候选列表**（早先版本的失败就因为
候选来自 `mhydump anchors`，而少数版本的 strsec 锚点没被恢复出来）。

实测矩阵（`mhydump cipher`，本机全量跑）：

| 版本 | 解码器 | strsec | score |
|---|---|---|---|
| 4.8.0 | 0x140538718 | 0x21A78D0 | 15430 |
| 5.0.0 | 0x140580AA5 | 0x2498BEC | 15414 |
| 5.1.0 | 0x1402FB563 | 0x41D2A0 | 15425 |
| 5.2.0 | 0x1403A6228 | 0x26BE5EC | 15449 |
| 5.3.0 | 0x140050123 | 0xB3CF1C | 15406 |
| 5.4.0 | 0x14005EE98 | 0x2B7E820 | 15454 |
| 5.5.0 | 0x140072C4B | 0x233E2CC | 15442 |
| 5.6.0 | 0x14047736B | 0x24E884C | 15423 |
| 5.7.0 | 0x140500CA9 | 0x1B34E34 | 15447 |
| 5.8.0 | 0x14052CEC3 | 0x16F828 | 15432 |
| 6.0.0 | 0x14045DE9A | 0x1936880 | 15409 |
| 6.1.0 | 0x14043A9CD | 0x2B0FA44 | 15177 |
| 6.2.0 | 0x140445C38 | 0x201CAC8 | 15147 |
| 6.3.0 | 0x14046364D | 0xCE0274 | 15134 |
| 6.4.0 | 0x14047539A | 0x2F7D00 | 15161 |
| 6.5.0 | 0x140493ADD | 0xAF27F4 | 15156 |
| 6.6.0 | 0x1404A7DD0 | 0x2576DD0 | 15141 |
| 6.7.0 | 0x1404BB5B2 | 0x4126798 | 15119 |
| 7.0.0 | 0x1404E102D | 0x3CF7480 | 15116 |
| 7.1.0 | 0x140510F62 | 0x3C58E68 | 15163 |

噪声底 20–100，因此每个版本的分离度都在 **150–700 倍**。
其中 5 个版本（4.8.0 / 5.2.0 / 5.4.0 / 6.7.0 / 7.1.0）的 strsec 与**独立路线**早就得到过，
此处**逐位一致** —— 这是交叉验证，不是自证。

**这条链路现在完全不含任何硬编码常数**：

    找密钥步进表（形状签名）
      -> 找引用它的代码（RIP 引用扫描）
      -> 向前找 and r32,0xFFFFFF（拿 off 寄存器），向后按指令模拟执行（链长/末环运算无关）
      -> 用 key(0) XOR "mscorlib" 反查 strsec
      -> 密度分（256 KiB 可打印窗口 >= 3000）判定

对"未来版本"而言，只要这三件事不变（表形状、解码器引用它、堆以 mscorlib 开头），
就应当零改码直接得到密码与 strsec；若哪一环变了，失败会表现为**明确无候选**，而不是输出垃圾。



### 下一步（自适应产品化）

把上面 4 步做进 `derive::cipher`：
- `find_key_step_tables`（已进仓库）
- `find_decoder_sites(table_va)`：RIP 引用扫描（numpy 版已在 `_gi_probe/table_refs_np.py` 验证）
- `eval_schedule(site, off)`：从 `and r32,0xFFFFFF` 到表引用之间的小型寄存器模拟器，
  直接按指令求值（常数链长度不限，能覆盖 3 常数/5 常数/xor 或 add 末环）
- 用 `density_score` 对 `mhydump anchors` 给出的候选 strsec 打分，≥3000 接受

这样"未来版本"就只依赖**形状签名 + 指令模拟 + 密度判据**三件事，不再依赖任何固定常数或固定指令形态。



### 补记：本轮又排除掉的假设（2026-10-12 深夜，同一会话）

在 §14 的否证之后继续排除，全部实测，**列出来是为了让下一次会话不要重复**：

| 假设 | 检验 | 结果 |
|---|---|---|
| 常数是 .rdata 里的 8 字节值（`mov r64,[rip+X]`） | 全 image 扫出 614 个可这样加载的值，与 101 个候选 strsec 的 key0 配对 | **0 命中** |
| 索引掩码不是 0xFFFFFF | 试 0x1FFFFFFF / 0x3FFFFFFF / 0x7FFFFFF / 0xFFFF 四种掩码重跑调度搜索（站点数 362/166/22/3） | **0 命中**（顺带发现 7.1 自己也有 `AND r15d,0x1FFFFFFF`，所以那不是区分特征） |
| key0 被原样存成 8 字节 | 对 101 个候选 strsec 求 key0 并在整个 exe 里搜该 8 字节 | 只有 3 例命中，且都是 `key0 = 0x62696C726F63736D`（= ASCII "mscorlib" 本身），即 body 处是**8 个零字节**导致的平凡解——**这也是一个陷阱：mscorlib 检测会把零填充当成命中**，好在密度分把这类假阳过滤掉了 |

**另一个读出来的（可能解释失败版本的关键线索）**：用 kuna 反编译 **7.1 自己的解码器**
（`win71_dec/win71.bin.c`，源 `--addr 0x140510EF5`）后，它的常数**也不是全在立即数里**：

```c
v15 = *(int *)(dat_145ad62b8 + 0x150) + -0x37abd22e;   // strsec = hdr[0x150] + bias
v8  = dat_145ad62c0 + v15;                              // body + strsec
...
v25 = a1 + dat_1439095e0;      // 密钥步进向量，来自 .rdata 表 0x1439095e0
v26 = SUB168(v24._0_16_,8) + dat_1439095e8;
...
v7 = *v10 ^ a1;  a1 += 0x889eeea326afb36;               // M4 在这条标量路径上是立即数
```

即：**同一版本里，部分常数是立即数、部分在 .rdata 表里**。这解释了为什么"只扫立即数"和
"只扫 .rdata 加载"两种做法都会漏。对 7.0.0 而言，剩下的可能是"常数由内存结构在运行时算出"，
而不是任何一种静态形态。

**下一步的最短路径**（已收敛到一条）：
1. 用 kuna 对 7.0.0 的 `0x145898168` 那个 buffer 的**初始化路径**做反编译追踪（它由
   `sub_1404f4160` 返回，见 0x140506427；先弄清它是什么 buffer）；
2. 在那附近找密钥步进表（7.1 的形式是 .rdata 里连续 6 个 qword，被 `MOVDQA` 一次读入，
   紧跟 `PADDQ` 递增）。7.0.0 的窗口里确有 `PADDQ XMM0,[0x14212d360]` 与
   `PADDQ XMM1,XMM4`（XMM4 来自 `[0x14213e2f0]`）——**这两个 .rdata 地址很可能就是
   候选密钥表**，值得优先验证：读出那 16 字节，按 7.1 的排程试解，用 `density_score` 判定。




---

## §15 第十七轮 — 密钥调度「即数据」+ 字符串堆真实结构（2026-10-13）

> 本节是 agent 日记，**不是需求**。需求见 `REQUIREMENTS.md` R2/R4/R5/R6。
> 本轮全部结论都有实测命令与输出支撑；推测处已显式标注。

### 15.1 本轮解决的三件事

| 上轮遗留 | 本轮结果 | 证据 |
|---|---|---|
| 3. 调度常数未导出成数据（profile 只能描述 3 常数一代） | **已解决**：@BT@CipherOp@BT@ / @BT@CipherSchedule@BT@ 把调度序列化成 op 列表；@BT@Profile.cipher@BT@ 携带它；@BT@decode_str_sched@BT@ 按数据解密 | `src/derive/cipher.rs`, `src/derive/profile.rs`, `src/decode_str.rs` |
| 2. dump 只认 7.1，换版本会静默出错 | **已加固**：@BT@dump71@BT@ 每次运行都零常数重推导本机调度并与 profile 比对，不一致直接 bail；@BT@--profile-in/--profile-out@BT@ 使 profile 可落盘 | 7.0.0 实测拒绝，见 15.4 |
| 1. 表锚点/列常数语义 | **未解决**，但本轮排除了一条看起来最省事的路（15.6 的负面结果） | 见 15.6 |

### 15.2 调度即数据：符号化推导代替形态假设

`eval_schedule` 原本是「具体值模拟器」，只能得到某个 off 的密钥值。本轮把它改成**符号化**的
`trace_schedule`：每个寄存器或是常量，或是一条 `Vec<CipherOp>` 链；`and`（第二操作数是立即数，
不走寄存器通道）、`mov imm/imm64/reg`、`imul/add/xor/sub` 按原控制流逐条累积。停止条件、
「最后一次算术写出的寄存器胜出」都与原实现逐条对齐，因此 `trace.key(off) == eval_schedule(off)`
是构造性成立的，而不是假设。

`CipherSchedule { ops: Vec<CipherOp>, step: u64 }`，`key(off) = ops.fold(off & 0xFFFFFFFF)`，
每条串内每 qword `key += step`。`step` 取自解码器 RIP 引用的那张 key-step 表（`[0,k,2k,2k,4k,4k]`）。

### 15.3 20/20 版本实测：调度形态**根本不统一**

命令：`mhydump cipher --exe <YuanShen.exe> --metadata <global-metadata.dat>`（无任何常数输入）

| 版本 | decoder VA | mask VA | strsec | score | step (M4) | key(off) 链长 |
|---|---|---|---|---|---|---|
| 4.8.0 | 0x140538718 | 0x140538676 | 0x21A78D0 | 15430 | 0x3BF3D8192287239D | 3 |
| 5.0.0 | 0x140580AA5 | 0x1405809F6 | 0x2498BEC | 15414 | 0x640D1D726500ED33 | 5 |
| 5.1.0 | 0x1402FB563 | 0x1402FB4A6 | 0x41D2A0 | 15425 | 0x2C50F46D29CE36F2 | 6 |
| 5.2.0 | 0x1403A6228 | 0x1403A6186 | 0x26BE5EC | 15449 | 0x17D9DBE24B579596 | 3 |
| 5.3.0 | 0x140050123 | 0x140050076 | 0xB3CF1C | 15406 | 0x5BDC8D961275D95C | 4 |
| 5.4.0 | 0x14005EE98 | 0x14005EDF6 | 0x2B7E820 | 15454 | 0x05510ECD3314C022 | 3 |
| 5.5.0 | 0x140072C4B | 0x140072BB6 | 0x233E2CC | 15442 | 0x254B990D17531907 | **2** |
| 5.6.0 | 0x14047736B | 0x1404772D6 | 0x24E884C | 15423 | 0x37387D741155E63E | **2** |
| 5.7.0 | 0x140500CA9 | 0x140500C06 | 0x1B34E34 | 15447 | 0x604DA00F6BA46CB7 | 3 |
| 5.8.0 | 0x14052CEC3 | 0x14052CE26 | 0x16F828 | 15432 | 0x64EAB58C6CF7C593 | 3 |
| 6.0.0 | 0x14045DE9A | 0x14045DDD6 | 0x1936880 | 15409 | 0x2294B0FD262219DD | **7** |
| 6.1.0 | 0x14043A9CD | 0x14043A926 | 0x2B0FA44 | 15177 | 0x70DD11245F19F77B | 4 |
| 6.2.0 | 0x140445C38 | 0x140445B76 | 0x201CAC8 | 15147 | 0x35ADCAE53E189E2B | **7** |
| 6.3.0 | 0x14046364D | 0x140463596 | 0xCE0274 | 15134 | 0x79E816B132CFA89F | 5 |
| 6.4.0 | 0x14047539A | 0x1404752E6 | 0x2F7D00 | 15161 | 0x559331335A8C1A01 | 5 |
| 6.5.0 | 0x140493ADD | 0x140493A26 | 0xAF27F4 | 15156 | 0x7855C7EB774C7ACF | 5 |
| 6.6.0 | 0x1404A7DD0 | 0x1404A7D26 | 0x2576DD0 | 15141 | 0x32FC3E6E0DCDFABC | 4 |
| 6.7.0 | 0x1404BB5B2 | 0x1404BB516 | 0x4126798 | 15119 | 0x3FF74ECE11DFA612 | 3 |
| 7.0.0 | 0x1404E102D | 0x1404E0F76 | 0x3CF7480 | 15116 | 0x26A1840875C05436 | 5 |
| 7.1.0 | 0x140510F62 | 0x140510EC6 | 0x3C58E68 | 15163 | 0x0889EEEA326AFB36 | 3 |

链长从 **2 到 7** 都有：5.5.0 / 5.6.0 的密钥只有 `(off*K1)+K2` 两项，6.0.0 / 6.2.0 有 6~7 项。
这直接证明「按常数个数/运算顺序设形态」的做法不成立，也证明本轮改成执行指令流是必要的。
噪声底 20~100，命中 15116~15454，分离度 ≥150 倍。

完整公式（`mhydump cipher` 原样输出，可直接抄进 profile）：

```text
4.8.0  ((((off & 0xFFFFFF) * 0x9C9BC1DE1BC7E406) + 0x187E17AE6D781B2A) ^ 0x79833B980C2747C1)
5.0.0  (((((off & 0xFFFFFF) * 0xE3236E3D2067A02E) + 0xA0C3CAC48F9BACD5) ^ 0x473F9D290AFA60AB) + 0x453513C259C49345)
5.1.0  ((((((off & 0xFFFFFF) * 0x34CD10990D7D9823) ^ 0x77D112F9514FB411) * 0x731B123777F518CA) ^ 0x1AB4E3F456BA7971) + 0x2C7C052765FEC6CE)
5.2.0  ((((off & 0xFFFFFF) * 0x8222E9E43A13197F) + 0x339A34E7CBFD38F7) ^ 0x4D37E7915DFE55F7)
5.3.0  (((((off & 0xFFFFFF) * 0x256402235F569E29) ^ 0x3521B384212505E3) * 0x66AE77CAC13366AC) + 0x4CDACAB74E3258A4)
5.4.0  ((((off & 0xFFFFFF) * 0xABA245CD4BE8E3B0) + 0x32AA522A0281FDAA) ^ 0x34CC45C5274E0D3A)
5.5.0  (((off & 0xFFFFFF) * 0xB4482F7F53B5E9E0) + 0xB19002C013F13850)
5.6.0  (((off & 0xFFFFFF) * 0xF16919F0DA468D7E) + 0x7B322578F9863689)
5.7.0  ((((off & 0xFFFFFF) * 0x97072D0A3FEC10F5) ^ 0x1CE7C2B84F1CF2B2) * 0x74ECAAEA09B925D7)
5.8.0  ((((off & 0xFFFFFF) * 0xD7A9357EF2702114) ^ 0x238342ED50371641) * 0x2D52846B435A3A00)
6.0.0  (((((((off & 0xFFFFFF) * 0x6D52B2CA1C6A412B) + 0x7ACD32280D2C5C80) ^ 0x446E591D6869B1DC) * 0x39909850750B716E) + 0x6685F90D269AB894) ^ 0x272770C13DB4E917)
6.1.0  (((((off & 0xFFFFFF) * 0x3CC7294F24214E1B) ^ 0x4B4C90710E83CB95) * 0xC5F0FA62F6DACAB0) + 0x37EFE465F8A0D79)
6.2.0  (((((((off & 0xFFFFFF) * 0x79DFBE452D3AB0AD) ^ 0x1182BD2830337353) * 0x6697113103627390) ^ 0x3817CD142A5CCA3F) * 0x6A21A4F92A1F2BCD) ^ 0x182244C0678DA397)
6.3.0  ((((((off & 0xFFFFFF) * 0x4F0F53D866C34467) ^ 0x3724E36F55DB2CB6) * 0x4CBF25321F6DD15F) ^ 0x457AE9BC5E28D170) + 0x7318A64763A88369)
6.4.0  ((((((off & 0xFFFFFF) * 0x548927AD008C6099) + 0x4E1009F7522E99BE) ^ 0x1E8630F6036CC924) * 0x1042DF475DCE9FE2) + 0x37B224710A440CC3)
6.5.0  ((((((off & 0xFFFFFF) * 0xFF781141A4BE1B0) ^ 0x341A5C2D39CAB4C5) * 0x59AAB7775B11E1DB) + 0x5578E3D60EA74FC4) ^ 0x2668A3370C4F7339)
6.6.0  (((((off & 0xFFFFFF) * 0xF22C9E39644B31EA) + 0x49B3B349FCC1AC34) ^ 0x44E8C5280EBC21B0) * 0x135E6F77652A2371)
6.7.0  ((((off & 0xFFFFFF) * 0xAA160EA68AC8FA68) + 0x24832E3F77AF01E6) ^ 0x7AC9A2F2697FEB99)
7.0.0  ((((((off & 0xFFFFFF) * 0x4348F5DAA8966D44) + 0xF4176615F38C2F5A) ^ 0x6814C42E4410ABD4) * 0x157501347813E1A5) ^ 0x5DF3519558F2F383)
7.1.0  ((((off & 0xFFFFFF) * 0xB33E40427D5668C0) + 0x6D8C4AAB00FE8E27) ^ 0x30EE5B43130FE0CD)
```

7.0.0 这一行与 `IMPLEMENTATION_LOG` 早前手工从反编译 C 里抄出的五常数逐位一致（M1=0x4348F5DAA8966D44,
X1=0xF4176615F38C2F5A, X2=0x6814C42E4410ABD4, M5=0x157501347813E1A5, X3=0x5DF3519558F2F383），
这是一条独立路线的交叉验证。
### 15.4 dump71 的密码交叉校验（R2.4「不许静默输出垃圾」）

`dump71` 现在每次都先零常数重推导本机调度，再与 profile 的调度比对；不一致直接 `bail`：

```text
$ mhydump dump71 --exe .../7.1.0/YuanShen.exe --metadata .../7.1.0/.../global-metadata.dat --out /tmp/d71.cs --profile-out /tmp/p71.json
INFO cipher cross-check OK: ((((off & 0xFFFFFF) * 0xB33E40427D5668C0) + 0x6D8C4AAB00FE8E27) ^ 0x30EE5B43130FE0CD)
INFO header OK: strsec=0x3C58E68 td=0x48F3FD8 md=0x23F8770 fd=0x391D4 params=0x10CB8E0 typearr=0x2E1EB30(683568) mptrs=0x2451BE8(460313)
wrote profile /tmp/p71.json
wrote /tmp/d71.cs + script.json: 88872 types, 440061 fields, 460282 methods

$ mhydump dump71 --exe .../7.0.0/YuanShen.exe --metadata .../7.0.0/.../global-metadata.dat --out /tmp/d70.cs
WARN cipher MISMATCH: profile key(off) = ((((off & 0xFFFFFF) * 0xB33E40427D5668C0) + 0x6D8C4AAB00FE8E27) ^ 0x30EE5B43130FE0CD) ;
     binary  key(off) = ((((((off & 0xFFFFFF) * 0x4348F5DAA8966D44) + 0xF4176615F38C2F5A) ^ 0x6814C42E4410ABD4) * 0x157501347813E1A5) ^ 0x5DF3519558F2F383)
     (step 0x889EEEA326AFB36 vs 0x26A1840875C05436)
Error: profile does not match this binary (strings would decode to garbage); pass --profile-in for this build, or --no-cipher-check to force
```

注意：**这不是「7.0.0 解不了」，而是「表常数还停在 7.1，所以拒绝出 dump」**。
字符串那一层 7.0.0 已经解出来了（15.3），卡点仍然只有表锚点/列常数（15.6）。

profile 往返（`--profile-out` → `--profile-in`）产出逐字节相同：

```text
$ md5sum /tmp/mhyout/dump71.cs /tmp/mhyout/dump71c.cs
f5cfe06b48b80b23e3f3345e5619a3b7  /tmp/mhyout/dump71.cs
f5cfe06b48b80b23e3f3345e5619a3b7  /tmp/mhyout/dump71c.cs
```

`--profile-out` 写出的是**推导得到的**调度（`"cipher": {"ops":[{"op":"And","v":16777215}, {"op":"Mul",...}...]}`），
不再是三常数硬编码；`Profile::schedule()` 在 `cipher` 为空时把老三常数三元组重建成等价 op 列表，
所以新旧 profile 走同一条代码路径。

### 15.5 字符串堆的真实结构（重要更正）

**上一轮（以及更早的 `decode_str` 注释）假设「字符串堆是一串 NUL 结尾、「紧密排列的字符串」——本轮实测把这个假设否证了。**

实测方法（7.1.0）：对堆内每个偏移 `o`，用 `key(o), key(o)+M4, ...` 解密，看边界字节。

| 观测 | 值 |
|---|---|
| `mono_runtime_install_handlers` | @0x5B，长度 29 → 下一个串在 **0x78 = 0x5B+29** |
| `InstallSignalHandlers` | @0x78，长度 21 → 下一个串在 **0x8D = 0x78+21** |
| `mono_runtime_cleanup_handlers` | @0x8D，长度 29 → 下一个串在 **0xAA** |
| `RemoveSignalHandlers` | @0xAA，长度 20 → 下一个串在 **0xBE** |
| `GetDisplayName` | @0xBE，长度 14 → 下一个串在 **0xCC** |
| `exception` | @0xCC，长度 9 → 下一个串在 **0xD5** |

六组全部是 `next = off + len`，**没有终止符、没有对齐填充**；而且边界字节在 key(off)+k·M4 下解出的
正是下一个串的首字节（例如 0xBE+14=0xCC 处解出 `exception`），不是 0x00。
所以字符串的**长度不在堆里，而在索引的高 8 位**（`idx = (len << 24) | off`），索引来自元数据表。
这解释了为什么 `"mscorlib"` 在偏移 0 处 8 字节后紧跟的不是 0，而是 `"mscorlib.dll"` 的首字节。

**可判定判据（保留且更强）**：密钥是绝对偏移的函数，所以把串整体挪一个字节解密就是噪声。
于是「偏移 o 处前 8 字节全落在 0x20..0x7E」当且仅当 o 是长度 ≥8 的串起点（外加约 0.04% 随机命中）。
这就是密度分数在数什么。

`decode_str::string_starts()` 按这条判据枚举，`text` 语义是**精确串 + 之后继续可打印的尾巴**，
文档里写清楚了，不允许把它当成精确串用。要精确串必须用 `decode_str_sched(idx)` 配上真实索引。

### 15.5.1 跨版本实测：20/20 版本堆头一致

命令（每个版本一次）：`mhydump strings --exe <exe> --metadata <dat> --head 4`

| 版本 | 扫到的长度≥8 串起点数 | offset 0 | offset 8 | offset 0x14 |
|---|---|---|---|---|
| 4.8.0 | 420,846 | mscorlib | mscorlib.dll | <Module> |
| 5.0.0 | 437,898 | mscorlib | mscorlib.dll | <Module> |
| 5.1.0 | 452,775 | mscorlib | mscorlib.dll | <Module> |
| 5.2.0 | 447,388 | mscorlib | mscorlib.dll | <Module> |
| 5.3.0 | 471,053 | mscorlib | mscorlib.dll | <Module> |
| 5.4.0 | 463,893 | mscorlib | mscorlib.dll | <Module> |
| 5.5.0 | 429,923 | mscorlib | mscorlib.dll | <Module> |
| 5.6.0 | 440,138 | mscorlib | mscorlib.dll | <Module> |
| 5.7.0 | 452,523 | mscorlib | mscorlib.dll | <Module> |
| 5.8.0 | 467,112 | mscorlib | mscorlib.dll | <Module> |
| 6.0.0 | 472,970 | mscorlib | mscorlib.dll | <Module> |
| 6.1.0 | 558,499 | mscorlib | mscorlib.dll | <Module> |
| 6.2.0 | 570,046 | mscorlib | mscorlib.dll | <Module> |
| 6.3.0 | 593,922 | mscorlib | mscorlib.dll | <Module> |
| 6.4.0 | 607,237 | mscorlib | mscorlib.dll | <Module> |
| 6.5.0 | 622,701 | mscorlib | mscorlib.dll | <Module> |
| 6.6.0 | 625,402 | mscorlib | mscorlib.dll | <Module> |
| 6.7.0 | 628,728 | mscorlib | mscorlib.dll | <Module> |
| 7.0.0 | 654,552 | mscorlib | mscorlib.dll | <Module> |
| 7.1.0 | 672,331 | mscorlib | mscorlib.dll | <Module> |

（表中是去掉尾巴后的串；实际输出会带 0~7 个字节的过读尾巴，例如 4.8.0 显示 `mscorlib~`。
这是 15.5 说的长度缺失导致的，不是解码错误——`mscorlib.dll`、`<Module>` 这些 12/8 字节的串
因为尾巴第一字节恰好不可打印而完整。）

**4.2.0 ~ 4.7.0（加壳老一代）**：`global-metadata.dat` 头仍是 `MHY\0`，但 exe 里找不到 `MHY\0` 内嵌头，
`mhydump strings` 明确报 `no embedded MHY header located` 并退出——不静默出垃圾。这三个版本用户已明确「随便」，
本轮维持不支持。
### 15.6 负面结果：表定位的两条捷径都不通（本轮实测否证）

上轮我在汇报里提过「表锚点与列常数的语义识别」是下一个卡点。本轮试了两条看起来最省事的路，**都失败**，
如实记录，避免后续 session 重走。

**(a) `td_magic` 不是每行的常量 → 不能用「常量等差数列」找 typeDef 表。**

`layout71::gen71()` 里 `td_magic = -0x2145AFB7`（即 u32 `0xDEBA5049`），`engine::td_count()` 用它计行数。
实测 7.1.0 的 typeDef 表（base=0x48F3FD8, stride=0x46, magic 列在 +0x1C）**88904 行里只有 62923 行（70.8%）**
等于 `0xDEBA5049`，其余 30% 落在 `0x214xxxxx` 一带（0x21431BB4、0x214C9459、0x21433FAE …，共 9311 个不同值）。
所以这个字面量**不是格式标记**，它更像是每行一变的掩码材料（`engine::td_parent()` 正是把 +0x1C 当 tag 用：
`parent = raw@0x2C ^ tag ^ 0x8177D738`），`td_count` 只是因为允许 5000 行连续失配才没炸。

**(b) 「任意 u32 值 + 等差位置」全表扫描没有找到任何表。**

做法（`_gi_probe/tbl/t2.py`）：对 4 个字节相位分别取 u32 视图 → `np.unique` 计数 → 对出现 >1500 次的值取位置
→ 求相邻差的众数即 stride → 求最长连续段。7.1.0 全部命中如下（节选）：

```text
shift=0 v=0xFFFFFFFF count=594831 stride=0xC n=543942 run=303289 base=0x13A6FB4
shift=0 v=0x00000000 count=321178 stride=0x4 n=135336 run=3127  base=0xECC434
shift=0 v=0xFFFF0000 count=247498 stride=0x1C n=244446 run=30155 base=0x6E5980
shift=2 v=0x29543783 count=39751  stride=0x8C n=35541  run=159   base=0x4D3169E
```

没有一条是 typeDef 表（0x46 / 0x1C，88904 行）。列出的都是填充区、指针数组这类高频重复值。
结论：**表不是靠「某列恒定」可发现的**——这与 (a) 一致，列普遍带每行掩码。

**(c) 顺带记录的表结构实测**（7.1.0，`_gi_probe/tbl/row.py`）：

typeDef 记录 stride 0x46，用 profile 常数解出的名字/命名空间是**正确的**：
row 0 → `<Module>`，row 1 → `Locale`，row 3 → `Runtime` / ns `Mono`，
row 1000 → `HMACSHA1` / ns `System.Security.Cryptography`。
记录尾部（0x2E~0x46）是**相互重叠的 u16 列**读出来的，直接按 u32 看会以为有「重复的常量」；
上一句的 (b) 之所以扫不到，部分原因就在这里。

### 15.7 本轮新增/改动清单

| 文件 | 改动 |
|---|---|
| `src/derive/cipher.rs` | 新增 `CipherOp`/`CipherSchedule`；`eval_schedule` 重写为 `trace_schedule`（符号化）+ 具体值 wrapper；`ScheduleCipher` 增加 `schedule`/`step_table` 字段；新增 `derive_build()` 单入口；新增 2 个测试 |
| `src/derive/profile.rs` | `Profile.cipher: Option<CipherSchedule>`（serde default）；`Profile::schedule/key/key_step` |
| `src/decode_str.rs` | 新增 `decode_str_sched`；`HeapString` 语义改正；`walk_heap`（错误模型）替换为 `string_starts`；新增 `is_printable_qword` |
| `src/derive/engine.rs` | `Meta.schedule`；`decode_str`/`find_header` 走调度而非三常数 |
| `src/derive/layout71.rs` | 注明 legacy 三元组就是 7.1 推导结果的校验 oracle，`cipher: None` |
| `src/main.rs` | `strings` 子命令；`cipher` 输出公式/step-table；`dump71` 增加 `--profile-in/--profile-out/--no-cipher-check` 与密码交叉校验 |

验证命令与结果：

```text
$ cargo test --offline --release
test result: ok. 17 passed; 0 failed; 5 ignored

$ MHY_SAMPLE_EXE=.../7.1.0/YuanShen.exe MHY_SAMPLE_DAT=.../7.1.0/.../global-metadata.dat \
  cargo test --offline --release -- --ignored
test derive::cipher::tests::finds_71_key_step_table ... ok
test derive::cipher::tests::derives_71_cipher ... ok
test derive::cipher::tests::derives_schedule_for_sample ... ok
test derive::anchor::tests::recovers_71_profile_exactly ... ok
test dump::tests::full_dump ... ok
test result: ok. 5 passed; 0 failed; 0 ignored
```

### 15.8 仍然没解决的部分（诚实清单）

1. **表锚点语义 + 列常数推导**：`derive::anchor` 能把每个 header 槽的偏置从代码里读出来，
   但「哪个槽是 typeDefs / stride 多少 / 每列是什么变换」仍然没有自动判定器。
   本轮排除了「常量等差数列」这条路（15.6），下一步要做的是**定向模拟执行那批访问器**（PLAN T1），
   或者对 `derive::anchor` 已经定位到的 site 做一次小型指令切片分析（读 stride 与列偏移）。
2. **非 7.1 版本出 dump**：字符串层已经 20/20（15.3、15.5.1），但表层没换，所以 `dump71` 在 7.0.0 上
   会**明确拒绝**而不是给出结果（15.4）。要真正出 dump 必须先解决第 1 条。
3. **R4 等价性缺口**：字段偏移（440061/440061 未解）、参数名与参数类型（361974 个 `object /*unresolved*/`）、
   property/event、默认值、GENERICINST、嵌套类型限定、Token、`il2cpp.h`/DummyDll —— 一个都没动。
   这些是 `dump71` 自己在 stderr 里报出来的（见 15.4 输出），不是本轮引入的。

---

## §16 第十八轮 — 把「表定位」也做成零常数结构判据（2026-10-13）

> 本节是 agent 日记，**不是需求**。目标仍是 `REQUIREMENTS.md` R2/R5：算法不大改时能适配未来版本。

### 16.1 本轮思路

上一轮把「密码」变成了数据（§15）。表这一层此前只有 `derive::anchor` 能从代码里读出「header 槽 →
body 偏移」，但「哪个槽是 typeDefs / stride 多少 / 每列什么变换」没有判定器。
本轮改成**找结构不变量**：不读代码、不看版本号，只用「解出来的值必须自洽」这一类可判定谓词。

### 16.2 判据一：索引列的高位不变性（零常数可判定）

typeDef 表里有两类列：一类是**每行掩码材料**（`engine::td_parent` 里的 `tag`），一类是**稠密行索引**
（`fieldStart` / `methodStart`）。对后者，若写成

```text
raw(i) = fs(i) ^ C          (real row, 0 <= fs(i) < T)
raw(i) = 0xFFFFFFFF ^ C     (the "empty" sentinel)
```

则因为 XOR 是逐位的，对任意 `k` 满足 `2^k > T`，`raw(i) >> k` **只可能取两个值**：
`C >> k`（实行）与 `(C >> k) ^ MASK`（哨兵行），其中 `MASK = (1 << (32-k)) - 1`。
这两个值互为按位取反。**这个性质只用原始字节就能验，不需要任何常数**：

- 6 行预筛 → 要求 `raw >> k` 的取值集合 ≤2 个且互补；
- 哨兵类是「raw 只有一个固定值」的那一类（7.1.0 实测：13,627 个哨兵行全是 0x8D9D7FF8），
  另一类有多个不同值 → `C = !sentinel_raw`；
- 解码后必须**单调不减**；
- 每个 u16 列 `fc` 必须满足 `fs(i+1) - fs(i) == (u16 raw) ^ cnt_c` 且连续匹配上千次
  （列链 tiling，这一段才是真正的判别器）。

`k` 是**冗余参数**不是常数：取小了 run 会在索引越过 `2^k` 的那一行被截断（实测会把同一列报成
88904/63770/54818/…多个长度），所以每个列取所有 `k` 里最长的 run。

### 16.3 判据二：字符串索引列的「首字节可打印」（零常数可判定）

名字列形如 `idx = raw + C`，`idx = (len << 24) | off`。**每一行都有名字**，所以 `off_i` 必定是一个
真实串的起点，于是有一个不需要任何常数的谓词：`off_i` 处解密出的第一个字节必须可打印。

对候选低 24 位常数 `l`，第 `i` 行要求 `printable((u_i + l) & 0xFFFFFF)`。对**错误**的 `l`，每条断言
成立的概率是 0.377（实测 = 堆内首字节可打印的偏移占比），所以把 24 行取交集后 2^24 空间里只剩真值：
实测收敛过程 6335898 → 2427508 → … → 4（第 16 行）→ **1（第 18 行起）= 0x11F779**。

交集用「16 Mibit 位图整体旋转再 AND」实现，每列约 4M 次字运算。最后剩下的 length 字节由
`1 <= len_i <= printable_run(off_i)` 定出（逐行给出一个 h 的允许区间，取交集）。

验证阶段必须把「首字节不可打印」的行计入**分母**（早期实现里把它 `continue` 掉，导致错误列也能报出
`54/54` 的完美比例——这是一个已修正的自欺 bug）。修正后 7.1.0 只剩**唯一一列**。

### 16.4 7.1.0 实测：全部命中 `layout71::gen71()`

```text
$ mhydump tables --exe .../7.1.0/YuanShen.exe --metadata .../global-metadata.dat --base 0x48F3FD8
      base stride idx_off     idx_c   sentinel    cnt_off    cnt_c   rows    real    trans
0x048F3FD8 0x0046 0x0008 0x0478AF59 0xFB8750A6 0x003C 0x8811  88904  77725   65536
0x048F3FD8 0x0046 0x0000 0x72628007 0x8D9D7FF8 0x0030 0x9A6B  88904  75277   65536

string-index columns of the first table above:
  col_off=0x14  +0xE811F779  ok 256/256
```

逐项对照 `src/derive/layout71.rs`：

| 本轮自动解出 | profile 里的值 | 结果 |
|---|---|---|
| stride 0x46 | `td_stride` | 一致 |
| idx_off 0x00 / idx_c 0x72628007 | `td_field_start` | 一致 |
| sentinel 0x8D9D7FF8 | `td_fs_sentinel_raw` | 一致 |
| cnt_off 0x30 / cnt_c 0x9A6B | `td_field_count` | 一致 |
| idx_off 0x08 / idx_c 0x0478AF59 | `td_method_start` | 一致 |
| rows 88904 | `td_walk()` | 一致 |
| max_index 440170 | 字段行 440172 | 一致 |
| col 0x14 / +0xE811F779 | `td_name` | 一致 |

**全量扫描**（不指定 `--base`，基址全部来自 `derive::anchor` 从代码里读出的 286 个候选）：

```text
INFO scanning 286 candidate bases from the anchor recovery
      base stride idx_off     idx_c   sentinel    cnt_off    cnt_c   rows    real    trans
0x048F3FD8 0x0046 0x0008 0x0478AF59 0xFB8750A6 0x003C 0x8811  88904  77725   65536
0x048F3FD8 0x0046 0x0000 0x72628007 0x8D9D7FF8 0x0030 0x9A6B  88904  75277   65536

string-index columns of the first table above:
  col_off=0x14  +0xE811F779  ok 256/256
real  2m18s   (12 threads)
```

即：**286 个候选基址 × 512 种 stride × 每个列偏移 × 9 种 k，最后只剩这一张表、这两个索引列、
这一个字符串列**。零常数、零地址、零列名。这是本项目第一次做到「表这一层不需要人工抄常数」。
### 16.5 跨版本实测：**判据在旧版本上不成立**（本轮最重要的负面结果）

同样的命令跑其它版本：

```text
7.0.0  → no row table found by the structural predicate
6.4.0  → no row table found by the structural predicate
5.2.0  → no row table found by the structural predicate
4.8.0  → no row table found by the structural predicate
```

为了区分「结构确实不同」和「搜索写坏了」，给 `analyse` 加了分阶段诊断（`Stage`），
并用 `MHY_ONLY_STRIDE=0x46 MHY_DEBUG=1` 把扫描限制在一个 stride 上，直接报告每个基址能达到的**最长 run**：

```text
=== 7.1.0 ===   base=0x48F3FD8  longest run 88904 rows  stride=0x46 off=0x0 shift=19   <-- 真值
=== 7.0.0 ===   base=0x7F5DE8   longest run 109742 rows stride=0x46 off=0x0 shift=20
=== 6.4.0 ===   base=0x2E87ED4  longest run 96115 rows  stride=0x46 off=0x2 shift=23
=== 5.2.0 ===   base=0xD8010C   longest run 56445 rows  stride=0x46 off=0x0 shift=20
=== 4.8.0 ===   base=0x2952DF4  longest run 534 rows    stride=0x46 off=0x34 shift=24
```

**第一个结论**：高位互补判据并不是 7.1 独有的，7.0.0 / 6.4.0 / 5.2.0 都存在能连续走 5 万~10 万行
的列。5.2.0 到 4.8.0 之间疑似有一次结构变化（4.8.0 最长只有 534 行）。

**第二个结论**：真正卡住的是后面的假设。把 run > 10000 的候选逐个报出它死在哪一步：

```text
=== 7.0.0 ===
  base=0x11B3F28  run 72067  stride=0x46 off=0x4  shift=24  -> rejected at Monotone
  base=0x10B5E18  run 86933  stride=0x46 off=0x28 shift=24  -> rejected at Monotone
  base=0x7F5DE8   run 109742 stride=0x46 off=0x0  shift=20  -> rejected at Run
=== 6.4.0 ===
  base=0xE7579C   run 77262  stride=0x46 off=0x0  shift=20  -> rejected at Monotone
  base=0xFA60E8   run 59440  stride=0x46 off=0x4  shift=17  -> rejected at Tile
=== 5.2.0 ===
  base=0xD8010C   run 56445  stride=0x46 off=0x0  shift=20  -> rejected at Sentinel
```

`Monotone` 的意思是「哨兵类找到了、解得动，但解出来的值不是单调不减的」。这与「这些版本里被判据命中的
其实是**另一类列**（例如每行一变的 tag 列，它的取值天然就是 K 与 ~K 两个互补高位）」完全一致，
也与「索引变换在旧版是加法而不是异或」一致。两种解释都能解释观测，**本轮没有区分它们**，
所以不下结论，只记录事实与两条待验假设：

- 假设 A：旧版的索引列变换是 `raw = C + fs`（加法）。可验方法：对同一 `(base, stride, off)` 检查
  「非哨兵 raw 是否落在宽度 < 2^24 的连续区间内」（加法情形 `raw>>k` 会散开，异或情形会聚成两类）。
- 假设 B：长 run 命中的是 tag 列而非索引列，判别器需要额外要求「解码值域小且稠密」
  （`max_index` 与 `rows` 同量级、值几乎不重复）。

### 16.6 本轮新增/改动清单

| 文件 | 改动 |
|---|---|
| `src/derive/tables.rs` | **新增**：`IndexTable`/`analyse`（高位互补 + 哨兵类 + 单调 + tiling）、
| | `Stage` 分阶段诊断、`StringColumn`/`PrintableFirstByte`/`printable_run`/`find_additive_string_columns`、
| | `find`/`find_from_base`（按 base 多线程）、2 个 `#[ignore]` 样本测试 |
| `src/derive/mod.rs` | 注册 `tables` |
| `src/main.rs` | 新增 `tables` 子命令（`--base` / `--json`），并串联字符串列查找 |
| `tools/table-probe/` | 本轮否证与判据验证脚本（`t2.py` 等差扫描、`tiling3.py`、`strcol*.py`、`hi.py`、`row.py`） |

环境变量（诊断用，均不影响正常路径）：`MHY_DEBUG=1` 输出分阶段诊断，`MHY_ONLY_STRIDE=0x46` 把扫描限制到单个 stride。

验证命令：

```text
$ cargo test --offline --release            -> 17 passed; 0 failed; 7 ignored
$ MHY_SAMPLE_*=<7.1.0> cargo test --release -- --ignored
  test derive::tables::tests::recovers_71_typedef_table ... ok
  test derive::tables::tests::recovers_71_name_column ... ok
  test derive::cipher::tests::derives_schedule_for_sample ... ok
  test derive::cipher::tests::finds_71_key_step_table ... ok
  test derive::cipher::tests::derives_71_cipher ... ok
  test derive::anchor::tests::recovers_71_profile_exactly ... ok
  test dump::tests::full_dump ... ok
  -> 7 passed; 0 failed
```

### 16.7 目标进度（对「算法不大改即可适配未来版本」）

| 层 | 7.1.0 | 其它 19 个版本 | 说明 |
|---|---|---|---|
| 内嵌头定位 | 自动 | 自动（4.8.0~7.1.0）/ 明确失败（4.2.0~4.7.0 加壳） | §12、§15 |
| header 槽偏置 | 自动（286 个锚点） | 自动（296~445 个锚点） | `derive::anchor` |
| 字符串密码（含 strsec） | 自动 | **自动，20/20** | §15.3 |
| 字符串堆访问 | 自动 | 自动，20/20 堆头一致 | §15.5.1 |
| typeDef 行表 + 索引列 | **自动（零常数，唯一解）** | **未通过**（判据在旧版不成立） | §16.4 / §16.5 |
| 名字列 | **自动（零常数，唯一解）** | 取决于上一行 | §16.4 |
| 命名空间/parent/iface 列 | 未做 | 未做 | 变换族还没覆盖 |
| methodDef / field / params 表 | 未做 | 未做 | — |
| R4 等价性缺口（字段偏移/参数名型/属性事件/默认值…） | 未动 | 未动 | `dump71` 自己在 stderr 里报 |

**下一步（按目标排序）**：把「索引列」的判别器做成变换无关的形式——对同一 `(base, stride, off)` 同时
检验异或类与加法类，并要求解码值域「小、稠密、单调」且 tiling 成立；然后用 7.0.0 的两个长 run 候选
（0x11B3F28/0x10B5E18）作为可判定的实验对象，看能否把 stride 0x46 上那张真表从 tag 列里挑出来。
这一步不需要任何新工具，全部是对已有字节的判定式检验。

---

## §17 第十九轮 — 判别器做成变换无关后，跨版本首次成功（2026-10-13）

> 本节是 agent 日记，**不是需求**。目标：算法不大改时能适配未来版本（R2/R5）。

### 17.1 做了什么

上一轮（§16.5）的结论是：高位互补判据在旧版**仍然成立**（run 达 5.6 万~10.9 万行），卡住的是后面
「哨兵类 / 单调 / tiling」这三步的假设。本轮把这三步改成变换无关：

1. **索引列族从「异或」扩成「异或 + 加法」**。同一个形状两代都在用：
   - `Xor` 族：`raw = fs ^ C`，因此所有实行的高位相同（`2^k > T` 时 `raw>>k` 只取一个值），
     哨兵行的 `raw = ~C` 取互补高位；
   - `Add` 族：`raw = fs + C`，因此所有实行落在一个宽度 `2^k` 的窗口内（`raw>>k` 会散开）。
   两族的 `C` 都由模型直接给出（Xor：`C = !sentinel_raw`；Add：`C` = 最小实行 raw，因为那一行的索引是 0）。
2. **计数列也试两种变换**：`delta = (u16 raw) ^ c` 或 `delta = (u16 raw) - c`。
3. **哨兵改成结构识别而不是多数表决**。

### 17.2 两个已修正的自欺点（都是实测抓出来的）

**(a) 70% 多数表决会误杀真列。** 最初用「第一个 32 行里出现最多的那个高位类占 ≥70%」来定实行，
结果 7.1.0 的 `methodStart` 列直接消失——实测该列前 32 行里有 **11 行是哨兵**（34%），实行只占 21/32：

```text
off=0x08  shift=20  hi counts={4024: 11, 71: 21}   complement distinct=1 {0xfb8750a6}
```

改成结构判据（**哨兵 = raw 只有单一值的那一个高位类**）后两列都回来了。

**(b) 加法族单独用太松，会造出假表。** 先用「连续 raw 的差分在 0..0xFFFF」做加法筛查，
7.1.0 一个 base 上就有 5 个不同列全部 63/63；放宽到 finder 里后 7.0.0 报出 1037~2696 行的假表，
5.2.0 报出 `max_idx = 0` 的退化表。加了两条**退化守卫**（不是阈值调参，是「这还能叫索引列吗」）：

- 加法族的列必须也带哨兵编码（没有「空」编码的列更像缓慢变化的普通数据）；
- 解码出的不同取值个数必须 ≥ 8（只取 1~7 个值的列是常量，不是索引）。

### 17.3 本轮结果：1/5 → 3/5 个版本

命令（零常数、零地址、无列名）：`mhydump tables --exe <exe> --metadata <dat>`

| 版本 | 结果 | 证据 |
|---|---|---|
| 7.1.0 | ✅ | 两列索引 + 名字列，与 `layout71::gen71()` 逐项一致（§16.4） |
| 5.4.0 | ✅ **新** | 见 17.4 |
| 4.8.0 | ✅ **新** | 两个索引列，tiling 精确（8538/0、8493/0），stride 0x4A、9585 行 |
| 7.0.0 | ❌ | no row table found |
| 6.4.0 | ❌ | no row table found |
| 5.2.0 | ❌ | no row table found |

### 17.4 5.4.0 实测：列偏移和变换都变了，仍然自动解出（并解码出真类型名）

```text
$ mhydump tables --exe .../5.4.0/YuanShen.exe --metadata .../5.4.0/.../global-metadata.dat
INFO scanning 427 candidate bases from the anchor recovery
      base stride   op idx_off     idx_c   sentinel cntop cnt_off cnt_c   rows   real  max_idx   trans
0x0213921C 0x0046  xor 0x0008 0x5CB2D477 0xA34D2B88  add 0x001A 0xED8D  58938  50401   285056   44903

string-index columns of the first table above:
  col_off=0x3E  +0xD13BCB2F  ok 256/256
```

关键点是**它和 7.1.0 的布局完全不同**，而 finder 没有改一行就处理了：

| | 7.1.0 | 5.4.0 |
|---|---|---|
| 索引列 | `idx_off 0x00` / `0x08` | `idx_off 0x08` |
| 索引变换 | xor | xor（常数不同） |
| 计数列 | `0x30`，**xor** | `0x1A`，**add** |
| 名字列 | `0x14`，`+0xE811F779` | `0x3E`，`+0xD13BCB2F` |
| 哨兵 raw | 0x8D9D7FF8 / 0xFB8750A6 | 0xA34D2B88 |

独立验证（用 5.4.0 自己推导出的密码逐行解码，`_gi_probe/tbl/v540.py`）：

```text
--- name column 0x3E, C=0xD13BCB2F ---
  row 0 raw=0x34C434ED idx=0x0600001C -> 'Locale'
  row 1 raw=0x30C43509 idx=0x02000038 -> 'SR'
  row 2 raw=0x35C43523 idx=0x07000052 -> 'Runtime'
  row 3 raw=0x40C435D9 idx=0x12000108 -> 'RuntimeClassHandle'
  row 4 raw=0x46C43626 idx=0x18000155 -> 'RuntimeRemoteClassHandle'
  row 5 raw=0x4BC4363E idx=0x1D00016D -> 'RuntimeGenericParamInfoHandle'
  row 6 raw=0x40C436B1 idx=0x120001E0 -> 'RuntimeEventHandle'
  row 7 raw=0x43C436C3 idx=0x150001F2 -> 'RuntimePropertyHandle'
--- index column 0x08 (idx_c=0x5CB2D477, sentinel 0xA34D2B88) ---
  sentinel rows=8537 real=50401 max_index=285056
--- fieldCount col 0x1A (add, C=0xED8D) ---
  tiling exact=50401 mismatch=0 final=285058
```

`Locale` / `SR` / `Runtime` 正是 7.1.0 表头第 1~3 行的同一族名字——所以这确实是 typeDef 表，
不是碰巧自洽的噪声。tiling **50401/50401 全对、0 个不匹配**，`final = max_index + 最后一行的 count`。

### 17.5 4.8.0 的情况（部分成功，如实记录）

```text
0x02CC8CC5 0x004A add 0x001F 0x697076A2 0x696D5325 xor 0x003F 0x2646   9585   8538    47112    7675
0x02CC8CC5 0x004A add 0x002B 0x4DEAED44 0x4DE5409E add 0x0039 0xD7FE   9585   8493    84836    7618
```

独立复查（`_gi_probe/tbl/v480c.py`）：两列的 tiling 都是**精确**的（8538/0、8493/0），所以是结构合法的真表，
不是噪声。但只有 9585 行，而 GI 4.8 的 typeDef 表理应更多，**这一张是不是 typeDef 尚未确认**，
也可能 run 在某个不连续点被截断。这里只记事实，不下结论。

### 17.6 仍然失败的三个版本

7.0.0 / 6.4.0 / 5.2.0 仍报 `no row table found`。§16.5 的分阶段诊断（旧代码）显示它们的长 run 候选死在
`Monotone`，而本轮扩了加法族之后依然如此。可能的解释有三条，本轮**没有**区分：

1. 这三个版本的索引列不在 `derive::anchor` 给出的候选基址里；
2. 索引列既不是纯 XOR 也不是纯 ADD（例如带每行掩码 `raw ^ C ^ mask(i)`）；
3. 哨兵编码不是「单一固定值」，因此模型拟合失败。

下一步可判定的实验：把这几个版本 `MHY_DEBUG=1 MHY_ONLY_STRIDE=0x46` 的输出按 `Stage` 聚合，
看它们分别死在哪一步；再针对该步放宽（而不是全盘重来）。

### 17.7 本轮改动与验证

| 文件 | 改动 |
|---|---|
| `src/derive/tables.rs` | `IndexTransform{Xor,Add}`；`fit`（两族模型 + 结构哨兵识别）；`run_len` 按模型扩展；`analyse` 两族都试、计数列两种变换都试；`MIN_DISTINCT` 退化守卫；`IndexTable.transform/cnt_transform/sentinel_raw: Option<u32>`；新增 5.4.0 测试 |
| `src/main.rs` | `tables` 输出增加 `op`/`cntop`/`max_idx` 列 |

```text
$ cargo test --offline --release                -> 17 passed; 0 failed; 8 ignored
$ MHY_SAMPLE_*=<7.1.0> MHY_SAMPLE2_*=<5.4.0> cargo test --release -- --ignored
  test derive::tables::tests::recovers_71_typedef_table ... ok
  test derive::tables::tests::recovers_71_name_column ... ok
  test derive::tables::recovers_540_typedef_table_and_names ... ok
  test derive::cipher::tests::derives_schedule_for_sample ... ok
  test derive::cipher::tests::finds_71_key_step_table ... ok
  test derive::cipher::tests::derives_71_cipher ... ok
  test derive::anchor::tests::recovers_71_profile_exactly ... ok
  test dump::tests::full_dump ... ok
  -> 8 passed; 0 failed
```

### 17.8 目标进度更新

| 层 | 7.1.0 | 5.4.0 | 4.8.0 | 7.0.0 / 6.4.0 / 5.2.0 |
|---|---|---|---|---|
| 内嵌头 + header 槽偏置 | 自动 | 自动 | 自动 | 自动 |
| 字符串密码 + 堆访问 | 自动 | 自动 | 自动 | 自动（20/20 已实测） |
| typeDef 索引列（零常数） | ✅ | ✅ | ✅（表身份待确认） | ❌ |
| 名字列（零常数） | ✅ | ✅ | 未测 | ❌ |
| 计数列（零常数） | ✅ | ✅ | ✅ | ❌ |

**进度口径**：上一轮「表定位」是 1/5 个版本；本轮是 **3/5**，且成功的那两个版本与 7.1.0 的**列偏移、
列变换、常数全都不同**——这正是「算法不大改即可适配」要验证的东西。

---

## 18. 第 4 轮：计数列越界修复 + ADD 窗口饱和守卫（2026-10-13）

> 本节是实现日志，**不是需求**。需求以 `REQUIREMENTS.md` 为准。

### 18.1 结论先行

1. 修掉一个**真实的定位 bug**：`analyse` 只在 `0 .. stride` 范围里找计数列，但扫描基址是 anchor
   给的，**不一定落在表的行边界上**。基址比行起点早 k 字节时，索引列落在 `off + k`、计数列落在
   `off_cnt + k`——两者仍在同一行内，却已经越过旧的搜索窗口。改为在 `off .. off + stride` 里找。
2. **6.4.0 因此被解开**（本轮唯一新增的版本）：base `0x00E7579C`、stride `0x46`、索引列 `0x3E`、
   计数列 `0x78`（**大于 stride**）、77261 行、max_idx 384409、trans 56976；名字列 `0x18`、
   常数 `0xE169AC15`、`ok 256/256`；逐行解码得到 `<Module>` / `RuntimeClassHandle` /
   `RuntimePropertyHandle` / `WIN32_FIND_DATA` / `HMACSHA256`。
3. 放宽搜索同时放进了一批**假表**（7.0.0 的 8186 行条目；6.4.0 的 131014 / 4193792 条目）。
   它们的加法族「窗口」被数据填到顶（`65535/65536`、`4193792/4194304`），说明那个 2^k 只是数据
   自身的范围、模型没有解释力。加了饱和守卫后它们消失，而 4.8.0 的真窗口（`47112/65536`）不受影响。
4. **口径修正**：上一轮把 4.8.0 记作「表身份待确认」，本轮用**名字列**做判据后应当降级为**未找到**。
   typeDef 每一行都有名字，7.1.0 / 5.4.0 / 6.4.0 各自都恰好解出 **1 个**字符串索引列，而 4.8.0 的
   候选**一个都没有**（`tables` 输出里没有 `string-index columns` 段）。

### 18.2 计数列越界：实测证据

6.4.0 在本轮之前的表现（`MHY_DEBUG=1 MHY_ONLY_STRIDE=0x46`）：

```text
[dbg] base=0xE75798 run=77262 stride=0x46 off=0x0 shift=20 hist=[Prefilter:40 Run:12 Monotone:13 Tile:2]
[dbg]   ...but rejected at Monotone
(no row table found by the structural predicate)
```

即：索引列**已经被找到**（2 个列走到 `Tile`），只有计数列找不到。用 Python 复刻 `analyse` 在
`base=0x00E75798, stride=0x46` 逐列打印，得到 `off=0x42` 的索引列（XOR、sentinel `0x90164A97`、
`idx_c=0x6FE9B568`、77262 行、max_idx 384409）。把「每行计数」与「每一个 (列, 宽度, 变换)」作
精确比较，唯一满分的组合是：

```text
delta(i) = u16( base + stride*(i+1) + 0x36 ) ^ 0xD846     exact, 2583/2583
```

也就是**计数列落在下一行**。把行网格对齐到 `0xE7579C` 后，同一行内的写法是索引 `0x3E` / 计数 `0x78`
（`0x78 = 0x3E + 0x3A`，`0x3A = 0x36 + stride - 0x42`）。

为什么 anchor 会落在错的位置：`mhydump anchors` 解出的 6.4.0 候选里**有** `0xE7579C`（≡14 mod 70），
而表行起点 `0xE757DA` ≡6 mod 70 —— 70 个余数里 anchor 覆盖了 47 个，恰好**没有** 6。
于是索引列总能在某个 `off` 被读到（`B + off ≡ 行起点`），但计数列的位置 `B + 0x78` 超过了旧循环上限。

### 18.3 ADD 窗口饱和守卫

```rust
// An ADD window that the data fills to its own top is not a fitted window ...
if model.transform == IndexTransform::Add
    && max_index >= (1u32 << shift) - (1u32 << (shift - 4)) {
    return Err(Stage::Monotone);
}
```

实测对照（守卫前 → 守卫后）：

| 版本 | 守卫前多出来的条目 | max_idx / 2^shift | 守卫后 |
|---|---|---|---|
| 7.0.0 | `0x011B3F28 add 0x0042 ... 8186 行` | 65535 / 65536 | 条目消失，回到 no row table |
| 6.4.0 | `0x00FA60E8 add 0x0042 ... 15914 行` | 131014 / 131072 | 消失 |
| 6.4.0 | `0x00FA60E8 add 0x0041 ... 2048 行` | 4193792 / 4194304 | 消失 |
| 4.8.0 | 保留 | 47112 / 65536、84836 / 131072 | 不受影响 |

### 18.4 本轮排除掉的思路（负结果，记下来避免重复踩）

- **「按频率找 sentinel 再反推基址」不可用**。设想是：sentinel 是一个重复上千次的固定 u32，所以按
  (stride, 余数) 统计 u32 频次就能定位基址。7.1.0 上它**确实**成立（余数 0x10 里 `0x8D9D7FF8` 出现
  13627 次、首次出现位置**正好等于** base `0x48F3FD8`）。但在别的版本上，频次榜首被大量
  **重叠窗口伪值**占据：7.1.0 榜首是 `0x29543783` ×79498（不是 sentinel）；5.2.0 的高频值来自
  连续 22 个余数共享同一个 8 字节周期图案；7.0.0 的候选 sentinel `0x149B1F48` 在原始解码下根本
  不是单调索引（复刻 `analyse` 显示 `real=2, DIE Monotone@3`）。结论：**频次不是判别器**，
  结构性判据（同一高位类内 raw 全同）才是。
- **7.0.0 / 5.2.0 在 stride 0x46 上不存在 XOR 互补对**。全 body 扫描：7.0.0 只在 `0x010B5E1C`
  一带有一组（`0x149B1F48 / 0xEB64E0B7`），但那不是 typeDef（解码不单调）；尾部 6.5 MB 扫描一个
  都没有。5.2.0 在 0x46 / 0x48 / 0x4A 三个 stride 上**全 body 都没有**互补对。两者在全部 stride
  （4..0x200）的 Rust 扫描（308 / 445 个 anchor）里都仍然找不到表。
- 4.8.0 尾部 stride 0x4A 找到 `0x8B239E19` ×31310，但 `--base 0x029C0888` 不成立——同样是伪值。
- `decode-one` / `header-dump` / `types-dump` / `dump` 四个子命令仍然走旧的
  `static_mhy_dumper::decrypt::file::load`（main.rs:417/515/546/558），对 7.1.0 以外的版本一律报
  `could not locate the embedded MHY header in GenshinImpact .rdata`；只有 `cipher` / `strings` /
  `tables` / `dump71` 走了新的 `derive_build`。这是**接线缺口**，不是算法缺口。

### 18.5 验证（本轮实际跑过的命令）

```text
cargo test --offline --release                            -> 17 passed / 0 failed / 8 ignored
MHY_SAMPLE*=<7.1.0> MHY_SAMPLE2*=<5.4.0> MHY_SAMPLE3*=<6.4.0>
  cargo test --offline --release -- --ignored             ->  9 passed / 0 failed
  新增：derive::tables::recovers_640_typedef_table_and_names
dump71 7.1.0 -> md5 f5cfe06b48b80b23e3f3345e5619a3b7（与改动前一致）
                88872 types / 440061 fields / 460282 methods
```

`recovers_640` 钉死：`stride 0x46`、`rows 77261`、`Xor`、`max_index 384409`、`cnt_off >= stride`、
逐行 `fs == expected` 全表 tiling、`real == 65289`、`dec(0) == "<Module>"`、
`dec(4) == "RuntimeClassHandle"`。

### 18.6 进度（口径按「名字列能解出真实类型名」算）

| 层 | 7.1.0 | 6.4.0 | 5.4.0 | 4.8.0 | 7.0.0 | 5.2.0 |
|---|---|---|---|---|---|---|
| 内嵌头 + header 槽偏置 | 自动 | 自动 | 自动 | 自动 | 自动 | 自动 |
| 字符串密码 + 堆访问 | 自动 | 自动 | 自动 | 自动 | 自动 | 自动 |
| typeDef 索引列 | ✅ | ✅ | ✅ | 候选（身份不成立） | ❌ | ❌ |
| 计数列 | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| 名字列（判据） | ✅ | ✅ | ✅ | **❌** | ❌ | ❌ |

**已核实版本：7.1.0 / 5.4.0 / 6.4.0 = 3 个**；4.8.0 从上一轮的「待确认」降级为未找到；
7.0.0 / 5.2.0 仍未找到。上一轮报的「3/5」里含 4.8.0，本轮更正为 **3/6**（6 个受测版本）。

**下一个可判定实验**：7.0.0 与 5.2.0 的 typeDef 行形状可能真的变了。先用复刻在**已知不是表的
基址**上取样，确认现有判据对它们的拒绝是「结构性」而非「参数性」，再考虑第二族判据（例如把
「计数列必须在索引列之后 stride 字节内」换成「计数列与索引列共同 tile 到同一个 max_index」）。

**另一个已知缺口**：`find_from_base` 只按 `(base, stride, idx_off)` 去重，所以同一列的**后缀**也会
被当成独立结果（6.4.0 输出里 `0x00FA60E8` 与 `0x00E7579C` 是同一个索引列的 17822 行后缀）。
下游若取 `found.first()` 恰好不受影响，但 `tables` 的使用者需要知道这一点。

---

## 19. 第 5 轮：不依赖 anchor 的字节级定位器（2026-10-13）

> 本节是实现日志，**不是需求**。需求以 `REQUIREMENTS.md` 为准。

### 19.1 结论先行

1. 新做了一个**完全不依赖 anchor 列表**的定位器。思路是把 shift-24 的判别式下沉到**字节层**：
   异或族在 shift 24 下两个类的最高字节必须**互补**（mask = `0xFF`），所以沿列相邻两行的最高字节
   只能是「相等或互补」；对这个谓词再取「32 行连续成立」的倍增 AND，就能用 numpy 对整个 body
   每个 stride 做一次 O(n) 扫描，**不需要任何地址先验**。
   （第一版写成「最高字节恒定」，实测 7.1.0 的哨兵行穿插太频繁、平均实心段只有 5.5 行，恒定性判据不成立。）
2. 定位器在**已知答案的两个版本上逐项复现**：
   - 7.1.0：5 个候选，其中 `0x8D9D7FF8` / maxidx 440042（fieldStart）与 `0xFB8750A6` / maxidx 733191
     （methodStart）正是 ground truth 的两列；rows 88872 = 88904 − 32（32 行窗口的必然截断）。
   - 6.4.0：5 个候选，含 `0x90164A97` / 384274，与第 4 轮 Rust 解出的 fieldStart 完全一致。
   - 加一条 `distinct >= 0.8 * real` 过滤后，两个版本都**只剩真索引列**（真实 fs 值几乎个个不同）。
3. **7.0.0 与 5.2.0 在 stride 0x20–0x60 上没有任何 XOR 族索引表**——这是 base-free 扫描，不是 anchor 扫描。
   因此**「基址没进 anchor 列表」这个假设被否定**：失败是**结构性**的，不是定位问题。
4. 第 4 轮被当成候选的 7.0.0 区域 `0x010B5E1C` 被**证伪**（两条独立证据）：
   - 该处确实有周期 70 的结构（`fit` 通过、常量哨兵 `0xEB64E0B7`），但
     `raw1=0x149B1F48`、`raw2=0x149B1F4C`、`raw3=0x149B1F48`。非降序要求
     `fs1 <= fs2 <= fs3 = fs1` ⇒ `fs1 = fs2` ⇒ `raw1 = raw2`，与 `raw1 != raw2` 矛盾。
     **不存在任何常数 C 能让这一列单调**，所以它不可能是指数列（这是证明，不是拟合失败）。
   - 把该区域 70 个行格对齐（`--base 0x010B5E1C - k`，k = 0..69）全部跑 `tables`，**0 命中**。
5. 5.2.0 的 `0x00D8010C` 一带同样被证伪：那里相邻行几乎逐字节相同（低变化行区域），
   字节级判据被**平凡**满足（相邻行相等 ⇒ 相等或互补恒真）。这类假阳性必须靠
   「2 类互补 + 常量哨兵 + 单调 + distinct」四道闸过滤掉。

### 19.2 工具（都在 `tools/table-probe/`）

| 脚本 | 作用 |
|---|---|
| `bytecomp.py` `rowruns.py` | 字节级「相等或互补」判据 + 按行索引的连续段提取 |
| `rowfit.py` | 在连续段上直接做 fit 检查（2 类互补、一类常量哨兵） |
| `sweep.py` | **主力**：给定 stride 区间，base-free 找全部通过 fit+单调+maxidx+distinct 的索引列 |
| `sweep2.py` | 同上，`xor` / `add` 两族（加法族的哨兵是 C−1，即最小值） |
| `rowview.py` `rawdump.py` | 打印一整行的全部 u32 / u16 列，用于人工读结构 |

用法：`python3 sweep.py <global-metadata.dat> <stride0> <stride1> <minrows>`（16 进制）。

### 19.3 本轮新增的负结果

- 7.0.0 / 5.2.0 在 stride 0x20–0x60 上**没有 XOR 族索引表**（base-free，全部 phase 都扫了）。
- 7.0.0 的 `0x010B5E1C` 区域：70 个行格对齐全部 0 命中 + 非单调性证明。
- 5.2.0 的 `0x00D8010C` 区域：低变化行区域，字节级判据被平凡满足。
- 字节级判据本身**不足以**作为接受条件：不加 fit/单调/distinct 闸门时，7.0.0 在 stride 0x20–0x60
  会给出 742 个候选（大多是全 0 / 全 F 的字节段）。**任何统计式判据都必须配一个结构式接受条件。**

### 19.4 下一步

7.0.0 / 5.2.0 的失败已经排除「定位」和「XOR 族」两个方向。剩下的可判定假设，按代价排序：

1. **加法族索引列**（`sweep2.py add` 已就绪，但本轮只跑到一半就被更慢的实现拖住，需要用向量化版本补完）。
2. **哨兵不是单个值**：`fit` 要求「有一类是单一常量」，若这些版本的哨兵是多值（或根本没有空类型），
   现有判据整体失效 —— 需要把 `idx_c` 从「由哨兵推出」改成「与计数列联合求解」。
3. **索引不是 `fs` 本身**（例如存了缩放过的偏移），此时 shift-24 的 2 类结构不成立。
   可先用 7.0.0 的 `strings`（密码已验证可用）确认名字列的 `idx` 是否仍是 `(len<<24)|off`。

### 19.5 第 5 轮续：`fit_all` 多模型 —— 5.2.0 被解开（同日）

**根因（三处，全在 `fit`）**：

1. `fit` 在「头 32 行只有一个最高字节类」时**直接 return** XOR 模型，**根本不试加法族**。
   5.2.0 的列正是这种情况（哨兵不在头 32 行里），所以加法族从不可达。
   → 改成 `fit_all` 返回**所有**适用模型，`analyse` 逐个试、按 `(rows, real_rows)` 取最好。
2. 加法族的哨兵是 `C - 1`（列的最小值），它不在头 32 行时，**32 行的窗口钉不住常数**。
   → 加法分支改用 **512 行前缀**。
3. 「最大化覆盖率的窗口下沿」不等于模型的常数：窗口够宽时下沿**就是哨兵本身**，
   于是哨兵落进窗口内、看起来不存在。→ 常数取「除最小值之外的最小值」，哨兵取该最小值。

**结果**：`mhydump tables` 在 **5.2.0** 上首次给出表（此前一律 `no row table found`）：

```text
0x00D800F4 0x0046 add 0x0020 0x20CF9B77 0x20CF9B76 xor 0x002C 0xF1FB 56445 49406 493135 44327
0x00D800F4 0x0046 add 0x003E 0x53930F94 0x53930F93 add 0x007C 0x339B 56444 48062 272385 42699
```

两列的 max_idx 是 493135 / 272385，与 5.4.0 的 methodStart 515378 / fieldStart 285056 只差版本增量；
行数 56445 < 5.4.0 的 58938，与版本顺序一致。

**两点必须说清（不要当成已解）**：

- 5.2.0 的表**没有解出名字列**（`string-index columns` 段为空）。typeDef 必有名字列，
  所以**不能确认它就是 typeDef**。可能原因：这一版名字列不是加法变换，或这两列不是 typeDef 的列。
- 6.4.0 现在会把**同一个物理列**同时描述成 XOR 表（77261 行，已验证）和 ADD 表（77262 行，
  `max_index` 631103），且 ADD 那条排在前面。**哪种描述才是真实行布局还没定**；
  `recovers_640` 已改成按哨兵身份取表，不再依赖排序。

**回归（真实跑过的命令）**：

```text
cargo test --offline --release                       -> 17 passed / 0 failed / 9 ignored
  ... -- --ignored                                   ->  9 passed / 0 failed
dump71 7.1.0 -> md5 f5cfe06b48b80b23e3f3345e5619a3b7（与改动前一致）
7.1.0 / 6.4.0 / 5.4.0 的 tables --base 输出逐项不变
```

**下一步**：

1. 加一条**模型仲裁规则**（同一列多模型时怎么选）；候选判据是「谁能解出名字列」。
2. 把名字列搜索从「只搜 `found.first()`」改成「搜到第一个有名字列的表为止」。
3. 7.0.0 在同样的多模型路径下重扫（本轮只跑了 stride 0x40–0x50 的加法族）。

### 19.6 第 5 轮再续：名字列仲裁 + kuna 路径坑 + 定向反编译窗口（同日）

1. **名字列搜索改成遍历所有候选表**（`main.rs::tables_cmd`）：同一个物理列可能有两种模型描述，
   能解出名字列的那条才是 typeDef —— 名字列因此同时充当**描述仲裁器**。
   实测 6.4.0 / 7.1.0 / 5.4.0 都在 table #0 上解出名字列，与改动前一致。
2. **5.2.0 在任何候选表上都解不出名字列** ⇒ 那两张表**不能确认为 typeDef**。
   最可能的原因：`find_additive_string_columns` **只支持加法变换**，而 5.2.0 的索引列已经证明是加法族
   （说明这一版整体换族），名字列很可能也跟着换。下一步应把名字列查找也做成「加法 + 异或」两族，
   与索引列对齐。
3. **kuna 不支持中文路径（实测）**：`~/gire/sample/gi` 是指向
   `/home/yangsanyi/项目/游戏音乐更新提取/standalone/bins/gi` 的**符号链接**，kuna 把路径解析成乱码后报
   `Unable to recognize imagefile ...: No such file or directory (os error 2)`。
   绕法：`ln -f <样本> /home/yangsanyi/kuna_in/<ver>/YuanShen.exe`（硬链接，不占额外空间），
   再对纯 ASCII 路径调用 kuna。
4. **定向反编译的窗口（实测映射，7.1.0）**：`.text` 覆盖 file `0x400–0x21AA000`（VA `0x140001000` 起）。
   表列常数与密码链常数集中在 file **`0x4B1B3A–0x53A000`** = VA **`0x1404B273A–0x14053AC00`**
   （约 565 KB，占 `.text` 的 1.6%）。锚点：
   - 密码链 `0x140510ECF`（该处三个 8 字节常数各命中 1 次）
   - `fieldStart` 常数 13 处（`0x1404B273A` 一带）、`methodStart` 3 处、`name` 4 处、`td_magic` 6 处
   - 哨兵 `0x8D9D7FF8` **0 命中** ⇒ 它是 `~常数` 算出来的（派生值，反编译也读不到，只能算）
5. **7.0.0 的密码链簇在 file `0x4E037F–0x4E03A7`**，与 7.1.0 的 `0x5102CF` 只差约 190 KB。
   ⇒ 「先找密码链簇（各命中 1 次的紧密簇）→ 再在 ±`0x40000` 内找表常数」是一条**可自动化的规律**，
   也是「不必每版反编译半天」的技术依据。

### 19.7 方法论错误一笔：`distinct` 不是接受条件（同日，自我纠错）

跨版本普适性测量里我先用「`distinct` 最大」挑候选，得到一张很漂亮的表：
**5.1.0–7.1.0 连续 16 个版本在 `add@0x46` 上都有表**，`real` 从 54415 平滑涨到 111922，
`maxidx` 从 740833 平滑涨到 460309 —— 看起来像完美的跨版本证据。

**但它是假的。** 拿 7.1.0 的候选 `0x0015355E` 去问真正的判据：

```text
mhydump tables --base 0x0015355E   ->  no row table found by the structural predicate
mhydump tables --base 0x048F3FD8   ->  2 张表 + 名字列 0x14 +0xE811F779 256/256   (真表)
```

原因：低熵区域（7.1.0 在 `0x1534xx`）能过「2 类互补 + 常量哨兵 + 单调 + distinct」，
**但过不了计数列 tiling**。`distinct` 只说明「解码出的值很多样」，不说明「它把另一张表切完了」。

**结论：接受条件必须是 tiling（+ 名字列），`distinct` 只能当排序用的启发式。**
`universality2.py` 已把 tiling 闸门加回去（逐个 `off2` 检查 `fs[i+1] - fs[i] == u ^ c` 或 `u - c` 恒定），
重测结果见下一节。

这与 §8.1「统计命中 ≠ 结构命中」是同一个坑的第二种形态，写在这里防止再犯。

---

## 20. 用 Ghidra 定位到元数据加载器（2026-10-13）

> 本节是实现日志，**不是需求**。

### 20.1 手段：不在 Ghidra 里全库搜，改用「本地字节搜 → Ghidra 查引用」

`get-strings` 在 445 MB 程序上会超时（实测），所以改成：
1. 本地 python 按字节搜 `global-metadata` 字面量 → 得到 VA（毫秒级，避开 Ghidra 全库扫描）
2. Ghidra `find-cross-references` 查该 VA 的引用 → 直接拿到引用它的函数

这条组合对「已知字面量、要找引用者」的场景比在 Ghidra 里搜快几个数量级。

### 20.2 结果：加载器 = `FUN_1405359e0`

- `global-metadata.dat` 字面量在 VA `0x143A390F8`；`startup-metadata.dat` 在紧邻的 `0x143A390E3`。
- 两者的**唯一引用者都是 `FUN_1405359e0`**（另一处 `global-metadata.dat` @`0x14398A631` 由 `FUN_1408b0790` 引用）。
- `FUN_1405359e0`：**25,417 字节**，`startAddress 0x1405359e0` / `endAddress 0x14053beaa`。
- 它的**唯一调用者** `FUN_1404b1f30` 只做 `setlocale(0,"")` 再调它 ⇒ 那是 **il2cpp_init**。

```text
il2cpp_init  FUN_1404b1f30
   └── FUN_1405359e0   元数据加载器（25,417 B，引用两个 metadata 文件名）
```

### 20.3 顺带确认的三件事

1. **header 全局 `DAT_145ad62b8` 有 4620 处引用**，其中 `FUN_140512880` 密集读取它 ⇒ 元数据热点。
   MHY blob 本身只有 **1 处**数据引用（`0x1402f3768`）。
2. **`FUN_1404b2710`（Ghidra 版）读通**：`puVar1 = *param_1 ^ 0x55d980367be5f6ca`；
   随后 `bsearch(&local_20, ...)` 在一个 8 字节项的排序数组上二分 ⇒ 这是 **metadata usage 查找**。
  其中 `(*(uint *)puVar1[0xc] ^ 0x72628007)` **就是我们盲推出的 fieldStart 常数**，用法（`raw ^ C`）完全一致。
  同一函数里还有更多每版常数：`0x4009a6bf`、`0xc5c0a0d0`、`-0x50105f4f`（都在 anchor 清单里出现过）。
3. **表偏移计算是内联的**：anchor 覆盖 header **107 个槽**（7.1.0 上 69 个 in-range），
   分布在 **30 多个函数**里，**不存在「一张总表」**。⇒ `mhydump anchors` 已经在自动做这件事。

### 20.4 工具组合经验

- **Ghidra 给可靠的函数边界**（`.pdata` 在 GI 里是假的，实测解析出 `Begin 0x1E5E1 / End 0xD5B27A00`）；
- **kuna 给快的反编译**（Ghidra 反编译器在 `FUN_1405359e0` 上 30 s 超时，kuna 没有这个限制）；
- kuna 必须走**纯 ASCII 路径**（`ln -f <样本> /home/yangsanyi/kuna_in/710/YuanShen.exe`）。

### 20.5 ★ 三重独立互证：结构法 / anchor 恢复 / 加载器反编译给出同一个答案

**加载器 `FUN_1405359e0`（25,417 B）里读到的表基公式**：

```c
314:  v18 = sub_140523f70("global-metadata.dat");
315:  dat_145ad62c8 = sub_140523f70("startup-metadata.dat");

2076: v42 = *(int4 *)(v18 + 8) + v35 + 0xccbb4740;                        // 行号
2078: v36 = v42 * 0x46ULL + ((header[0xdc] ^ 0x5278ca3b) + dat_145ad62c0); // 行地址
2079: v30 = *(int4 *)(v36 + 0x1c);                                        // 读 +0x1C 列
2085: if (v30 != -0x2145afb7) goto label_14053a7ad;                        // -0x2145afb7 = 0xDEBA5049
2086: sub_14051e390(*(uint8 *)(v18 + 0x20) ^ 0x6aff73a46c9233d6, v36);
```

**三条独立路径的结论对照**：

| 路径 | 得到的东西 |
|---|---|
| ① 结构判据（零常数，从乱码里反推） | typeDef 基址 `0x48F3FD8`、stride `0x46`、fieldStart@`0x00`、methodStart@`0x08`、name@`0x14`、fieldCount@`0x30` |
| ② `mhydump anchors`（零常数，从机器码读立即数） | `0xDC xor 0x5278CA3B -> 0x48F3FD8`（site `0x1404B241F`） |
| ③ Ghidra/kuna 反编译加载器 | `header[0xdc] ^ 0x5278ca3b + body_base`，stride `0x46`，魔数在 `+0x1C` |

**三者完全一致**：
- ② 的 `0x48F3FD8` = ① 找到的表基址；
- ③ 的 `header[0xdc] ^ 0x5278ca3b` = ② 的槽位/运算/常数；
- ③ 读的魔数在 `+0x1C`，而 ① 找到的 `0xDEBA5049` 列位置是 `0x048F3FF4 - 0x48F3FD8 = 0x1C`；
- ③ 的 stride `0x46` = ① 的 stride。

**意义**：这是对「不依赖常数、靠结构不变量解元数据」这条路线的**最强验证** —— 它和真正的运行时加载器逐字对上了。
同时说明 `mydump anchors` 不是启发式猜测，而是**准确地复现了加载器的偏移计算**。

**加载器顺带暴露的其它槽**（都在我们的 anchor 清单里，可交叉核对）：

```text
0x118 xor 0x4009A6BF -> 0x1BDE458   (metadata usage 数组)
0x5C  xor 0x6B2B3963 -> 0x4EE3588   (紧随 typeDef 表尾 0x4EE3548 之后的下一张表)
```

### 20.6 ★ 7.0.0 解开，并且我前面的「证伪」要更正

`mhydump tables --base 0x010B5E1C`（7.0.0）现在给出：

```text
base       stride op  idx_off idx_c      sentinel   cntop cnt_off cnt_c  rows  real  max_idx  trans
0x010B5E1C 0x0046 add 0x001C  0x33AB5AF8 0x33AB5AF7 xor   0x0038  0x37E5 86932 76000 713952   65536
```

**更正**：§19.1 第 4 条我写过「`0x010B5E1C` 被证伪 —— 不存在任何常数 C 能让这一列单调」。
那句话只对**异或族**成立（证明本身没错），但我把它过度推广成了「它不可能是指数列」。
它其实是**加法族**的索引列。第 4 轮加的多模型 `fit_all` 把它救回来了。
教训：**「在模型 X 下不可能」不等于「不可能」**，否定性结论必须限定在已验证的模型集合内。

### 20.7 ★ 7.0.0 完整解开 + 一个重要的族翻转规律

**名字列是异或族。** 用「已解密字符串堆的合法起点表」做交集（24 行采样），
在 7.0.0 的表基 `0x010B5E1C` / stride `0x46` 上逐列反解低 24 位常数：

| 列偏移 | 24 行交集后幸存者 | 候选 |
|---|---|---|
| 0x04 | 14 | 0xdb86, 0x7e9bb, ... |
| 0x05 | 102 | ... |
| **0x0C** | **1** | **`0x6B619D`** |
| 0x13 | 34 | ... |
| 0x14 | 210 | ... |
| 0x15 | 193 | ... |
| 0x2B | 29 | ... |

`off = 0x0C` 唯一幸存 ⇒ **名字列 = 字节偏移 `0x0C`，异或族，低 24 位常数 `0x6B619D`**。
用它解码（`idx = (raw & 0xFFFFFF) ^ 0x6B619D`）得到真类型名：

```text
row  0 -> 0x000014  '<Module>'
row  4 -> 0x000106  'RuntimeClassHandle'
row  5 -> 0x000153  'RuntimeRemoteClassHandle'
row  6 -> 0x00016B  'RuntimeGenericParamInfoHandle'
row  7 -> 0x0001DE  'RuntimeEventHandle'
row  8 -> 0x0001F0  'RuntimePropertyHandle'
row  9 -> 0x000205  'RuntimeGPtrArrayHandle'
row 10 -> 0x00025A  'RuntimeMarshal'
row 11 -> 0x0002E1  'RuntimeStructs'
```

`<Module>` 在 row 0、后面紧跟 `Runtime*Handle` 家族 —— 与 7.1.0 / 6.4.0 / 5.4.0 的首类型序列同族。

**⇒ 7.0.0 完整解开**：

```text
typeDef  base 0x010B5E1C  stride 0x46  add  idx_off 0x1C  idx_c 0x33AB5AF8  sentinel 0x33AB5AF7
          cnt_off 0x38  xor 0x37E5   rows 86932  real 76000  max_idx 713952
名字列     off 0x0C  xor  低 24 位常数 0x6B619D
```

### 20.8 ★ 规律：两个族会被**同时翻转**

| 版本 | 索引列 | 名字列 |
|---|---|---|
| 7.1.0 | **异或** | **加法**（`0x14 +0xE811F779`） |
| 7.0.0 | **加法** | **异或**（`0x0C ^ 0x6B619D`） |

这不是「某一列碰巧适合哪个模型」，而是**整版同时换族**。所以：
- 只做索引列的两族是不够的，**名字列也必须两族**（`find_additive_string_columns` 目前只有加法，这就是 7.0.0 / 5.2.0 解不出名字列的原因）；
- 这条规律同时给出跨版本的**强判据**：一版的索引列若从异或翻成加法，名字列极可能同步翻成异或。

### 20.9 ★ 名字列两族落地 —— 5.2.0 与 7.0.0 同时完整解开

**代码改动（三个文件/三处）**：

1. `src/derive/tables.rs` 新增 `PrintableFirstByte::permute_xor(u, dst)`：位图异或置换
   `dst[l] = self[l ^ u]`。做法是块交换 —— 索引 bit 6..24 是整字块交换，bit 0..6 是字内组交换。
2. 新增 `find_xor_string_columns`（镜像 `find_additive_string_columns`）。注意异或**不进位**：
   堆偏移是 `(raw ^ l) & 0xFFFFFF`、长度字节是 `(raw >> 24) ^ h`，两半互相独立（加法版里它们是有进位的）。
3. `src/main.rs::tables_cmd`：对每张候选表先试加法列，解不出再试异或列。

**结果（`mhydump tables --base <表基>`）**：

| 版本 | 索引列 | 名字列 |
|---|---|---|
| 7.1.0 | xor `0x00` | add `0x14` `+0xE811F779` 256/256（不变） |
| **7.0.0** | add `0x1C` | **xor `0x0C` `+0x616B619D` 256/256** |
| 6.4.0 | add `0x14` | add `0x18` `+0xE169AC15` 256/256（不变） |
| 5.4.0 | xor `0x08` | add `0x3E` `+0xD13BCB2F` 256/256（不变） |
| **5.2.0** | add `0x20` | **xor `0x04` `+0x50ED8EC2` 256/256** |

**两条独立验证**：
- 7.0.0 工具给出的名字列常数低 24 位是 `0x6B619D`，与上一节手工用字符串堆反解出来的**完全一致**；
- 5.2.0 用它解码得到真类型名：`<Module>`(row 0)、`RuntimeClassHandle`、`RuntimeRemoteClassHandle`、
  `RuntimeGenericParamInfoHandle`、`RuntimeEventHandle`、`RuntimePropertyHandle`、`RuntimeGPtrArrayHandle`、
  `RuntimeMarshal`、`RuntimeStructs` —— 与其它四个版本的**首类型序列同族**。

**⇒ 6 个受测版本里 5 个已完整核实**：7.1.0 / 7.0.0 / 6.4.0 / 5.4.0 / 5.2.0。只剩 4.8.0（`add@0x4A`，未确认）。

**回归（真实跑过）**：

```text
cargo test --offline --release            -> 17 passed / 0 failed / 9 ignored
  ... -- --ignored                        ->  9 passed / 0 failed
7.1.0 / 6.4.0 / 5.4.0 的 tables 输出逐项不变（加法族仍优先命中）
```

### 20.10 当前跨版本状态（诚实口径）

| 版本 | 索引列 | 名字列 | 状态 |
|---|---|---|---|
| 7.1.0 | ✅ xor | ✅ add | **完整核实** |
| 7.0.0 | ✅ add | ✅ xor | **完整核实** |
| 6.4.0 | ✅ add | ✅ add | **完整核实** |
| 5.4.0 | ✅ xor | ✅ add | **完整核实** |
| 5.2.0 | ✅ add | ✅ xor | **完整核实** |
| 4.8.0 | 候选 add@0x4A | ❌ | 未确认 |

**仍待验证的是我的 Python 定位器**：它对 5.4.0 / 7.1.0 这类异或表有盲点（会报「–」），
所以只可看趋势、不可当结论。权威测量是用产品本身跑 20 个版本（后台进行中）。

### 20.11 跨版本全景（20 版本产品扫描）+ 一个必须修的假阳性

`mhydump tables` 在 **20 个版本上逐个跑通**（4.8.0 – 7.1.0，`xargs -P 6`，当前二进制）：

| 版本 | 表数 | 名字列 | | 版本 | 表数 | 名字列 |
|---|---|---|---|---|---|---|
| 4.8.0 | 4 | `0x2F` | | 6.1.0 | 2 | `0x10` |
| 5.0.0 | 67 ⚠ | `0x1C` | | 6.2.0 | 2 | **✗** |
| 5.1.0 | 2 | `0x0C` | | 6.3.0 | 2 | `0x0C` |
| 5.2.0 | 2 | `0x32` ⚠ | | 6.4.0 | 4 | `0x18` |
| 5.3.0 | 2 | `0x26` | | 6.5.0 | 26 ⚠ | `0x28` |
| 5.4.0 | 2 | `0x3E` | | 6.6.0 | 2 | `0x2C` |
| 5.5.0 | 71 ⚠ | `0x26` | | 6.7.0 | 2 | `0x18` |
| 5.6.0 | 8 | `0x08` | | 7.0.0 | 4 | `0x10` ⚠ |
| 5.7.0 | 4 | `0x1C` | | 7.1.0 | 2 | `0x14` |
| 5.8.0 | 4 | `0x04` | | | | |

**20/20 能定位到表；19/20 能解出名字列**（6.2.0 缺）。所有解出的名字列都是 256/256。

#### ★ 但 7.0.0 的名字列是假阳性（实测）

工具报 `off=0x10  c=0x616B619D`。用同一个常数、两个偏移分别解码真实字符串堆：

```text
off=0x10 (工具报的): row0 -> 0xE2B2CD '<missing>'  row1 -> 0xF2B5CD '<missing>'  ...  全是垃圾
off=0x0C (手工验证): row0 -> 0x000014 '<Module>'   row4 -> 0x000106 'RuntimeClassHandle' ...
```

**⇒ 工具选中了一个排在真列之前的伪列。**

#### 根因（已量出）

现在的接受判据是 `PrintableFirstByte`——「解码偏移处的**首字节可打印**」。实测这个谓词对随机偏移的
通过率约 **37.7%**，太松。而真正的「字符串起点」只占约 **3.9%**（实测 654552 / 16777216）。

#### 修法（原则性，依然不需要明文）

把谓词从「首字节可打印」换成「**可打印串的起点**」：

```text
start(o) = printable(o) && (o == 0 || !printable(o-1))
```

`printable` 本来就由密码算出，所以这个加强**不引入任何明文**，但选择性提高约一个数量级，
正好对应真实字符串堆的起点集合。预计同时修掉：
- 5.2.0 报 `0x32`（真列在 `0x04`，低 24 位常数同为 `0xED8EC2`，与 7.0.0 同一症状）；
- 6.2.0 解不出名字列；
- 5.0.0 / 5.5.0 / 6.0.0 报 67 / 71 / 76 张表的假表问题。

**教训**：Python 探针里我用的是「真实字符串堆的起点集合」，Rust 侧用的是它的弱代理
（首字节可打印），两边判据不一致，导致 Rust 输出看起来「更全」，其实是**多了一堆伪列**。
以后探针与产品必须用同一判据，否则探针的结论无法迁移。

#### 20.11.1 更正：假阳性的根因是「表选错了」，不是名字列判据

我先按「名字列判据太松」去改（把 `PrintableFirstByte` 换成「可打印串起点」
`printable(o) && !printable(o-1)`）。**改完把已验证的行为也弄坏了**：7.1.0 和 7.0.0 都解不出名字列了。
⇒ 作为**唯一**判据太严（真列在某个采样行上过不了），已回退。

回退后重测，得到真正的根因：

```text
tables --base 0x010B5E1C   ->  col_off=0x0C  +0x616B619D  ok 256/256   ← 真列
tables（不带 --base）      ->  col_off=0x10  +0x616B619D  ok 256/256   ← 伪列
```

**同一条命令、同一个二进制，差别只在有没有 `--base`。** 不带 `--base` 时会扫全部 anchor，
**先撞上一张伪表**，然后在伪表上找名字列。

⇒ 病根在**表的接受条件**（加法族模型太松，产生伪表），不在名字列判据。
这同时解释 5.0.0 / 5.5.0 / 6.0.0 报 67 / 71 / 76 张表的异常。

**要做的事改成**：收紧 `analyse` 里加法族表的接受条件（可用的独立判据：
`trans` 覆盖率、计数列 tiling 的精确比例、`rows` 与 `max_idx` 的合理性、以及同名表在不同 anchor 下的一致性），
或者**按名字列质量给表排序**（能解出名字列者优先），而不是只按 `(rows, real_rows)`。

**负结果记录**：「可打印串起点」不能单独当判据——它会误杀真列。

#### 20.11.2 ★ 再次更正：7.0.0 的「伪列」是同一列的另一种参数化（我错了两次）

近期版本重扫后逐条核对**绝对地址**，发现 §20.11 的「伪列」结论是错的：

```text
工具报:  base 0x010B5E18  off 0x10   -> 绝对地址 0x010B5E18 + 0x10 = 0x010B5E28
我验证的: base 0x010B5E1C  off 0x0C   -> 绝对地址 0x010B5E1C + 0x0C = 0x010B5E28
```

**同一个物理地址。** 同理两张「不同的表」也是同一张：

```text
base 0x010B5E18 + 70*i + 0x20  ==  base 0x010B5E1C + 70*i + 0x1C   (对每一行 i 都成立)
```

因为 base 和 off 同时平移 4 字节，**对任何行都等价**。所以 7.0.0 根本没有伪列，
是工具把同一列用另一组 `(base, off)` 表达了，而我拿旧的 `base` 去配新 `off`，自然解出垃圾。

**教训（比上面那条更重要）**：`(base, off)` 不是唯一表示 —— **核对时必须换算成绝对地址**，
不能直接跨参数化比较。这一个坑我这轮踩了两次（先误判伪列、又据此误判「表选错了」）。

#### 20.11.3 近期版本重扫结果（当前二进制，7.x 优先）

| 版本 | 表数 | 名字列 | 第一张表 |
|---|---|---|---|
| 7.1.0 | 2 | `0x14 +0xE811F779` ✅ | `0x048F3FD8 xor 0x08 0x0478AF59`（= 已验证基址） |
| 7.0.0 | 4 | `0x10 +0x616B619D` ✅ | `0x010B5E18 add 0x20 0x33AB5AF8`（≡ 0x010B5E1C） |
| 6.7.0 | 2 | `0x18 +0x17FB1577` ✅ | `0x021F77B0 xor 0x0C 0x4DFA3BEC` |
| 6.6.0 | 2 | `0x2C +0xE5549FEF` ✅ | `0x03E7AD7C add 0x04 0x565FC12F` |
| 6.5.0 | 26 ⚠ | `0x28 +0x2538D0A2` ✅ | `0x000020A0 xor 0x00 0x489CB3F9` ← **基址 0xA0 荒谬** |
| 6.4.0 | 4 | `0x18 +0xE169AC15` ✅ | `0x00E7579C add 0x14 0x7589193B`（= 已验证基址） |
| 6.3.0 | 2 | `0x0C +0xA1C386A9` ✅ | `0x0076387C add 0x24 0x19983FBA` |
| 6.2.0 | 2 | **✗** | `0x027BDD20 xor 0x0C 0x48482004` |
| 6.1.0 | 2 | `0x10 +0x2AD8D3A1` ✅ | `0x010050B8 add 0x24 0x7396821F` |
| 6.0.0 | 76 ⚠ | `0x08 +0x85A69E32` ✅ | `0x001D6BD4 add 0x14 0x0BA968F3` |

**9/10 近期版本解出名字列**（只差 6.2.0）；7.1.0 与 6.4.0 的基址与已验证值完全一致。

**剩下的真问题**（不是伪列，而是伪表）：
- 6.5.0 的第一张表基址 `0x000020A0` 落在 metadata **header 区**内，物理上不可能是行表；
- 5.0.0 / 5.5.0 / 6.0.0 报 67 / 71 / 76 张表。
⇒ 仍应收紧加法族表的接受条件（判据候选：基址必须落在 body 的有效区间、`max_idx` 与
`rows × stride` 的规模关系、以及同一 (base mod stride, off) 的等价类去重）。

### 20.12 ★★ 实测判决：`in-range` 阈值既漏真槽又留噪声（支持 R8 槽驱动）

**加载器实际访问 24 个 header 槽**（`FUN_1405359e0` 内 `dat_145ad62b8 + <slot>`，去重）：

```text
0x10 0x1c 0x2c 0x5c 0x60 0x6c 0x78 0x80 0x84 0x8c 0x98 0xa0 0xa4 0xac
0xdc 0xe8 0x120 0x134 0x15c 0x170 0x188 0x1a4 0x1b0 0x1dc
```

逐一对照 `mhydump anchors` 的清单：

| 状态 | 数量 | 说明 |
|---|---|---|
| 24 个槽**全部**出现在 anchor 清单中 | 24 | **anchor 扫描这一层是对的**，原始材料没问题 |
| 但**只有 OUT-OF-RANGE 条目** | **3**（`0x78` / `0xE8` / `0x170`） | **现有 `in-range` 过滤会漏掉 3 张真表** |
| 同时有 in-range 与 OUT-OF-RANGE 条目 | 8（`0x10` `0x1C` `0x2C` `0x5C` `0x60` `0x80` `0x98` `0xA4`） | 同一槽在不同站点解析成不同基址，**其中必有误判** |

**结论**：`in-range` 是一个**阈值**，它同时造成两类错误（漏真、留假），正是 R8 明令禁止的做法。
按代码逻辑，候选集应当是**加载器函数（及其调用树）内访问过的槽** = **24 个**；
而现在实际扫描的是 **427 个候选基址**（由全部 anchor 展开）。

**据此的通用定位器（代码驱动，无阈值）**：

1. 用 `global-metadata.dat` 字面量的引用者定位加载器（**版本无关**，7.1.0 已证：唯一引用者 `FUN_1405359e0`）；
2. 只在加载器（及其调用树）内做 anchor 扫描 → 得到槽集合；
3. 每个槽给出 `(op, K)`，与同一表达式里的 stride 组成**一张表**；
4. **删除 `in-range` 之类阈值**；自相矛盾（如基址落在 0x210 字节的 header 区内）只在最后兜底，不计入成功率。

**自测标准答案**：在 7.1.0 上，该方法必须还原出 `(slot 0xDC, xor, 0x5278CA3B, stride 0x46)` —— 

### 20.13 ★★ 修正：「把 anchor 扫描限制在加载器内」不够，会漏掉已确认的槽

把 `/tmp/anch710.txt` 的 `site` 列按加载器范围 `0x1405359e0–0x14053beaa` 过滤：

| | 条目数 | 覆盖槽数 |
|---|---|---|
| 站点在加载器内 | 34 | 29 |
| 站点在别处 | 261 | 60 |

**加载器内的槽集合里既没有 `0x5C` 也没有 `0xDC`** —— 而这两个正是从加载器反编译里直接读到的：

```c
*(int4 *)(dat_145ad62b8 + 0xdc) ^ 0x5278ca3b     // typeDef 表基（三重互证过）
*(int4 *)(dat_145ad62b8 + 0x5c) ^ 0x6b2b3963     // 紧随 typeDef 表尾的下一张表
```

**原因**：加载器把 header 指针**缓存在寄存器里**（循环外提升），而 anchor 扫描匹配的是
「在同一处把全局读进来、再按槽索引」这种**指令形状**，所以在加载器内部匹配不到这两条。

**⇒ 修正计划**：通用定位器不能靠「限制函数范围 + 匹配指令形状」，而要做**最小的寄存器数据流**：

1. 定位 header 全局（`DAT_145ad62b8`）；
2. 在 `.text` 内跟踪哪个寄存器持有它（`mov reg, [rip+global]`）；
3. 此后所有 `[reg + disp]` 的 32 位读都算**槽访问**，再往后续指令取 `(op, imm)`；
4. 这样既覆盖「就地索引」形状，也覆盖「寄存器缓存」形状 —— 后者正是加载器用的。

**教训**：把「共同特征」定义成**指令形状**会漏；应当定义成**代码语义**（header 指针 + 槽索引），
再用最小数据流实现。这与 R8 一致：以实际执行代码逻辑为基础，而不是匹配表面模式。

这个四元组已由「结构判据 / anchor 恢复 / 加载器反编译」三重独立确认。














---

## §21 代码驱动的表定位器：从「扫描 + 阈值」改成「复现加载器的算术」（2026-10-14）

> 本节是**方案与实测**，不是需求。需求见 REQUIREMENTS.md R7 / R8。

### 21.1 问题

mhydump tables 原本把「anchor 恢复出的全部 body offset」当作候选基址。7.1.0 上是 **286 个**，
每个基址都要遍历 4..=0x200 的所有 stride 和行内列，端到端接近 100 秒；而基址集合里绝大多数
其实是**游戏读到的其它 metadata 段**，不是行表。这既慢，又违反 R8.c（过滤/阈值只能兜底，
不能当主路径）。

### 21.2 共同特征：把「指令形状」换成「代码语义」

7.1.0 加载器里有三处**完整的表定义**，它们不是「读一个槽」，而是**算一个行地址**：

    0x14053A73F  mov    rcx, [rip+global]      ; rcx = header 指针
    0x14053A746  movsxd rcx, [rcx+0xdc]        ; rcx = hdr[0xdc]
    0x14053A74D  xor    rcx, 0x5278CA3B        ; 每版本偏置
    0x14053A754  add    rcx, [rip+global+8]    ; rcx += body 基址
    0x14053A75D  imul   rdx, rax, 0x46         ; rdx  = index * stride
    0x14053A761  add    rdx, rcx               ; row  = base + index * stride
    0x14053A764  cmp    dword [rdx+0x1C], 0xDEBA5049   ; 表魔数

关键点：**「body 锚定的 header 槽」与「一个 stride」由同一条指令合起来**。这个**联合特征**
比任何一半都强得多；而且 stride 是**从代码里读出来的**，不靠假设。

实现：derive::anchor::TableDef + recover_tables()。在既有的前向扫描里维护一个小的符号状态机
（Hg / Body / Slot / SlotOp / Base / Scaled / Imm），寄存器与栈槽都跟踪，遇到 Base + Scaled
就产出一个 TableDef。

### 21.3 实测结果（26 个版本）

| 版本 | 恢复出的 (slot, op, imm, stride) | 备注 |
|---|---|---|
| 7.1.0 | 0xDC xor 0x5278CA3B 0x46 | 三重互证的类型表，正确 |
| 7.0.0 | 0xC4 add 0xC42E5C8F 0x46 | 修正后才出来 |
| 6.7.0 | 0x1E0 xor 0x4E66A4F6 0x46 | |
| 6.6.0 | 0xE8 xor 0x786B40A8 0x46 | |
| 6.5.0 | 0xB8 xor 0x65DDFF7C 0x46 | |
| 6.4.0 | 0xE0 xor 0x584D480A 0x46 | |
| 6.3.0 | 0xE4 xor 0x40F8965A 0x46 | |
| 6.2.0 | 0x1CC add 0x99E75364 0x46 | 修正后才出来 |
| 6.1.0 | 0x12C xor 0x46A23FE6 0x46 | |
| 6.0.0 | 0xB8 xor 0x5F815D53 0x46 | |
| 5.1.0 – 5.8.0 | 各 1 个，全为 stride 0x46 | 见运行输出 |
| 4.8.0 | 3 个，stride 0x4A | 4.x 纪元；5.0.0 也是 stride 0x4A |
| 4.2.0 – 4.7.0 | **0 个** | 4.x 纪元的算术形态不同，未解 |

**命中 24 / 26**；除 4.2.0–4.7.0 外全部至少给出 1 个表定义。stride 只出现两种：
0x46（70，主纪元）与 0x4A（74，4.8.0 / 5.0.0）。

### 21.4 一次必要的修正：偏置常在寄存器里

第一版只处理**立即数**形式的 OP imm，于是 7.0.0 与 6.2.0 都返回 0 个表定义。实测 7.0.0 的写法是：

    0x1404E6982  mov ecx, 0xc42e5c8f        ; 偏置先物化到寄存器
    0x1404E6987  add eax, ecx               ; 再相加，不是立即数
    0x1404E698B  add rax, [rip+body]
    0x1404E6994  imul rsi, rcx, 0x46
    0x1404E6998  add rsi, rax               ; ← 表定义在这里

加入 Sym::Imm（跟踪 mov r, imm）并在 reg-reg 与 reg-mem 两条路径上使用它之后，
**7.0.0 与 6.2.0 都被恢复**，26 版本命中数从 8 升到 24。

**教训**：同一语义在不同版本里可能用不同的**编码形式**。符号状态机要覆盖的是语义
（值从哪来），不是某一种编码。与 §20.13 的教训同源。

### 21.5 端到端回归（10 个最近版本，基址改为代码导出）

tables_cmd 现在**优先**用 recover_tables 解析出的基址；只有在代码里找不到表定义时才回退到
anchor 全集（日志里能区分两条路径）。候选基址：7.1.0 从 **286 降到 1**。

结果与原 286 基址扫描**逐项一致**：

| 版本 | 基址 | 名称列 |
|---|---|---|
| 7.1.0 | 0x048F3FD8 | 0x14 +0xE811F779 256/256 |
| 7.0.0 | 0x010B5E18（原记 0x010B5E1C） | 0x10 +0x616B619D 256/256 |
| 6.7.0 | 0x021F77B0 | 0x18 +0x17FB1577 256/256 |
| 6.6.0 | 0x03E7AD7C | 0x2C +0xE5549FEF 256/256 |
| 6.5.0 | 0x000020A0 存疑 | 0x28 +0x2538D0A2 256/256 |
| 6.4.0 | 0x00E7579C | 0x18 +0xE169AC15 256/256 |
| 6.3.0 | 0x0076387C | 0x0C +0xA1C386A9 256/256 |
| 6.2.0 | 0x027BDD20 | **无名称列** |
| 6.1.0 | 0x010050B8 | 0x10 +0x2AD8D3A1 256/256 |
| 6.0.0 | 0x001D6BD4 | 0x08 +0x85A69E32 256/256 |

7.0.0 的基址从 0x010B5E1C 变成 0x010B5E18、名称列偏移从 0x0C 变成 0x10，
**绝对地址都是 0x010B5E28**，与 §20.x 的自我修正一致（(base, off) 不是唯一表示）。

### 21.6 自测（R8.4 的验收）

derive::anchor::tests::recovers_71_type_def_table_from_code：

- 断言恢复集合里存在 (0xDC, Xor, 0x5278CA3B, 0x46)；
- 断言该四元组按 7.1.0 的 header 解析出的基址 == 0x048F3FD8。

实测：

    test derive::anchor::tests::recovers_71_type_def_table_from_code ... ok
    test result: ok. 1 passed; 0 failed

该自测与加载器反编译**逐项对齐**（槽位 / 运算 / 常数 / stride / 基址），满足 R8.4。

### 21.7 仍未解决（供下一轮）

1. **4.2.0 – 4.7.0 全部 0 个表定义** —— 4.x 纪元的表地址算术形态不同，需要单独看。
2. **6.2.0 没有名称列** —— 已排除两个疑点：
   - 字符串密钥**正确**：strings 输出 “first entry OK: offset 0 -> mscorlib”，逐条可读；
   - 该版本是 **5 常数**密钥代（cipher 明确报 “no 3-constant string cipher derived”），
     但 5 常数 schedule 已成功导出且解密正确。
   所以问题在**索引列 / 名称列搜索**，不在密钥。基址 0x027BDD20 下两个模型
   （xor 0x0C / add 0x42）都没有给出通过 97% 判据的名称列。**未定位，不许猜。**
3. **6.5.0 基址 0x000020A0 不合理**（只有 8 KB），但名称列 256/256 通过。仍存疑。
4. in_range / 大于 0x40 / 大于 0x1000 这类阈值仍留在 body_offsets() 与 derive_build() 里，
   只在「代码里找不到表定义」的回退路径上使用；主路径已不依赖它们。


---

## §22 与 Il2CppDumper 的差距清单（2026-10-14，实测）

> 本节是**实测差距分析**，不是需求。需求见 REQUIREMENTS.md R1（完整性对等）与 R7（先最近版本）。

参照物（磁盘上的真实产物，非记忆）：

- /home/yangsanyi/Documents/git-repo/Genshin-Impact-Dump-collection/6.4Dump.cs（6.4.0，2,837,268 行 / 148 MB）
- /home/yangsanyi/Documents/git-repo/EndField/Dump/（Il2CppDumper 完整产出集：dump.cs 101 MB、
  il2cpp.h 74 MB、script.7z 23 MB、stringLiterals.json 5.6 MB、DummyDll/）
- /home/yangsanyi/项目/逆向和数据提取/out/export/4.6.51/script.json（GI 4.6.51 的真实 script.json）
- 我们对 7.1.0 的产物：/tmp/gi710_dump.cs（2,531,883 行 / 68 MB）、/tmp/script.json

### 22.1 交付物级别

| Il2CppDumper 产出 | 体量 | 我们 | 结论 |
|---|---|---|---|
| dump.cs | 101 MB | 有 | 内容缺项见 22.2 |
| il2cpp.h（C 结构体，Ghidra/IDA 可导入） | 74 MB / 2,168,818 行 | **无** | 完全缺 |
| script.json | 23 MB（7z） | 有 | 字段缺项见 22.3 |
| stringLiterals.json | 5.6 MB | **无** | 完全缺 |
| DummyDll/ | 目录 | **无** | 完全缺 |

### 22.2 dump.cs 逐项（6.4Dump.cs vs 我们的 7.1.0 dump，均为实测计数）

| 项 | 参考 | 我们 | 判定 |
|---|---|---|---|
| 类型种类与可见性 | class 64,437 / struct 3,294 / interface 1,345 / enum 6,552 | class 39,917 / struct 1,963 / **interface 42,484** / enum 4,508 | **错**：大量 class 被标成 interface |
| 基类 | 64,808 条 | 41,705 条 | 有，覆盖率待查 |
| 方法 Token | 631,108 | **0** | 缺 |
| 方法 Slot（非 -1） | 211,652 | 1,833 | 大量缺 |
| 方法 RVA | 653,556 | 460,282 | 少 193k |
| 参数名 + 参数类型 | 完整（System.String name 等） | 全为 object /*unresolved*/ | **缺**，208,695 处 unresolved |
| 字段体 | 384,411 | 440,061 | 有 |
| 字段偏移注释 // 0x10 | 384,411 | **0** | **缺（全部）** |
| 枚举成员字面值 = 0 | 有 | 无 | 缺 |
| 特性 [DllImport] 等 | 11,525 | **0** | 缺 |
| Properties 节 | 77,260 节（含 get; set;） | **0 节** | **缺整节** |
| Constructors 节 | 77,260 节（独立） | 0（并入 Methods） | 缺分类 |
| Events / Nested Types / Interfaces 节 | 0 | 0 | 两边都没有，非差距 |
| TypeDefIndex 条数 | 77,260（6.4.0） | 88,872（7.1.0） | 版本不同不可直接比；见 22.4 |

**类型种类错误的直接证据**（同 TypeDefIndex 逐条对照）：

    idx 0  REF: internal class <Module>            OURS: public interface <Module>
    idx 1  REF: internal class Locale : Object     OURS: public interface Locale
    idx 2  REF: internal abstract class SR : Object  OURS: public interface SR
    idx 3  REF: public abstract class Mono.Runtime : Object  OURS: public interface Runtime
    idx 4  REF: internal struct Mono.RuntimeClassHandle  OURS: public struct RuntimeClassHandle : System.ValueType

即 struct / enum 能判对，class 家族（含 abstract / static / 可见性）**判不出来，回退成 public interface**。

### 22.3 script.json 逐字段（4.6.51 参考 vs 我们 7.1.0）

| 字段 | 参考 | 我们 |
|---|---|---|
| ScriptMethod | 320,084 | 460,282 |
| ScriptString | 689,799 | **0** |
| ScriptMetadata | 0 | 0 |
| ScriptMetadataMethod | 0 | 0 |
| Addresses | 239,153 | **3** |
| 单条 Signature | public void GetText(); | 空字符串 |

（ScriptMetadata / ScriptMetadataMethod 两边都是 0，不是差距。）

### 22.4 诚实的不确定项

1. **类型条数**：我们 7.1.0 是 88,872，参考 6.4.0 是 77,260，版本不同**不能直接判定谁对**。
   反证：6.4.0 上我们的表 rows = 77,262，与参考的 77,260 吻合（差 2），说明**行数本身是准的**。
   要坐实需要**同版本**对照，而 dump71 目前只支持 7.1 一代的 profile。
2. 我们 dump 里被标成 interface 的类型（例如 idx 88000 那个带 7 个字段的）
   有真实字段和混淆名，不是填充行；问题在**种类判定**，不在行筛选。

### 22.5 建议优先级（按 R1 + R7：先最近版本、先准确性）

P0（准确性，污染所有下游）：
1. 类型种类 / 可见性 —— 42,484 个类型被标错，dump 的可用性直接受损；
2. 参数名 + 参数类型 —— 36 万+ 参数是 object；
3. 字段偏移 —— 结构体布局是逆向与改数据最需要的东西，现在一条都没有。

P1（交付物）：
4. il2cpp.h（用户在用 Ghidra，这个可直接导入）；
5. 方法 Token / Slot；
6. script.json 的 ScriptString 与 Addresses（IDA/Ghidra 重命名脚本依赖）。

P2：stringLiterals.json、DummyDll、Properties/Constructors 分节、特性、枚举字面值。


---

## §23 同版本参照获取 + 类型 flags 定位受挫（2026-10-14）

> 方案与实测，不是需求。需求见 REQUIREMENTS.md R1 / R7 / R8。

### 23.1 拿到了同版本参照（本轮的真正收获）

按用户指示「先专攻有参考或者最新版本」，把 GI 社区 dump 解到 /tmp/giref/：

    6.1Dump.cs  94 MB   6.2Dump.cs  95 MB   6.3Dump.cs  99 MB
    6.4Dump.cs 148 MB   6.5Dump.cs 184 MB

样本库里有 6.1.0 / 6.2.0 / 6.3.0 / 6.4.0 / 6.5.0 的 exe 与 global-metadata.dat，
所以 **6.1–6.5 现在是同版本对照**，不再需要跨版本推测。参照数量从 1 个变成 5 个。

### 23.2 类型种类错误的根因（已定位，代码级）

src/dump71.rs:163 的 type_kind **只看 parent 类型**，parent 解析不出来时**默认返回 interface**：

    fn type_kind(...) -> &'static str {
        if parent_tarr != u32::MAX { ... "enum" / "struct" / "class" ... }
        "interface"
    }

它从不读 typeDef 自己的 flags。后果（6.4Dump.cs vs 我们的 7.1.0 dump）：

    参考  class 64,437  struct 3,294  interface  1,345  enum 6,552
    我们  class 39,917  struct 1,963  interface 42,484  enum 4,508

同 TypeDefIndex 逐条对照可见 0/1/2/3 号本该是 class / class / abstract class /
abstract class，我们全报 interface。**这是 P0，必须先修。**

### 23.3 定位 flags 列：本轮失败，且知道了为什么

我按 R8 的顺序做：先拿参照验证，再找可复用的共同特征。搜索空间与结果：

- 读法：u32 与 u16，byte offset 0..stride-1，行偏移再扫 -70..+70；
- 变换：plain = raw 异或 C，以及 plain = raw 加 C；
- 判据：interface(0x20) / public(0x7==1) / abstract(0x80) / sealed(0x100)
  四个语义位必须由**同一个 C** 同时解释（每位的吻合率必须接近 1 或 0）；
- 结果：**5 个参照版本、以上全部空间内，没有任何列通过。**
  最高分 0.798/0.806 恰好等于 public 的基准率（80.4%），即「全判 public」的平凡解。

**失败原因的实测证据（重要）**：

1. find 报出的 base **不等于行起点**。7.1.0 上 base=0x48F3FD8 确实是行起点
   （魔数正好落在 +0x1C）；但 6.4.0 的 base=0xE7579C 落在行起点前 0x3E 字节
   （0x3E 与 stride 0x46 的关系解释了为什么 cnt_off 会算到 0x78）。老日志记过，我本轮又踩一次。
2. **行号不等于 TypeDefIndex**。7.1.0 上 u32@(row+0x1C) 只有 62,923 / 88,904 行等于
   加载器要求的 0xDEBA5049（cmp dword [rdx+0x1c], 0xdeba5049）。
   而我们 dump 出了 88,872 个类型。**若加载器那个比较是有效性判据（它所在的位置像判据），
   我们可能多输了约 26,000 个不是 typeDef 的行。** 这一条需要再做一次实验坐实，现在只算待验证。
3. layout71 自己的注释写着 parent 的解码是
   raw@0x2C 异或 tag@0x1C 异或 0x8177D738 —— 即 **tag@0x1C 参与其它列的解码**。
   所以「每列 = raw 异或常数」这个模型本身就可能不成立；凡是 tag 不等于该常数的行，
   用常数 XOR 解出来的值就是错的。我按「per-row tag 异或 raw」又试了一轮，仍无信号，
   但那一轮的 grid 是靠「最常见重复常数」猜的，**没有锚定到 typeDef 表，所以这一轮否定不算数**。

### 23.4 结论与下一步（按 R8：回到逆向，而不是继续凑相关）

本轮是**负结果 + 一个方法论教训**，不是突破。教训是：
**先锚定表，再做相关。** 我一直在用猜出来的 grid 去比对参照，grid 一错，
后面所有否定都不可信（6.3.0 那轮甚至把 grid 锚到了 0xFFFF0000 上）。

下一步应严格按 R8.a 走代码，而不是继续统计：

1. 在 7.1.0 加载器里找**读 typeDef flags 的指令**（il2cpp 的 Class::IsInterface /
   GetTypeAttributes 一类），把它读的 (row offset, op, imm) 直接读出来 ——
   这正是 §21 那套符号数据流已经会做的事，扩展到「任意列」即可。
2. 用 6.1–6.5 五个同版本参照**验收**该列（interface / public / abstract 三位必须 100% 对齐）。
3. 再谈 4.2–4.7 的纪元差异。

### 23.5 顺带确认的差距（供排序，来自 §22 的补充）

6.1/6.2/6.3/6.4 的参照 dump **不输出 sealed / static**（参考里 sealed 率 0.000），
只有 6.5Dump.cs 有（0.308 / 0.053）。所以用旧参照验收时**不能拿 sealed 当判据**。


---

## §24 读原版 Il2CppDumper 源码后的修正（2026-10-14）

> 用户问「你看过原版 il2cppdumper 的源码了吗」——**没有**。此前只看过它**产出的 dump**
> 和一个**同名不同源**的工具（IL2CPP-Dumper，Arknights Endfield 注入式）的 README。
> 现已 git clone 到 /tmp/il2cppdumper（Perfare/Il2CppDumper，depth 1）。本节记源码给出的事实。

### 24.1 P0（类型种类 / 可见性）的判定规则，源码原文

dump.cs 的写出者在 Outputs/Il2CppDecompiler.cs，规则在 62–106 行：

    visibility = flags & 0x7   ; 1/2=public  0/5/6=internal  3=private  4=protected  7=protected internal
    static   : (flags & 0x80) != 0 && (flags & 0x100) != 0
    abstract : (flags & 0x20) == 0 && (flags & 0x80) != 0
    sealed   : !IsValueType && !IsEnum && (flags & 0x100) != 0
    kind     : (flags & 0x20) != 0 -> interface
               else IsEnum         -> enum
               else IsValueType    -> struct
               else                -> class

而 Il2Cpp/MetadataClass.cs:231–232 **规定 kind 不来自 flags**：

    public bool IsValueType => (bitfield & 0x1) == 1;
    public bool IsEnum      => ((bitfield >> 1) & 0x1) == 1;

**结论：只需要 typeDef 行里的两个 uint —— flags 与 bitfield。**
我们现在的 type_kind 是「用 parent 反推 kind」，是替代品，不是本源；
而 flags 列从未被定位过，这正是 42,484 个类型被写成 interface 的直接原因。

### 24.2 这同时给了 grid 锚定的正确方法

§23 失败的根因是用「出现最多的重复常数」猜行 grid，没有锚定到 typeDef 表。
现在有了**精确布尔判据**：bitfield 的 bit1 必须与参照的 enum 集合逐行相等，
bit0 必须与 (struct 并 enum) 相等 —— 70k 行的精确匹配，足以一次同时钉死
「grid 相位」和「bitfield 列」。锚定之后再搜 flags，否定才可信。

### 24.3 字段偏移根本不来自 global-metadata.dat（重要）

Il2Cpp/Il2Cpp.cs:274–291：

    public int GetFieldOffsetFromIndex(...) {
        if (fieldOffsetsArePointers) { var ptr = fieldOffsets[typeIndex]; offset = ReadInt32(...); }
        else offset = (int)fieldOffsets[fieldIndex];
        if (offset > 0) { if (isValueType && !isStatic) { if (Is32Bit) offset -= 8; else offset -= PointerSize; } ... }
    }

fieldOffsets 来自 **Il2CppMetadataRegistration**（二进制里的运行时表），
不是 GlobalMetadataHeader。所以：

- 我们「纯 metadata」的管线**永远拿不到字段偏移**，必须去 exe 里定位
  MetadataRegistration 并取出 fieldOffsets 数组；
- 好消息是这正好是 §21 那套符号数据流能做的事（找读取该指针的代码）；
- 另外 il2cppdumper 对值类型要做 offset -= pointerSize 修正，照抄即可。

### 24.4 顺带确认：两处「未定位的列」其实都有明确目标

- interfaces_count：Il2Cpp/MetadataClass.cs:213 是 typeDef 行里的 **ushort**，
  Il2CppDecompiler.cs:54–61 直接用 interfacesStart + i 枚举接口。
  我们日志里写的「per-type count column not located，只能用 run-length 近似」——
  **目标字段是已知的**，只是还没定位。
- token：Il2Cpp/MetadataClass.cs:229 是 typeDef 行里的 **uint**（Version >= 19），
  用于输出 Token: 0x...。同样是已知目标。

### 24.5 参照 dump 的枚举顺序（顺带核对）

Il2CppDecompiler.cs:41 按 image 遍历 typeDefIndex 从 imageDef.typeStart 到
typeStart + typeCount，TypeDefIndex 是全局 typeDef 下标 —— 与此前对齐参照时的假设一致。


---

## §25 更正 §23：行号就是 TypeDefIndex（2026-10-14）

§23.3 写过「行 0–3 是哨兵行，行号 = TypeDefIndex + 4」。**该结论错误，现撤回。**

真实原因是把 0x8D9D7FF8 误读成「填充行标志」。它其实是 layout71 已定义的
td_fs_sentinel_raw，含义是「该类型没有字段」。用 7.1.0 的 base=0x48F3FD8 逐行核对：

    行 0  fieldStart=无(0xFFFFFFFF)  fieldCount=0   参照 idx 0  <Module>                 Fields 空  ✓
    行 1  fieldStart=无             fieldCount=0   参照 idx 1  Locale                   Fields 空  ✓
    行 2  fieldStart=无             fieldCount=0   参照 idx 2  SR                       Fields 空  ✓
    行 3  fieldStart=无             fieldCount=0   参照 idx 3  Mono.Runtime             Fields 空  ✓
    行 4  fieldStart=0              fieldCount=1   参照 idx 4  Mono.RuntimeClassHandle  1 个字段   ✓

逐条吻合 ⇒ **行号就是 TypeDefIndex，7.1.0 的 grid 是确定的**（魔数落在 base+0x1C=0x48F3FF4，
即 base 就是 0 号行起点）。

因此 flags 列定位失败的原因**不是**行号错位 —— 这个借口不成立，不能拿它解释 §23 / §24 的否定。

未独立复核、仍按日志原记录对待的一条：6.4.0 的 find base=0xE7579C 落在真实行起点前 0x3E 字节
（依据是历史日志的记录 + find 把 count 列算到 0x78 > stride 0x46 这一吻合现象，本轮没有重新验证）。


---

## §26 第一轮代码驱动逆向：类型表行字段（2026-10-14）

> 用户要求「去逆向，不要猜」。本节全部结论都来自**指令本身**，不是统计匹配。
> 工具：capstone 直读 7.1.0 的 .text（35 MB）。

### 26.1 从指令里读出来的字段（7.1.0，行 stride = 0x46）

| 行内偏移 | 宽度 | 解码 | 指令出处 |
|---|---|---|---|
| 0x00 | 4 | 异或 0x72628007 | 加载器 + layout71 链走查 |
| 0x08 | 4 | 异或 0x0478AF59 | 加载器（*(int4*)&v29[1] 异或 0x478af59）|
| 0x14 | 4 | 加 0xE811F779 | **0x1405167DC**（本轮新读出）|
| 0x18 | 4 | 异或 0x666769B5 | **0x1405167EF**（本轮新读出）|
| 0x1C | 4 | 校验 == 0xDEBA5049 | 全 .text 共 6 处，只落在 2 个函数 |
| 0x30 | 2 | 异或 0x9A6B | layout71 + find 的 cnt 列 |
| 0x3C | 2 | 异或 0x8811 | 加载器反编译（method 循环上界）|
| 0x3E | 2 | 减 0x1398，0xFFFF = 无 | **0x140512994 / 0x140512FAA / 0x14051A382** |

0x14 / 0x18 两条与 layout71 的 td_name / td_ns **逐字一致**，是独立复核。

### 26.2 顺带读出的表基址（新）

在 0x140512990 与 0x140512FA6 两处，指令直接给出了另外两张表：

    0x140512F8E  mov    rdi, [rip+0x55c3323]        ; header 全局
    0x140512F95  movsxd rbx, [rdi + 0xdc]
    0x140512F9C  xor    rbx, 0x5278ca3b
    0x140512FA3  add    rbx, rdx                   ; 类型表基址
    0x140512FA6  imul   rsi, rcx, 0x46              ; 行号 x 70
    0x140512FAA  movzx  ebx, word [rsi + rbx + 0x3e]  ; 行+0x3E，u16
    0x140512FAF  add    ebx, 0xffffec68            ; - 0x1398
    0x140512FB5  cmp    bx, -1                     ; 0xFFFF = 无
    0x140512FC3  movsxd rdi, [rdi + 0xc8]
    0x140512FCA  xor    rdi, 0x8d701a3
    0x140512FD1  add    rdx, rdi                   ; Il2CppType 数组基址
    0x140512FD7  shl    r12, 4                     ; 索引 x 16  => 元素 16 字节

即 hdr[0xc8] 异或 0x8D701A3 加 body = Il2CppType 数组（stride 16），
行+0x3E 是其中一个 u16 索引（0xFFFF = 无）—— 与 dump71.rs 里 (off - typearr)/16 吻合。

另一处在 0x140516871 起：hdr[0x5c] 异或 0x6B2B3963 加 body 得到一张 u32 表，
里面存的是 typeDef 索引（-1 = 无），再回类型表取名字 —— 导出类型表。

### 26.3 没做到：flags 仍未定位（附确切搜索范围）

- 加载器 FUN_1405359e0 里**没有**读 flags 的痕迹；它只读 0x1C（校验）、0x08、0x3E 等。
- 全 .text 里带类型表行校验指纹（cmp dword [mem+0x1c], 0xdeba5049）的只有 **2 个函数**，
  都不读 flags。
- 11 个行地址计算点（imul reg, reg, 0x46）所在的函数里，
  出现的 0x20 / 0x80 / 0x100 / 0x7 掩码全部作用在 **klass 对象**上
  （[reg+0xc9] 与 [reg+0xac]），不是类型表行。

**关键发现**：klass 的 flags 不是原始 TypeAttributes，而是被**重新打包**过的：
[klass+0xac] 低 3 位是可见性（and eax, 7），[klass+0xc9] bit5 是 interface。
也就是说运行时把 typeDef.flags 读出来之后做了一次「解包 -> 重打包」，
**flags 的读取点在那个转换里**，不在加载器、也不在直接判 interface 的地方。

### 26.4 下一步（精确、可执行）

不要在行上找掩码，去找**重打包**：以 [klass+0xac] 与 [klass+0xc9] 的写入点为锚，
向上追它读的源。已定位到的候选写入点：

    0x1404950C2   mov [rsi+0xac], eax     ; 源 [rax+0x5c]，与 0x98..0xac 一整块一起拷贝
    0x14050EBA6   mov [rdi+0xac], eax     ; 源 [r15+0xac]（模板 klass）
    0x1406BC08E   mov [rsi+0xac], eax     ; 源 [r10+rcx+8]
    0x140686F14   mov [rdx+0xac], r8d     ; shl/shr 重打包位域

其中 0x1406BC080 那条的源形式 [r10+rcx+8] 最像「表 + 行 + 列」，
下一轮先把它的 r10/rcx 追出来，确认是不是类型表行、rcx 是不是 行号 x 70。


---

## §27 第二轮代码驱动逆向：metadata 加载流程全景（2026-10-14）

> 用户目标升级为「通过逆向完全掌握 metadata 加载流程」。本节全部结论来自指令读取，
> 工具：capstone 窗口扫描 + kuna 反编译（FUN_1406bb570 / FUN_140518030 / sub_14051e390 /
> sub_14051e0f0 / sub_1405153f0）+ Ghidra 边界查询。样本 7.1.0。

### 27.1 入口链与初始化序列（加载器 FUN_1405359e0，kuna 全文 /tmp/kuna_loader.txt）

唯一调用者：0x1404B1F49（FUN_1404b1f30，0x27 字节 thunk）。加载器内部顺序：

1. 解析自身 PE，按名字找 "il2cpp" section（sub_141c2fae0("il2cpp",...)），
   记录到 dat_145ad4900/4908 = il2cpp 段 VA 范围（.text 后有独立 il2cpp 段 0x146C05000+0x13255BC6）。
2. 打开两个文件（明文名，来自加密 blob 参数）：
   - sub_140523f70("global-metadata.dat")：magic 串 "Metadata"、错误日志 "ERROR: Could not open %s"、
     IAT = CloseHandle/GetLastError；返回文件镜像。
   - sub_140523f70("startup-metadata.dat") → 存 dat_145ad62c8。
3. BODY：dat_145ad62c0 = 文件镜像 + 0x210（dat 自己的前 0x210 字节被直接丢弃，不是头部！）。
4. 头部：dat_145ad62b8 由 CRT 初始化器 0x1402F3730 写入**静态 .rdata 地址 0x1427D5CB0**，
   blob 以 "MHY\0" 开头、长 0x210。验证：slot 0xDC ^ 0x5278CA3B = 0x48F3FD8 与已知 typeDef 基址
   精确一致；dat[0:0x210] != 头 blob（实测 False）。
   同一初始化器还写入：6298←0x1422DF450、62A0←0x142871B68、62A8←0x142871C08、62B0←0x1422DF4F8。
5. 分配运行时缓存（sub_1405002f0=alloc、sub_141fc84c0=memset）：
   - 62D0：62A0[6]^0x28A0FA2D 个 ×8
   - 62D8：hdr[0x60]^0x15335474 ÷0x46 = typeCount 个 ×8
   - 62E0：klass-by-typeDefIndex 缓存（sub_14051e0f0 按 typeDefIndex 索引它）
   - 62E8：泛型实例缓存，(hdr[0xAC]^0x6F3B0AC0)÷3 个（配 0x188 表索引）
   - 62F8：image 表，(hdr[0xA4]^0x1496B860)÷0x28 个 ×88B，哨兵初始化（见 27.5）
   - 6308：assembly 表，(hdr[0x170]>>4 ^0x28D714C) 个 ×80B（>>4=SHR+XOR 新形态）
   - 方法表大小 = hdr[0x134]+0x8EEFDB56（÷0x1A=行数）
6. metadataUsage 对表在 **startup-metadata.dat** 的 hdr[0x120]^0x1C3F68EA 偏移处，
   逐对 {u32 idx, u32 typeIdx} → typearr[typeIdx*0x10] 解引用建指针数组。

### 27.2 取表统一成语与完整槽清单

成语：mov regA,[0x145AD62C0]; mov regB,[0x145AD62B8]; movsxd regC,[regB+slot];
      (xor|add|sub) regC,imm; add regC,regA  → 表基址 = body + (hdr[slot] OP imm)。
扫描方式：字节级定位全部 mov r64,[rip] 加载点（62B8 356 处 / 62C0 249 处），逐点 0x150 字节窗口。
结果 702 条槽读取、77 组 (slot,op,imm)（/tmp/tblre/slotrec4.json），分布 256 个函数，
集中区 0x1404B0000–0x140549000 = il2cpp vm 代码。多站点高置信表：

    slot 0x5C  ^0x6B2B3963  导出类型索引 u32（-1=无）
    slot 0x60  ^0x15335474  typeDef 表字节数（/0x46=行数）
    slot 0x74  ^0x245177E0  泛型方法索引，stride 6 有序 {i32 key,u16 idx}；大小=hdr[0x110]^0x1AB6109A
    slot 0x98  ^0x76A06155  203 站点：打包 (类别3位|索引29位) 表；类别=6 走 0x188 泛型路径
    slot 0xA4  ^0x1496B860  image 表（÷0x28=行数，行 88B）
    slot 0xAC  ^0x6F3B0AC0  ÷3 = 0x188 表行数（泛型实例数）
    slot 0xC8  ^0x8D701A3   Il2CppType 数组（stride 16；静态副本指针在 62A0[5]=+0x28）
    slot 0xDC  ^0x5278CA3B  typeDef 表（stride 0x46）
    slot 0x110 ^0x1AB6109A  0x74 表的字节数
    slot 0x118 ^0x4009A6BF  26 站点，大表（语义待定）
    slot 0x134 +0x8EEFDB56  方法表字节数（÷0x1A=行数）
    slot 0x170 >>4 ^0x28D714C assembly 行数
    slot 0x188 ^0x57DD5CA8  207 站点：泛型实例表 stride 12 {i32,i32(-1=无),i32}
    slot 0x1B8 ^0x586ABAF1  嵌套类型 u32 索引表
    slot 0x1E0 ^0x2EE480FB  方法表（stride 0x1A，与 layout71 md_stride 互证）
    slot 0x200 −0x4BC1F14F  u32/方法（-1=无）→ 6298[+0x8] 数组索引（invoker/signature 类）
    （另有 ~30 个单点槽：0x0C/0x34/0x44/0x68/0x80/0x164/0x174/0x1E0 外见 slotrec4.json）
    repo layout71 既有：0x70 −0x6EA5B3FD（iface 表，本扫未捕=变换形式不同）

### 27.3 typeDef 行（stride 0x46）列清单（全部指令级）

    +0x00 u32 ^0x72628007           fieldStart
    +0x08 u32 ^0x0478AF59           methodStart（加载器+sub_1405153f0 三处互证）
    +0x14 u32 +0xE811F779(≡−0x17EE0887) nameIndex（sub_14051e390 负数形式互证）
    +0x18 u32 ^0x666769B5           namespaceIndex
    +0x1C u32 ==0xDEBA5049          行校验 tag
    +0x20 u32 ^0x6C9A5100           interfacesStart（FUN_1400010f0+加载器两处）
    +0x30 u16 ^0x9A6B               fieldCount
    +0x36 u16 ^0xC87C               nestedTypesStart（索引 0x1B8 表）
    +0x3C u16 ^0x8811               methodCount
    +0x3E u16 −0x1398(0xFFFF=无)     byvalTypeIndex
    +0x45 u8  ^0xAB                 nestedTypesCount（sub_14051e390+加载器两处互证）
    未定位：flags、bitfield、token（见 27.6）
注意：layout71 的 td_iface_start 0x3A^0x4BCE 与代码读出的 0x20 冲突，0x3A 列语义需重验

### 27.4 方法行（stride 0x1A）与 mask2 公式（sub_1405153f0，kuna 全文）

    mask2(i) = ((i*0x4E94 ^ 0x62D8B7B8)*0x7572748A + 0x1F4D9EEA ^ 0x6E8931D6) * 0x39036375  (mod 2^32)
    +0x0C u16 ^0x1E2A − mask2        slot（-1=无）
    +0x0E u32 ^0x394729C + 每行项     declaringType（sub_14051e0f0）
    +0x12 u16 − mask2 − 0x7269       parameterCount
    +0x14 2×u16 − mask2 + 常数(dat_143909610/612)
    +0x18 u8  − mask2 + 0x8C
    +0x19 u8  ^0xB1 − mask2          attrs 位（bit0/bit1 参与静态位重打包 v8[0x2F]）
klass 侧：+0x58=methods 数组、+0xC0(u16)=methodCount、+0xCA bit5=含泛型方法；
methodinfo 结构 0x38 字节（7 qword）

### 27.5 运行时结构

klass 0xD0 字节：+0x60=typeDef 行指针、+0xAC=重打包 flags（低 3 位=可见性，FUN_140518030
  ((uint4*)v9)[0x2b] = a0[..]&7 直证）、+0xC9 bit5=interface、+0xC9 bit6=?、+0xC0=methodCount。
数组/指针 klass 工厂 FUN_140518030：绑定占位行 (typeCount−2)；即**表末尾行是合成类型占位**。
静态注册结构：62A0(0x142871B68)≈Code+MetadataRegistration 混合（+0x28 Il2CppType 数组指针、
  +0x30 ^0x28A0FA2D=某计数、+0x50=模块基址）；6298(0x1422DF450)：+0x8 invoker 数组、
  +0x28 方法指针数组、+0x78 泛型方法数组。
image 表(62F8) 88B 行的加密零哨兵常量 = 后续读取该字段时的解密常数（0x7362B478 等 11 个，
  与 +4 typeStart/+0x18 导出计数/+0x20/+0x50 导出起点 的运行时解密完全对应）。
assembly 表(6308) 80B 行，哨兵 9 常量同理。

### 27.6 flags 未竟与下一步

本轮排除：FUN_1406bb570（0x1406BC080 源是 .rdata 0x1439206E0 的静态二分表 stride 12，
与 typeDef 行无关）；sub_1405153f0 是方法表构建器（不读行 flags）。
行→klass 转换（flags 读取点）锁定在 sub_14051db00（111 个调用者的统一解析器，
内层应有 Class::FromTypeDefinition 等价物）；kuna 反编译已排队（/tmp/kuna_51db00.txt）。
klass flags 的重打包事实（0xAC 低 3 位 / 0xC9 bit5）意味着行内 flags 列在解包处被读——
与 mask2 家族同源的每行掩码大概率参与。

### 27.7 工具教训（本轮三次返工）

1. 全量 capstone+detail 存 9.5M 指令 → OOM 被杀两次；改「字节定位加载点+小窗」后 30 秒完成。
2. 自造寄存器号 ≠ capstone 枚举（X86_REG_RDX=40 非 2）；REX.R 是 0x4 位不是 0x8。
3. 变换有两种操作数方向：dst,imm 与 dst,[mem]（mov reg,K 先装常数），都要扫。
4. kuna 后台 PATH 不含 cargo/bin，需绝对路径
   /home/yangsanyi/Documents/git-repo/kuna/decompiler/target/release/kuna；CWD=/tmp。
5. Ghidra run-script（连字符工具名）批量 getFunctionContaining 很快（2 s/256 函数）。


### 27.8 追加：行→klass 转换在壳内（本轮最后一锤）

sub_14051db00（111 个调用者的统一 klass 解析器）整个函数体只有一条
jmp 0x159F63C4D —— 位于 .upx0 段（0x159E5B000..0x15ACEEBB8，VMProtect）。

这解释了 §23/§24/§26 至今找不到行内 flags 列的根本原因：
typeDef 行→klass 的转换核心（含 flags/bitfield 解包）在 .upx0 壳里，
明文 .text 里只有外围（表定位、字符串、方法表构建、数组类工厂）。

下一步路径（按优先级）：
1. 用本工作区已验证的 NoVmp 管线（记忆 C2 线：GI 全 26 版可用）脱壳 7.1.0，
   在脱壳输出里找 0x159F63C4D 对应代码，读 flags 列与变换。
2. 或在 memdump_ingame 的对应区段按 imul 0x46 + 槽 0xDC 指纹搜。

---

## §28 第三轮：壳内直读 —— flags/bitfield/elementTypeIndex 全破（2026-10-14）

> 用户指令：固化成果防复研 + 维护 NoVmp 并继续逆向。
> 实际路径：0x19f63c4d 用 NoVmp 报 "first instruction is not PUSH imm32" —— 它属于交接文档
> 所说 91 入口中的「只变异、未虚拟化」函数。变异原生代码仍是 x86，直接 capstone 反汇编
> 即可读（变异=插入垃圾指令，真逻辑完整保留）。flags 问题就此解决。

### 28.1 目标函数与调用链

    sub_14051db00（111 个调用者的统一 klass 解析器，明文 .text）
      └─ jmp 0x159F63C4D（.upx0，变异原生，非 VM）
           = il2cpp Class::FromTypeDefinition 等价物：
           按 typeDefIndex 建 klass（0xD0 字节），填 flags/bitfield/类型索引/父/嵌套/泛型容器，
           写缓存 dat_145ad62e0[idx]。

### 28.2 typeDef 行新列（全部来自该函数指令）

| 列 | 解码 | 语义 | 指令 |
|---|---|---|---|
| +0x0C u32 | −0x205F6070 | **flags** → [klass+0xAC] | 0x159F64354–0x159F6436A |
| +0x32 u16 | ^0x8BA4 | **bitfield**：bit0=IsValueType、bit1=IsEnum | 0x159F63DC2（bit 0x100/0x200 测试）、0x159F64372+（低字节位散布到 klass 0xC7/0xC9/0xCA）|
| +0x1C u32 | ^0x2145AFB6，-1=无 | **elementTypeIndex**；-1 的密文恰为 0xDEBA5049，"tag" 即哨兵 | 0x159F64626–0x159F64652 |
| +0x10 u32 | ^0x37EEAE45 | byvalTypeIndex（×16 取 Il2CppType 拷到 klass+0x68）| 0x159F641B7 |
| +0x28 u32 | ^0x1B7494B5 | this/element 类型索引（→klass+0x10）| 0x159F641FD |
| +0x2C u32 | ^0x5FCD8771，-1=无 | parent 类型索引（调 0x14050e7a0 得值→klass+0xB0）| 0x159F645D2 |
| +0x40 u8 | ^0x06 | 小列（→klass+0xBE）| 0x159F63DAC |
| +0x42 u8 | +0xA2 | 小列（→klass+0xC2）| 0x159F645AE |
| +0x3C u16 | ^0x8811 | methodCount → [klass+0xC0]（第三次独立互证）| 0x159F64572 |
| +0x04 u32 | +0x89DE8E6E | 接口相关列（待终判 count/start）| 0x159F646C9 |

layout71 旧 parent 模型（^tag^0x8177D738）与本轮（^0x5FCD8771）精确等价：
0x8177D738 ^ 0xDEBA5049 = 0x5FCD8771 —— 旧模型把 elementTypeIndex 的哨兵值当 tag 混进去了。

### 28.3 统计验证（7.1.0 全量 78,000 行）

    interface 率 0.0181（6.4 参考 0.0174）  abstract 0.0890  sealed 0.5052
    public 0.7903  IsValueType 0.1464（参考约 0.128，7.1 类型更多）  IsEnum 0.0916（参考 0.085）
    逐行：row0 <Module> flags=0 正确；row2 SR=abstract|sealed 正确；
    row4 Mono.RuntimeClassHandle=sealed|vt 正确（§25 已校准 rows 0–4 真实身份，逐行全对）。

### 28.4 新表

| 表 | 槽/解码 | 结构 |
|---|---|---|
| typeDef 附表 | hdr[0x198]^0x5303F399 | u32×typeDefIndex（r13，配合 r8 表 → klass+0xB6）|
| 泛型容器 | hdr[0x20]−0x5A2DBA9E（即 +0xA5D24562）| 8B 行 {u32 typeDefIdx, u16@4, u16@6, u8@+7 再 +0xEA}，按 typeDefIdx 有序可二分；行数 = (hdr[0x1E8]>>3)^0x074314EC |

### 28.5 NoVmp 状态

- NoVmp-pub（10月12日构建）对 0x19f63c4d 正确拒绝（非 vmenter）；对已知成功目标 0x19f64842
  的健康检查结果见对话记录。管线可用；87 个真 VM 入口仍需它（token/属性等可能还藏在其中）。
- 自动发现模式还报出 .upx0 内部的额外入口（0x159e5bb34/0x159e5c314/0x159e5c68c/0x159e5d98c/
  0x159e5dea4/0x157ece3a0），不在 91 清单内 —— 后续覆盖率工作的候选。

### 28.6 对主线（Il2CppDumper 对齐）的意义

P0 缺口（type_kind 全错：42,484 假接口）的修复条件已齐：flags+bitfield 列可直接接入
layout71/dump71；Il2CppDumper 渲染规则（Il2CppDecompiler.cs:62–106）可直接套用。


### 28.7 flags/bitfield 已接入 Rust 端（2026-10-15 补）

profile 新增 td_flags/td_bitfield（Option<Column>，serde default 兼容旧 JSON）；
engine 新增 td_flags()/td_bitfield()；dump71 type_kind 重写为 Il2CppDumper
规则（interface->enum->struct->class，flags 缺失时回落父链推断），
新增 type_modifiers（else-if 链，static 吞并 abstract+sealed），
方法行改为 oracle 单行格式 + Token（非构造顺序 0x06000001..，构造 0x00000000，
与 6.5Dump.cs Locale/SR 三行逐位对齐），Constructors 段拆分，Properties 空段诚实占位。

实测 7.1.0：interface 42,484->1,580（期望~1,550）、enum 8,123、struct 4,797、
class 74,372（期望~74,150）；行 0-4 与 oracle 逐字一致；回归 17 passed / 0 failed。
剩余差距清单见 docs/re/gap-inventory.md（10 项，含解锁路径）。


### 28.8 dump71 更名 dump-gen（R9，2026-10-15）

用户指令：71 是 7.1 专属命名，版本通用化后要去掉。已执行：
src/dump71.rs -> src/dump_gen.rs；CLI Dump71 -> DumpGen（clap name=dump-gen，alias=dump71 过渡）；
README 命令表更新；REQUIREMENTS 新增 R9（含「最小支持版本须实测确立后才入命名」的约束）。
回归 17 passed / 0 failed；dump-gen 与 alias dump71 均验证可用。


## 29. 6.7.0 相邻版本 profile 推导（R9 第一个实测版本）

> 不是需求，是执行记录。目标：验证「相邻版本快速梳理 → profile → dump-gen」管线，为最小支持版本的确立积累实测。

### 29.1 自动层（复用现有工具，零改码）

- `mhydump cipher`（6.7.0）：M1=0xAA160EA68AC8FA68 X1=0x24832E3F77AF01E6 X2=0x7AC9A2F2697FEB99
  step=0x3FF74ECE11DFA612 strsec=0x4126798 site=0x1404BB517 score=15119；堆[0]=mscorlib ✓。
- `mhydump anchors`（6.7.0）：354 锚点；typeDef 槽 0x1E0 ^0x4E66A4F6 stride 70（tables_from_code 直接给出）。
- triage out/6.7.0.json 互证：base=0x21F77B0（49 站点多数判据）。

### 29.2 数据驱动层（本轮新工具）

写 colsolve2（numpy 非对齐滑动堆解密 + 行 0 明文）→ colsolve4（全自动列求解）→ colverify（全表验证）。
6.7.0 结果（详见 version-matrix.md §6）：name/flags/fieldStart/fieldCount/parent 五列定案，
fs/fc 链 60000/60000 零坏行；ns/methodStart/methodCount/elementType/bitfield 静态形态无解，疑似行级掩码。

### 29.3 过程中的负结果（省后续时间）

- 8 对齐堆扫描找不到 <Module>（在 0x14）——堆无对齐无终止符紧打包。
- 「7.1 布局 + 常数轮换」假设证伪：6.7.0 列位置重排（name 0x14→0x18 等）。
- 6.7.0 Mono 类型名无前缀（Runtime 非 Mono.Runtime）——7.1 锚点表不可跨版硬套。
- colscan/densescan v1/v2 在变异码上漏事件：单向变换假设 + 线性扫描失步。v3 双向+4KB 重同步后
  用 7.1 已知常数校准通过（name@0x159f64158、flags@0x159f6435b 双中）。
- 0x38 列 bitfield/fieldCount 判据冲突：加「值≤7 占 99%」后 bitfield 无候选、fieldCount 定案（max 859）。

### 29.4 下一步

1. 读 6.7.0 变异码里的行级掩码链（builder 区 ~0x157fb9000，r15 行指针；densescan3 事件已定位 6 个列站点）。
2. 解 ns/methodStart/Count/elementType/bitfield → 完整 typeDef profile。
3. 方法表（stride 0x1A?）+ 字段表 + 参数表常数。
4. 组 profile JSON → `mhydump dump-gen --profile-in` 端到端 6.7.0 dump。

## 30. R10 模块划分落地：derive 分析提取命令（2026-10-17）

> 不是需求，是执行记录。需求见 REQUIREMENTS.md R10。

### 30.1 需求映射

- 分析提取模块 = 新命令 `mhydump derive`（cipher + 锚点 + 表基址一次性导出 JSON 工件，内置
  mscorlib 自检，失败拒绝导出）。
- 解包模块 = 既有 `dump-gen --profile-in`（只读导出数据）。
- 一次性做完 = `dump-gen --profile-out`（同场导出+解包）；7.1 实测：export → profile-in 解包
  两次输出 `cmp` 逐字节一致（78,750,080 B dump.cs，88,872 类型）。
- 唯一接口 = 数据文件（derive 工件 + profile JSON），代码不携带版本常数（R24）。

### 30.2 实测（2026-10-17）

- 6.7.0：354 锚点、cipher strsec=0x4126798 score=15119、typeDef 槽 0x1E0 ^0x4E66A4F6 stride 70、
  heap0=mscorlib ✓（与 10-16 的 cipher/anchors 独立运行逐位一致）。
- 7.1.0：326 锚点、strsec=0x3C58E68、typeDef 槽 0xDC ^0x5278CA3B stride 70（与 §28 已知值一致）、
  heap0=mscorlib ✓。
- cargo test --release：17 passed / 0 failed（基线不变）。

### 30.3 缺口（到 R10 完整达成还差什么）

1. derive 工件目前只含「机器层」（密码/锚点/表基址）；列常数层（name/flags/starts/counts…）
   还在 Python 工具链（colsolve4），且 6.7.0 只解出 5/9 列（ns/starts/elementType/bitfield 疑行级掩码）。
2. 工件格式与 Profile JSON 尚未统一（R10.3 已标注「未明确」）；列层并入后应收敛为单一格式，
   使 `derive --out p.json && dump-gen --profile-in p.json` 对任何版本成立。
3. 掩码链推导自动化（变异码读取）是列层补全的关键路径。

## 31. derive 分析层 26 版全量实测（2026-10-17）

> 不是需求，是执行记录。回答「未来版本能力」问题的证据基础。

### 31.1 方法与结果

对 ~/gire/sample/gi 全部 26 版逐一跑 `mhydump derive`（-P3，150s/版超时）：

- 成功 20 版：4.8.0 5.0.0 5.1.0 5.2.0 5.3.0 5.4.0 5.5.0 5.6.0 5.7.0 5.8.0 6.0.0 6.1.0 6.2.0
  6.3.0 6.4.0 6.5.0 6.6.0 6.7.0 7.0.0 7.1.0（每版：cipher 导出 + 锚点 291–485 个 + 表列表 + heap0=mscorlib 自检通过）。
- 失败 6 版：4.2.0–4.7.0（exit=1，另一纪元形态）。

交叉验证：6.x 八版 + 7.1.0 的 typeDef 常数与历史独立推导逐位一致（详表见 version-matrix §7）。

### 31.2 对「未来版本能力」的结论（用于对外表述）

- 机器层（字符串解密 + 表定位）：当前世代（4.8.0+）**20/20 零改代码实证**；4.2–4.7 世代失败（已知缺口）。
- 列层/profile 层：**未自动化到可宣称「未来版本一定能 dump」**——仅 7.1.0 有完整 profile；
  6.7.0 相邻版 5/9 列。端到端 dump 能力 = 1/26 版本（但 6.7.0 收尾中）。
- 设计保证（一定能兑现）：常数零硬编码、解不出显式报错（mscorlib 自检 / cipher cross-check）、
  profile 跨版本误用被拦截。

## 33. 单版本全量优先（R11）第一轮：方法/类型表截断修复（2026-10-17）

> 不是需求，是执行记录。需求见 REQUIREMENTS.md R11。

### 33.1 发现经过

按 R11 先做 7.1.0 的差距清单 #5（方法 Slot）时，对比 oracle 6.4 的 Slot 分布（211,652 非零）
发现我们只有 1,833，继续追查发现更严重的问题：**方法表被截断 37%**。

### 33.2 两个计数 bug（都是「行数来源取错」，不是提取难度）

1. `md_count()` = min(body 剩余/stride, 方法指针数组长度=460,282)。方法指针数组只覆盖有直接
   代码指针的方法；真值 = 方法表大小槽 hdr[0x134]+0x8EEFDB56 = 19,070,516 ÷0x1A = 733,481。
   数据级验证：行 733,000 解出 decl=88,855 name='get_container'；行 733,480 后为垃圾。
2. `td_walk()` 链式铺瓦在 88,872 行提前停止；真值 = 类型表大小槽 hdr[0x60]^0x15335474 =
   6,223,280 ÷0x46 = 88,904（尾部 2 行全哨兵）。实测尾部 30 行为真实类型（MonoCrucibleEndPage 等）。
3. 附带：`if td.name.is_empty() { continue; }` 静默跳过 30 个无名类型；oracle 6.4 保留
   `public abstract class  : Object`，已对齐（不再跳过）。

### 33.3 修复（profile 驱动，无硬编码）

- profile.rs：`TableBase` 增加 `add` 变换；Profile 增加 `td_size`/`md_size`（**大小槽**，rows=size/stride）。
- layout71：`td_size = hdr[0x60]^0x15335474`，`md_size = hdr[0x134]+0x8EEFDB56`。
- engine：load() 解析 md_rows/td_rows；`md_count()` 直接用 md_rows；`td_count()` 用大小槽 +
  尾部全哨兵裁剪（无名+无方法+无字段），旧 magic 列为 fallback。
- dump_gen：collect 用 td_count()；去掉空名跳过。

### 33.4 结果（7.1.0 dump-gen 实测）

| | 修复前 | 修复后 |
|---|---|---|
| 类型 | 88,872 | **88,902**（索引 0–88,901 无缺口）|
| 字段 | 440,061 | **440,172** |
| 方法 | 460,282 | **733,442**（+273,160，+59%）|
| 参数（连带）| 361,974 | 548,097 |
| Token 行 | 460,282 | 733,442 |
| 回归 | — | 17 passed / 0 failed |

剩余 39 行方法（733,481-733,442）decl 指向 ≥88,902 的不存在类型，属表尾填充，未输出。

### 33.5 待办（R11 后续）

1. 方法 Slot 公式仍未解：`(raw^0x1E2A^pmask)` 给 99.6% -1；`(raw^0x1E2A)-mask2` 给 1,833 个值
   各一次（疑似掩码泄漏）。需要从 .upx0 方法构建器读真实公式。
2. 字段偏移（#1）：已排除——不是明文连续数组（.rdata 无 1.76MB 小 int32 长跑），静态注册结构里
   相关成员是 BSS 指针（运行时填充）。下一步：追类初始化代码写入 FieldInfo 的路径。
3. 其余 8 项按 gap-inventory 顺序推进。

## 34. R11 单版本全量：逆向进展（Slot 验证 / 参数表 / 特性表）（2026-10-17）

> 不是需求，是执行记录。方法：对 .text 里的槽常数做字节定位 → capstone 反汇编窗口 → 读真实变换。

### 34.1 方法行构建器定位（关键）

掩码链常数（0x4E94/0x62D8B7B8/0x7572748A/0x1F4D9EEA/0x6E8931D6/0xC6FC9C8B/0x39036375）
在 .text 有 6–21 个站点；首个完整构建器 @ **0x1405155FC..0x1405157xx**（方法行 → 内部结构）。

实测语义（逐指令）：
- md_base = hdr[0x1E0] ^ 0x2EE480FB + body（一致）
- 行偏移 rdi = 26×i（lea 链确认）
- **slot**：`movzx ecx,[row+0xC]; xor ecx,0x1E2A; sub ecx,r8d; movsx edx,cx`，
  其中 r8 = mask2 = chain(i)×0x39036375 → **与引擎 XorCSubMask2I16 逐句一致**；gap #5 的「1,833 个值各一次」
  来自二进制本身（GI 7.1 元数据确实几乎无 vtable slot），不是解码 bug。
- **paramCount**：`movzx edx,[row+0x12]; sub edx,r8d; add edx,0xFFFF8D97; [out+0x28]=dx`；
  但 +0x18 u8 方向才是引擎用的：**逐行验证已知签名**（Locale..ctor=0、GetText(msg)=1、
  GetText(fmt,args)=2、SR.Format=2、Mono.Runtime..ctor=0）→ u8@0x18 变换正确，paramCount 无需改。

### 34.2 参数「特性/键值表」定位（gap #6 相关）

- 全文本唯一引用 hdr[0x1D0] 的代码：**0x1405287A0**（参数信息访问器，唯一调用者 0x14052ADB0）。
- 表：hdr[0x1D0]^0x07D0BBF9，行 12B `{key@0(明文), typeIdx@4(i32,-1=null), dataOff@8(i32,-1=null)}`，
  行数 =(hdr[0x18]+0xA1C835BE)/12 = **25,374**（稀疏，key∈[4868,548372]）。
- key 计算（反汇编确认）：`(raw@方法行+0x08 ^ 0x20D55D01) + pmask(i)×0xC6FC9C8B + [paramInfo+0x10]`。
- dataOff 指向 hdr[0x128]^0x371354A2 的 **u32 数据区**（实测是 0,1,2,3,4 序列表，不是字符串堆）
  ⇒ 该表不是「参数名表」，更像参数上的特性数据（gap #6）。

### 34.3 对 gap #2（参数名/类型）的结论

- 已知事实：hdr[0x1D0] 全文本仅一个代码引用（keyed 查找），没有顺序遍历 → 它不是全参数表。
- 参数名/类型全表（548,097 行）**尚未定位**；三种可能：MHY 在 dat 里换槽存放 / 按 image 存放 /
  只在 .upx0 类初始化时生成。下一步：追「方法行构建器」的输出结构被谁消费（MethodInfo 参数填充）。
- 已排除：参数名不在主字符串堆的 8 对齐位置（名字串解析验证过）；也不在 hdr[0x128] 区（u32 表）。

### 34.4 本轮未做但已标记

- gap #5 Slot：结论「实现忠实」→ 从缺陷清单移到「已验证」；oracle 差异记录为 oracle 侧语义。
- gap #6 attributes：疑似表已定位（34.2），下一轮做数据/结构验证后接线。

## 35. R11 单版本全量第二轮：字段偏移/接口数/参数特性的逆向结论（2026-10-17）

> 不是需求，是执行记录。全部结论来自反汇编 + 数据对账。

### 35.1 字段偏移（gap #1）：不在字段定义行里（新负结果）

字段行构建器 @0x1405162A9 逐指令读出（10B 行）：
- +0..3 name：`(raw + 0xEE8895EA) ^ fd_mask(i)` → 名字表
- +4..5 type：`(u16 + 0xFFFFDC71) ^ mask` → typearr 索引 → typearr[i] ^ 0x30EA9C9D1A323195
- +6..7 attrs（已知）
- +8..9：`(u16 ^ mask_low16 ^ 0x0DB1)` → 又一个 **Il2CppType 索引**（^-1=无），typearr[i] ^ 0x62DC8A0B7235EC6A

⇒ 字段定义行只有 3 个类型引用 + 名字 + attrs，**没有偏移列**。与 34.1 的「静态注册成员是 BSS 指针」
合并结论：GI 7.1 的磁盘元数据**不携带字段偏移**（运行时由类初始化生成 FieldInfo.offset）。
oracle 6.4 的 `// 0x10` 属 oracle 侧来源（很可能来自内存/注册数组的运行时版本），静态 dat 无法直接取。
可选替代：按类型布局自行计算 + 与 oracle 抽样互证（未开始，风险：继承/对齐细节）。

### 35.2 接口数（gap #4）：无独立静态列（负结果）

用 iface_start（u16@0x3A ^ 0x4BCE）的去重差值作为「期望计数」基准（41,793 行 >0，总和 109,607），
对 typeDef 行全部 u16 偏移 × {xor, add} + u32 × xor 共 70+ 候选做反解：**>90% 命中为零**。
⇒ 接口数不是独立列（或使用行级掩码）。当前 run-length 近似（41,789 类型）暂无更优替代。

### 35.3 参数特性表（gap #6）：行结构 + 值读取路径确认

- 12B 行 {key, typeIdx, valOff}，25,374 行（key 稀疏覆盖 4868..548372）。
- 访问器 0x1405287A0 之后：**0x1404C7D57** 处 `body + (hdr[0x128]^0x371354A2) + valOff`，
  然后按 Il2CppType 类型分派读取值（字符串/整数…）→ 确认 valOff 指向**特性值**（非名字）。
- 该表 = 参数上的自定义特性数据（每参数一条、稀疏）。下一轮可接线到 #[Attribute] 输出。

### 35.4 对 gap #2 的强化结论

参数名/类型全表在 7.1 元数据中**大概率被剥离**：运行时可见的 params 表只有 25,374 行（hdr[0x18] 大小槽），
而 paramCount 总和 548,097。结合 35.1/35.3，MHY 7.1 的反射信息只保留稀疏子集。
【待验证】6.4 oracle 的完整参数名若来自内存 dump，则静态工具无法复现，需在文档中降级该项期望。

## 36. R11 第三轮：希望评估（范围修正 + 新判读）（2026-10-17）

> 不是需求，是执行记录。目的：把「不能静态 / 目前不能」分清，纠正前两轮的过强表述。

### 36.1 il2cpp 段（321MB）负结果（新扫）

分段统计（numpy）：int32 小值（<0x20000）占 7.6%，但**没有任何 ≥8 连续小 int32 段**；
qword 指向镜像的指针段 ≥32 也没有 ⇒ il2cpp 段是纯代码/少量零散数据，
**不含 fieldOffsets 这类静态数组**。

### 36.2 字段偏移：范围修正

- 已证伪：字段定义行（10B）、.rdata/.data 明文数组、il2cpp 段静态数组。
- 未探索：运行时**计算**路径（.upx0 类构建器内的字段布局累加）——若 GI 在类初始化时算偏移，
  可读码复刻或用 Unicorn 模拟执行同一个函数。
- 次选：按 IL2CPP 布局规则自行计算 + 与 6.4 oracle 同类型抽样互证（oracle 有 `// 0x10` 注释）。
- 判定：**目前不能，但有希望**（两条可执行路径）。

### 36.3 参数 25,374 行稀疏表：判读修正（重要）

复核 35.3：访问器之后按 Il2CppType 类型分派读取值（0x1404C7D57：string→指针、整数→u32…），
这是 **Il2CppParameterDefaultValue 的读取模式**（{key, typeIndex, dataIndex}，按类型解码默认值），
而不是「参数特性」。
⇒ 该表 = **有默认值的参数表**（25,374 条），对应 gap #7 的参数侧；
   field 默认值（枚举字面值）应有同构表（key=field 表索引），可同法定位。
⇒ 「参数名/类型被剥离」的证据仍然成立（运行时可见表只有默认值表，没有全参数表）。

### 36.4 iface 表基址可疑（新发现）

hdr[0x70] 解析出的 iface 表（profile iface_base=0x973064, stride 6）条目 typeIdx 出现 246106/439029
（> 类型总数 88902）⇒ 基址或 stride 误判，当前接口列表数据不可信。
判定：**可修**——用数据形态重定位（连续行 u32<88902 的 stride-6 表），并用父链过滤继承项即可精确化。

### 36.5 结论表（供用户判断）

| 项 | 已证伪范围 | 未探索空间 | 判定 | 希望 |
|---|---|---|---|---|
| 字段偏移 | 字段行/明文数组/il2cpp 段 | 运行时计算路径、加密数组 | 目前不能 | 中（两条路径） |
| 接口数/列表 | 静态列 70+ 形态 | iface 表重定位+父链过滤 | 目前不能（数据可疑） | 高 |
| 参数名/类型 | 运行时表仅默认值表 | 6.4/7.1 dat 对照 | 疑版本剥离 | 低 |
| 默认值（参数/字段） | 参数侧已定位 | 字段侧同构表 | 进行中 | 高 |
| stringLiterals | 未开始 | 字面量表/堆 | 未知 | 中 |

## 37. R11 第四轮探索：接口表三种假设全负 + 字段偏移布局验证（2026-10-17）

### 37.1 接口表定位（gap #4）：三种假设全负

1. **typeDef 索引 + stride 6**：接口集合（flags u32@0x0C+0xDFA09F90 & 0x20 = 1,580 个）作过滤器，
   全 body 扫描连续 4 行命中：**0 处**。
2. **typearr 索引 + stride 6/8/4**：先构造接口的 typearr 索引集合——发现 typearr 中
   kind==0x11 的条目共 45,695 个，但 data 落在接口 td 集合的为 **0**（说明 typearr 的 data 语义
   与 engine 注释（data=tdi）在接口上不成立，或接口用了其他 kind）。
3. 也排除了 stride 4/8 的同类形态。

⇒ 接口表**不在 body 中表现为简单索引数组**（可能：加密/变换、或接口数据在未识别的槽、或从别处派生）。
当前 run-length 近似（41,789 类型）仍是唯一可用数据。**开放项**。

### 37.2 字段偏移：oracle 布局复算验证（新数据）

用 6.4 oracle（76,994 类型、318,663 字段全部带 `// 0x…`）反算布局：

- 规则：类/结构体起始 0x10（boxed 布局，oracle 实测连 struct 也从 0x10 起）；
  原始类型尺寸表；字段按尺寸对齐；派生类起始=父类实例末尾。
- 结果：**全长 37.8%**（21,931/57,959）；**仅实例字段 46.2%**（24,609/53,231）。
- 关键发现：**oracle 偏移包含静态字段**（如 ContractionComparer.Instance=2944、
  MSCompatUnicodeTable.isReady=912）——这是**模块级静态存储区偏移**，由 AOT 编译器全局排布，
  **不可能由类型布局推导**。
- 剩余实例字段不匹配主因（样例）：继承链起始、结构体尺寸（含数组/泛型值类型）、字段对齐细节。

⇒ 结论：字段偏移**部分可计算**（实例字段方向对但精度不足 46%）；静态字段偏移静态不可得。
与「7.1 元数据不带偏移表」合并：gap #1 的完整闭合需要读 .upx0 运行时计算路径或接受实例字段近似。

### 37.3 后续可尝试

1. 接口：检查未识别槽（0x118 大表/0x198 等）是否含 {typeIdx, off} 变体；或从 typeDef 行+父链派生。
2. 字段偏移：把 46% 提到 >95% 需要精确对齐规则（用 oracle 失配样本迭代），或读 .upx0 的布局代码。
3. 参数/默认值：参数默认值表已定位（25,374），字段默认值（枚举值）同构表可按同一访问器模式找。

## 38. R11 第五轮：字段偏移布局复算 46% → 核心 97.9%（2026-10-17）

> 不是需求，是执行记录。方法：用 6.4 oracle 作 ground truth，迭代布局规则。

### 38.1 迭代记录（instance fields）

| 轮次 | 规则修正 | 匹配率 |
|---|---|---|
| 1 | 类 0x10 起、父=0x10、原始尺寸 | 37.8%（全长）/ 46.2%（实例）|
| 2 | 父类名唯一后缀解析 | 69.2% |
| 3 | 结构体也 0x10 起（boxed） | 63.3% ↓ |
| 4 | **值类型内嵌用 unboxed 尺寸（end−0x10）** | 82.3% |
| 5 | 派生类起点 8 对齐 + 泛型父类跳过 + 健壮字段解析 | 83.2% |
| 6 | **按根因拆分：Object 根类+结构体（无继承噪声）** | **97.9%**（19,873/20,289）|

### 38.2 关键结论

1. **布局规则正确**：核心场景（无继承或 Object 根 + 结构体）97.9% 精确匹配 oracle 偏移。
   剩余 416 个失配 = **显式布局结构体**（`[StructLayout(LayoutKind.Explicit)]`：MonoAssemblyName、
   System.Variant、ConsoleScreenBufferInfo、PaddedHeadAndTail 等，偏移由字段特性指定，无法从类型结构推出）。
2. **值类型偏移是 boxed 语义**（含 0x10 头）；内嵌到别的类型时占 **unboxed 尺寸**（end−0x10）。
   例：Vector3 字段 0x10/0x14/0x18，内嵌尺寸 12。
3. **oracle 的 extends 渲染不可靠**（嵌套类型父类名渲染成 Object 等）→ 之前 83% 的「start」类失配
   大部分是 oracle 噪声，不是算法错。7.1 侧要用我们自己的 parent_tarr（元数据父链）计算，更可靠。
4. 96.5% 的字段类型可解析出尺寸；泛型定义（TypeDef 名含 '<'）无法验证（跳过 3,734 类型）。

### 38.3 7.1 落地计划（下一轮）

在 dump_gen 内实现 Rust 布局计算：
1. 输入：tds 的 parent（已有 parent_tarr）、fields（fs/fc + fd_type → il2cpp_type → 类型名/尺寸）；
2. 递归算布局（memo + 环检测），类起点 = 父布局末尾 8 对齐；结构体 0x10 起；
3. 输出：字段偏移注释（Il2CppDumper 风格 `// 0x10`）+ 显式布局不可靠计数 warn（诚实标注）；
4. 抽样互证：与 6.4 oracle 的同类同名字段比对（7.1 类型多，可覆盖大量共享名）。

## 39. R11 第六轮：字段偏移接线进 dump（2026-10-17）

> 不是需求，是执行记录。

### 39.1 实现

- dump_gen.rs 新增 `LayoutCalc`：顺序布局复算（值类型 boxed 0x10 起、内嵌 unboxed 尺寸、
  派生类起点=父末尾 8 对齐、字段按声明序自然对齐、memo+环检测）。
- **显式布局检测**：`flags & 0x18 == 0x10`（TypeAttributes.LayoutMask=Explicit）→ 该类型字段
  全部不输出偏移（[FieldOffset] 特性决定的偏移不可由结构推）。
- 字段输出格式：`private static readonly UnityEngine.Vector3 foo; // 0x10`（Il2CppDumper 风格）。
- 静态字段不输出偏移（模块级静态区偏移不可推导），计数 warn。
- 字段修饰符源核对：与 6.4 oracle 抽样 89,287 字段 → **99.91% 一致**（差异为版本真实变化）。

### 39.2 7.1.0 实测

`wrote 88,902 types, 440,172 fields, 733,442 methods`：
- 偏移已计算：**321,796** 字段（73%）
- 未解：9,162（显式布局/尺寸不可推）
- 静态字段无偏移：109,214（不可推导）

### 39.3 交叉验证（7.1 计算值 vs 6.4 oracle）

仅比「类型字段集合与字段类型均相同」的 (type, field) 对：**33,898/36,562 = 92.71%**。
失配样例（System.Xml.Schema.XmlSchema 等）疑为父链版本差异或个别尺寸误算，待进一步分析。

### 39.4 后续

1. 92.71% → 目标 >97%：分析失配簇（父链/泛型/显式布局漏检）。
2. 参数默认值接线（25,374 条已定位）。
3. Properties/Events 槽位、stringLiterals、script.json ScriptString/Addresses/Signature。

## 40. R11 第七轮：GENERICINST 渲染缺口定位（2026-10-17）

> 不是需求，是执行记录。目标：补齐「泛型类型渲染」——此前未列入差距清单的大缺口。

### 40.1 缺口量化

- 我们 dump 中字段类型渲染为裸 `object` 的：**42,313 个**；
- 与 6.4 oracle 共享的 89,275 字段里，oracle 泛型类型 5,017 个，我们渲染成 object 的 4,517 个
  （≈90% 的泛型类型丢失）；
- 影响面：字段类型、方法返回/参数、基类、接口列表。

### 40.2 运行时解析路径（反汇编确认）

- GENERICINST（kind 0x15）的 Il2CppType.data = **32B Il2CppGenericClass 表的索引**；
  代码：`140525362 movzx eax,[rsi+0xa]; shl eax,0x10; cmp eax,0x150000;` 命中后：
  `mov rax,[G+8]; rcx=data; shl rcx,5; mov rsi,[rax+rcx+8]` → class_inst（{argc@0, argv@8}）；
  另一路径 0x140525095 同构，并读 entry+0x10（method_inst）。
- entry 布局 = 标准 Il2CppGenericClass：+0 type*、+8 class_inst*、+0x10 method_inst*、+0x18 klass*。
- **表基址 [G+8] 的全局 G=0x145AD5E98 在 .data BSS（运行时初始化）**：静态反查 .rdata/.data 找不到
  32B 静态表（结构扫描 0 命中）⇒ 表由加载器在启动时从元数据构建。
- 0x188 表（12B 行）实测内容 = {f0:0/16/-1, f1:-1/0, f2:769+行号递增} —— **不是** 泛型类表，
  其语义仍待定（原 doc 的「泛型实例表」标注需修正）。

### 40.3 结论与下一步

- 泛型渲染需要：定位加载器构建 32B 泛型类表的输入表（候选：0x118 大表 8B 行、typearr 相邻区）；
  或改从 typearr 的 GENERICINST entry + 某输入表重建。
- 已确认 0x118 首行 {0x02000059, 0x01000000} 递增模式，符合「(打包类|索引) 双字段表」，下一轮验证。

## 41. R11 第八轮：泛型表构建机制（加载器追踪）（2026-10-17）

> 不是需求，是执行记录。

### 41.1 写入点

BSS 全局 0x145AD5E98（泛型解析路径的 G）唯一写入点 = **0x140535FA6**，位于加载器
FUN_1405359e0（§2 的启动序列）。其模式（0x140535E9B..0x140535FA6 连续多段同构）：

1. `mov rax,[header_global]; eax = hdr[slot]`（slot 依次 +8/+0xC/+0x10/+0x14…）
2. size = hdr[slot] << 20（非零时），否则用固定值（0x15E00000/0xF00000/0x1E00000…）
3. src = 某个 BSS 段基址全局（带指针 tag 检查 0xfffffaff00000000/1）
4. `dest = alloc(0x30); call 0x140500180(dest, src, size*2, 0)` → 结果存入 BSS 全局

⇒ 泛型类表（[G+8]）是**加载器在启动时从 hdr 描述的区域构建**的运行时结构（0x30B 描述符），
不在 .rdata 静态区；这与 40.2 的结构扫描 0 命中一致。

### 41.2 待确认（下一轮）

1. 0x140500180 的函数语义（memcpy？解密？是否是「从 dat 复制并解密」）——决定输入表能否静态提取；
2. 48B 描述符结构布局（哪些字段是 count/ptr）；
3. 30MB 区域（hdr[0xC]<<20）与 hdr[0x8]/0x10/0x14 区域各是什么表（可能是类型数组副本/泛型类/泛型实例等）。

## 42. R11 第九轮：枚举字面值/字段默认值解出并接线（gap #7 关闭）（2026-10-17）

### 42.1 表与解码（反汇编 0x1404C7C00）

- **字段默认值表**：base = `hdr[0x164] ^ 0x03893506`，**12B 行 {valueOffset@0, fieldIndex@4, typeIndex@8}**，
  行数 = `(hdr[0x144] + 0xD1F800F2) / 12`（7.1.0: **75,548 行**）。
  查找方式 = 线性扫描比较 row.fieldIndex（构建器对每个字段做一次）。
- **值数据区**：`body + (hdr[0x128] ^ 0x371354A2) + valueOffset`，按值的 Il2CppType kind 解码：
  原始类型按 kind 尺寸直接读；**字符串 = {u32 长度, UTF-8 字节}**（实测 "True"/"False"/"ticks"）。
- 反汇编证据：0x1404C7C94 起 `sar rdi,5 → [klass+0x60] → xor 0x72628007 (fs) → +fieldIdx`，
  表基址/计数/行布局与上述一致；0x1404C7D57 值指针计算；0x1404C7D6B 按 kind 分派（2..0xc 原始类型）。

### 42.2 Rust 接线（dump_gen）

- profile 新增 `field_defaults / field_defaults_size / default_value_data`（layout71 已填）。
- engine：load 时构建 fieldIndex→(valueOff,typeIdx) 映射 + 值区基址；新增 `field_default()` /
  `default_value_bytes()`。
- dump_gen：const 字段渲染 ` = {literal}`（包含枚举成员、const 字符串/数值）。
  有符号规则对齐参考输出：**枚举成员按无符号**（4294967295/255/32768），**普通原始类型 const 按有符号**（-32768）。
  float/double 支持 ±Infinity/NaN 字面风格；char 输出 `'\uXXXX'`。

### 42.3 验证

- 7.1.0 实测：**74,614 个 const 字段全部渲染**，0 未解。
- 枚举字面值 vs 6.4 oracle：**9,582/9,598 = 99.83%**（失配均为 7.x 真实改值，如 InteractionType 数值右移）。
- 全部 const 值 vs oracle：99.26%（余差为浮点格式差异 9.99999975e-06f vs 0.00001f，数值等价）。
- 回归 17 passed / 0 failed。

### 42.4 状态

- gap #7 关闭。剩余：泛型渲染（#11，需加载器追踪）、参数名/类型（疑剥离）、Properties/Events、接口精确化、
  stringLiterals/script.json ScriptString、attributes。

## 43. R11 第十轮：未识别大表排查（参数表/属性表/泛型表）负结果与新线索（2026-10-17）

> 不是需求，是执行记录。目的是避免下轮重复研究。

### 43.1 已排查但未找到（负结果）

1. **参数定义表（Il2CppParameterDefinition {nameIdx, token, typeIdx}）**：
   - 用「12B 行 + 合法 typearr 索引 + 可解码名字」扫描 86 个已解表基址 × stride 8/12/16/20/24 → 0 命中；
   - 用全 body 向量化扫描「任一字段 = 合法 typearr 索引」的长游程（≥10 万行）→ 只有 0x13A73C0 区的 166k 行命中，
     但该区每 3 字出现 -1，且值不是我们 typearr 的索引空间（对已知 List<GameObject> 的 typearr 索引 0 命中）⇒ 不是参数表；
   - 结论：参数表（548,097 行）**不是**以「原始 type 索引」明文存放；名字/类型列可能整列变换，或该表在 7.1 被剥离。
     需要新证据源（如运行时 GetParameters 路径）才能定论，**目前不能断言已剥离**。
2. **Properties/Events 表**：用「两/三个字段为合法 method 索引（<733,442）」扫描 stride 16/20/24/28/32 → 长游程候选经检查
   均为 `{i32, i32, -1}` 三元组（见 43.2），不是属性/事件；名字列解不出（变换未知）。
3. **0x188 表**（原文档标「泛型实例表」）：实测行内容 `{f0:0/16/-1, f1:-1/0, f2:769+行号递增}` —— **不是**泛型类表；
   0x188 的用法（0x140001214）是「打包 (3bit kind|29bit idx) → typearr 索引 + 调用解析」，与 metadata usage 相关。

### 43.2 新识别的大表家族：`{i32, i32, -1}` 12B 三元组

- 位置（body 偏移）：0x122FA34（~474,887 行）、0x138CC78/0x138CC84（~156,279 行）、0x13A73C0（~166,000 行）。
- 结构：每条 12B = `{a, b, -1}`；a/b 均为 <733,442 的整数（部分落在 typearr 索引区间但**不是**我们的 typearr 索引空间）。
- 候选语义（未验证）：virtual/vtable 方法对（impl↔decl）、generic 方法实例参数对、接口实现对。
- 与 Il2CppDumper dump.cs/script.json 的直接数据项关系未知；若为 vtable 对，则不属于 dump.cs 数据项，优先级低。

### 43.3 其它线索

- **0x118 大表**（26 站点）：0x1404B2400 反汇编显示它是 **8B 行 {packedKey, value} 的二分查找表**：
  键 = 打包类型（`tag 0x2000000 | typeDefIndex`），查找后调用 0x140526AF0。疑似 metadata usage 映射表
  （对 script.json 的 ScriptMetadata/Addresses 有用，待验证）。行内容 = {(0x02000000+n), (0x01000000+m)} 递增。
- 大表空隙（与已解表互补）：0x122FA34+5.70MB、0x3633350+6.30MB、0x1F6A08C+4.39MB 等区段仍未归属；
  其中 0x3633350/0x1F6A08C 区「packed-name 形」比例 ~25%（可能是某种索引列，变换未知）。

### 43.4 下一步建议

1. 用**运行时路径**定参数表：找 `GetParameters`/ParameterInfo 代码，看它怎么读 param 表（槽位+列变换），比盲扫高效；
2. 0x118 表验证：用 Il2CppDumper 的 metadataUsage 语义对照（encodedSourceIndex 3-bit tag）；
3. 泛型渲染：继续按「加载器区域 → 32B 泛型类表」路线（§40–41）。

### 43.5 方法教训（重要，避免重复踩坑）

- 用「×12 寻址」反查槽位时，`[rsi+0x1c]` 这类**结构体字段偏移会被误判为 hdr 槽**：
  必须先确认基址寄存器来自 header 全局（`mov rX, [rip+header_global]`），再匹配 slot。
- 「合法 type 索引 / 合法 method 索引 / 可解码名字」这类单条件统计判据在 82MB 体上噪声大：
  0x122FA34 / 0x138CC78 / 0x13A73C0 三处 `{i32,i32,-1}` 表的值都 <733,442（方法索引空间），
  但对我们已知的 typearr 索引 0 命中 ⇒ **它们的索引空间与我们的 typearr 不同**。
- 定位大表应优先用「代码访问路径 + 槽位」；内容统计只作佐证。


## 44. R11 第十一轮：参数名/类型解出（gap #2 关闭）（2026-10-17）

### 44.1 定位方法（关键：边界约束 + 常数反查）

1. 把参数总数 548,400 当作行数约束，在「相邻已解表锚点差值」里找 `diff = 548,400 × stride`：
   命中 `0x1F6A08C → 0x239920C`，diff = `0x42F180` = **548,400 × 8** ⇒ 参数表（8B 行）。
2. 表基址常数：对全部 hdr 槽试 `raw ^ base / raw - base / base - raw`，得到槽 `0x68`、常数 `0x146BE503`；
   立即数在 .text 的命中点 `0x14052980E` 反汇编出访问器。
3. 访问器 0x1405297EE（运行时为每个方法构造参数信息）：
   - `mov eax,[rdi+8]; xor eax,0x20d55d01` → paramStart（rdi = 方法元数据行；后接 mask2 已在
decoded 结构里，实测公式 B 正确）
   - `esi = paramStart + k`；`r13 = body + (hdr[0x68]^0x146BE503)`；行 = `r13 + esi*8`
   - **mask(esi)** = `((((i*0x4A23)^0x5F268FCF)*0x2B0352A0)>>9 ^0x1028EA75 +0x68B376F1) ^0x4F86A723`
   - **name**：`(raw@+4 ^ 0x6B95F108) - mask` → 主串堆解码（cipher）
   - **type**：`(raw@+0 ^ 0x76621606) - mask`；`-1` = 无类型；否则 typearr 索引
4. 副产物修复：**byref 标志不在 kind 字节**，而在 Il2CppType flags 字节（+0xB）bit6；
   旧 type_name 把 `UnityEngine.Object` 也映射成 `object`（应按 (namespace,name) 精确匹配 System）。

### 44.2 接线与验证

- profile 新增 `param_defs(param_def_stride/name_xor/type_xor/param_def_mask)`；engine 新增
  `param_name(i)` / `param_type(i)` / `il2cpp_type_flags`；dump_gen `self_params` 改为
  `Type name` 形式，BYREF 渲染 `T&`（无 param flags 列，无法区分 ref/out，诚实省略前缀）。
- 7.1.0 实测：**全部方法签名带参数名+类型**（如 `GetText(string fmt, object[] args)`、
  `GetCurrentTextElementLen(string str, int index, int len, UnicodeCategory& ucCurrent, int& currentCharCount)`），
  不再有 "parameter names/types unresolved" 警告。
- vs 6.4 oracle（共享类型 14,445 / 方法 126,546）：**参数名 91.37%**（失配全是混淆名跨版本改名）；
  类型一致性 81.7%，失配构成：泛型 object 2,792（gap #11）、嵌套类型短名 1,490、混淆类型改名 1,857、
  比较器按 arity 配错重载 ≈5,377。
- 回归 17 passed / 0 failed。

### 44.3 经验

- 大表定位：「已知行数 × stride = 表边界差」比内容统计靠谱得多（本轮一次命中）。
- hdr 槽位 → 常数反查：把 `raw ^ target` 作为立即数在 .text 搜索，再校验指令边界（伪命中很多）。
- Il2CppType 的 byref/pinned 在 +0xB 的 bit6/bit7，kind 字节不含 byref。

## 45. R11 第十二轮：泛型表与嵌套关系的边界确认（2026-10-17）

> 不是需求，是执行记录。本轮主要是负结果 + 2 个正事实。

### 45.1 泛型类表：静态数据形态已排除

- 结构判据（强）：32B 行 `{type*, class_inst*, method_inst*, klass*}`，其中 class_inst = `{u32 argc∈1..8, u64 argv*→type 数组}`。
  在 **exe 全文件**扫描 → **0 命中**；在 dat body 也 0 命中（q0 指向 0x142E1FB30 起的 type 数组）。
- 唯一「q0→type 数组」的 32B 结构在 exe `.data` 0x54D9FC0，23,455 行，但四个 qword 全部指向 type 数组
  （q0 diff 多为 0x200/0x270），是 **type 指针缓存**，不是泛型类表。
- 结论：泛型类表**没有静态数据形态**（GI 反 dump 设计），必须走模拟执行/加载器深挖；
  它不是 0x188 表（§43 已证），也不是 `{i32,i32,-1}` 区（下）。

### 45.2 `{i32,i32,-1}` 密集区身份修正

- 区域：body 0x122FA34（~474k 行）、0x138CC78/84（~156k）、0x13A73C0（~166k）。
- 值空间 = **方法索引**（<733,442），对 typearr/tdi 索引空间 0 命中 ⇒ 不是泛型/接口数据。
  语义很可能是 **vtable/虚方法对**（impl↔decl），不属于 dump.cs/script.json 数据项，优先级降低。

### 45.3 嵌套类型父关系：不在 typeDef 行已测列

- 用 6.4 oracle 提取 **4,778 组 (nested tdi, parent tdi)** 真值；
- 对 typeDef 行所有未知 u32 列（0x04/0x10/0x20/0x24/0x28/0x34/0x38/0x3C/0x40/0x44）测试：
  原值、`^tag@0x1C`、以及 4 条已知掩码链（field/pmask/mask2/param）减法后再比 → **无常数关系**；
  对 u16 列也试过（tdi 88,902 超出 u16 范围，排除）。
- 结论：declaringTypeIndex 要么不在 typeDef 行（另有 nestedTypes 表且带未知变换），要么掩码链未知。
  嵌套类型全名渲染暂不可得（影响 ~1,490 处参数类型显示，仅显示差异不影响类型身份）。

### 45.4 正事实

1. **静态元数据注册 +0x50 = type 数组**：0x142871B68+0x50 = 0x142E1FB30，与 engine 定位的 typearr 完全一致（此前靠启发式定位，现有权威交叉验证）。
2. **byvalTypeIndex 列重确认**：typeDef 行 `u16@0x3E − 0x1398`（反汇编 0x140512990，比较 -1；
   实测 Selectable/Transition 均为 -1 ✓）。注：elementTypeIndex 是 0x1C 列（哨兵 0xDEBA5049，见 §7 文档）；
   parent 公式里把它当「tag」只是公式等价，列语义以本节为准。

### 45.5 方法教训

- 找「每项含 2-3 个指针的结构表」时，先构造**双字段联合判据**（如 argc+argv 双条件），比单字段命中率判据强得多。
- Il2CppDumper 的 script.json 生成代码不在 Perfare master 仓库（Program/Decompiler/Executor 均无 ScriptJson 引用，
  仅 ScriptJson.cs 定义 schema），无法从源码核对 Signature 格式 ⇒ **不猜格式**，暂不实现。

## 46. R11 第十三轮：嵌套类型全名 + dump.cs 头部格式对齐（2026-10-17）

> 不是需求，是执行记录。

### 46.1 嵌套类型关系（已关闭 gap 3b）

- 线索来自 `docs/re/metadata-loading-flow-7.1.0.md`：`0x36 u16 ^0xC87C = nestedTypesStart`、
  `0x45 u8 ^0xAB = nestedTypesCount`、`0x1B8 表 ^0x586ABAF1 = 嵌套类型 u32 索引表`。
- 验证：Selectable(tdi 3533) → nested start=795 count=2 → [3534 Transition, 3535 SelectionState] ✓ 与 oracle 完全一致。
- 实现：profile 增 `td_nested_start/td_nested_count/nested_types/nested_stride`；engine 增
  `td_nested_start/td_nested_count/nested_types_at`；dump_gen 构建 child→parent 映射。

### 46.2 dump.cs 头部格式对齐（按 Il2CppDumper 实际行为）

从 6.4 oracle 反推出规则，并与 Il2CppDumper 源码（Il2CppDecompiler.cs）核对：

| 元素 | 旧输出 | 新输出（对齐后）|
|---|---|---|
| 类型头名 | 短名（依赖 // Namespace 行）| **全限定**：`public class System.ObjectDisposedException`；嵌套类型带声明链 `UnityEngine.UI.Selectable.Transition` |
| 基类 | 全限定 `: System.InvalidOperationException` | **短名** `: InvalidOperationException`；直接继承 Object 显示 `: Object`；enum/struct/interface 不显示基类 |
| 接口 | `, X` 前缀拼接 | ` : a, b, c`；接口**全限定**；遇 System.Object 垃圾项即截断 |
| 枚举 extends | 打印继承接口 | 仍打印（见下——近似限制）|
| script.json 方法名 | namespace+name 手工拼接 | 同一 joined 全名逻辑（嵌套类型也正确）|

- 实测样例：
  `public class UnityEngine.UI.Selectable : UIBehaviour, UnityEngine.EventSystems.IMoveHandler, ...`
  `public enum UnityEngine.UI.GraphicRaycaster.BlockingObjects : ...`
  `public struct System.ValueTuple // TypeDefIndex: 108`

### 46.3 仍未解决（本轮确认）

- **接口 own-count 列**未定位：近似列表包含继承接口（enum 显示 System.Enum 的 IComparable/IFormattable/IConvertible，
  而 6.4 oracle 的 enum 不显示），说明 iface 表里是**全量接口集**，需要 per-type count 截断；
  且 `0x3A`（ifaceStart）列语义存疑（部分类型 span=0 导致丢接口，如 ValueTuple 无接口输出）。
- 嵌套关系的「反向」也需注意：`declaringTypeIndex` 列未找到（§45），但嵌套表已足够渲染全名。
- 泛型定义名仍是 `` `1 `` 形式（oracle 为 `<T1>`），需 genericParameters 表（未定位）——不猜命名。

### 46.4 验证

- 回归 17 passed / 0 failed；dump 88,902 类型 / 440,172 字段 / 733,442 方法；
- 参数类型一致性 83.2%（嵌套类型解析后提升），参数名 91.37% 不变。

## 47. R11 第十四轮：接口 own-count 列解出（接口列表精确化）（2026-10-17）

> 不是需求，是执行记录。

### 47.1 定位

- 数据驱动：候选小列测试「decoded_count ≤ 同起点 run 长度」约束，`u8@0x42 + 0xA2` 满足：
  **86,587/88,902 类型 count == run 长度**、sum(count)=108,758 ≈ 近似表总长 109,607、47,108 类型 count=0；
  703 处 count > 相邻起点差（原因是相邻类型共享同一起点——用 count 直接遍历即可，不再依赖 run 长度）。
- 语义确认：doc 早先的「0x42 +0xA2 →klass+0xC2 小列」就是 **interfacesCount**。
- 验证：Selectable 用 count=8 输出 8 个接口，与 6.4 oracle **完全一致**（旧近似多出 IPointerClickHandler/ISubmitHandler）。

### 47.2 实现

- profile：`td_iface_count_off=Some(0x42)`、`td_iface_count_add=0xA2`；engine `td_iface_count(i)`；
  dump_gen 优先用 count，缺失时才退回 next-start run 近似。
- 泛型接口（GENERICINST 0x15）暂不能渲染（gap #11）→ **跳过并计数**，不再输出 bogus `object`：
  7.1 实测 24,529 条泛型接口被跳过（如 IEquatable<T>）；warn 明示。
- 顺带修复：上一轮添加的「object 即截断」会把泛型接口当垃圾项截断，已改为仅对 kind 0x12=System.Object 截断。

### 47.3 验证

- 接口列表 vs 6.4 oracle（共享类型 20,189）：**严格全等 80.17%**；失配样例主要为
  7.1 元数据真实差异（enum/delegate 的 InterfaceImpl 在 7.1 有、6.4 无：ICloneable/IComparable/IFormattable/IConvertible）
  以及泛型接口被跳过。Selectable/ValueTuple/String 等关键类型与 oracle 一致。
- 接口近似警告从「41,793 类型近似」降为 0（全部走 count 列）。
- 回归 17 passed / 0 failed。

## 48. R11 第十五轮：全限定类型名 + Properties 合成（2026-10-17）

> 不是需求，是执行记录。

### 48.1 发现：我们的类型名格式与 Il2CppDumper 系统性不同

oracle 用**全限定 C# 名**（`System.Void`/`System.Int32`/`System.String`/`System.Object`），我们用关键字（`void`/`int`/`string`/`object`）。
对比 oracle/Il2CppDecompiler 源码后统一为：原始类型 → `System.*`，类/值类型 → 全限定（含嵌套链），数组 `System.Int32[]`，byref `System.Int32&`。
样例（与 oracle 逐字一致，仅 RVA 版本不同）：
`internal static System.String Format(System.String resourceFormat, System.Object p1)`

- 效果：参数类型 **精确一致率 88.54%**（此前 81.7% 含别名归一化）；剩余差异 = 泛型 3,488 + 混淆类型跨版本改名 + 比较器重载配对。

### 48.2 Properties：从访问器方法合成（元数据表仍未定位）

- 现象（oracle）：property 行 = `\t{mods}{type} {name} { get; private set; }`；我们此前输出空段 + 警告。
- 本轮实现**合成**：扫描类型方法 `get_X`/`set_X`（get: 0 参、set: 1 参），类型取真实签名（getter 返回/ setter 参数），
  setter 可见性与 getter 不同时输出 `{ get; private set; }` 形式；跳过 add_/remove_（事件）。
- 7.1 实测：**62,879 个属性 / 10,102 类型**（warn 明示 SYNTHESIZED）。
- 局限（已记录）：GI 的属性名与访问器方法名**独立混淆**（oracle 里大量属性没有同名 get_ 方法，如 `OOBFJPMGFKC { get; }`），
  所以合成只能覆盖未混淆库（~60k/96k，6.4 参考）；属性表本体仍未定位。

### 48.3 其它确认

- 类构建器反射信息填充函数 0x14010F560 读 typeDef row 的 +0x28/+0x3C/+0x24（写入结构 +0x1C/+0x20/+0x24）；
  raw@0x24 是「常量 0x31DEBE33 + 行号小扰动」的 tag 形态、raw@0x28 = 0x1B7226xx 形态 —— 均为掩码材料而非直接列值。
- 属性表候选按尺寸匹配（93,130×20 等）检查内容后均非 20B 属性行结构；属性表定位仍需运行时路径。

### 48.4 验证

- 回归 17 passed / 0 failed；dump 88,902 类型 / 440,172 字段 / 733,442 方法 / 59,734 属性行。

## 49. R11 第十六轮：方法修饰符精确对齐 + 泛型/静态偏移负结果（2026-10-17）

> 不是需求，是执行记录。

### 49.1 方法修饰符：72.69% → 96.75%

用 oracle 反推 flags→修饰符规则（从 120 种 (flags, mods) 真实配对拟合）：

- 可见性(0x7) → private/internal/protected/protected internal/public
- static(0x10) → static；abstract(0x400) → abstract
- 否则若 virtual(0x40)：
  - **private 方法不输出 virtual/override/sealed**（显式接口实现，oracle 只显示 private）
  - final(0x20) → `sealed override`；newslot(0x100) → `virtual`；否则 → `override`
- extern(0x2000) → extern（oracle 有 1,296 处使用）

旧实现用 0x80(hidebysig) 当 newslot 代理是错的。实测 sampled（2,500 共享类型、19,098 方法）：96.75% 全等。

### 49.2 泛型类表输入：更多负结果

- 「行 g 含 (def, arg) 表示」全表搜索（86 基址 × stride 4–32 × 每行位置）：对已知 List<GameObject>(g=3347) 的 def/arg 的 tdi 与 typearr 索引 **0 命中**；
- 「泛型定义 tdi 列」（711 个定义、distinct 200–3000）特征扫描：0 候选；
- 结论：泛型类表输入不是「按 g 索引、行内直接存 def/arg 索引」的简单表；仍需运行时代码路径/模拟执行。

### 49.3 静态字段偏移：**定论不可静态推导**

用 oracle 9,208 个含静态字段类型的「首个静态偏移 vs TypeDefIndex」检验：非递减仅 **50.2%**（恰随机）
⇒ 静态区分配是**运行时类初始化顺序**，不是元数据顺序。109,214 个静态字段的偏移无法从 dat 静态推导（此前只有定性结论，本轮给出量化证据）。

### 49.4 其它探测（未解）

- 候选表 `0x48DC8D8`：12,000 行、8B `{递增 tdi(11750..88901), 0x1A9x 打包值}`；
  与 oracle 属性类型集合相关性仅 0.075% ⇒ 非特性表；`0x1A9xFEEy` 按字符串打包索引解码为乱码（非主串堆 cipher）⇒ 身份未知。
- images/assemblies 表：按「列解码出 *.dll」扫描 86 基址 × stride 8–64 → 0 命中（表基址不在已解锚点内或列变换未知）。

### 49.5 验证

回归 17 passed / 0 failed；dump 88,902 类型 / 440,172 字段 / 733,442 方法。

## 50. R11 第十七轮：发现 startup-metadata.dat —— 附加表容器（2026-10-17）

> 不是需求，是执行记录。本轮为**结构性发现**，为剩余缺口（泛型/属性/事件/泛型参数）打开新路径。

### 50.1 事实

1. 游戏 Metadata 目录除 global-metadata.dat（82.7MB）外还有 **startup-metadata.dat（4,060,728 字节）**。
2. 加载器（0x14053617E 起）连续调用 0x140523F70（读文件）两次：
   - 第一个 → global-metadata；**body = 数据+0x210** 存全局；
   - 第二个 → startup-metadata；**数据指针存 BSS 全局 0x145AD62C8**。
   随后按 main-header 槽分配运行时缓存数组：`[reg+0x30]^0x28A0FA2D` = 683,568（typearr 数量）×8、
   `hdr[0x60]^0x15335474`/0x46 = 88,904 类型 ×8、`hdr[0x134]+0x8EEFDB56`/0x1A = 733,442 方法 ×8。
3. **startup-metadata 是附加表容器**：main-header 的若干槽是「startup 数据内偏移」（加载器把槽值 XOR/ADD 常数后加到 startup 指针上），
   记录按各自 stride/掩码解码。已知映射：

| main-hdr 槽 | 变换 | startup 偏移 | 表 |
|---|---|---|---|
| 0x84 | `^0x582F3633` | 0x35D5E8 | **images/assemblies 名表**：28B 记录，名字@+0x18，nameIdx = `(raw ^ 0x5E8998A9) − ((((i*0xBD1E70EB664)>>16)+0x724F4CCB) ^ 0x2BE02F3D)` |
| 0x2C | `+0xE412B6A9` | 0x43020 | 待解（也是 derive 锚点之一）|
| 0x6C | `+0xE028E1F0` | 0x3DE954 | 待解 |
| 0x78/0x15C/0x1A4/0x10/0x1C | 待解 | — | 加载器 0x140538DB9 附近使用 |

4. 验证（images 表）：解码得到 `mscorlib.dll`、`Mono.Security.dll`、`System.dll`、`System.Core.dll`、
   `System.Runtime.CompilerServices.Unsafe.dll`、`UnityEngine.CoreModule.dll`… 与 GI 程序集列表一致 ✓。

### 50.2 重要影响

- 之前 derive 的 87 个锚点里，**小偏移（<4MB）的锚点可能是 startup-metadata 偏移而非 global body 偏移**（两者数值相加方式相同，易混）。
  candidates：0x43020(slot 0x2C/0x8C)、0x3DE954(slot 0x6C)、0x35D5E8(slot 0x84)、0x113C0、0x31A118 等需重审语义。
- 因此之前「属性/事件表在 global body 找不到」可能是找错文件：**propertyDefs/eventDefs/genericParameters/genericContainers 很可能在 startup-metadata 里**（标准 il2cpp 这些表本来就在 metadata；GI 把它们拆到 startup 文件并加密）。
- 6.4 参考 dump 无 `// Image` 头部行（该 fork 未输出），images 表仅作分组辅助，低优先级。

### 50.3 下一步

1. 逐个解 startup 表的记录布局与字段掩码（方法：在加载器范围内每个 `startup_ptr + hdr[slot]` 使用点读循环体，提取 stride/字段变换/调用 decode 的位置）；
2. 优先找 propertyDefs/eventDefs/genericParameters/genericContainers 表（名字列能解出属性名/泛型参数名即确认）；
3. 若有泛型类/实例表 → 解决 gap #11。

## 51. R11 第十八轮：startup/global 表基址分辨 + 泛型实例数据链（2026-10-17）

> 不是需求，是执行记录。

### 51.1 重要纠正：同一个函数里混用两种基址

0x140538DB2 处的泛型构建循环里，**6 个槽分属两种基址**（之前笼统当成 startup 偏移是错的）：

| 槽 | 变换 | 基址 | 偏移 | 表 |
|---|---|---|---|---|
| 0x15C | `^0xA282EB` | **startup(B)** | 0x380DFC | 68,616 个 u32 = **kind 0x15 的 typearr 索引**（升序子集，实测 68,615 distinct）|
| 0x78 | `^0x70C36CAC` | **startup(B)** | 0x0 | 68,616 u32 索引（周期 7 模式，见 51.3）|
| 0x8C | `+0xD7BBE415` >>2 | — | — | 循环次数 = **68,616** |
| 0x1A4 | `^0xD8C5D0A` | **global body(A=0x145AD62C0)** | 0xCD026C | **12B 行** `{u32, u32 packed, u32}` |
| 0x10 | `^0xBBFCA3A` | **global body** | 0x1F0F850 | u16 数组（值域 0..4,678，540 distinct）|
| 0x1C | `^0x49CCBAD1` | **global body** | 0x1F5E9C4 | **10B 行** `{u32 value, u32 index, u16}` |

基址判定证据：`mov rcx,[rip+0x559d4fa]` → 0x145AD62C8（startup 指针 B）；
第二条 `mov rcx,[rip+0x559d4aa]` → 0x145AD62C0（global body 指针 A）。A/B 由加载器 0x1405361B0/0x1405361B7 分别 STORE。

### 51.2 本循环语义（已确认部分）

对 i < 68,616：
- `tarr = startup[B + 0x380DFC + 4i]`（实测全部 kind 0x15）；
- 32B 泛型类条目指针 = `[G+8] + typearr[tarr].data * 32`（G=0x145AD5E98）⇒ 每个 generic inst 在运行时表中有一项；
- 行索引 = `startup[B + 0 + 4i]` → `12B 行 @ A+0xCD026C`；
- `u16 = A + 0x1F0F850 + 2i` → `10B 行 @ A+0x1F5E9C4`；
- 随后用 xxHash64 常量链（0xC2B2AE3D27D4EB4F/0x9E3779B185EBCA87…）计算哈希并为 68,616 项建映射。

### 51.3 12B 行样本与待解

- 行 0..: `{0, 0x8000010, 0}`、`{0,0x8000018,0}`、`{0x8,0x8000010,0x181}`、`{0,0x8010020,0x3818E}` …
  field1 形如 `0x8000000|低字节`（低字节 0x10/0x11/0x18/0x20/0x30/0x38/0x48/0x60/0xb0），像打包类型描述；field2 有时 <683,568（可作 typearr 索引）。
- startup[B+0] 数组实测周期 7 非零（`{23151,0,0,0,0,0,0}` 重复）⇒ 该区域实际是 **28B 记录表**，与「stride 4」读法矛盾，需回到循环确认是否有 imul 7/28（下一轮）。

### 51.4 附带纠正（重要数字）

- typearr 全量 kind 直方图：**0x15 = 438,390**、0x12 = 182,889、0x11 = 45,695、0x1D = 9,473、0x13 = 3,320、0x1E = 3,267 …；
- GENERICINST 的 data(g)：min 0 / max **406,562** / distinct **406,563**，非线性 ⇒ 少数 generic class 被多个 typearr 条目共享（438,390 条目 → 406,563 个不同泛型类）。

### 51.5 下轮

1. 回到 0x140538F1C 附近确认 0x250/0x258 两个表的真实 stride（是否有 imul）；
2. 若 startup[0] 是 28B 记录表，则按 28B 重解，直接得到 g → (def, args) 映射；
3. 用已知 `List<GameObject>` 类型验证后接入 dump_gen 泛型渲染。

## 52. R11 第十九轮：**泛型渲染打通**（gap #11 关闭）（2026-10-17）

> 不是需求，是执行记录。

### 52.1 完整数据链（已实测验证）

`GENERICINST` 的 `data` = 泛型类索引 g，按以下链解析：

1. **startup-metadata.dat** 中 8B 行表：`base = startup + (i32(hdr[0x120]) ^ 0x1C3F68EA)`；行 = `{defTypeDefIndex u32, genericInstIndex i32}`
   （加载器 0x1405365BE..0x140536660：分配 0x20 条目，`entry[0]=row.u32`、`entry+8 = registration+0x28 + row.i32*16`）。
2. **Il2CppGenericInst 数组** = `Il2CppMetadataRegistration+0x28` = VA 0x14234_4A40：16B 行 `{argc u32, pad u32, Il2CppType** argv}`。
3. `argv` → 8B `Il2CppType*` 数组 → 每个 16B Il2CppType `{data u32, attrs u16@8, kind u8@0xA, flags u8@0xB}`。

### 52.2 验证（Python 侧）

| g | 结果 |
|---|---|
| 3347 | `List`1<UnityEngine.GameObject>` |
| 0 | `InternalEnumerator`1<System.Object>` |
| 100 | `IComparer`1<Mono.Globalization.Unicode.Level2Map>` |
| 200000 | `ReadOnlyCollection`1<MoleMole.BeyondChatChannelMonoInfo>` |

### 52.3 Rust 接入

- `Profile` 新增 `generic_class_rows: Option<Box<TableBase>>`（槽 0x120 ^ 0x1C3F68EA）与 `generic_insts_va: Option<u64>`（0x1_4234_4A40）；
- `Meta::load_with_startup(exe, dat, startup: Option<&[u8]>, profile)`，新增 `va_to_file` / `il2cpp_type_at` / `generic_instance(g)`；
- `dump_gen`：`type_name_inner` 拆出 `render_kind(kind,data)`；新增 `type_name_at`（按文件偏移渲染独立 Il2CppType）、`pointee_name`（数组/指针/byref 目标可落在主 typearr 或独立类型结构）、`strip_generic_arity`、`generic_inst_name`；
- dump.cs 输出格式对齐参考：`System.Collections.Generic.Dictionary<System.String,System.LocalDataStoreSlot>`（全限定定义名、去 arity、逗号无空格）；
- 泛型接口不再跳过：`System.IEquatable<System.ValueTuple>` 等正常输出（仅当 startup 文件缺失时回退 + 计数）；
- CLI：自动读取 `global-metadata.dat` 同目录的 `startup-metadata.dat`；缺失时显式 warn 并回退为 System.Object。

### 52.4 实测效果（vs 6.4 oracle，共享类型 20,189）

- **字段类型精确一致率 98.33%**（101,521/103,250）
- **泛型字段类型一致率 95.23%**（5,276/5,540）
- 剩余差异 = 混淆类型跨版本改名（如 `DPJCOILPAEL` vs `IGIAJAGDOND`），非解析错误
- 回归 17 passed / 0 failed；dump 88,902 类型 / 440,172 字段 / 733,442 方法，11.5s

### 52.5 遗留

- 泛型**参数引用**（kind 0x13 VAR / 0x1E MVAR）仍输出 `object/*k0x13*/` 占位（字段 7,937 + 2,246 处）：需要 genericParameters 表（nameIndex）——应在 startup-metadata 的 slot 0x2C(0x43020)/0x6C(0x3DE954) 等表中，下一轮解析。

## 53. R11 第二十轮：方法 Token 修正（真实元数据 token）（2026-10-17）

> 不是需求，是执行记录。

### 53.1 问题：ctor Token 被硬编码为 0（未验证假设）

旧代码注释声称「参考 dump 中构造函数 Token 为 0」，实测 **6.4 oracle 中 631,108 条方法 Token 无一个 0**；
我们 7.1 dump 有 82,004 个（11.2%）Token 0x00000000，**全部是 .ctor/.cctor**。

### 53.2 修正

Token = `0x06000001 + 方法表行号`（与方法表顺序一致，构造器同样有 token）。

验证（vs 6.4 oracle，共享类型 20,189）：
- 对齐方法 86,481 对；
- **同类型内相邻方法的 (our-oracle) delta 100% 保持恒定**（65,422/65,422）⇒ token 顺序/编号规则与参考工具一致；
- 85.77% 共享类型内 delta 全程恒定（= 无版本插入）；delta 差异来自 7.1 在之前插入了更多方法（版本差异，非错误）。

修正后 dump 中 Token 0 数量：82,004 → **0**。

### 53.3 其他探测（本轮）

- 泛型参数名（kind 0x13/0x1E）仍未定位：全程序 29 处字符串解码调用点逐一分析（0x1404D965A / 0x1405159BE / 0x14051DA23 等），
  分别对应 method 名（slot 0x1E0 表 = 方法表本身）、field 名（slot 0x4C 字段表）、类型名，均非 genericParameters；
- startup-metadata 的 44B 行表（0x3DE954，`{add 0xFE3F0D29}/0x1C 名字 + {add 0xE291EE7B}`）经解码确认为 **assembly 名表**（mscorlib/Mono.Security/System/UnityEngine.*），非泛型参数表。

### 53.4 验证

回归 17 passed / 0 failed；dump 88,902 类型 / 440,172 字段 / 733,442 方法。

## 54. R11 第二十一轮：typeDef parent 公式纠错 + 头部规则对齐（2026-10-17）

> 不是需求，是执行记录。

### 54.1 parent 列公式错误（25,981 行受影响）

旧公式：`parent_tarr = raw@0x2C ^ tag@0x1C ^ 0x8177D738`。
实测**应为固定掩码**：`parent_tarr = raw@0x2C ^ 0x5FCD8771`（= 0xDEBA5049 ^ 0x8177D738）。

- 旧公式仅在「element-type 列 == 0xDEBA5049 哨兵」的行上与正确值一致；
- **25,981 行**（所有带真实 element-type tag 的类型）解码成越界值 ⇒ 基类静默丢失；
- 证据：tdi=11289 (LuaCache) 与 tdi=10139 (MTRMsgLooper.<>c) raw parent 相同（0x5FCD8770），
  旧公式后者得 0xFFF8D2D5，新公式两者都得 1（System.Object），与 oracle 一致。
- 新公式全表：**87,244/88,902 (98.1%)** 解码为合法 typearr 索引（旧 61,671）。

### 54.2 头部规则对齐（Il2CppDumper 行为实测）

1. **enum 不打印接口列表**：6.4 oracle 中 `enum ... : ` 行 = **0**（struct 有 669 行）⇒ 我们对 8,127 个 enum 输出的
   IComparable/IFormattable/IConvertible 是多余；已跳过（`kind != "enum"`）。
2. **System.Object 基类**：直接继承 Object 的类的 parent_tarr kind = **0x1C (OBJECT)**，旧 base_name 只接受 0x11/0x12
   导致大量类丢失 `: Object`；接受 0x1C 后修复。

### 54.3 效果（vs 6.4 oracle，共享类型 15,183–20,189）

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 类基类精确 | 87.08% | **97.13%**（15,991/16,464）|
| 接口列表精确 | 49.75% | **84.52%**（17,064/20,189）|
| 头部（kind+base+ifaces）全等 | — | **83.76%**（16,911/20,189）|

剩余差异：混淆类型跨版本改名、版本新增接口/基类变化。

### 54.4 验证

回归 17 passed / 0 failed；dump 88,902 类型 / 440,172 字段 / 733,442 方法。

## 55. R11 第二十二轮：定位 attributeTypes 数组（特性表线索）（2026-10-17）

> 不是需求，是执行记录。

### 55.1 找到 attributeTypes 数组（明文）

body 偏移 **0x9BACA4** 起、**74,864 项** u32，全部是 **kind 0x12 的 typearr 索引**，且这些类型都是特性类：

- 分类器：特性类 = tdi 名以 `Attribute` 结尾 **或** parent 链到达 `System.Attribute`(tdi 169)（`SerializeField` 这类无后缀者靠父链识别）；
- 该区纯连续 74,864 words 全部命中（全 body 最长纯 True run）；
- 值分布（79 distinct）：`SerializeField` 45,156、`IDTagAttribute` 16,299、`MonoPInvokeCallbackAttribute` 4,283、
  `PreserveAttribute` 1,391、`InternalsVisibleToAttribute` 1,093、`ComVisibleAttribute` 715、`ParamArrayAttribute` 469 …
- 数组前（0x9A0000–0x9BACA4）是**打包/加密行表**（值形如 `0xD17E0017`/`0xAB990004`/`0x170005`）；数组后（0xA03E64 起）是另一张表（值 0,1,2,2,3,3,3…）。

### 55.2 关键判读：参考 dump 的 [Attribute] 行只是「可解析的 5 种」

6.4 oracle 共 11,525 条 `\t[...]` 行，**全部**是这 5 种（合计恰为 11,525）：

| 特性 | 条数 |
|---|---|
| CompilerGenerated | 8,538 |
| DllImport | 1,296 |
| FixedAddressValueType | 893 |
| NonSerialized | 750 |
| MarshalAs | 48 |

且 oracle 的 `extern` 数也是 1,296（= DllImport 数，对应 PInvokeImpl flag）。
⇒ 参考工具只解析出 corelib 的少数特性；7.1 metadata 实际保有 74,864 条特性数据（含 45,156 个 `SerializeField`），
若能解出 ranges 表，我们的输出会比 oracle **更完整**（Il2CppDumper 若能解析同样会打印全部）。

### 55.3 未解

attribute ranges（成员 → `{start,count}`）表未定位：
- 明文 token 列扫描（高字节 0x02/0x04/0x06/0x08/0x14/0x17）→ 无匹配 12B 行表；
- 「start 列 0→74,864 单调递增」列扫描（stride 2–12）→ 无匹配；
- 数组前区域是加密行表，需 loader 访问点 RE（下一轮）：可用「数组首值 425,808 / 属性类型数组」的双层索引代码特征定位消费者。

### 55.4 验证

回归 17 passed / 0 failed（本轮无代码改动）。

## 56. R11 第二十三轮：特性行（可推导子集）实现（2026-10-17）

> 不是需求，是执行记录。

### 56.1 规则来源（对 oracle 实测反推，非猜测）

6.4 oracle 共 11,525 条 `\t[...]` 行，**只有 5 种**：CompilerGenerated 8,538 / DllImport 1,296 /
FixedAddressValueType 893 / NonSerialized 750 / MarshalAs 48。逐条核对放置对象：

| 特性 | 实测规则 | 证据 |
|---|---|---|
| `[CompilerGenerated]` | 出现在**每个** `k__BackingField` 字段前、且仅在此类字段前 | 8,538 行 == 8,538 个 `k__BackingField` 字段，严格 1:1（脚本验证 0 例外）|
| `[NonSerialized]` | 字段前；对应 FieldAttributes.NotSerialized (0x80) | 该 attrs 由字段类型的 Il2CppType.attrs 提供（既有 const/static/readonly 修饰符同源，字段修饰符一致率 99.91%）|
| `[DllImport]` | 方法前，全部为 extern（PInvokeImpl 0x2000）| oracle 中 0 条例外；本轮**未实现**（见 56.3）|
| `[FixedAddressValueType]` | `__StaticArrayInitTypeSize=N` 静态 readonly 字段前，但**不是全部**（893/1,088）| 无法用命名规则精确区分，未实现 |
| `[MarshalAs]` | 少量特定位（48 条）| 需字段 marshal 信息，未实现 |

### 56.2 实现

- 字段 attrs bit7 → 输出 `\t[NonSerialized]`；
- 字段名含 `k__BackingField` → 输出 `\t[CompilerGenerated]`；
- 7.1 实测：CompilerGenerated **9,980** 条、NonSerialized **829** 条（vs 6.4 oracle 8,538/750，量级吻合，差异为版本增长）。

### 56.3 属性行一致率（vs 6.4 oracle，共享类型 20,189）

- 共享类型内 oracle 字段特性对 2,650，我们命中 **2,006（75.70%）**；
- 其余 oracle-only = 字段被跨版本改名/删除（469 CompilerGenerated）或需属性表（FixedAddressValueType 100、MarshalAs 45、NonSerialized 30）。
- `[DllImport]` 未实现：我们的 extern（PInvokeImpl）方法数 19,486 ≫ oracle 1,296（GI 7.1 的 Mono 包装方法 `__Gen_Wrap_*` 也带该 flag）；直接按 flag 输出会过度生成，需先判明 GI 中 0x2000 的真实语义。

### 56.4 验证

回归 17 passed / 0 failed；dump 88,902 类型 / 440,172 字段 / 733,442 方法。

## 57. R11 第二十四轮：方法 flags 哨兵 + 修饰符规则修正 + [DllImport]（2026-10-17）

> 不是需求，是执行记录。

### 57.1 发现：18,135 个方法的 flags 是哨兵 0xFF86

反查所有 733,442 个方法的 flags 解码值：**18,135 行恰好解出 0xFF86**，抽样 12/12 全部是 Mono AOT 编组包装器
`__Gen_Wrap_*`。逐字解码会输出 `abstract extern`（C# 非法组合），而 oracle 对同名方法输出**纯 public**：

```
ours(旧): public abstract extern System.Int32 __Gen_Wrap_0(...)   // 错
oracle  : public System.Int32 __Gen_Wrap_0(...)                  // 对
ours(新): public System.Int32 __Gen_Wrap_0(...)                  // 逐字一致（仅 RVA/Token 版本不同）
```

修复：flags == 0xFF86 → MethodAttributes.Public (0x0006)。效果：extern 数 **19,486 → 1,351**（oracle 6.4 = 1,296），
abstract extern 18,151 → 16。

### 57.2 修饰符规则修正：final+newslot 不输出 sealed override

oracle 中接口实现方法（如 `SemaphoreSlim.Dispose`）输出纯 `public`；旧规则把 final+newslot 渲染成 `sealed override`。
新规则（120 组 (flags,mods) 拟合 + 本轮验证）：

- private virtual → 仅可见性；
- virtual 且 newslot：final → 仅可见性；否则 `virtual`；
- virtual 且非 newslot：final → `sealed override`；否则 `override`。

sampled 一致率 **96.65% → 99.29%**（19,369/19,507）。`sealed override` 出现 121 次（oracle 108，版本差异）。

### 57.3 新增 [DllImport] 特性行

oracle 规则实测：所有 `[DllImport]` 行都在 extern(PInvokeImpl 0x2000) 方法前、0 例外。
实现后 7.1 输出 **1,351 条**（oracle 1,296），全部后接 extern 方法（0 例外）。

### 57.4 汇总（7.1 dump）

- 特性行合计 **12,160** 条 = CompilerGenerated 9,980 + NonSerialized 829 + DllImport 1,351（oracle 6.4 = 11,525，量级吻合）
- 方法修饰符 99.29%；extern 1,351；sealed override 121
- 回归 17 passed / 0 failed；dump 88,902 类型 / 440,172 字段 / 733,442 方法

## 58. R11 第二十五轮：`[FixedAddressValueType]` 特性行（2026-10-17）

> 不是需求，是执行记录。

### 58.1 规则（对 oracle 逐类型核对）

6.4 oracle 中 `[FixedAddressValueType]` 共 893 条，按类型统计后**严格 1:1**：

| 类型 | 特性行 | 字段数 |
|---|---|---|
| `<PrivateImplementationDetails>` | 583 | 583 |
| `<PrivateImplementationDetails>{C85D4D1A-…}` | 310 | 310 |

⇒ 规则：**编译器生成的 `<PrivateImplementationDetails>` 类型下所有字段**都带该特性（且只有这些类型）。
（1,088 个 `__StaticArrayInitTypeSize=` 命中里 213 个是 struct 定义行，875 个是字段；另 18 个是 Int64 静态数据字段，合计 893 ✓）

### 58.2 实现与效果

- dump_gen：字段所在类型名以 `<PrivateImplementationDetails>` 开头 → 输出 `\t[FixedAddressValueType]`；
- 7.1 输出 **934 条**（oracle 6.4 = 893，版本增长）；
- 特性行合计 **13,094**（CompilerGenerated 9,980 + NonSerialized 829 + DllImport 1,351 + FixedAddressValueType 934）；
- 共享类型字段特性对命中率 **75.70% → 78.30%**（2,075/2,650）；
- 剩余 oracle-only：CompilerGenerated 469（字段跨版本改名/删除）、MarshalAs 45（需 marshal 信息）、FixedAddressValueType 31、NonSerialized 30。

### 58.3 附带：本轮负结果已汇总到 gap-inventory「四、已排除的搜索路径」

泛型参数名（4 种扫法）、属性 ranges（4 种）、属性表本体（2 种）、stringLiterals（2 种）均实测排除，避免后续重复研究。

### 58.4 验证

回归 17 passed / 0 failed；dump 88,902 类型 / 440,172 字段 / 733,442 方法。

## 59. R11 第二十六轮：字段偏移注释规则修正（const / 泛型 / 固定地址）（2026-10-17）

> 不是需求，是执行记录。

### 59.1 发现：74,614 条 const 字段缺少 `// 0x0`

oracle 对**所有 const 字段/枚举成员**打印 `; // 0x0`（6.4 共 66,306 行）；我们此前 74,614 条 const 行全部无偏移注释。
修复后逐字一致：

```
public const Mono.Globalization.Unicode.SimpleCollator.ExtenderType None = 0; // 0x0
```

### 59.2 泛型类型实例字段：布局不可静态确定 → `// 0x0`

证据（oracle）：`System.ValueTuple<T1>` 的 `public T1 Item1; // 0x0`（6.4 中 3,129 个泛型类型实例字段为 0x0）。
根因：布局计算把通用参数（VAR 0x13 / MVAR 0x1E）当 8 字节引用，得到错误偏移（我们此前 `Item1 // 0x10`）。
修复：`type_size` 对 VAR/MVAR 返回 None（大小不可知）⇒ 布局不可得 ⇒ 泛型定义类型的实例字段打印 `// 0x0`。
效果：`System.ValueTuple`1/`2/`3` 字段与 oracle 逐字一致；7.1 输出 513 条实例字段 0x0。

### 59.3 `<PrivateImplementationDetails>` 静态字段

oracle 893 条此类字段全部 ` // 0x0`（fixed-address 静态区偏移 0）；我们已匹配（7.1 = 934 条，均为 `; // 0x0`）。

### 59.4 验证

回归 17 passed / 0 failed；dump 88,902 类型 / 440,172 字段 / 733,442 方法。
const 行 74,614 全部带 `// 0x0`；固定地址字段 934 全部带 `// 0x0`；泛型实例字段 513 条 0x0。

## 60. R11 第二十七轮：参数 ref/out 前缀 + 字段顺序分析（2026-10-17）

> 不是需求，是执行记录。

### 60.1 参数 ref/out（系统性缺失，影响所有 byref 参数）

oracle 的所有 byref 参数都带 `ref ` / `out ` 前缀；我们此前只输出 `System.X&`。规则实测：
**ParameterAttributes 的 attrs 字（Il2CppType.attrs）bit1 (0x0002) = Out**；byref 且 attrs&0x2 → `out`，其余 byref → `ref`
（C# 的 ref 不落任何 flag）。实现后逐字一致示例：

```
private static System.Int32 DecodeBlobSize(System.IntPtr in_ptr, out System.IntPtr& out_ptr) { }
private static System.Void SetCJKReferences(..., ref System.Byte*& catTable, ...) { }
```

效果：方法签名（去重后按类型对比）与 oracle 相交率 **77.34% → 79.29%**（143,577/181,071）。
剩余 oracle-only 主要 = 泛型参数名（T1/TKey 我们仍是占位）+ 混淆名跨版本改名（不可调和）。

### 60.2 字段顺序分析（解释剩余偏移失配）

- oracle 的**静态字段顺序 = 运行时静态区分配顺序**（同一 UnityEngine.Vector3 的 10 个 static readonly 字段，6.3 与 6.4 oracle 顺序不同，7.1 又不同） ⇒ 静态顺序不可静态推导（与静态偏移不可推导同源）。
- 实例字段：与 6.4 oracle 对比 9,584 个类型顺序一致、**1,962 个类型顺序不同但字段集合完全相同**（14,950 个实例字段）。
  这些差异来自混淆器的跨版本字段重排/改名（如 `<>c__DisplayClass` 与游戏类型），属版本差异；**不是** 7.1 元数据行序被打乱的证据。
- 结论：字段偏移失配（44,989 行）主要来自 ①静态字段运行时偏移（~30k 行，oracle 有值我们没有）②版本间字段重排（~15k 行）；静态布局复算本身在顺序一致的 9,584 类型上仍准确。

### 60.3 验证

回归 17 passed / 0 failed；dump 88,902 类型 / 440,172 字段 / 733,442 方法。

## 61. R11 第二十八轮：输出格式逐字对齐 + C# legacy "R" 浮点格式（2026-10-17）

> 不是需求，是执行记录。

### 61.1 十六进制格式差异（系统性，影响全部行）

oracle 全用小写、不补零的十六进制：`// RVA: 0x15862eb0`、`Token: 0x60002c5`、字段偏移 `// 0xa8`。
我们此前用大写/补零（`0x15862EB0`、`0x0600002C`、`// 0xA8`）⇒ **所有行逐字比对都失败**（即使数值相同）。
已统一为小写不补零。

效果（字段行原文逐字比对，共享类型 106,434 行）：**56.85% → 70.73%**（差距全部来自格式而非数值）。

### 61.2 浮点常量：C# legacy "R" 格式

oracle：`3.40282347e+38f`、`9.99999975e-06f`、`0.0174532924f`、`2.0f`（低位补 e±NN、`f` 后缀）。
我们此前：`-340282346638528859811704183484516925440.0f`、`0.00001f`。

实现 `format_csharp_single(v: f32)`：9 位有效数字、去尾零（fixed 形式至少保留一位小数）、
指数量级 [-4, 9) 用定点否则科学计数（`e±NN` 两位）、加 `f`。7.1 的 233 个 float 常量现已与 oracle 逐字一致
（样例：MinValue/Epsilon/MaxValue/kEpsilon/PI/Deg2Rad/Rad2Deg/kLogBase/kMaxEffectDistance）。

### 61.3 剩余字段行差异归因（29,999 行）

- 静态字段：oracle 的偏移来自运行时静态区分配（我们无值）——不可静态推导；
- 实例字段：1,962 个共享类型存在跨版本字段重排（混淆/源码差异），偏移随顺序变化。
- 其余类型/修饰符差异 1,159 行 = 混淆名跨版本改名。

### 61.4 验证

回归 17 passed / 0 failed；dump 88,902 类型 / 440,172 字段 / 733,442 方法。

## 62. R11 第二十九轮：类型修饰符 / 泛型基类 / indexer 属性（2026-10-17）

> 不是需求，是执行记录。

### 62.1 类型修饰符：oracle 从不打印 sealed/static

实测 6.4 oracle：`sealed class/struct` **0 处**、`static class` **0 处**，只有 `abstract`（5,584 处，含静态类——C# 静态类 = abstract+sealed，oracle 只打印 abstract）。
我们此前输出 `public sealed`（15,602 型）/`private sealed`（11,232 型）/`public static`（4,344 型）。
修复：类型修饰符 = 可见性 + (TypeAttributes.Abstract 0x80 ⇒ `abstract`)，其余忽略。修复后 sealed/static 类型头 **0 处**，abstract 6,259（版本增长合理）。

### 62.2 泛型基类缺失（`kind 0x15` parent）

oracle 对泛型基类打印**定义名+arity 后缀**（`: Task`1`、`: ParameterOverride`1`），不打印实例化形式。
我们此前 `base_name` 只接受 0x11/0x12/0x1C，泛型基类直接丢失。修复：kind 0x15 → `generic_instance(g)` 取定义 tdi → 原样输出 `td.name`（保留反引号）。

### 62.3 indexer 属性（get_X 带参数）

oracle 把 indexer 当普通属性打印（`public System.Char Chars { get; }`，无参数列表）。我们此前要求 getter 0 参 ⇒ 所有 indexer 属性丢失（如 String.Chars）。
修复：getter 允许任意参数；setter 允许 ≥1 参且属性类型取**最后一个参数**。属性数 62,879 → **63,117**。

### 62.4 效果（vs 6.4 oracle）

- 类基类精确率 97.13% → **98.96%**（16,293/16,464）
- 头部（kind+base+ifaces）全等 83.76% → **84.33%**
- System.String 块与 oracle 逐行几乎一致（含 [NonSerialized]、const `// 0x0`、Chars/Length 属性）
- 方法签名相交率保持 79.29%（本轮修复影响类型头，不影响方法行）

### 62.5 验证

回归 17 passed / 0 failed；dump 88,902 类型 / 440,172 字段 / 733,442 方法。

## 63. R11 第三十轮：images / assemblies 名字表（startup-metadata）（2026-10-17）

> 不是需求，是执行记录。

### 63.1 修正一个旧错误：image 记录是 40 字节，不是 28

历史笔记把 startup 的 image 表记成「28B 行」——实际 stride 是 **0x28 = 40 字节**（7 个 u32 之后 name@+0x18 仍有值）。
按 40B 走：**75 条 image 名**正确解出（mscorlib.dll / Mono.Security.dll / System.dll / … / Assembly-CSharp.dll），与 75 个 assembly 一一对应。

### 63.2 两条表的解码链（已验证）

| 表 | 头部锚点 | stride | 名字列 | 名字变换 | 行掩码 |
|---|---|---|---|---|---|
| images | `hdr[0x84] ^ 0x582F3633` → startup 0x35D5E8 | 40 | +0x18 | `(raw ^ 0x5E8998A9) − mask(i)` | `((i*0xBD1E70EB664)>>16) + 0x724F4CCB ^ 0x2BE02F3D` |
| assemblies | `hdr[0x6C] + 0xE028E1F0` → startup 0x3DE954 | 44 | +0x1C | `((raw + 0xFE3F0D29) & 0xFFFFFFFF) ^ mask(i)` | `((i*0x42DCDAFE4FA8)>>20) * 0x1E70F997 + 0x50F12A02` |

名字值 = packed 字符串索引（`len<<24 | off`）→ 共享字符串密码解密，与其他表同一密码体系。
自校验：逐行解到第一个不是合法名字（字符集/首字符）的行即停止 ⇒ 锚点错时输出空表而不是垃圾。

### 63.3 实现（profile 驱动，非硬编码）

- `Profile::startup_images` / `Profile::startup_assemblies`: `StartupNameTable { table, stride, name_off, name_op, name_c, mask_mul/shift/mul2/add2/add/xor }`
- `Meta::startup_image_names()` / `startup_assembly_names()`
- CLI: `dump-gen --images-out <path>` → JSON `{ "Images": [...75], "Assemblies": [...75] }`
- 7.1 实测：Images 75（首 mscorlib.dll、末 Assembly-CSharp.dll）、Assemblies 75（首 mscorlib、末 Assembly-CSharp），与独立 Python 解码逐项一致。

### 63.4 验证

`cargo test --release` 17 passed；`--profile-out` 往返正常（新字段序列化）；
完整 dump 仍 88,902 类型 / 440,172 字段 / 733,442 方法。

## 64. R11 第三十一轮：assembly↔image 配对 + 三处负结果（2026-10-17）

> 不是需求，是执行记录。

### 64.1 assembly↔image 配对（已验证不变量）

75 个 image 与 75 个 assembly **按索引一一对应**：`image 名去掉 .dll == assembly 名`，75/75 全部成立（mscorlib.dll↔mscorlib …
Assembly-CSharp.dll↔Assembly-CSharp）。`--images-out` 现在同时输出 `AssemblyImages: [{Index, Image, Assembly}]`；
数量不等时只告警、不臆造映射。

### 64.2 负结果（勿重复）

1. **header 槽枚举**：把 132 个槽 × {raw, ^c, +c, −c}（已知常数集合）里落进 startup/body 对齐区的候选逐一检查；
   除已知表外只多出 `hdr[0x108]`（raw 0xF6EF70 → body 16MB 处）与 `hdr[0x204]^0x4009A6BF`（→ body 0x217FF70），
   实测两区都是**均匀随机字节**（hi-byte 直方图平坦、<2M 词 0/2000），且反查 344 个 header 读取点没有代码用这两个槽 ⇒ 不是表锚点（前者更像尺寸，后者是我把 slot 0x118 的常数错配）。
2. **image 行其余列**：40B 行里 10 个 u32 列全部随机（75 行内无小值列、无单调列）⇒ typeStart/typeCount 等列同样被逐行掩码，需 loader 掩码公式才能解。
3. **assembly 行其余列**：44B 行 11 列中 0–8 全随机，仅 col9/col10 有 63/75 行为 0（疑为残留/尾部字段），非 imageIndex。
4. **startup 内 string-literal 表**：扫 8B `{len 1..200, dataOff 落在 body 明文串区 0x8E0000–0x940000 / 0x4600000+}` 双相位稠密窗口 = 0。

### 64.3 验证

`cargo test --release` 17 passed；`--images-out` 输出 75 Images / 75 Assemblies / 75 AssemblyImages，首尾与 Python 独立解码一致。

## 66. R11 第三十二轮：custom-attribute 渲染实现（2026-10-17）

> 不是需求，是执行记录。

### 66.1 实现（profile 驱动）

- `Profile::attribute_types_off` (7.1: body **0x9BACA4**) / `attribute_count` (**74,864**) / `attribute_instance_tag` (**0x01000000**)；
- `Meta::attribute_type_idx(i)`、`Meta::attribute_instance_tokens()`（全 body 扫 8B 行 `{token, tag+i}`，first-wins）；
- `dump_gen` 构建 `token → [属性类短名]`：
  1. token 种类校验（0x02/0x04/0x06/0x08 且索引在表界内）；
  2. `attributeTypes[i]` → typearr → 必须 `kind=0x12` → typeDef（属性类）；
  3. **仅当属性类存在无参 `.ctor`** 时渲染 `[Class]`（这正是 C# 允许 `[Attr]` 简写的条件；含参属性需要参数 blob，尚未解出 ⇒ 明确跳过并计数）；
  4. 类名按 C# 习惯去掉 `Attribute` 后缀。
- 输出位置：typeDef 头（列 0）、字段（`\t[Class]`）、构造器、方法；属性/参数上的属性无 dump 语法位置，计入 skipped。

### 66.2 实测（7.1）

```
[warn] custom attributes: 47976 rendered as [Class] ..., 22146 skipped because their constructor
       takes arguments ..., 2113 skipped (parameter attribute / unknown token kind),
       2629 attribute instances have no member row
```
47,976+22,146+2,113+2,629 = **74,864** ✓（与 attributeTypes 长度完全对上）。

| 渲染出的属性 | 行数 |
|---|---|
| `[SerializeField]` | 44,191 |
| `[CompilerGenerated]`（标志位启发式）| 9,980 |
| `[Preserve]` | 2,032 |
| `[DllImport]`（标志位）| 1,351 |
| `[FixedAddressValueType]`（标志位）| 934 |
| `[NonSerialized]`（标志位）| 829 |
| 混淆名 `[BOOJLDIOCFM]` | 345 |
| `[ShowInInspector]` | 326 |
| `[RequiredByNativeCode]` | 118 |
| `[ThreadStatic]` | 73 |

属性行总计 **61,070**（上轮 13,094），其中 47,976 条来自真实属性表。
放置核对：字段 56,256、方法 3,849、类型 767，其余为连续属性行（198）。

### 66.3 负结果：属性参数 blob 未定位

attributeTypes 数组之后（0xA03E64）是 769 个小整数（0..176），随后即 `0xFFFFFFFF/0x27/0x8D…` 数据，非 74,864 项参数表；
0xA03E64–0xC00000 区间无明文可打印串（字符串参数会以加密串堆索引出现）。属性参数仍需另行定位。

### 66.4 验证

`cargo test --release` 17 passed；dump 88,902 类型 / 440,172 字段 / 733,442 方法；dump 耗时 ~7 s。

## 67. R11 第三十三轮：attributes.json 工件（2026-10-17）

> 不是需求，是执行记录。

### 67.1 新工件

`dump-gen --attributes-out <path>`：把**全部**属性实例导出为 JSON，包括无法在 dump.cs 里写成 `[Name]` 的含参属性：

```json
{"AttributeCount": 74864, "Recovered": 70693, "Attributes": [
  {"Instance": 6, "MemberToken": 33554571, "Member": "TypeDef: System.LocalDataStore", "Attribute": "ComVisible"},
  {"Instance": 743, "MemberToken": 100670846, "Member": "Method: System.Threading.OSSpecificSynchronizationContext::Post", "Attribute": "MonoPInvokeCallback"}
]}
```

成员身份解析：`TypeDef: 全限定名` / `Field: 类型::字段名` / `Method: 类型::方法名` / `Parameter: 参数名` / `Property: #索引`（属性表未解）。
7.1 实测：`AttributeCount` 74,864、`Recovered` **70,693**（9.6 MB）。

### 67.2 修复一处接线错误

上轮把 `attributes_out` 块误插进 `images_out` 块内部（且复用了同名 `p`），导致 `--attributes-out` 从不执行、`--images-out` 还会把 image JSON 写到属性路径。已移出并回归：`--images-out` 75 images/75 assemblies、`--attributes-out` 70,693 条，二者同时指定互不影响。

### 67.3 验证

`cargo test --release` 17 passed；完整 dump 88,902 类型 / 440,172 字段 / 733,442 方法（6.9 s）；
产物写入 `~/gire/out/71/`（dump.cs 120 MB、script.json 77 MB、attributes.json 9.6 MB）——**不再写 /tmp**（ramdisk，曾写满导致工具链不可用）。

## 68. R11 第三十五轮：`.upx0` 静态模拟路线打通（2026-10-17）

> 不是需求，是执行记录。详见 `docs/re/upx-emulation.md`。

### 68.1 `.upx0` 性质判定（此前误记为「加密/VM 字节码」）

实测：熵 6.8（代码级）；`0x159F63C4D` 是合法 x86-64（push 全寄存器 + 只作用于 bp/ebp 的 junk 变形）；
指向 `.upx0` 的 DIR64 重定位仅 **20/1,658,208** ⇒ 位置无关、无 handler 指针表；
`.text→.upx0` 入口 **206 个**（109 call + 97 jmp），`.upx0` 内部 call/jmp 目标 27,139 个。
⇒ **VMProtect 式逐函数变形原生代码**，不是字节码 VM，也不是加密数据。

**反调试不影响本路线**：静态反汇编 + Unicorn 模拟都不运行游戏进程。

### 68.2 模拟器（已入仓 `tools/emu_upx.py`）

映射 PE（preferred base）、重建的 body/startup/header、loader 全局、TEB/栈；
自建 `0x145AD62D8[typeDef]` 运行时缓存表指向真实 typeDef 行；hook 记录 metadata 读。
实测 entry=0x14051DB00/rcx=293 完整返回（0x159F63C4D→0x159F647C7），rax=0x3048F8FF6。

### 68.3 顺带确认的新表候选

flags/klass 解析器内部读 `hdr[0x198]^0x5303F399` = body **0x10500E0**，88,902 条 u32，
值稠密覆盖 0..23,150（按 typeDefIndex 索引）——候选映射表，语义待定，已记为待解项。

### 68.4 下一步

打通 cache-miss 构建路径（初始化 `.rdata` 槽 0x143B4B248 与 registration），再批量跑 206 个入口建「入口→表」映射，
目标：propertyDefs / genericParameters / attribute-args 的读取器。

## 69. R11 第三十六轮：静态上限判定 + 模拟器工程化（2026-10-17）

> 不是需求，是执行记录。详见 `docs/re/remaining-static-limits.md`。

### 69.1 把「找不到」拆成「不存在」与「未定位」

本轮对剩余缺口做了系统性判定（证据见 docs/re/remaining-static-limits.md）：

**A. 静态已证不可得（oracle 值来自运行时 / GI 构建期丢弃）**
- 静态字段偏移 109,214（运行时类初始化顺序）；方法 Slot 非零（元数据全 -1）；
- interface 基接口（元数据哨兵）；metadataUsage（BSS 运行时写入；扫 `{start,count}` 连续表 0 命中）；
- stringLiterals（exe il2cpp 段 306MB 无 ASCII 文本池；metadata 明文字符串仅 ~45KB 默认值）；
- 属性表本体（标准 20B `{nameIdx,get,set,attrs,token}` 扫描含名字可解码校验，0 命中）；
- 泛型参数名（4 类扫描 0 命中）；属性参数（attributeTypes 后无对应结构）。

**B. 未定位但可能存在**：attribute 参数 blob、属性表（若存在）、`.upx0` 内更多 metadata 访问器。

**C. 工程类可产出**：DummyDll、il2cpp.h、script.json Signature、多版本通用化。

### 69.2 模拟器工程化（tools/emu_upx.py）

- 重构为库：`build_emulator(fill_cache, lenient)` + `run_once(ctx, entry, rcx, max_insns)`；
- 新增故障记录（fault rip/addr/access）与宽容模式（未映射执行地址补 `xor eax,eax; ret` 桩）；
- 批量跑 206 个 `.text→.upx0` 入口：11 个可完整执行，195 个卡在 VMP 运行时解析槽
  （文件里是 RVA 形占位，如 0x3b4d7a4；宽容模式对 addr=0 无效）⇒ 要跑通需先模拟 VMP 初始化器。

结论：`.upx0` 里只有 3/206 入口与 metadata 相关（flags/klass 解析器已解），
故「模拟解 .upx0」对补齐剩余表**帮助有限**；剩余表更可能是 GI 未保留。

## 70. R11 第三十七轮：script.json 升级为 Il2CppDumper 兼容格式（2026-10-17）

> 不是需求，是执行记录。参考实现：`Il2CppDumper/Outputs/StructGenerator.cs::WriteScript`（本轮拉取源码逐行核对）。

### 70.1 生成规则（从参考源码逐行复刻）

- `ScriptMethod.Address` = **RVA**（`GetRVA(ptr) = ptr - ImageBase`）；
- `ScriptMethod.Name` = `<TypeDefName>$$<methodName>`；
- `ScriptMethod.Signature` = C 原型 `"<retCType> <FixName(Name)> (<this>, <params>, const MethodInfo* method);"`：
  非静态方法首参为 `{structName}_o* __this`，每参 `ParseType(paramType) name`（byref 追加 `*`），末尾固定 `const MethodInfo* method`；
- `ScriptMethod.TypeSignature` = 类型字母序列（v/bool~int→i/i8→j/f/d），含 __this 与末尾 MethodInfo；
- `ParseType` / `FixName` / 结构体命名（`FixName(GetTypeDefName(td,true,true))` + 去重后缀）逐条对齐；
- `Addresses` = 排序去重后的方法指针 RVA。

### 70.2 实测结果（7.1）

```
ScriptMethod: 679,867   Addresses: 460,313
File size: 160 MB
```

样例（与参考 dump 的语义一致）：

```json
{"Address": 372950656, "Name": "System.String$$Concat",
 "Signature": "System_String_o* System_String__Concat (Il2CppObject* arg0, const MethodInfo* method);",
 "TypeSignature": "iii"}
```

自洽性校验：**679,867/679,867** 条满足 `len(TypeSignature) == 参数数 + 1`。
嵌套类型命名修复：`typedef_name` 曾把 **typeDef 索引**误传给按 **typearr 索引**解析的 `type_name` ⇒ 嵌套类型前缀错乱
（如 IAttrList 显示成 `IReadOnlyCollection<object>.IAttrList`）；改为独立的 typeDef 链命名后，
`Mono.Xml.SecurityParser.OnStartElement(..., Mono.Xml.SmallXmlParser.IAttrList attrs)` 的 C 原型正确。

### 70.3 未覆盖（已判定运行时/元数据不可得）

- `ScriptString` / `ScriptMetadata` / `ScriptMetadataMethod`：需要 metadataUsage（BSS 运行时写入，§69）；
- methodSpec 泛型实例方法条目：需要 methodSpecs 与 genericMethodPointers；
- `md.rva == 0` 的 53,575 个方法（抽象/PInvoke 桩）按参考实现跳过；
- `Addresses` 只含 method pointers（参考还合并 genericMethodPointers/invokerPointers/customAttributeGenerators）。

### 70.4 验证

`cargo test --release` 17 passed；完整 dump 88,902 类型 / 440,172 字段 / 733,442 方法；script.json 160MB 可 `json.load`。

## 71. 纯静态恢复方法 Slot（vtable 重建，2026-10-17 第 39 轮）

> 不是需求，是执行记录。

### 71.1 背景
GI 把 metadata 的 method slot 字段抹成 -1；参考 dump 的 Slot 列来自 6.4 构建期数据。
Slot 是 C# vtable 布局的确定性结果，可纯静态重算。

### 71.2 规则（用 6.4 oracle 的 Stack 等类反推并验证）
1. 从父类 vtable 开始（System.Object 顺序：Equals / Finalize / GetHashCode / ToString，与 metadata 顺序一致）；
2. 先追加接口槽：按类型声明的接口顺序、每个接口内的方法顺序，一方法一槽；
3. 再按 metadata 顺序追加本类型自己的 virtual newslot 方法；实现接口方法者映射到接口槽，
   且 final(sealed) 或显式实现（名字形如 IFace.Method）不额外占类槽；非 final 隐式实现两者都占；
4. 非 newslot 的 override 按签名匹配父类槽。

### 71.3 实现与验证
- 新模块 src/vtable.rs（签名 key 用规范类型串，兼容 GI 重复 typearr 条目；impl_key 用简单方法名匹配显式接口实现）；
- dump-gen 输出的 Slot 列改为静态计算值，共 245,235 个 virtual 方法；
- 验证脚本 tools/validate_slots.py：与 6.4 oracle 只比较「方法序列/修饰符/基类/接口顺序/接口内容完全一致」的类型，
  得 8,548 / 8,901 = 96.03%（9,598 个类型）；剩余差异可归因于更深的基类链在 6.4→7.1 之间的差异
  （过滤器未递归校验整条继承链），非算法规则问题；
- 早期版本（本类型方法先、接口后）仅 41%；显式接口实现 + final 规则修正后 72% → 接口槽前置后 96%。

### 71.4 结论
Slot 列不再标记为静态不可得；属于纯静态可恢复项（来源：metadata 方法/接口表 + C# 布局规则）。


## 72. 静态字段偏移：oracle 统计与 arena 模型（2026-10-17 目标第 1 轮）

> 不是需求，是执行记录。

### 72.1 先用 6.4 oracle 量化「静态偏移到底有多少可真值」
- oracle 6.4 中 static 字段带 offset 注释共 30,587 个；其中非零真值 29,337（95.9%），0x0（常量或读不到）1,250。
- 结论：Il2CppDumper 能给出绝大多数静态偏移，不能简单按「运行时不可得」略过。

### 72.2 形态：每程序集独立 arena，非 GC 区在前、GC 引用区在后
- 偏移分布：min 0x10、max 0x30410，存在同偏移重复（多个程序集各自从 0x10 起算）→ 每程序集一个 static arena。
- 反例证据：DateTime 非 GC 字段 MaxValue=0x20/MinValue=0x28，GC 引用 DaysToMonth365/366=0x60/0x68；
  ContractionComparer.Instance（单引用字段）=0xb80，与 MSCompatUnicodeTable 的引用区 0xbc0/0xbd0 同段。
- 用 oracle 全量验证：同时含 GC 与非 GC 静态字段的类型 2,344 个，其中 2,248（95.9%）满足 max(非GC偏移) < min(GC偏移)
  （剩余 4% 主要是 oracle 无字段类型信息导致的值类型误判）。分析脚本：tools/analyze_static_offsets.py。

### 72.3 剩余未知与下一步
- arena 内精确打包顺序（按 程序集→类型→字段？对齐规则）尚未确定；需要 6.4 metadata 解码结果做拟合。
- 已尝试 mhydump derive 6.4 → 产物是半成品（缺列解 ops），需走 version-triage：derive → colsolve4 → colverify → profile。
- 备选：用 images 表的 typeStart/count 得到 7.1 类型→程序集映射后，直接模拟 arena 规则；用 6.4 oracle 的
  DateTime/MSCompatUnicodeTable 等类型做定点核对。

## 73. DummyDll 生成器 v1（2026-10-17 目标第 2 轮）

> 不是需求，是执行记录。

### 73.1 实现
- Rust 侧导出：dump-gen --dummy-out（src/dummy_export.rs），逐行 JSONL：T 类型 / I 接口 / F 字段 / M 方法（含参数）。
  7.1 实测：88,902 T / 440,172 F / 733,442 M，文件 111MB。
- C# 生成器：tools/dummygen/（net10.0，System.Reflection.Metadata，无外部依赖）。
  单次生成单文件 DummyDll.dll：TypeDef（按 tdi 顺序，类型名/命名空间/可见性/abstract/sealed/interface/struct/enum），
  基类（struct→System.ValueType、enum→System.Enum、class→父类或 System.Object、<Module> 无基类），
  InterfaceImpl（84,377 行），FieldDef（清 Literal/HasDefault，常量降级为 static 字段），
  MethodDef（签名+参数；接口/abstract 无方法体，其余给 ldnull/throw 或 ret 最小方法体），Param（548,400 行）。

### 73.2 产物与验证
- 产物：~/gire/out/71/DummyDll.dll，38 MB。
- 生成器内置校验：类型/字段/方法/参数计数与 JSONL 一致。
- 独立验证（venv + dnfile 解析 PE/CLI）：TypeDef 88,902 / MethodDef 733,442 / Field 440,172 /
  Param 548,400 / InterfaceImpl 84,377 / Assembly=1 / Module=1，与导出一致；样例类型名/命名空间/基类行号正确；
  87 个重名类型（GI 多程序集合并导致），可被解析器接受。

### 73.3 与 Il2CppDumper 参考实现的差异（v1 已知）
- 参考实现按 image 生成 **75 个程序集**（互相引用）；v1 生成单个自包含 DummyDll.dll（便于直接反编译浏览）。
- 未生成：AddressAttribute / FieldOffsetAttribute / AttributeAttribute / TokenAttribute 等自定义特性行，GenericParam 表。
- 这些都是后续可增量补齐项；v1 已满足"可浏览类型/字段/方法结构"的目标。

## 74. 字符串字面量静态恢复（2026-10-17 目标第 3 轮）

> 不是需求，是执行记录。

### 74.1 结论
前序会话的「stringLiteral 表未定位」在 7.1 上已可解决，且不需要运行时：
外部工具 gi-stringliteral（github.com/kuma-dayo/gi-stringliteral，commit 1008fd7）版本无关地从 .exe 里
自动抽取字面量 keystream（op-chain）与表解码算术，再按 KS 前缀和签名定位 metadata 内的字面量表与数据区。

### 74.2 7.1 实测
- 命令：tools/recover-literals.sh（包装外部工具，不 vendor 第三方代码；已实测可运行）
- 结果：table @0x1ebb8ec，data @0x1c6c828，86,108 条唯一字面量，索引 0..86107 连续无重复；
  平均长度 27.8、最长 837、含 1 条空串、1,431 条非 ASCII；
  含 Data/_BinOutput 路径 243 条、Data/_JsonOutput 68 条。
- 与前序 ~/gire/meta_string_literals.txt（31,589 唯一串）对比：覆盖 31,444（99.54%）；
  未覆盖的 145 条是 exe 原生串/运行时拼接串（如 [Packet Before Encrypt - Hex]），不属于 il2cpp 字面量表。
- 产物：~/gire/out/71/literals.json（6.0MB）。

### 74.3 跨版本性
- 6.4.0 样本运行失败（工具报 could not extract decryption logic，混淆代次不同），
  说明该工具对版本并非无条件通用（作者只测过 6.4.51/6.5.51/6.6.50 与后续 OSRELWin6.7.0）。
- 7.1（本目标版本）验证通过；未来版本若失败，需要适配 extract_constants 的符号执行或移植进本项目 derive 流程。
  已作为显式外部依赖记录（tools/recover-literals.sh 会检查并提示）。

### 74.4 对 Il2CppDumper 兼容性的含义
- 字面量「值」已静态可得；script.json 的 ScriptString 还差「使用点地址」（metadataUsage 槽），
  那部分仍属运行时/加密数据，与字面量表本身是两件事。

## 75. 接口继承与属性参数：7.1 静态可得性判定（目标第 3 轮）

> 不是需求，是执行记录。

### 75.1 接口继承（interface 的基接口）
- 6.4 oracle：interfaces 1,371 个，其中 270 个带基接口（398 条 link）。
- 7.1 我方 metadata：interfaces 1,580 个，**带基接口行 0 个**（全量统计，非抽样）。
- 结论：GI 7.1 在 metadata 里**删掉了接口的 InterfaceImpl 行**（sentinel），这不是解码问题。
  运行时的接口列表从同一份 metadata 构建，因此运行时 dump 大概率也拿不到（待快照实测确认）。
  该字段对 7.1 属于「元数据未保留」，与参考 dump 的差异是版本数据差异。

### 75.2 属性参数
- 已知：attributeTypes 表在 body 0x9BACA4（74,864 个 typearr 索引，明文）。
- 扫描 body 全部 u32：落在方法 token 区间 [0x06000001, 0x06000001+733442) 的只有 25,791 个，
  且最长连续段仅 11 —— 不存在「属性构造函数 token 表」。
- 结论：属性构造 token / 参数 blob 未在 metadata body 中以明文表存在（被删除或移入 exe 加密区）。
  与第 69 轮「属性参数运行时不可得」判定一致；参考 dump 的含参属性行无法静态复现。

## 76. 静态字段偏移：arena 归属与 image 表障碍（目标第 4 轮）

> 不是需求，是执行记录。

### 76.1 新证据：offset 窗口分析（oracle 6.4，按 dump 顺序）
- 0x380–0x400 窗口内出现同一 offset 被多个类型使用（如 0x3e0 同时出现在 MSCompatUnicodeTable 与 System.Empty.Value；
  0x380 出现在 ParamsArray/CompareInfo 等）→ 说明偏移空间是「每程序集 arena」，重复来自不同程序集（GI 多程序集含重复类型定义）。
- 同一类型内部：非 GC 字段偏移随声明顺序严格递增、按自然对齐（MSCompatUnicodeTable: bool 0x390 → int 0x394 → ptr 0x398 → 0x3a0 → … → 0x3f8），
  证实「类型内按声明顺序 + 自然对齐」；GC 引用字段在另一区（该类型引用区 0xb80+）。
- 由此确定 arena 规则：每程序集两个区（非GC 区、GC 区），类型内按声明顺序分配，类型间按「程序集的类型顺序」推进。

### 76.2 障碍：6.4 的 image 分组无法从 oracle 直接得到
- oracle 的 TypeDefIndex 注释是**全局 0..77,229 连续**（不是每 image 重置），无法据此切分程序集。
- 尝试从 7.1 startup-metadata 的 image 表解出 typeStart/typeCount 以便建立类型→程序集映射，但该表所有列都被掩码
  （row 值全为密文；name 列的掩码公式已知，其它列未知），结构化解列（找 start/count 累加关系）无解。
- 下一步两条路（下轮）：① 先解 image 表其余列的掩码（同 name 列的 mask 形式，用「start 累加 == 77/88k」做约束求解）；
  ② 或先实现 DummyDll v2 的自定义特性（不依赖 image 映射），再回头做偏移。

### 76.3 已保存分析脚本
tools/analyze_static_offsets.py（第 1 轮的假设检验）；本轮的窗口/分组分析在其基础上扩展，结论记录于此。

## 77. DummyDll v2：自定义特性（目标第 5 轮）

> 不是需求，是执行记录。

### 77.1 新增数据（Rust 导出 v2）
dump-gen --dummy-out 的 JSONL 新增列：
- M：rva（方法 RVA）、token（0x06000001+gmi）、slot（vtable 静态计算结果，见 §71）；
- F：token（0x04000001+fieldRow）、off（instance 字段偏移；由 dump_gen::instance_offsets 用布局规则静态重建，explicit layout/泛型参数类型为 null）。
实现：dump_gen 暴露 pub fn instance_offsets；dummy_export 调 vtable::compute_slots 与布局计算。

### 77.2 C# 生成器 v2（tools/dummygen）
- 在主类型之后追加 2 个特性类型（同程序集，共 88,904 TypeDef）：
  Il2CppDummyDll.AddressAttribute { public string RVA/Offset/VA/Slot }、FieldOffsetAttribute { public string Offset }；
- 按参考实现（DummyAssemblyGenerator.cs）的**命名参数**格式写 CustomAttribute blob：
  prolog 0x0001 + named count + (0x53 字段, 0x0E string, SerString 名字, SerString 值)；
- 输出：所有非抽象且 rva>0 的方法挂 AddressAttribute(RVA/VA[/Slot])；所有有静态布局偏移的 instance 字段挂 FieldOffsetAttribute(Offset)；
- 实测：CustomAttribute 行 1,041,595；DummyDll.dll 77 MB；内置校验同时解码前 500 条 blob（prolog/命名参数/ctor 类型）全部通过。

### 77.3 与参考实现的剩余差异
- 多程序集划分（75 个 DLL，参考实现按 image 生成）：依赖类型→程序集映射；当前卡在 startup-metadata image 表列掩码（本轮已尝试列解，未成功，见 §76）。
- GenericParam 表与 Address 的 Offset 字段（需要 exe 段表映射）未生成；v1 的已知差异仍成立。

## 78. image 表解列：反汇编 loader 得到全部列公式，确认无 typeStart/typeCount（目标第 6 轮）

> 不是需求，是执行记录。

### 78.1 loader 位置与解码公式（capstone 反汇编 0x140536d60–0x140537104）
- image 表基址：startup + i32(hdr[0x84]) ^ 0x582F3633；行 stride 0x28；
- 行掩码（所有列共用）：r15d = (((i*0xBD1E70EB664)>>16) + 0x724F4CCB) ^ 0x2BE02F3D（与 name 列 profile 参数一致）；
- 各列解码（t=行内 u32，m=行掩码）：
  +0x00: ((t^0x57631D22)-m)+0x3A3F5F30     +0x04: (((t-m)+0xBB4B5110)^0x4FBFA07B)
  +0x08: (((t-m)+0x96612B2C)^0x7362B478)   +0x0c: (t^0x1066FCA3)-m
  +0x10: (t-m)+0xD3ED43CA                  +0x14: ((t^0x0F90FC6D)-m)+0x50105F4F
  +0x18: (t^0x5E8998A9)-m（name）           +0x1c: (t-m)+0xB789942C
  +0x20: (((t-m)+0xD61DDDDC)^0x06E0B2A6)   +0x24: ((t^0x40B24EE6)-m)^0x07B236BA
- 目标结构 stride 0x58：name 存 +0x48、+0x04/+0x08/+0x18/+0x28/+0x2c/+0x30/+0x40/+0x50 各列。

### 78.2 实测解码结果（用上述公式解 75 行）
- **+0x0c 列 = 0,1,2,...,74**（图像序号，严格 +1）。
- +0x10 列：单调递增，差值像类型数（1335, 85, 665, …），但全 75 行累计仅 **11,748**（≈ exportedType 数量级），不是 88,902。
- 其余列：常量/指针/字符串索引量级，无 0..88902 的累计语义。
- 结论：7.1 的 image 定义行**只保留 name、索引、exported 范围等，不含全量 typeStart/typeCount**（GI 剥离）。
  这也解释了我们此前按「start 累加 == 88,902」约束解列必然无解。

### 78.3 影响
- 参考 Il2CppDumper 的 DummyDll 以 75 个程序集输出，其划分依赖 image.typeStart/count；7.1 该数据被剥离 →
  多程序集 DummyDll **静态不可复现**（当前单程序集 DummyDll 是 7.1 能给出的最接近形态）。
- 静态字段偏移的「每程序集 arena」分组同样缺少程序集边界；后续改为不依赖分组的路线（见下）。
- assemblies 表：base = startup + (i32(hdr[0x6c]) + 0xE028E1F0)，行 stride 0x2c，行掩码
  eax = ((((i*0x95F44748)+0x0BBE3F00)^0x24A3038F)+0x42C9B098)^0x76878AF8（本轮到 assembly 表为止）。

### 78.4 下一步（替代路线）
1. 静态偏移：不依赖 image 分组——在 exe 的静态数据里按「已知 instance 偏移序列」匹配每类型 fieldOffsets 数组
   （类型内字段顺序已知、instance 偏移由布局重算已知），命中后同一数组即含该类型的静态字段偏移；
2. 或用 6.4 oracle 的静态偏移 + 跨版本类型对照做回归校验（只校验，不生成）。

## 79. 静态字段偏移：7.1 文件内不可得的证据链（目标第 7 轮）

> 不是需求，是执行记录。

### 79.1 假设与验证
验证「7.1 exe 里存在每类型 fieldOffsets u32 数组（含静态字段偏移）」：
1. 从 dump.cs 解析全部类型的 instance 偏移（59,967 个类型有偏移，平均 3.48 个 instance 字段）；
2. 取「前若干字段连续为 instance 且含 >0x80 的 distinctive 偏移」的类型（2,555 个），随机抽 400 个；
3. 用其连续 instance 偏移序列（u32 LE）在 445MB exe 里全量搜索：
   - 原始模式命中 28 次；
   - 逐值校验后仅 8 次"完整匹配"，但**全部落在同一文件偏移 0x397516c、同一通用序列 [0x70,0x78,0x80,0x88]**（通用小偏移数组的误报）；
   - 换用更长/更挑序列（如 System.Threading.InternalThread 的 29 个偏移，含 0x38/0x3c）→ **0 命中**。
4. 交叉排除：metadata 无 field offset 表（此前已证）；runtime dump 无 FieldInfo token 连续数组（第 3 轮扫描 0 命中）。

### 79.2 结论
- 7.1 **文件里不保留 fieldOffsets 数组**（既不在 metadata，也不在 exe 数据段），因此：
  - instance 偏移只能靠布局规则静态重建（当前 dump 已用；与 6.4 oracle 类型级一致率 ~79.55%）；
  - **静态字段偏移在 7.1 静态不可得**（参考 dump 中 29,337 个静态偏移值对应 6.4 构建期数据，7.1 已被剥离）。
- 该结论有可复现证据（tools/check_field_offset_arrays.py，本轮新增），不是"还没找到"。

### 79.3 对目标的意义
- 「静态偏移规则」项：规则本身（每程序集 arena、非GC 区/GC 区、类型内声明序）已确认，但 7.1 缺数据载体，
  只能作为"已知但本版本无法落地"记录；不再计入未完成任务。
- DummyDll 的 FieldOffsetAttribute 只覆盖可重建的 instance 偏移（v2 已如此），静态字段不写假 offset。

## 80. DummyDll v3：GenericParam 表 + AddressAttribute.Offset（目标第 8 轮）

> 不是需求，是执行记录。

### 80.1 新增
- Rust 导出：M 记录新增 foff（方法 RVA → exe 文件偏移，基于 PE 段表映射；不可映射为 null）；
- C# 生成器：
  - GenericParam 表：按类型名尾部 arity（如 List 加反引号 1 → 1）为 2,455 个泛型类型写入 1,195 个 GenericParam 行
    （名字 T1..Tn，无约束——GI metadata 未保留泛型参数名与约束）；
  - AddressAttribute 命名参数改为 RVA / Offset / VA（Offset=文件偏移，与参考实现字段名一致；Slot 有值时追加）。

### 80.2 产物与校验
- DummyDll.dll 89 MB：88,904 TypeDef / 440,177 Field / 733,444 Method / 548,400 Param /
  84,377 InterfaceImpl / 1,041,595 CustomAttribute / 1,195 GenericParam；
- 内置校验：CustomAttribute 采样解码 500 条（含 Address 的 RVA/Offset/VA 与 FieldOffset 的 Offset）全部通过；
  GenericParam 行数 = 按类型名 arity 的期望值。
- 差异更新：单程序集；RVA/Offset/VA 已对齐参考格式。

### 80.3 仍不可得的 DummyDll 细节
- 75 程序集划分（image 表无 typeStart/count，§78）；方法 GenericParam（metadata 未解码出 method 泛型容器信息）；
  GenericParamConstraint（约束数据未保留）。

## 82. 结合模拟执行：loader 解码块 emulation 打通（用户追加任务第 1 步）

> 不是需求，是执行记录。

### 82.1 思路
不逐列转写公式，而是让 Unicorn **直接执行 loader 的真实解码基本块**：
- 反汇编定位：image 表 loader 的直行解码块 0x140536FE6..0x1405370BB（块内无 call）；
- 输入：rdi=行指针、r15d=共享行掩码、r14=输出结构基址、r13=i*0x58；
- 输出：解码后的列值写入 0x58 字节结构。

### 82.2 实现（tools/emu_loader_columns.py）
- 映射整个 PE 到 preferred base；把 startup-metadata 行写入 scratch page；
- 从 header blob（VA 0x1427D5CB0）读 hdr[0x84] 推导 image 表基址（无硬编码 slot）；
- 每行设置寄存器、emu_start(0x140536FE6, 0x1405370BB)，读回解码列；
- 同时用反汇编恢复的公式做参考解码，逐行逐列对比。

### 82.3 结果
- **75/75 行完全一致**（列 +0x04/+0x08/+0x18/+0x28/+0x2c/+0x30/+0x50 全部相同），
  说明：① 反汇编出的列公式正确；② "模拟执行真实 loader 代码"这条路线可用（未来版本可省去逐列反推）。

### 82.4 静态偏移可行性（第 2 步初步）
- profile 注释指出 typeDef flags 列在 .upx0 class builder（0x159F64354）读取；实测该函数入口为 0x159F63C4D，
  函数体内确实内联读取 [r15+0xC]（flags，+0xDFA09F90）与 [r15+0x32]（bitfield），r12=klass、r15=typeDef 行指针；
- 但**字段布局相关常数**（td_field_start 1919057927、td_field_count 39531、fields table sub 492068044、fd_stride/name/type 常数）
  在该函数体内 **0 命中**，且整个 .upx0 扫描 **0 命中** → 字段布局不在该变异函数内联，推测在 .text 的通用列访问/布局函数里；
- 结论：静态偏移的模拟路线**仍开放但成本更高**（需先在 .text 中定位字段布局例程，再构造 klass/metadata 环境模拟）；
  下一轮实验：在 .text（35MB）中扫描这些列常数与 fields 表引用，定位布局例程后再评估块级模拟。

## 83. 真实 propertyDefs 表定位：115,596 条属性（静态解码，2026-10-18）

> 不是需求，是执行记录。用户追加任务「继续」后本轮推进。

### 83.1 定位路径（反汇编运行时构建函数，不是猜）
`hdr[0x158]` 这张 10 字节行表此前在 profile 里名为 `fields`（`fd_base` 读入后从未被消费）。
本轮从运行时内存 dump（memdump_ingame 的 klass 缓存 0x145AD62D8）出发，反汇编 .text 中的属性/字段
cache 构建函数，确认其语义是 **propertyDefs**：

- `0x1405121B0` = `klass->props` 迭代器：元素 0x28 字节，end = klass+0x48 + count*0x28，
  count = u8[typeDefRow+0x43]^0x86；首次访问调用 0x140515FC0 填充；
- `0x140515FC0` = propertyDefs -> PropertyInfo 数组构建器：
  - 表基址 = body + (i32(hdr[0x158]) - 0x1D545CCC)（0x1405162A9..0x1405162C0）；
  - 行 stride 10：+0 u32 name（packed string index）、+4 u16 getter、+6 u16（未定列）、+8 u16 setter；
  - 行掩码 mask(i) = (((i*0xA593 ^ 0x3CA3FFA0) * 0x5CD0B62E + 0x63A341E6) ^ 0x2411ED71)（0x1405162C9..0x1405162E5）；
  - name = (raw + 0xEE8895EA) ^ mask；getter = ((raw - 0x238F) ^ mask) & 0xFFFF；
    setter = ((raw ^ mask) ^ 0xDB1) & 0xFFFF；0xFFFF = 无 accessor；
  - 0x140516280 路径显示 u16@+6 参与 +0x720A / ^0x7F39AD03 的变换后写入 PropertyInfo+0x20，语义未定（Il2CppDumper 不输出）；
- typeDef 侧：propertyStart = u32@0x24 + 0xCE2141CC，propertyCount = u8@0x43 ^ 0x86。

### 83.2 全量验证（不是抽样）
- 115,596 行：propertyStart/count 在全部 88,902 个 typeDef 上**精确铺瓦 [0,115596)，0 处不规则**；
- getter 112,107 个 / setter 19,907 个，索引**全部 < 该类型 methodCount**（0 越界）；
- 属性名用已有字符串 cipher 解码（packed = len<<24|off）：DateTimeFormatInfo 依次解出
  CultureName / Culture / LanguageName / InvariantInfo / CurrentInfo / AMDesignator / Calendar / …，与 6.4 oracle 同序；
- 与 6.4 oracle 对拍（新增 tools/validate_properties.py）：corelib 类 shared 类型 1,318 个里
  **1,272 个属性序列完全相同（96.5%）**，属性名 Jaccard **0.9899**；全量差异来自版本新增属性
  （7.1 的 UriBuilder.Fragment、MHYAsyncLoad 的新属性等）与游戏类型跨版本改名/混淆；
- 全量 line-match 14,996 条，说明格式（可见性 / get; set; / 类型）与参考实现一致。

### 83.3 实现与产物
- profile 新增 `property_defs` / `property_stride` / `td_property_start` / `td_property_count` /
  `property_mask` / `property_name_add` / `property_get_sub` / `property_set_xor`（7.1 常量见 src/derive/layout71.rs 注释）；
- engine 新增 `td_prop_start` / `td_prop_count` / `property_row`；
- dump_gen 的 Properties 段优先用真实表（profile 无表时保留旧合成回退）；可见性/修饰取自 getter（缺则 setter）方法 flags；
- 产物：`~/gire/out/71/dump.cs` 125,190,007 B -> **127,953,647 B**；Properties 行 **63,117（合成）-> 115,596（真实）**，
  新增 52,479 条是旧合成遗漏（accessor 方法名被混淆、无 get_/set_ 前缀的属性），221 条属性名为空（metadata 本身空名）；
- `cargo build --release` / `cargo test --release`：17 passed / 0 failed。

### 83.4 附注
- `profile.fields`（hdr 0x158）现确认就是 propertyDefs 表；新增的 `property_defs` 与之同源，历史 `fd_base` 从未被消费；
- 中间 u16@+6 列语义未定（疑似 attrs/token），不影响 Il2CppDumper 兼容输出；
- 下一步候选：propertyDefs 接入 DummyDll/JSONL（PropertyDefinition 行）、事件表（若 metadata 保留）、attribute 参数。


## 84. DummyDll 属性表接入：Property / PropertyMap / MethodSemantics（2026-10-18）

> 不是需求，是执行记录。目标第 2 轮。

### 84.1 导出侧（src/dummy_export.rs）
- 新增 P 记录（每类型、metadata 顺序）：`{k:"P", id, name, get, set}`；
  get/set 是**全局方法表索引**（propertyDefs 的每类型方法索引经 per_type 解析；-1 = 无 accessor）；
- 7.1 实测 **115,596 条 P**（与 dump.cs 属性行一致）；dummy.jsonl 178,907,427 -> **186,487,969 B**；
- main.rs 的 `dump-gen --dummy-out` 汇总行同步打印 properties 计数。

### 84.2 生成器侧（tools/dummygen）
- Property 表：签名按 accessor 重建（getter -> 返回类型 + 索引参数；set-only -> setter 末参类型 + 其余参数），
  calling convention 0x08（`BlobEncoder.PropertySignature`，实例属性带 HASTHIS）；
- PropertyMap：每类型一行，FirstProperty = 该类型首个 Property 行（类型按 tdi 顺序、属性按 metadata 顺序 ⇒ 行连续）；
- MethodSemantics：getter -> Getter、setter -> Setter，共 **132,014** 行（112,107 + 19,907，与 propertyDefs 完全一致）；
- 内置校验：Property=115,596 / PropertyMap=30,226 / MethodSemantics=132,014；逐行检查签名首字节含 0x08 且至少一个 accessor。

### 84.3 独立验证
- 用独立 System.Reflection.Metadata 程序（不复用生成器代码）读回：表计数一致；
  DateTimeFormatInfo 属性依次为 CultureName / Culture / LanguageName / InvariantInfo / CurrentInfo /
  AMDesignator / Calendar / OptionalCalendars，accessor 解析为 get_CultureName、get_AMDesignator + set_AMDesignator 等；
- CLR `Assembly.LoadFrom` 失败（TypeLoadException: System.Object 必须来自 corlib）——这是"单程序集自包含"
  设计（我们自建 System.Object 等 core 类型）的既有性质，不是本轮回归；metadata/表结构层验证通过。

### 84.4 产物
- DummyDll.dll 93,113,344 -> **96,367,616 B**（+Property 115,596 / PropertyMap 30,226 / MethodSemantics 132,014）；
- `cargo build --release` / `cargo test --release`：17 passed；
- 下一步候选：事件表、attribute 参数 blob、il2cpp.h。


## 85. 真实 eventDefs 表定位 + DummyDll 事件（2026-10-18）

> 不是需求，是执行记录。目标第 2 轮。

### 85.1 定位（运行时 EventInfo 缓存构建器反汇编）
- 0x140515AE0 = EventInfo 缓存构建器（结果写 klass+0x38，元素 0x30）；邻近 0x1405163B0 等为同类迭代器；
- 表锚点 hdr[0x64] + 0xE6130C67 -> body 0x43A8；行 stride **14**；
- 行布局 {u32 name, u32 type, u16 remove, u16 raise, u16 add}；
  mask(i) = ((i*0x9C54 ^ 0x1F0DA79F) * 0x1BF89D8B64959BB7 + 0x295EE0EBA6CAFAEA) >> 15；
  name = (raw ^ mask) ^ 0x05C273ED；type = (raw + 0x979C7DA9) ^ mask；
  remove = ((raw + 0x38EB) ^ mask) & 0xFFFF；raise = ((raw + 0xFFFFE40A) ^ mask) & 0xFFFF；
  add = ((raw ^ mask) ^ 0x7D45) & 0xFFFF；
- typeDef eventStart = u16@0x38 + 0xFFFFD6AB；eventCount = u8@0x44 ^ 0xB5。

### 85.2 全量验证
- **628 行 / 225 类型**：eventStart/eventCount 在全部 88,902 个 typeDef 上精确铺瓦 [0,628)，0 处不规则；
- 行内 type 索引全部 < typearr 长度 683,568（0 非法）；名称经字符串 cipher 解码（AssemblyLoad / DomainUnload /
  ProcessExit / Elapsed / KeyGenerated / afterScriptRunDelayedDynamicFrameRate …）；
- add/remove 列在未混淆类型上落到 add_*/remove_* 方法（AppDomain：add_AssemblyLoad idx 30、remove_AssemblyLoad idx 31，
  与 typeDef methodCount=36 的运行时方法数组顺序一致）；混淆类型无法按名字复核，但索引均 < methodCount；
- raise 列 628/628 全为 0xFFFF（7.1 元数据未保留 raise，与参考 DummyDll 的 Fire 语义一致——无 raise 就只发 add/remove）；
- 独立 SRM 程序读回 DummyDll：Event 628 / EventMap 225 / MethodSemantics 133,270（属性 132,014 + 事件 1,256），
  事件类型解析为真实委托类型（AssemblyLoadEventHandler / EventHandler / ElapsedEventHandler …）。

### 85.3 接线与产物
- profile：新增 EventMaskChain（64-bit 乘数，不能复用 FieldMaskChain）+ event_defs/event_stride/td_event_start/
  td_event_count/event_name_xor/event_type_add/event_remove_add/event_raise_add/event_add_xor（7.1 常量见 layout71.rs）；
- engine：td_event_start / td_event_count / event_row；
- dummy_export：新增 E 记录；tools/dummygen：Event + EventMap + MethodSemantics(Adder/Remover/Raiser)；
- dump.cs **不输出 Events 段**（与 Il2CppDumper StructGenerator 参考格式一致；参考实现的 events 只出现在 DummyDll 中）；
- 产物：DummyDll.dll 96,367,616 -> **96,388,096 B**；dummy.jsonl 186,487,969 -> **186,550,006 B**；dump.cs 不变（127,953,647 B）；
- cargo test：17 passed / 0 failed。


## 86. DummyDll 与参考实现对齐：Token / Attribute 标记 + 参数归属修复（2026-10-18）

> 不是需求，是执行记录。目标第 3 轮。

### 86.1 参考实现差异盘点（独立读取 bundled Il2CppDummyDll.dll）
参考 DummyDll 的 5 个标记类型（全部 string 字段 + 无参 ctor）：
AddressAttribute(RVA/Offset/VA/Slot)、AttributeAttribute(Name/RVA/Offset)、FieldOffsetAttribute(Offset)、
MetadataOffsetAttribute(Offset)、TokenAttribute(Token)。参考实现还生成 TokenAttribute（type/field/method/
property/event）、AttributeAttribute（无法还原的属性实例；RVA/Offset 来自运行时 customAttributeGenerators，
静态不可得）以及字段/参数 Constant（下一轮）。

### 86.2 本轮实现
- 标记类型 2 -> 5（字段布局与参考逐字一致；+10 字段 / +5 ctor）；
- **TokenAttribute**：type 0x02000001+tdi、field 0x04000001+row、method 0x06000001+gmi、
  property 0x17000001+propRow、event 0x14000001+eventRow，共 **1,378,740** 条；
- **自定义属性实例**：dummy_export 新增 A 记录（tok/tdi/name/ctor），7.1 共 **70,692** 条；
  - 与参考相同的"可还原"判定（属性类恰好 1 个方法且为无参 .ctor）-> 真 CustomAttribute（blob 01000000）；
  - 其余 -> AttributeAttribute(Name=类原名)；RVA/Offset 省略（运行时生成器指针，静态不可得）；
- property/event 记录补充 row 字段，用于 token 与 metadata handle 定位；
- **修复两个既有 DummyDll 缺陷**（此前版本都存在，dnfile 只统计行数所以从未暴露）：
  1) MethodDef 的 ParamList 游标与参数总数共用一个变量 —— 旧产物所有 MethodDef 的 ParamList 都等于
     paramTotal+1，任何方法都不"拥有"参数；现分离 paramRows（游标）/paramTotal（计数）；
  2) Parameter.SequenceNumber 恒为 1 —— 现为方法内 1..n。

### 86.3 验证
- 生成器内置：customAttrs = **2,491,027** = 1,041,595（Address/FieldOffset）+ 1,378,740（Token）+ 70,692（属性实例）；
  types=88,907（+5）、fields=440,182（+10）、methods=733,447（+5）；CustomAttribute 抽样 600 条 prolog/命名参数全部合法；
- 独立 SRM 程序读回（不复用生成器代码）：
  - System.LocalDataStore（token 0x200008B）：TokenAttribute Token=0x200008B + AttributeAttribute Name=ComVisibleAttribute；
  - Param row 2（"fmt"）：ParamArrayAttribute；参数归属与 seq 正确（Locale.GetText: msg seq1；第二重载 fmt/args seq1/2）；
  - Property row 0x42（PrimeGeneratorBase.PrimalityTest）：TokenAttribute 0x17000042 + AttributeAttribute Name=ComVisibleAttribute；
- 产物：DummyDll.dll 96,388,096 -> **145,609,728 B**；dummy.jsonl 186,550,006 -> **193,164,322 B**；dump.cs 不变（127,953,647 B）；
- cargo test 17 passed。


## 87. DummyDll Constant 表 + MetadataOffsetAttribute（2026-10-18）

> 不是需求，是执行记录。目标第 4 轮。

### 87.1 数据与接线
- 字段默认值表 75,548 行（已有），本轮导出到 DummyDll：
  - 可表示为 CLR Constant 的 kind（bool / char / s8..u64 / f4 / f8 / str）-> **Constant 74,632 行**；
  - 其余 kind（class / valuetype / generic 等）-> **MetadataOffsetAttribute(Offset=值 blob 的 body 偏移) 916 条**；
  - 74,632 + 916 = 75,548，与默认值表行数精确相等（无静默遗漏）。
- dummy_export 的 F 记录新增 cv（{"t":kind,"v":"value"}）与 mo（u64 偏移）。
- dummygen：字段 flags 不再无条件清掉 Literal/HasDefault（HasDefault 只在写 Constant 时置位）；
  AddConstant 按类型写入 bool/char/全部整数/float/double/string；const 字段没有实例偏移，
  MetadataOffsetAttribute 与 FieldOffsetAttribute 独立判断（修复了第一版把 MetaOffset 判断放在
  "有实例偏移"的 continue 之后导致 916 条全部漏发的问题，计数暴露后立即修正）。

### 87.2 验证
- 生成器内置：Constant = 74,632（与期望相等），抽样 300 条逐条解码并核对 HasDefault 标志；
  customAttrs **2,491,943** = 1,041,595（Address/FieldOffset）+ 1,378,740（Token）+ 70,692（属性实例）+ 916（MetadataOffset）；
- 独立 SRM 读回（不复用生成器代码）：
  - System.Int32.MaxValue = 2147483647（Int32；Literal + HasDefault + Static）；
  - System.Boolean.TrueLiteral = "True"（string Constant）；
  - System.DayOfWeek.Monday = 1（enum 常量按底层 Int32 写入）；
  - <PrivateImplementationDetails> 的 class-kind 默认值字段带 MetadataOffsetAttribute(Offset=0x...)，且无 Constant 行；
- 产物：DummyDll.dll 145,609,728 -> **146,508,800 B**；dummy.jsonl 193,164,322 -> **203,232,915 B**；dump.cs 不变（127,953,647 B）；
- cargo test：17 passed / 0 failed。


## 88. 参数默认值表定位 + DummyDll Parameter Constant（2026-10-18）

> 不是需求，是执行记录。目标第 5 轮。

### 88.1 表定位（推翻旧笔记的"未定位/窗口未解"结论）
- 旧笔记把 hdr[0x1D0] 的 12B 行表 key 当成"paramStart 编码 + 未解窗口"，参数默认值一直暂缓。
- 本轮重新反汇编访问器 **0x1405287A0** 并对全表做结构验证：
  - base = body + (hdr[0x1D0] ^ 0x07D0BBF9)，size = hdr[0x18] + 0xA1C835BE，stride 12，rows = **25,374**；
  - 行 = {parameterIndex u32, valueTypeIndex u32, dataOffset i32 (-1 = 无值)}，按 parameterIndex 升序；
  - 值存放于共享 blob：body + (hdr[0x128] ^ 0x371354A2) + dataOffset（与字段默认值同一 blob）。
- **决定性验证（全量）**：25,374 个 key 全部 < 参数总数 548,400；对应参数 **100% 带
  ParameterAttributes.Optional|HasDefault (0x1010)** —— 即这些行恰好就是全部可选参数；
  15,595 行有值，9,779 行 dataIndex = -1。旧"key 是编码 paramStart"是对运行时算术的误读；
  key 就是全局参数索引，升序可直接二分。

### 88.2 接线
- profile 新增 param_defaults_size（hdr[0x18] + 0xA1C835BE）；engine 新增 param_default_base/rows 与
  param_default(gpi) 二分查找；dummy_export 的参数记录新增 a（ParameterAttributes）/cv/mo，复用
  enc_default（与字段默认值同一套 kind 判定）。
- dummygen：Parameter 行按 metadata attrs 写 Optional 等；**HasDefault 与 Constant 行严格一致**——
  dataIndex=-1 的 9,779 个 Optional 参数不写 HasDefault（避免"有 flag 无 Constant"的非法元数据；
  参考实现会保留 dangling flag，这里选择合法化并在文档说明）；另 3 个无 CLR Constant 表示的参数默认值
  写 MetadataOffsetAttribute。

### 88.3 验证
- 生成器内置：Constant **90,224** = 74,632（字段）+ 15,592（参数）；metadataOffsets 919 = 916 + 3；
  params HasDefault=15,592、with Constant=15,592、mismatched=0；抽样 300 条参数 Constant 解码通过；
- 独立 SRM 读回：
  - System.TimeZoneInfo.GetUtcOffset(DateTime, bool forOffset = false)：forOffset HasDefault + Constant Boolean false；
  - 字符串默认值样本：MiHoYo.SDK.WebDelegate.InitDelegate::Invoke(url = "")、SetJoypadStatus(strType = "0") 等；
- 产物：DummyDll.dll 146,508,800 -> **146,666,496 B**；dummy.jsonl 203,232,915 -> **217,786,835 B**；
  dump.cs 不变（127,953,647 B）；
- cargo test：17 passed / 0 failed。


## 89. 最终审计：泛型参数名负结果 + 全量可复现校验（2026-10-18）

> 不是需求，是执行记录。目标第 6 轮（收尾）。

### 89.1 泛型参数名 / 约束（最后一次尝试，负结果）
- 6.4 oracle 类型头显示真实泛型参数名（List<T> / Tuple<T1,T2> / Lazy<T>），说明 6.4 metadata 保留；
- 7.1 侧检查：
  1) 字符串池：全池解码后 TKey / TValue / TResult 出现次数 = **0**（T/U/V 单字母大量存在，属普通标识符）；
  2) 数据区结构扫描：对 12/14/16B stride、所有字节对齐位置，要求「名称可解码为标识符 + owner 单调 +
     约束列合理」连续 ≥50 行 -> **0 命中**（startup-metadata 同样 0 命中）；
  3) 旧笔记 29 个字符串解码调用点逐一分析 = 0（§69 遗留）。
- 结论：7.1 的泛型参数名/约束与接口基接口一样**被剥离**；dump.cs 只能对 VAR/MVAR 以 object/*k0x13*/ 占位、
  类型头保持 List`1 形式。不是"没找到"，是元数据无此数据。

### 89.2 全量可复现校验（tools/final_verify.sh + tools/final_verify.py）
- 一条命令重建全部工件：mhydump dump-gen（dump.cs/script.json/attributes/images/dummy.jsonl）
  + dummygen（DummyDll），可选 WITH_LITERALS=1 重跑 gi-stringliteral；
- 断言：7 个文件大小 + dump.cs 类型/方法/属性计数 + dummy.jsonl 六类记录数 + attributes/images/literals 计数；
- 2026-10-18 实测：**全部 PASS，端到端 31.7s**（dump.cs 127,953,647 B、DummyDll 146,666,496 B、
  dummy.jsonl 217,786,835 B 等，与 71-final-status §2 完全一致）。
- 结论：静态可解数据已全部恢复且可从干净构建复现；剩余项均为已证不可得 / 需运行时数据，
  详见 docs/re/71-final-status.md §3.2。

## 90. R19：metadataUsage / stringLiterals 表解码（2026-10-18）

> 触发：用户要求沿"未解密内容"找可疑函数与关键解密点。以下全为实测。

1. 运行时解析器 0x140524250（8 分支 jump table）读 metadata usage：
   - usage 索引表 = body + (hdr[0x19C] ^ 0x159FBC84)；maskA(i)=(((i*0x6536)^0x138D67F3)*0x44B1AAD4+0x1F9EA55AD057D0)>>0x15 *0xD0DC29D5；
   - pair 表 = body + (hdr[0x14C] ^ 0x2F249C2F)；handle=raw4^maskB(j)^0x5CD30101，kind=handle>>29；
   - 全量 **311,730 usage / 788,057 pair**，kind 分布 1:376,243 / 3:84,875 / 6:185,864 / 5:137,466 / 7:2,564 / 4:1,035 / 0:10。
2. stringLiteral 分支（kind 5）：offset 表 body+(hdr[0x88]+0xF3C0B2FE)、数据 body+(hdr[0x13C]^0x28B1D785)、
   解密器 0x140526BD0（唯一 caller 0x14052460F）：key=(((seed*M1)^X1)*M2^X2)*M3，per-qword += 0x70BA8080760AC800。
   解码 **86,108** 条，与 literals.json 逐条一致（参考工件保留内嵌 NUL；旧 27 条差异由此而来）。
3. 属性参数结论修订：slot 0x118 = 成员→属性实例表；slot 0x1A8 add 0xA8B3BA59 = body 0x9BACA4 属性类型数组；
   4 个属性查询 API（0x1404B2400/2710/2C90/5353DC）经 0x140526AF0 只返回 attribute klass，全程序无属性对象构造 ⇒
   属性参数在构建期丢弃，运行时不需要。
4. 修正旧记录：body 0xA03E64 起是每方法 invoker 索引表（slot 0x200 add 0xB43E0EB1，733,481×u32），不是属性数据。
5. 新增 tools/inspect_usage_tables.py（2.8s，输出 OK）；文档 docs/re/71-usage-tables.md；同步更新
   metadata-loading-flow / remaining-static-limits / gap-inventory / 71-final-status。
6. 下一步（R20）：把 usage/literal 表接入 Rust 流水线，使 script.json 的 ScriptString/Addresses 与 Il2CppDumper 语义一致。
## 91. R20：metadataUsage / stringLiteral 接入 script.json（2026-10-18）

> 目标轮次：把 R19 解出的表接入流水线并全量验证。

1. 新增 `src/usage_tables.rs`：usage 索引表 / pair 表 / literal offset 表 / literal 数据 / 0x140526BD0 cipher 的 Rust 实现，
   `scan_usages()` 返回 groups/pairs/kind 直方图；`literal(i)` 解密单条字面量。
   样本测试（`#[ignore]`，需 MHY_SAMPLE_EXE/MHY_SAMPLE_DAT）：groups=311,730 pairs=788,057 kind5=137,466，
   literal(0..7)=i,m,s,u,x,evt,"",navMeshData；Python 侧 `tools/inspect_usage_tables.py` 结论一致。
2. `script.json` 接线（src/dump_gen.rs + src/script_json.rs）：
   - ScriptString 137,466 条（kind5；Value 精确）；
   - ScriptMetadataMethod 84,875 条（kind3；`Method$<类型>.<方法>()` + MethodAddress=RVA；977 条无代码指针=0）；
   - Addresses 维持 460,313（方法指针数组；generic/invoker 数组未定位）；
   - **Address 字段=0**：GI 7.1 无静态 usage slot（生成代码以立即数 usage 索引调 0x140524250，结果缓存在运行时
     registration 数组；exe 内无编码 token，已搜）。语义偏差已在代码注释 + docs/re/71-usage-tables.md §3 标注。
   - 未接线：kind6 185,864（需 methodSpecs）、kind1 376,243、kind7 2,564、kind4 1,035。
3. 验证：
   - 全量比较：137,466 条 Value 全部 ∈ literals.json（0 例外），MethodAddress 除 0 外全为合法 RVA；
   - `tools/final_verify.py` 增加 script.json 两个计数断言 + 新 size（176,561,152）；
   - `tools/final_verify.sh` 全 PASS；`cargo test --release` 通过。
4. 下一步：Addresses 语义补全（genericMethodPointers/invokerPointers）、kind1→ScriptMetadata、kind6→methodSpecs；
   然后回到泛型参数名 / 接口基接口的运行时来源追查。
## 92. R21：Addresses 按 Il2CppDumper 语义合并（2026-10-18）

> 目标轮次 R2：补全 script.json Addresses 的参考语义。

1. 定位静态代码注册数组（`0x1422DF450`）：
   - +0x8 → invokerPointers 数组（VA 0x1427D5EC0）；计数由 hdr[0x200] 每方法表的最大值+1 推导 = **25,651**
     （首处非镜像指针在 79,766，>= 25,651，且表中无 >1e6 的合法值）；
   - +0x78 → genericMethodPointers 数组（VA 0x142238130）；计数由 0x74 表 `(hdr[0x110]^0x1AB6109A)/6` 行数 +
     u16 列最大值+1 交叉验证 = **12,827**（数组首个非镜像指针正好在第 12,827 项）；
   - 方法指针数组仍用 locate_methodptrs（.rdata 最长 il2cpp 指针段，460,313；实测位于 VA 0x142452BE8 = codeReg+0x18+8）。
2. 新增 `src/code_addresses.rs`：合并三类指针 → RVA → 排序去重（丢 0），样本测试断言 12,827 / 25,651 且地址严格递增；
   实测 **Addresses = 483,496**（460,313 + 12,827 + 25,651 = 498,791，去重后 483,496）。
   reversePInvokeWrappers / unresolvedVirtualCallPointers 两张数组未定位，运行时日志显式报告（不静默）。
3. 验证：script.json 176,561,152 → **176,764,249 B**；final_verify.py 增补 Addresses=483,496 断言；
   `tools/final_verify.sh` 全 PASS；`cargo test --release` 通过（新增 code_addresses 样本测试）。
4. 下一步：ScriptMetadata（kind1/kind7 归类仍待 jump-table 语义确认）、kind6 methodSpecs；然后回到泛型参数名/接口基接口。
## 93. R22：泛型参数名 / 接口基接口的运行时来源追查（2026-10-18）

> 目标第二轮：沿用「反汇编解析器→表锚点」方法追查这两项。

1. 泛型参数名（新证据）：
   - identifier 字符串堆 0 命中 TKey/TValue/TResult（R18）；新增 literal 表检查（86,108 条，R19 解密）：同名 0 条；
   - 新增 tools/scan_generic_tables.c：body/startup 扫描标准 16B genericContainers 与 14B genericParameters，
     containers = 0/0，genericParameters 仅 11 个 0xB9C98C 附近的全零退化候选 / 0 ⇒ 标准形式表不存在。
2. 接口基接口（新证据）：
   - 7.1 自身 dump：`System.Resources.ResourceReader : IResourceReader, IEnumerable, IDisposable`，
     6.4 oracle 相同 ⇒ 实现类接口列表已扁平化；而 interface 类型本身无基接口行（哨兵）；
   - 运行时判定函数 0x140513260 反汇编：遍历 klass+0x20 接口指针数组、无基接口递归 ⇒ 运行时不需要该边。
3. 结论（写入 docs/re/71-generics-interface-origin.md）：两项均为构建期裁掉而非解析未遂；若要补只能跨版本推断
   （6.4 oracle 泛型名 ~85%、接口基接口 131 条）。
4. 唯一未证点：GI runtime 的 genericParameter 结构是否存在（可从 Il2CppType kind 0x13/0x1E 分派入口继续）。
5. 验证：final_verify.py 仍全 PASS（工件未变）；docs 同步更新。
## 94. R23：泛型参数表定位并接线（2026-10-18）

> 本轮推翻 R18/R22 的"泛型参数名已剥离"结论：表存在，逐行加密。

1. 定位：Class::FromIl2CppType 0x14050E7A0 的 30 项 type-kind 跳表中，VAR/MVAR 分支
   (0x14050E897/0x14050E986) 计算
     base = body + (i32(hdr[0x174]) + 0xCED1EDB1) = body 0xDF8708
     mask(i) = ((i*0x6F1C0337A0897415 + 0x31061C4212D60D89) >> 22) & 0xFFFFFFFF
     nameIndex = (u32[row+0] + 0x9E5299B1) ^ mask ; ownerTI = ((u16[row+0xC]+0xA8E2) ^ mask16)
   然后调 0x14050EDF0（Class::FromGenericParameter，kuna 反编译确认只读这两列）。
2. 计数：header 无 count；typearr 中 VAR/MVAR 最大 data=5,795 ⇒ 5,796 行，与连续可解区间一致。
3. 全量结果：5,796 行；5708 个可打印名字 + 81 个单控制字符混淆名；distinct 47；
   TKey 289 / TValue 305 / TResult 97 / T 2835 / TRest 1；owner 分组 4,425。
4. 接线：Meta 新增 gp_base/gp_count/generic_param_name；dump_gen::render_kind 的 0x13/0x1E 改用真实名字
   （控制字符名保留 object/*k0x13*/ 占位）。dump.cs 127,953,647 → 127,769,231 B；
   Dictionary`2 字段/接口现为 TKey,TValue，ValueTuple`8 为 TRest。
5. 验证：新增 sample-gated test generic_param_names_sample（5,796 / T / TKey / TValue / TRest）；
   final_verify.py 更新 dump.cs 尺寸后全 PASS。
6. 未解：泛型约束（accessor 不读；标准约束表 0 命中）、owner 容器语义、DummyDll GenericParam 名字接线。
## 95. R24：泛型容器表解码 + DummyDll GenericParam 真实名字（2026-10-18）

1. 容器表：参数行 +0xC = genericContainerIndex；容器表 = body+(hdr[0xC8]^0x8D701A3)，16B 加密行，4,425 行。
   解码（Class::FromGenericParameter 0x14050EDF0）：
     mask2(V) = ((V*0x8187 ^ 0x42D5A190)*0x7B2D0E18 + 0xB6F00C08) ^ 0x7A3E254D
     data == mask2(V)+0xE276AF5D  ⇒ VAR（owner=typeDefIndex），否则 MVAR（owner=methodIndex）
     owner = attrs ^ (mask2(V)+0x71555646) ^ 0x5C56350B
   验证：ValueTuple`1..`8 → T1..T7/TRest；Dictionary`2 → TKey/TValue；List`1 → T；前 8 个 MVAR 容器
   分别对应 ValueTuple.Create<T1..T7> 方法（method 800..806），V0 = method 769。
2. DummyDll 接线：dummy_export T 记录新增 "gp" 数组（按 arity 对齐，控制字符名→空串）；dummygen 用真实名字
   AddGenericParameter，并在 Verify 中断言 ValueTuple`8（第 8 个=TRest）与 Dictionary`2（TKey,TValue）。
3. 工件：dummy.jsonl 217,786,835 → 218,514,639 B；DummyDll.dll 146,666,496 → 146,667,520 B；
   dump.cs/script.json 不变；tools/final_verify.sh 全 PASS。
4. 未接线：泛型**方法**的参数（DummyDll GenericParam 行仍 1,195 类型级；metadata 总 5,796，方法级约 4,601）；
   泛型约束仍未解；下一轮可接方法级 GenericParam 与约束 accessor。
## 96. R25：方法级泛型参数接线，DummyDll GenericParam 全量 5,796（2026-10-18）

1. 引擎：容器 owner 解码同时产出 type/method 两张表（MVAR owner=methodIndex），新增
   Meta::method_generic_param_names；dummy_export 的 M 记录新增 "gp" 数组（按参数槽对齐）。
2. dummygen：
   - MethodDef 创建时收集方法级 GenericParam；因 ECMA 要求按 owner 编码索引排序
     （TypeOrMethodDef = (row<<1)|tag，TypeDef/MethodDef 按 row 交错），统一收集后排序再 Add；
   - 嵌套在泛型类型里的类型名字无 `N 后缀，arity 取 max(name arity, gp 长度)，
     否则会丢掉嵌套类型的泛型参数（此前 GenericParam 只有 4,294）。
   - Verify 断言：ValueTuple`8 第 8 参数=TRest、Dictionary`2=TKey/TValue、存在 T1/T2 泛型方法。
3. 结果：GenericParam = **5,796**（类型级 2,697 + 方法级 3,099），与 metadata 参数表一致；
   dummy.jsonl 224,397,559 B；DummyDll.dll 146,724,352 B；dump.cs/script.json 不变。
4. 验证：tools/final_verify.sh 全 PASS；spot checks 通过。
5. 仍未解：泛型约束（参数行 +4/+6/+8 未找到约束表读取路径；+6 已确认是 variance 位，
   被 0x140512880/0x14051A330 的接口变体判定使用）。
## 97. R26：泛型约束负结果复核 + 容器行字段补全（2026-10-18）

1. 读取泛型参数锚点（hdr[0x174]）的 8 个函数全部反编译完毕（kuna，/tmp 下 ASCII 样本路径）：
   0x14050E7A0/0x14050EDF0/0x1404B8990/0x1404C7E90/0x1404E4A90/0x140512880/0x14051A330/0x1405472D0/0x140547410。
   结论：没有任何路径把参数行 +4/+8 当约束 start/count 读取；FromGenericParameter 只读 name 与 owner container；
   变体判定用 +6 低 2 位（variance）；类型对象解析用 +0xA（参数位置）。标准约束表扫描 0 命中。
   ⇒ 判断 7.1 构建期丢弃泛型约束（同接口基接口），保留极小不确定性（未发现的独立校验路径）。
2. 容器行 16B 字段补全：{+0 kind/data, +4 paramStart, +8 argc, +0xC ownerAttrs}；
   start=u32[+4]^m2^0x2BAD4D8C、argc=u32[+8]^m2^0x07F8A45C（0x1404B8990/0x1404E4A90 反编译确认）。
   与 R25 的 5,796 = 类型级 2,697 + 方法级 3,099 分组一致，方法级泛型参数接线得到二次验证。
3. 本轮无工件变化；final_verify 仍应 PASS（未改代码）。文档 71-generic-params.md §3 已更新。

## 98. 跨版本通用解法：模块定位 + 形态迁移 + 方法设计（2026-10-18）

1. **模块定位（新增）**：4.3.0–4.7.0 的 MHY 头不在 YuanShen.exe，而在
   YuanShen_Data/Native/UserAssembly.dll；把 DLL 作为 --exe 传给 derive 后全部成功（cipher + typeDef）。
   4.2.0 的 exe/DLL 都无 MHY 魔数，仍失败。derive 覆盖面 20/26 → **25/26**。
2. **头结构随机化证据**：typeDef 槽位逐版漂移（6.0 0xB8 / 6.4 0xE0 / 6.7 0x1E0 / 7.0 0xC4 /
   7.1 0xDC / 5.4 0x1E8 / 4.8 0x60），op 在 Add/Xor 间翻转；body 内 typeDef 基址 7.0 0x10B5E18 vs
   7.1 0x48F3FD8 ⇒ 槽位与偏移都不能跨版搬运。
3. **访问器形态稳定（新工具/新证据）**：
   - tools/version-triage/loadsites.py：缓存每个模块全部 mov reg,[rip+hdr_global] 加载点及
     去常数指令指纹（数字→#，3-gram 倒排 + Jaccard）；7.1 约 72 s。
   - tools/version-triage/shape_transfer.py + docs/re/artifacts-7.1.0/shape-seed.json（25 条 7.1 语义，
     常量即数据）：匹配目标函数并读回 (slot,op,imm)。typeDef 在 7.0/6.7/6.4/6.0/5.4 上 **5/5 与 derive
     独立结果逐位一致**；4.8 匹配分仅 0.25、结果不符（形态差异，待单独处理）。
   - 24/25 语义在 6 个目标版本上都产出候选；未过数据验收的候选（如 7.0 td_size 0x5CDA78 不被
     70 整除）明确标注为原始候选，不当作结论。
4. **常数在代码里被直接证实**：7.1 方法 builder 0x1405155AD 内联 md_pmask 全链常数
   （0x4E94/0x62D8B7B8/0x7572748A/0x1F4D9EEA/0x6E8931D6）与 method_defs 槽 0x1E0/0x2EE480FB；
   事件 builder 0x140515E42 内联事件表全部常数；字段/属性 builder 0x1405162A9 内联字段基址、
   property name_add/get_sub/set_xor 与共享 mask 链；stride 以 lea 链编码（字段 10、方法 26）。
   ⇒ 「算法=函数形态，常数=形态内立即数/位移」成立，列常数/掩码可走「模板常数迁移」。
5. 文档：新增 docs/re/generalize-method.md（分层流水线 L0–L6、实测覆盖、未解项与下一步）；
   REQUIREMENTS 增补 R12。
6. **L5 验收器（size 语义）已接入**并给出独立验证：size 必须整除 stride，候选里唯一通过者被选中。
   6.4.0 迁移得到 td_size/70=77,262（减 2 尾部 padding = 77,260）与 md_size/26=631,108（减 1 = 631,107），
   与 6.4Dump.cs 逐行统计的类型 77,260 / 方法 631,107 **完全吻合**；7.0 得到类型 86,930 / 方法 713,955
   （无 oracle，7.1 为 88,902 / 733,442，量级一致）。6.7/6.0/5.4 的 size 候选未过验收（扫描覆盖/匹配歧义），
   4.8 形态差异失败——均显式标记，不当作结论。
7. 未闭环：L5 验收器接入候选选择（已做 size 语义，其余语义待做）；L4a builder 常数模板迁移（下一步主线，
   先在 7.0 闭环）；
   L4b 数据自解兜底（colsolve 需换成 schedule 密码）；.upx0 常数（flags/bitfield）；4.8 形态差异；
   4.2.0 头定位。

## 99. R28 数据自解 typeDef 行布局：name/ns/fs/fc/ms/mc（2026-10-18）

R12 通用方法的关键一步：typeDef 行布局不再依赖 7.1 代码迁移，改为纯数据求解，并用 oracle 验证。

1. Rust 改进（src/derive/tables.rs + src/main.rs）：
   - StringColumn 新增 transform family（Add/Xor），JSON 与 CLI 都输出；此前只有常数 c，
     同一列两种族都可能、调用方无法判断（7.0/6.7 名字列是 XOR，6.4/6.0/5.4 是 ADD）。
   - tables 子命令同时运行 additive 与 xor 两个列搜索器（旧逻辑先 additive、非空就不再试 XOR，
     会漏掉另一种族的列）。
   - 字符串列采样改为“按列去重 raw”：空 namespace 的哨兵 raw 在 typeDef 上重复约 25%，
     旧采样 24 行几乎同值，常数交集不收敛（7.1 namespace 列 survivor 数万）。
   - 允许 len==0 的空名为合法，并在选择长度键 h 时计入空名投票；同时要求非空行 >= 8，
     排除 h = m 的平凡解。修正前 7.1 namespace 的 h 会被错选成 0x6F 而整列被拒。
2. 结果（mhydump tables --base 类型表基址，全表解码）：
   7.0.0 name 0x10 Xor 0x616B619D / ns 0x18 Xor 0x7351490A / fs 0x00 Add 0x20749BC2 /
   fc 0x32 Xor 0x6B9B / ms 0x20 Add 0x33AB5AF8 / mc 0x3C Xor 0x37E5；
   6.7.0 name 0x18 Xor 0x17FB1577 / ns 0x2C Xor 0x4AAC4BAB / fs 0x14 Xor 0x1D37F888 /
   fc 0x38 Xor 0xEB4C / ms 0x0C Xor 0x4DFA3BEC / mc 0x30 Xor 0x8EED；
   6.4.0 name 0x18 Add 0xE169AC15 / ns 0x20 Xor 0x468CB988 / fs 0x3E Xor 0x6FE9B568 /
   fc 0x78 Xor 0xD846 / ms 0x14 Add 0x7589193B / mc 0x28 Xor 0xE8D4；
   6.0.0 name 0x08 Add 0x85A69E32 / ns 0x0C Add 0x9FA88537 / fs 0x04 Add 0x6635464F /
   fc 0x28 Xor 0x787B / ms 0x14 Add 0x0BA968F3 / mc 0x32 Xor 0x1D76；
   5.4.0 name 0x3E Add 0xD13BCB2F / ns 0x42 Add 0xA1316236 / fs 0x08 Xor 0x5CB2D477 /
   fc 0x1A Xor 0xED8D / ms 0x36 Xor 0x6C8996BE / mc 0x56 Xor 0xF755；
   7.1.0 name 0x14 Add 0xE811F779 / ns 0x18 Xor 0x666769B5（与 profile 逐位一致）。
   行数：7.0 86,932 / 6.7 83,775 / 6.4 77,262 / 6.0 59,631 / 5.4 58,938；字段行 430,288 / 413,630 /
   384,410 / 304,855 / 285,057；方法行 713,953 / 687,452 / 631,104 / 475,153 / 515,379。
3. 验证：6.4 名字全表 77,232 条解码、99.94% 合法标识符；namespace 376 个 vs 6.4Dump.cs 377 个
   （Jaccard 0.9973）；6.4 方法行 631,104 vs md_size/26=631,108（差 4 行 padding）；类型行 77,262-2=77,260
   与 6.4Dump.cs 逐行统计完全一致。6 个版本解出的 namespace 样本集完全一致（含同一混淆 GUID）。
4. 影响：typeDef 行布局（name/ns/fs/fc/ms/mc + 行数）已不依赖代码迁移；L4a 模板迁移只剩其余表
   （方法/字段/参数/属性/事件/泛型）与 .upx0 常量（flags/bitfield）。
5. 验证命令：cargo test --release = 18 passed / 13 ignored；tools/version-triage/loadsites.py +
   shape_transfer.py 供表基址迁移；docs/re/generalize-method.md §3.2b 记录方法+表格。

## 100. R29 跨版本 typeDef 清单生成（数据驱动，7.1 逐字一致 / 6.4 与 oracle 吻合）（2026-10-18）

1. 新工具 tools/version-triage/type_defs_dump.py：输入 版本目录 + derive 工件 + tables --base JSON，
   输出 JSONL {i, ns, name, fieldStart, fieldCount, methodStart, methodCount}。解码规则严格按
   IndexTable 语义（Add: raw = plain + C；Xor: raw = plain ^ C；raw == sentinel_raw 表示无字段/方法；
   行号超过该模型拟合行数的尾部 padding 不读列，否则列偏移会越过行栅格读到下一表的数据）。
2. 六个版本全部产出（~/gire/out/cross/typedefs/<ver>.jsonl）：7.1.0 88,904 / 7.0.0 86,932 /
   6.7.0 83,775 / 6.4.0 77,262 / 6.0.0 59,631 / 5.4.0 58,938 行；每版 field 链与 method 链均为
   0 断裂，链尾分别等于 sum(fieldCount)/sum(methodCount)。
3. 验证：
   - 7.1：产出 (ns,name) 与既有 ~/gire/out/71/dump.cs 完全一致（85,709/85,709，Jaccard 1.0）；
     field 链尾 440,172、method 链尾 733,442 与 dump.cs 统计一致。
   - 6.4：type pairs 74,483 vs oracle 74,555（Jaccard 0.961）。差异全部是编译器生成泛型类的
     显示格式（metadata 名是 <>c__0 + arity，6.4Dump.cs 用 GenericParam 表重建为 <>c<T>），
     不是解码错误；字段行 sum = 384,411 与 6.4Dump.cs 字段行完全一致；方法 sum = 631,108 vs
     6.4Dump.cs 631,107（1 行 padding）。
   - 版本间 namespace 数 376/373/376/376/376/363，量级一致。
4. 意义：第一条跨版本数据产物，不依赖任何版本常数——布局来自 R28 的数据自解，基址来自 derive/
   形态迁移。仍未覆盖：typeDef 的 flags/bitfield/parent/接口/property/event/nested 范围列，
   方法/字段/参数表行布局与掩码，所以尚未到完整 dump.cs。
5. 复现：mhydump tables --base <类型表基址> --json → tools/version-triage/type_defs_dump.py →
   （校验脚本在 ~/gire/out/cross/validate_typedefs.py）。

## 101. R30 数据自解 typeDef 范围列（方法/字段/属性/事件）自动发现（2026-10-18）

1. 新工具 tools/version-triage/find_type_ranges.py：纯数据找 typeDef 行的「起始列+计数列」对。
   计数常量：多数类型无成员 ⇒ 该列 raw 众数 = plain 0 的编码（xor C=raw / add C=-raw），
   第 0 行 <Module> 作第二候选；起始常量：取一个计数为 0 的行，其起始 raw = 全 1 哨兵编码
   （xor C=raw^mask / add C=mask-raw）。全表铺瓦：start 非减、不与上一段重叠、gap 计数；
   重叠 > 4 即拒绝。count 偏移扫描到 stride+0x60，覆盖跨行存储的布局。
2. 六版本结果（start/end 均与 R29 用 typeDef 计数字段独立求出的 sum 吻合）：
   - 7.1.0：方法 0x08/0x3C → 733,442；字段 0x00/0x30 → 440,172；属性 0x24 Add 0xCE2141CC /
     0x43 Xor 0x86 → 115,596；事件 0x38 Add / 0x44 Xor 0xB5 → 628。（与 profile 逐位一致）
   - 7.0.0：方法 0x20/0x3C → 713,956（=md_size/26）；字段 0x00/0x32 → 430,290；
     属性 0x1C Add 0xF6929062 / 0x45 Add 0xDB → 112,949；事件 0x3E Xor 0x66AD / 0x44 Add 0x3A → 625。
   - 6.7.0：方法 0x0C/0x30 → 687,467；字段 0x14/0x38 → 413,644；属性 0x00 Add 0xF43F5BDC /
     0x44 Add 0x7C → 108,747；事件 0x34 Add 0xFD33 / 0x40 Xor 0x10 → 617。
   - 6.4.0：方法 0x14/0x28 → 631,108（=md_size/26）；属性 0x1C Xor 0x1AF4F14C / 0x3A Add 0x6D →
     99,320；事件 0x2A Add 0xE909 / 0x3B Xor 0x52 → 596；字段对未发现（count 偏移 0x78 越过
     行宽 0x46，属 IndexTable 跨行模型，见 R28 的 tables 模型）。
   - 6.0.0：方法 0x14/0x32 → 475,157；字段 0x04/0x28 → 304,855；属性 0x18 Xor 0x08B87A48 /
     0x38 Xor 0xFC → 77,319；事件 0x2C Xor 0xBA4E / 0x3D Xor 0xC0 → 508。
   - 5.4.0：字段 0x08/0x1A → 285,058；事件 0x18 Add 0x1255 / 0x20 Xor 0x33 → 486；
     0x32 Add 0x20A5 / 0x68 Add 0x6 → 35,864（疑似嵌套表，gap=0）；方法/属性对未发现。
3. 验证：7.1 四对与 layout71 逐位一致；各版本 end 与 R29 的 sum 字段独立互证；7.0/6.4 方法 end
   等于 md_size/26；事件 end 628/625/617/596/508/486 同源码量级一致。
4. 已知缺口：6.4 字段对、5.4 方法/属性对、嵌套/接口对多数版本（数组可跨类型乱序、接口含继承项，
   需要不同链判据）。下一步：把发现器并入 tables 子命令并生成 profile 草稿。

## 102. R31 类型清单并入属性/事件范围 + 逐类型 oracle 校验（2026-10-18）

1. 范围对发现器收紧：start 必须完全非减（bad == 0）；无缝时要求 end == sum(count)，否则按
   多段/重叠拒绝（5.4.0 的 35,864 行对即被拒并显式报告）。
2. type_defs_dump.py 接受 ranges JSON，每个类型行新增 propStart/propCount/eventStart/eventCount。
   属性对 = chain_rows>10k 且 end>5k；事件对 = chain_rows>=50 且 end<=5k；选中后用 sum==end 复核，
   失败显式拒绝。
3. 六版本结果：属性总数 115,596 / 112,949 / 108,747 / 99,320 / 77,319 /（5.4 被拒）；事件总数
   628 / 625 / 617 / 596 / 508 / 486（均与发现器 end 一致，7.1 与 profile 逐位一致）。
4. 逐类型 oracle 校验（dump.cs 按类型聚合属性行 vs 我们的 propCount）：7.1 比较 88,872 个类型，
   88,304 一致 = 99.36%；6.4 比较 75,764，75,179 一致 = 99.23%。差异集中在同名/嵌套类型的块名
   匹配和区间边界，不是列解码错误。
5. 已知缺口：5.4 属性对（数组重叠）；6.4 字段对（跨行 count 偏移 0x78）；嵌套/接口对多数版本。
6. 复现：find_type_ranges.py → type_defs_dump.py（5 参数：版本目录/derive/tables/out/ranges）→
   校验脚本在 ~/gire/out/cross/validate_props2.py。

## 103. R32 7.0 方法/参数表行布局：从代码提取并全量验证（2026-10-18）

1. 定位方法：先用 64 位掩码常量做指纹在 .text 里搜（numpy bytes.find，秒级），命中 327
   组 → 5 个站点/3 个函数：0x1404E5560（运行时方法缓存 builder）、0x1404E59E0（方法指针解析器）、
   0x1404F9750（方法元数据 decoder，参数解析）。避免了对 4,525 个加载点做全量 capstone 扫描
   （Python 会超时）。
2. 从这三处读出方法行布局（写入 docs/re/artifacts-7.0.0/method-layout.json，纯数据，带 provenance）：
   - 方法表基址 hdr[0x138] + 0xD37E9675；stride 26（lea 5*5+1）；掩码链
     mul 0x3639B538F896 / add 0xCC49CF2E948F28F / shr 13 / mul 0x3209B9A2 / add 0x066E3EE5EEBB7B78；
   - paramStart = raw[+4] + 0xAC706A39 - mask；paramCount = (raw8[+0x18] ^ 0x5B) - mask8；
     flags = raw16[+0x0E] - mask + 0x13；decl = raw[+8] - mask + 0x997E86CD；
   - 参数表基址 hdr[0x1FC] + 0xFC3EC0CE，stride 8，掩码链 mul 0x2F64C993DFFE / add 0xAB42C68E0D4A /
     shr 17 / mul 0x272E941C / xor 0x705880A8；name=(raw[+4]+0xDA14EDA6)^mask、type=(raw[+0]+0x8FE5701B)^mask。
3. 新工具 tools/version-triage/method_rows.py 应用布局并做数据验收（7.0.0 实测）：
   - 713,956 方法行（= md_size/26）；paramStart 哨兵 401,636 行且这些行 paramCount=0；
   - 非哨兵 paramStart 链 0 违例；sum(paramCount)=532,361；
   - 参数表 532,361 行 name/type 全部解码成功（0 失败），样本 msg/fmt/args/resourceFormat/p1；
   - flags 66 种取值、static(0x10)=83,868；decl 989 个哨兵，非哨兵值域待定。
4. 尚未定位：方法 name 与 returnType 列（其余偏移用现行掩码族未过全量验证，怀疑 mask2/另一条链）；
   decl 语义（token/container）。
5. 复现：python3 tools/version-triage/method_rows.py <版本目录> <derive> <sites> <layout>。

## 104. R33 7.0 方法表 name/returnType 补齐 + slot 负结果（2026-10-18）

1. 纠正 R32 的列归属：方法行 +0x08 不是 decl，而是 **name**——解析器 0x1404E59E0 把该列传给
   0x1404E0110（名字解析），且 (raw[+8] + 0x997E86CD) - mask 解码后全表 99.82% 是标识符
   （712,680 标识符 + 989 个 0xFFFFFFFF + 287 其它）。样本 .ctor/GetText/Format/
   mono_runtime_install_handlers。
2. returnType 无已知明文，改用窗口性质钉常数：value = (raw - mask) + C、真实值落在 [0,B)，
   对 200k 行求 A = raw - mask，A 必在长度 < B 的环形窗口内 → 唯一 C = 0xDF812A65；
   解码值 0..0x15390（86,928）、76,000 种不同取值。
3. 最终 7.0 方法行布局（docs/re/artifacts-7.0.0/method-layout.json v2）：
   paramStart +0x04 (raw+C)-mask C=0xAC706A39；name +0x08 (raw+C)-mask C=0x997E86CD；
   flags +0x0E raw16-mask+C C=0x13；returnType +0x10 (raw+C)-mask C=0xDF812A65；
   paramCount +0x18 (raw8^C)-mask8 C=0x5B。参数表布局沿用 R32（532,361 行 100% 解码）。
4. 负结果：slot 列候选 +0x16（i16，(raw-mask-0x3EBD)）与 virtual(0x40) 相关性不符
   （10,288 个 virtual 中 10,278 解成 -1）⇒ 候选不对/或 flags 位映射未定，slot 留待后续。
5. method_rows.py 现在同时输出 name/returnType 验收；7.0 全表：name 99.82% 有效、
   returnType max 86,928、paramStart 链 0 违例、参数表 100%。

## 105. R34 7.0 属性表行布局：代码提取 + 全表验证（2026-10-18）

1. 缓存构建器 0x1404E6180 读属性表：base = hdr[0x15C] ^ 0x368C9997，stride 10（lea x5 两次）；
   掩码链 mul 0xE0F8 / xor 0x22F6DA00 / mul 0x3AA8EE62 / add 0x49880E3C / xor 0x3E17E98E / add 0x7EC31F32。
   列：name = (raw[+0] ^ 0x5DC2119E) - mask；getter = raw16[+8] - mask + 0xFFFF945B；
   setter = (raw16[+6] ^ 0xFFFFC45A) - mask（0xFFFF = 无）。访问器是每类型相对方法索引。
2. 新工具 tools/version-triage/property_rows.py + docs/re/artifacts-7.0.0/property-layout.json。
   7.0 全表验证：112,949 行；属性名 99.94% 标识符；128,776 个非空访问器越出所属类型方法区间
   **0 个**；+8 列 61,967 个 get_ / 0 个 set_ ⇒ getter，+6 列 8,781 个 set_ / 0 个 get_ ⇒ setter；
   未混淆子集里 getter 17,153 / setter 5,761 与属性名严格配对（GI 属性名与访问器名独立混淆，
   故只作参考）。
3. 更正：shape-transfer 语义中的 fields（槽 0x15C）实际是属性表；7.0 字段表仍未定位。
4. 复现：property_rows.py <版本目录> <derive> <sites> <property-layout> <typedefs JSONL> <method-layout>。

## 106. R35 7.0 profile 草稿流水线 + 方法名跨版本对照（2026-10-18）

1. 新工具 tools/version-triage/profile_draft.py：把 derive 密码、typeDef 布局+区间、方法/参数/
   属性布局合成单一 profile 草稿 JSON（docs/re/artifacts-7.0.0/profile-draft.json）；缺块不静默，
   写入 unresolved 列表。
2. 7.0 草稿计数：类型行 86,932（有名字 86,900）、字段行 430,290、方法行 713,956（= md_size/26）、
   属性行 112,949、事件行 625。
3. 跨版本 oracle 性质对照：7.0 解码的前 200 个方法名 vs 7.1 dump.cs 前 200 个方法名，
   **逐位相同 170/200**（差异主要是 dump 把 .ctor 写成 ctor 与少量顺序差异）。corelib 方法序列
   相邻版本一致 ⇒ 方法 name 列、行序、掩码解码正确。
4. unresolved：字段表（name/type/attrs）、方法 slot 列、typeDef flags/bitfield/parent/nested 区间、
   泛型表、参数默认值表、usage/literal 表。
5. 复现：profile_draft.py <版本目录> <out> <derive> <tables> <typedefs> <ranges> <method-layout> <property-layout>。

## 107. R36 7.0 字段表：调用图定位 + 掩码解码（2026-10-18）

1. 新增 mhydump 子命令 str-cols（--base/--stride/--rows）：用派生密码对给定 (base,stride)
   跑两族字符串列搜索。Purpose: 发现没有 start/count 对的表（字段表）。
2. 负结果：105 个候选基址 × stride 10 无掩码扫描 **0 命中** ⇒ 7.0 字段列是逐行掩码的。
3. 改用调用图：名字解析器 0x1404E0110 的 52 个调用者中，0x1404EDB50 是惰性字段名访问器：
   - base = hdr[0x1D0] + 0xB98BE77F（0x17A2444），stride 8；
   - mask = (((i*0x1147E475DFA9)>>0x12) * 0x2CD0F4EE + 0xC16316113B52) >> 0x10（i 为绝对字段索引）；
   - name = (raw32[+4] ^ 0x6040B64C) - mask；
   - 访问器里 row = fieldStart_encoded + local + 0xDF8B643E，与 R30 解出的 fieldStart 常数
     0xDF8B643E 一致（互证）。
4. 新工具 tools/version-triage/field_rows.py + docs/re/artifacts-7.0.0/field-layout.json。
   7.0 全表验证：430,290 行；名字 429,297 标识符（99.77%）、793 其它、200 哨兵；typeDef 字段区间
   覆盖 429,297 行、993 行不可解码（恰为其它+哨兵），区间与表行数完全对齐。
5. profile 草稿已并入 field 块（profile-draft.json），unresolved 更新为 field type/attrs 列等。
6. 复现：str-cols 子命令；field_rows.py <版本目录> <derive> <field-layout> <typedefs JSONL>。

## 108. R37 7.0 字段表 type 列（窗口性质）+ 参数 type 列未决（2026-10-18）

1. 字段表 +0 列（type 索引）无已知明文，用窗口性质解：value = (raw - mask) + C，对 430,290 行
   求 A = raw - mask，环形窗口 232,881 ⇒ C = -min(A) = 0xA90E9923，解码 type 索引
   0..232,880、68,305 种不同取值、25% < 1000、top 取值各覆盖 7k–20k 字段（基础类型集中）。
   field-layout.json 增列 type（AddCSubMask32），field_rows.py 增加 type 列验收输出。
2. 参数 type 列同法检查三族窗口：add 4.29e9 / sub 1.32e6 / xor 2.41e9 —— 均不收敛到可解释
   type 索引范围，判断可能叠加 mask2/打包位或另一条掩码链，本轮不定案并显式记录。
3. 结论：7.0 字段表 {type,name} 两列均可解码；参数 type 列留待后续。

## 109. R38 7.0 端到端验证脚本 + 两个待确认点（2026-10-18）

1. 新增 tools/version-triage/verify_70.py：把 R28–R37 的 7.0 布局汇成回归门禁，逐表抽样重解码并
   断言结构不变量，失败非零退出。当前 12 项全 PASS：
   - typeDef 86,932 行 / 86,900 有名字；字段 430,290 / 方法 713,956 / 属性 112,949 / 事件 625；
   - 方法 name 20k 抽样：19,237 标识符 / 723 个 0xFFFFFFFF / 40 其它 / 0 个非哨兵失败；
   - paramStart 链 20k 抽样 0 违例；参数表 name/type 20k 全可解；
   - 属性名 20k：19,779 标识符；字段名 20k：19,415 标识符 / 90 哨兵；字段 type max 13,504。
2. 跨版本字段名：7.0 与 7.1 dump 前 20 个字段名顺序完全一致，之后同名不同序（构建期重排，
   与既有 §60 结论一致）⇒ 字段 name 解码正确，顺序是构建期属性。
3. 两个显式未决：① 方法 returnType 分布可疑（最高频仅 16,567/713,956，top 50k–83k，违反 void/int
   占大头预期，疑 mask2/列错）；② 参数 type max 662,533 vs 字段 232,880/方法 ret 86,928，
   是否同一 typearr 索引空间未定，需 typearr 本体定案。
4. 复现：python3 tools/version-triage/verify_70.py（PASS 12 checks）。

## 110. R39 Il2CppType 数组定位 + returnType 列纠正（2026-10-18）

1. 结构扫描定位 Il2CppType 数组：16 字节记录 {u64 data, u16 attrs, u8 type, u8 flags,
   4B padding=0}，连续 662,534 条，文件偏移 0x2D3C7F0（VA 0x142D3DFF0）。判定依据：
   参数 type 最大 662,533 = count-1；字段 type 232,880 < count；方法 return 全在界内；
   记录 type 枚举合法、CLASS/VALUETYPE 的 data 是 typeDefIndex（可解析出 System.Int32 等）。
2. 纠正 R33：方法 returnType 列在 +0x00（value = (raw ^ 0x215FCCB1) - mask），不是 +0x10。
   713,956 个方法：全部在 [0,662,534)、437,167 个 System.Void（61.2%）、distinct 32,246；
   前 12 个方法 Void/String/String/String/Void... 与 <Module> 的 .ctor/GetText 对应；
   高频返回 Void 437,167 / Boolean 66,823 / Int32 30,854 / String 13,880。
   原 +0x10 列从布局移除并标注未知。
3. 新增 docs/re/artifacts-7.0.0/typearr.json（file_off/va/count/entry layout/type enum）；
   method_rows.py 输出 return_type 解析样本/void 比例/越界数；verify_70.py 增至 13 项
   检查全部 PASS（新增 return type column 检查：50k 抽样 25,021 个 Void 且全部在界内）。
4. 未完成：GENERICINST/PTR/SZARRAY 的 data 语义（索引还是指针）与泛型实例表解码；
   参数 type 列用 typearr 复核在界内（max 662,533=N-1）。

## 111. R40 Il2CppType 渲染 + 与 7.1 dump 方法级对照（2026-10-18）

1. typearr data 语义确认：VALUETYPE/CLASS data=typeDefIndex；VAR/MVAR data=泛型参数位置；
   PTR/SZARRAY/ARRAY data=元素类型在 typearr 的 VA（换算索引后递归）；GENERICINST data=泛型实例
   表索引（表未定位，暂 genericinst#N）。
2. 新工具 tools/version-triage/type_render.py：输出 7.0 全部 713,956 个方法行（声明类型+方法名+
   渲染返回类型），例 Locale.GetText : System.String、Runtime.mono_runtime_install_handlers :
   System.Void、Runtime.LoadBinData : System.Byte[]。
3. 与 7.1 dump.cs 逐类型对照（corelib 60 类型）：方法名交集 5,166；返回类型逐项一致
   5,164/5,166 = 99.96%；2 个不一致均为泛型方法 MVAR 返回（!!1895 vs public T）⇒ 需要泛型参数名映射。
4. 结论：方法表的声明类型/方法名/返回类型在本版本已端到端可用；剩余 GENERICINST 表定位、
   VAR/MVAR 名字映射，然后渲染字段/参数/属性并生成 dump.cs。

## 112. R41 7.0 字段表 type 列定案（已知明文）+ 分布验收（2026-10-18）

1. R37 的窗口常数 0xA90E9923 错误（解码 top 全 genericinst）。改用已知明文：字段 0
   (Mono.RuntimeClassHandle.value) 类型是 MonoClass*；在 typearr 的 PTR(0x0F) 条目中解析元素类型，
   找到 MonoClass 指针条目 429,796/429,798/429,829；以 429,796 反解常数，15 族 × 偏移 0..4 中只有
   value = (raw + C) - mask（C = 0xA9152807）满足 0 越界且分布可解释。
2. 定案后 kind 分布（430,290 字段）：CLASS 111,845 / VALUETYPE 111,199 / GENERICINST 41,875 /
   Boolean 36,449 / Int32 35,523 / UInt32 27,565 / Single 23,481 / String 19,554 / SZARRAY 12,484；
   前几个字段 MonoClass*/RemoteClass*/GenericParamInfo*/IntPtr/IntPtr/GPtrArray* 与 corelib 结构体吻合；
   全表仅 64 行越出 typearr（尾部）。
3. verify_70.py 字段 type 检查改为 primitive-kind>=100k 且越界<=100（实测 149,852 / 64）；
   13 项检查全部 PASS。
4. field-layout.json type 常数更新为 0xA9152807；field_rows.py 输出越界计数。

## 113. R42 方法签名端到端渲染 + 逐参数对照（2026-10-18）

1. type_render.py 升级为完整签名输出：声明类型 + 方法名 + 渲染返回类型 + 每参数 (名字:类型)；
   Il2CppType flags 字节 bit6=byref，渲染加 &（修正了同索引递归导致 &&&&&& 的 bug）。
2. 样例：Locale.GetText : System.String (fmt:System.String, args:System.Object[])；
   SR.Format : System.String (resourceFormat:System.String, p1:System.Object)；
   Mono.Runtime.GetNativeStackTrace : System.String (exception:System.Exception)。
3. 与 7.1 dump.cs 逐类型逐参数对照（corelib 60 类型）：返回类型 990/994=99.6%；
   参数类型按位置 **1,457/1,485=98.11%**；剩余 = genericinst#N 占位（泛型表未定位）
   + 少量跨版本混淆改名（JAAJEOLDNPH vs FPBCFBKKCFG）。
4. 结论：参数名 name 列、参数 type 列、参数顺序（paramStart 链）、byref 标志在 7.0 均验证；
   只差泛型实例表即可完整渲染签名。

## 114. R43 字段/属性类型渲染 + 7.1 dump 对照（2026-10-18）

1. 用 typearr 渲染器渲染字段 type 列与属性 getter 返回类型，与 7.1 dump.cs corelib 前 60 类型对照：
   字段类型 205/207 = 99.03%（按字段名匹配）；属性类型 34/37 = 91.89%；
   属性访问器存在性 35/37 = 94.6%。残余差异来自泛型占位与跨版本混淆改名。
2. 修复属性访问器解码：getter 用 SubMaskAddC16、setter 用 XorCSubMask16（16 位截断），
   method_rows.col_value 补 XorCSubMask16；用 32 位 xor 会解出 5 万级假索引。
3. 负结果：GENERICINST 泛型实例表三种结构扫描全 0 命中（16B {argc,pad,argv_ptr}、
   24/32B generic-class 记录、metadata body generic class 表 stride 8..24）⇒ 指针可能加密或布局不同。
4. 新增 tools/version-triage/validate_fields_props.py（字段/属性对照验收）。

## 115. R44 7.0 第一份端到端类型清单（dump70-partial）+ 泛型表负结果（2026-10-18）

1. 新增 tools/version-triage/dump70_partial.py，输出 7.0 全量类型清单 dump70-partial.txt
   （63.8 MB）：类型 86,932、字段 430,290、属性 112,949、方法 713,956；字段/属性/方法均渲染
   真实类型名（类/值类型/基础类型/指针/数组/byref），泛型仍占位 genericinst#N、!n、!!n。
   样例与 7.1 dump corelib 开头一致（Locale.GetText 等）。
2. 该清单还不是可编译 dump.cs：typeDef flags（class/struct/interface/enum）、属性、RVA/Token/Slot、
   泛型实例名未解；但“表→名字/类型”通路已打通。
3. GENERICINST 表三轮扫描全部 0 候选：exe 16B {argc,pad,argv_ptr}、24/32B generic-class 记录、
   metadata body 任意列<86,932 的规则表（stride 8..64）。判断泛型实例表在加密指针区域
   （7.0 .data 全局指针为密文），需先找运行时全局指针解密例程。

## 116. R45 typeDef byval/parent 列 + class/struct/interface 分类（2026-10-18）

1. byvalTypeIndex：typeDef 行 u32 @+12 raw^0x1253E298 → typearr 里该类自身 Il2CppType 条目
   （条目 data == typeDefIndex 的自反关系做交集求解）；86,905/86,932 行成立（27 行尾部 padding）。
   条目 kind：class 0x12 = 74,238、valuetype 0x11 = 12,649。
2. parentTypeIndex：typeDef 行 u32 @+4 raw^0x149B1F48；接口 parent=0xFFFFFFFF，类 parent 合法。
3. 分类规则 parent sentinel→interface、byval kind 0x11→struct、否则 class、<Module> 特判：
   与 7.1 dump corelib 114 类型对照 108/114 = 94.7%（class 87/87、struct 18/18、interface 3/3；
   5 个 enum 归为 struct、<Module> 特判）。
4. enum 无法与 struct 区分：System.Enum 父类信息缺失，parent 列对 valuetype 的值不可解释
   （同簇都解出 0x4A），显式记为未完成。
5. 新增 tools/version-triage/type_kinds.py；dump70_partial.py 接入分类，清单输出
   class/struct/interface 关键字（72,632 / 12,649 / 1,624）。

## 117. R46 enum 检测（value__）+ 四类分类 100% 对照（2026-10-18）

1. enum 与 struct 都是 valuetype，parent 列无法区分。改用字段签名：enum 必有 value__ 字段。
   对 byval kind=0x11 的 12,649 个 valuetype 解码字段名检查 value__，有则 enum、否则 struct。
2. 与 7.1 dump corelib 114 类型对照：**114/114 = 100%**（class 88、struct 18、interface 3、enum 5，
   无假阳性）。
3. 全量分类（86,905 有效 typeDef）：class 72,632、struct 4,690、interface 1,624、enum 7,959。
   dump70_partial.py 接入 enum 规则，清单输出四种关键字（样例 enum Mono.Security.UriPartial 等）。

## 118. R47 跨版本转移：6.7.0 方法/参数表布局（2026-10-18）

1. 7.0 方法/参数解码函数 0x1404F9750 作种子，hdr 载入点指纹在 6.7 的 4,334 个载入点匹配，
   最佳 0x1404D3990（jaccard 0.3163）；反汇编读出常数写入
   docs/re/artifacts-6.7.0/method-param-layout.json。
2. 6.7 布局：方法表 hdr[0x38]+0xD515CAA3 stride 26；方法行掩码 mul 0xCB87/xor 0x1D9A1A7A/
   mul 0x38036D18/shr 8/add 0x7964C76C/xor 0x324CAF19；paramStart=(raw32[0]^0xD62B555)-mask；
   paramCount=(raw8[+0x18]+0xA8-mask低8位)；参数表 hdr[0x14C]^0x12C9258B stride 8；
   参数行掩码=idx*0x2A2E98A6+0x59887B45；参数名=raw^掩码^0x3CBE0533，类型=raw^掩码^0x5A301FB。
3. 新工具 tools/version-triage/decode_params.py；6.7 全表 687,452 行、哨兵 385,937、坏行 0；
   前 8 方法参数名 msg/fmt,args/resourceFormat,p1/exception/flag/obj/klass/ptr 与 7.1 dump 一致。
4. 与 7.1 dump 前 1200 方法位置对齐：参数个数 1050/1200、参数名 1495/1542；残余为版本间方法
   增删导致的顺序错位。

## 119. R48 6.7.0 方法 name/flags 列（2026-10-18）

1. 在 6.7 方法缓存初始化函数 0x1404BFD90 读出方法行另两列：name 行 +8 u32
   ((raw ^ 0x06BBF48D) - mask)，flags 行 +0x14 u16 ((raw ^ 3) - mask)，代码用 bit 0x10 判 Static。
2. 验证（687,452 行）：方法名 686,183 标识符（99.82%）、989 哨兵、280 其它；前 200 个方法与
   7.1 dump 逐位对照 199/200 相同（GetText/Format/GetNativeStackTrace/...）；static 位 80,860 个。
3. flags 完整语义暂定：distinct 992、部分高位超出标准 MethodAttributes 范围（如 0x9266），
   先记“static 位可用、其余待交叉验证”。
4. 更新 docs/re/artifacts-6.7.0/method-param-layout.json 与 decode_params.py（输出方法名）。

## 120. R49 6.7.0 Il2CppType 数组 + returnType 列（2026-10-18）

1. 用 7.0 相同的 16 字节记录结构扫描定位 6.7 typearr：VA 0x1429FA400 / 文件 0x29F9200，
   最长连续命中 404,360 条；再用参数 type 列反推表长：解码后最大值 633,861，取 count=633,862
   时有效条目占 98.78%，条目 0/1/2/9 与 7.0 同构（genericinst#0 / System.Object / ... / System.Type）。
2. 解 returnType 列：方法行 +4 u32，ret = (raw ^ 0x546F8F09) - mask（方法 0 .ctor 到 Void 已知明文，
   15 族 x 偏移 0..22 唯一命中）。全表 687,452 行：越界 0、System.Void 420,731（61.2%）、
   distinct 31,096；高频 Void 420,731 / Boolean 64,168 / Int32 29,859 / String 13,461 / UInt32 9,239，
   与 7.0 分布一致。
3. 新增 docs/re/artifacts-6.7.0/typearr.json；method-param-layout.json 增加 return_type 列；
   decode_params.py 可打印 6.7 方法签名（GetText -> String、GetTypeFromClass -> IntPtr 等）。

## 121. R50 6.7.0 属性表：构建器定位，布局未定案（2026-10-18）

1. 7.0 属性构建器 0x1404E6180 的载入点指纹在 6.7 匹配到 0x1404C07E9（所属函数 0x1404C0020，
   jaccard 0.2421）。反汇编得到候选：base = hdr[0x140]+0xB8765480（0x389AFCC）、stride 14、
   行掩码 = (idx*0xFDA4FDC7922E20A0 + 0x52ED0039DCB14F2E) & 0xFFFFFFFF；列候选 +0 type
   (raw+0xE2CC29CA)^mask、+4 name (raw+0xA16DD35B)^mask、+8/+0xA/+0xC 访问器（0xC054/0xC0EE/0x5B99）。
2. 数据验收不通过：108,747 行里只有 1,406 个名字能解出标识符（前 617 行连续正确：
   KeyGenerated/AssemblyLoad/ProcessDomain/Completed…），其余 packed index 无效 ⇒ 行掩码用的
   索引不是线性全局属性索引（可能是局部/编码起点），或表长/列语义与 7.0 不同。
3. 本轮只记录构建器与候选常数，不把 6.7 属性表当作已解；下一步彻底读清循环起点
   (u16 + 0xFFFFFD33 与 r14b) 的含义。

## 122. R51 更正：6.7 那组常数是事件表（617 行 100% 验证）（2026-10-18）

1. R50 命中的 6.7 函数 0x1404C0020 行数正好等于事件数 617（非属性 108,747），行内结构为标准
   EventDefinition {type u32, name u32, raise/add u16x3} ⇒ 那是事件构建器。
2. 事件表验收：617/617 名字均为标识符（KeyGenerated/AssemblyLoad/DomainUnload/ProcessExit/
   Elapsed/ConnectionClosed/Completed 等 AppDomain 事件）；add=11/remove=12/raise=0xFFFF 落在
   类型方法索引范围；type 0x63F78 等 < typearr 633,862。
3. 定案（docs/re/artifacts-6.7.0/event-layout.json，纯数据）：base=hdr[0x140]+0xB8765480,
   stride 14, 掩码 (idx*0xFDA4FDC7922E20A0+0x52ED0039DCB14F2E)；type=(raw32[0]+0xE2CC29CA)^mask32；
   name=(raw32[4]+0xA16DD35B)^mask32；raise=(raw16[8]^mask16)^0xC054；
   remove=(raw16[0xA]^mask16)^0xC0EE；add=(raw16[0xC]+0x5B99)^mask16，0xFFFF=无。
4. 属性表仍未定位：6.7 属性行也大概率 14 字节，但属另一组常数/构建器；事件/属性构建器指纹相似，
   下一轮用行数区分后重新匹配。

## 123. R52 6.7.0 字段表 name 列（2026-10-18）

1. 7.0 字段名访问器 0x1404EDB50 载入点指纹在 6.7 匹配到 0x1404C7EAF（函数 0x1404C7E10，
   jaccard 0.2581）；反汇编读出布局：base=hdr[0xC]+0xD34ADB03（0xC4C0B8）、stride 8、
   rows 413,644；行掩码=(i*0x1BB4F2A67161+0x251BA412D3BC6)>>18；
   name=cipher_dec(((raw32[0]^0x70F1D209)+extra)&32)，extra=((((mask+0x2C7618B2)&32)^0x14BDA7A6)*0xC9B392C3)&32。
2. 全表验收 413,644 行：412,658 个标识符（99.76%）、200 哨兵、786 其它；前 8 个字段名
   value×6/default_vtable/xdomain_vtable，与 7.0 一致。
3. 新增 docs/re/artifacts-6.7.0/field-name-layout.json；字段 type/attrs 列尚未解。

## 124. R53 6.7 端到端类型清单 + 字段 type 列负结果（2026-10-18）

1. 新增 tools/version-triage/dump67_partial.py：用 6.7 已解布局输出 dump67-partial.txt（47.8 MB）：
   类型 83,775、字段 413,644（名字）、方法 687,467（含签名）；方法按 6.7 name/flags/returnType/
   paramStart/paramCount + 参数表渲染，字段 type 列未解（写 ?），属性/事件未接入。
   样例与 7.1 dump corelib 开头一致（Locale.GetText、Mono.Runtime.* 等）。
2. 字段 type 列负结果：字段 0 = MonoClass*，6.7 typearr 里 MonoClass 指针条目 409,207/409,209/409,240；
   以其做已知明文对字段行 +0/+4 的 15 族 x 3 目标搜索，全部候选 2000 行抽样中 1996 行越界；
   窗口性质检查 +0/+4 也完全不收敛（4.29e9）⇒ 6.7 字段 type 不在简单 row+mask 模型里，
   可能另有二次变换链或位于别的表。未作为已解记录。

## 125. R54 6.7 字段表 type 列（2026-10-18）

1. 上轮 row+mask 简单模型失败，实际该列用类似 name 列的二次变换链。在 6.7 类构建器
   0x1404BDB90 读到完整公式：m=((i*0x1BB4F2A67161+0x251BA412D3BC6)>>18)&32；
   extra=((((m+0x2C7618B2)&32)^0x14BDA7A6)*0x364C6D3D)&32；
   type_index=((raw32[+4]-extra)+0xF94BD493)&32（-1 表示无）。
2. 全表 413,644 行：越界仅 13（尾部）；字段 0 = 409,207 = MonoClass* ✓。kind 分布与 7.0 一致
   （CLASS 107,329 / VALUETYPE 107,229 / GENERICINST 40,180 / Boolean 35,009 / Int32 34,253 /
   UInt32 26,469 / Single 22,398 / String 18,914 / SZARRAY 11,875）。
3. field-name-layout.json 增加 type 列与验收数据；dump67_partial.py 字段行从 “?” 升级为真实类型，
   dump67-partial.txt 已重新生成。

## 126. R55 6.7 属性表定案 + 常数/算法索引 + 记录审计（2026-10-18）

1. 在函数 0x1404C0020 的第二条分支找到 6.7 属性构建器（行数 108,747 与属性数一致、名字为 corelib
   属性名）：base=hdr[0x1E8]+0xE9FF5F7F（0x1F10840）、stride 10；
   行掩码 idx*0x137D ^ 0x70B05CB7 * 0x42639239 >>13 * 0x525521B3 >>13 + 0x5F17108D；
   name=(raw32[0]^mask^0x2BFBE794)；getter=(raw16[8]^mask16^0x5D18)；
   setter=(raw16[4]^mask16^0xD662)；+6 列不是访问器（全部越界），公式未定。
2. 全表 108,747 行：名字 108,464 标识符（99.74%）、221 哨兵、62 其它；getter 列 56,483 个 get_、
   setter 列 8,584 个 set_；样例 Constraints/Attributes/Length/Item/Value 与 7.1 dump corelib 一致。
   新增 docs/re/artifacts-6.7.0/property-layout.json。
3. 新增 docs/re/constants-index.md：按版本索引每个关键常数/算法（从 7.0/6.7/7.1 表基址、stride、
   掩码链、列常数、索引语义、类型分类到负结果），含方法、验证数字、出处小节、JSON 路径与复现命令。
4. 记录审计：逐常数 grep docs/re/generalize-method.md、IMPLEMENTATION_LOG.md、MEMORY.md——除本轮新
   发现的 0xE9FF5F7F 外全部已有记录；已补入并建立索引，常数清单唯一入口 = constants-index.md。

## 127. R56 6.7 端到端验证：与 7.1 dump 逐类型对照全绿（2026-10-18）

1. dump67_partial.py 升级：CLASS/VALUETYPE 解析真实类型名、PTR/SZARRAY/ARRAY 递归、byref 加 &，
   追加 Properties（名字/类型/get-set）与 Events（名字/类型）；清单仍 83,775 类型/413,644 字段/
   687,467 方法。
2. 与 7.1 dump.cs corelib 前 60 类型逐项对照：字段类型 281/281=100%；方法返回类型 425/425=100%；
   方法参数类型 587/587=100%；属性类型 52/54=96.3%（残余 2 个泛型占位）。
3. 结论：6.7 的 typeDef/方法/参数/字段/属性/事件在 corelib 上与相邻版本 oracle 完全对齐；
   6.7 profile 除「属性 +6 列、字段 attrs、泛型实例表、flags 完整语义」外已闭环。

## 128. R57 6.4.0 方法/参数表常数（候选，未验证）（2026-10-18）

1. 6.7 方法元数据解码器作种子，形态转移 6.4 最佳命中 fn 0x140479C80；顺名字解析器（cipher site
   0x14047539A 的 52 个调用者）找到 6.4 参数/默认值解码器 fn 0x14048D770，读出常数：
   方法表 hdr[0x1FC]^0x22414276 stride 26；方法行掩码 (idx*0x11D36B90D36A8EDD+0x68C1F6C86562CBFC)>>0x13；
   paramCount=(raw8[0x18]^mask8^0x63)；paramStart=((raw32[8]+0xEE6D5044)^mask32)+local；
   参数表 hdr[0x2C]+0x934F4900 stride 8；参数行掩码 ((((j*0x227BBC409D01)>>0xE)^0x224F51C3)*0x25E50B2E)>>0xC；
   参数名=((raw32[0]+0xE7B06DEA)^mask32)。
2. 数据验收失败：用线性全局方法索引代入，paramStart 解出 ~1.5e10 越界 ⇒ 6.4 行索引来自类字段
   (r8=[rdi+0x18])，语义与 6.7 不同（疑编码 methodStart）。
3. 常数写入 docs/re/artifacts-6.4.0/method-param-layout-candidate.json（status CANDIDATE - NOT
   VALIDATED），不当作已解；下一步读清 r8 来源或找真正方法元数据解码器。

## 129. R58 6.4.0 补充事实（typeDef 布局、类初始化行公式）与未决点（2026-10-18）

1. candidate JSON 补齐 6.4 typeDef 布局（cross/tables-6.4.0.json，R28/R30 已验收）：base 15,161,244、
   stride 70、rows 77,262、name off24 Add 0xE169AC15、ns off32 Xor 0x468CB988、两组 start/count 对
   （off20/off40 与 off62/off120，后者跨行属已知 IndexTable 跨行模型）。
2. 6.4 类初始化 0x140479C80 的方法行公式：起点 = dword[typeDefish+0x1C] + 0x8A76E6C5；
   行 = 方法表 base + 26*index；掩码 = (index*0x11D36B90D36A8EDD+0x68C1F6C86562CBFC)>>0x13；
   paramCount 读 word[row+0x16]（非 6.7 的 byte +0x18）。
3. 未决：index 是类初始化器的编码索引；线性全局方法索引代入解出 22/85/88 等不可能值 ⇒ 全局索引到
   编码索引的映射未定。6.4 方法与参数列继续 CANDIDATE-NOT VALIDATED。

## 130. R59 6.4 索引映射尝试（代数关系解开，表语义仍未定）+ 索引补 6.4 节（2026-10-18）

1. 解开常数关系：类初始化的 +0x8A76E6C5 是 typeDef methodStart Add 常数 0x7589193B 的补数
   （和 = 2^32），故循环起点 = plain methodStart，不存在额外编码域。
2. 但继续验证仍失败：name = cipher(raw32[+0] ^ mask ^ 0x0834AA45) 前 12 个方法全 None；
   以 7.1 dump 前 11 方法参数个数为约束，对方法行 0..25 的 u8/u16 列 x 256 个 xor 常数穷举，
   无任何 (offset, constant) 成立。
3. 可能原因（均未验证）：slot 0x1FC 不是方法表；或 6.4 方法表 base/mask 与 7.0/6.7 不同。
   6.4 方法/参数继续 CANDIDATE - NOT VALIDATED。
4. constants-index.md 新增 2b 节（6.4 typeDef 已验收、方法/参数候选、负结果）；build_index.py 同步更新。

## 131. R60 跨版本 profile 差异报告工具（2026-10-18）

1. 新增 tools/version-triage/diff_profiles.py：读两版 artifacts 目录，按语义（方法/参数/字段/
   属性/事件/typearr）对比 slot+op+imm、stride、mask 链、列偏移，输出 markdown 差异报告。
2. 已生成 docs/re/cross-version-diff.md（7.0.0 vs 6.7.0）：stride 稳定（方法 26/参数 8/字段 8/
   属性 10）；表基址与掩码链每版随机化需逐版重导；列偏移有交换（方法 param_start 4↔0、
   return_type 0↔4；字段 name/type 4↔0；属性 setter 6↔4）；6.7 多事件表（stride 14）与更长掩码链；
   typearr 位置/条数不同（662,534 vs 633,862）。
3. 结论：结构可跨版继承、常数必须每版重导；差异报告作为下一版推导 checklist。

## 132. R61 6.4 slot 0x1FC 作为方法表的假设被否定（2026-10-18）

三组独立数据检验全部失败：
1. paramStart 链扫描（start_off 0..22 x 族 xor/sub/add；count_off 0..24 x 族；A_i+C_i==A_{i+1}
   在 600 行上检验）最高命中率 2.33%，无链关系；
2. 名字解码：从解码堆取 80 个 ".ctor" 候选偏移，4 种公式族反解常数，前 200 方法标识符名字最多 7 个；
3. flags 合理性：(raw16[row+0x16]+2)^mask16 的 static 位占 22.1%（6.7 为 11.8%），分布可疑。
结论：slot 0x1FC 不是 6.4 方法表（或类初始化用法与方法行无关）。6.4 方法/参数继续
CANDIDATE-NOT VALIDATED；下一步从 typeDef methodStart/paramCount 数据反查真实表，或借字段/属性构建器旁路。

## 133. R62 6.4 方法解码器 fn 0x1404799E2：表身份被支持，列索引仍对不上（2026-10-18）

1. 找到 6.4 方法元数据解码器 0x1404799E2：用 hdr[0x1FC]^0x22414276 + 26*index 行与同一掩码链，
   读出列：param_count row+0x18 (raw^mask8^0x63)；flags row+0x16 ((raw+0xFFFFE182)^mask16)；
   token 类 row+0x0C ((raw+0x1B9E)^mask16) 符号扩展；row+0x0E dword（两 u16 SIMD paddw/pxor）；
   row+0x19 位域 ((raw^mask8^0x27) 拼标志)。
2. 因此 R61 的“0x1FC 不是方法表”过强：表身份其实对，问题在行索引/列公式。用 plain 全局索引
   仍解出 paramCount 22（期望 0）；名字公式 (raw32[0]^mask^0x0834AA45) 仍 None；以 .ctor/GetText/
   GetText/Format 四个已知方法名与堆候选偏移做 K 交集（80/46/333 候选）无解。
3. 结论保持 CANDIDATE - NOT VALIDATED：基址/stride/掩码链可信，行索引/列公式待修正。

## 134. R63 6.4 方法表部分验证：paramCount 列定案（2026-10-18）

1. 用 6.4Dump.cs 前 60 个方法参数个数做 oracle，对方法行穷举 (offset 0..25) x 族
   (xor/sub/add/xor_nomask) x 常数 0..255：唯一命中 paramCount = row+0x10 u8，
   (raw8 ^ mask8 ^ 0x63)，60/60 完全一致。
2. 这同时验证 6.4 方法表身份：base=hdr[0x1FC]^0x22414276、stride 26、
   掩码=(index*0x11D36B90D36A8EDD+0x68C1F6C86562CBFC)>>0x13（解码器 0x1404799E2 的
   [r12+0x18] 与表公式 row+0x10 相差 8 字节，两者一致）。
3. 仍未解：paramStart（累计和约束穷举无候选）、name（已知名字 x 堆偏移 x 4 族最佳 9/30，
   疑有二次变换链）。6.4 状态 PARTIALLY VALIDATED。

## 135. R64 oracle 驱动的列暴力求解器（可复用管线组件）（2026-10-18）

1. 新增 tools/version-triage/oracle_column_bf.py：输入行表参数（base slot/op/imm、stride、掩码链）
   与 oracle dump.cs，自动穷举 (列偏移 x 变换族 x 常数)；支持 param_count（u8，族 xor/sub/add/
   nomask x 0..255）与 param_start（u32，累计和约束）。
2. 在 6.4 自动复现：param_count 唯一 MATCH off 16 / xor / 99（row+0x10, raw^mask^0x63）与 oracle
   60/60；param_start NO MATCH（与人工穷举一致）。
3. 该工具把“oracle 反推列常数”流程化：6.1–6.5 的 rar、6.0 zip 里都有 dump，可对每个历史版本
   自动重新发现列常数，是可自动化 profile 管线的第一个成形组件。

## 136. R65 各版本 profile 状态矩阵（自动生成）+ 进度面板（2026-10-18）

1. 新增 tools/version-triage/status_matrix.py：扫描 cross 与 artifacts 目录，生成
   docs/re/version-status.md（26 版本 x derive/sites/tables/ranges/typedefs/shape/
   method/param/prop/field/event/typearr/typeDef 行数）。
2. 当前覆盖：完整 profile+oracle 验证 = 7.0.0、6.7.0；部分验证 = 6.4.0（typeDef 验收、
   paramCount 60/60，paramStart/name 未解）；typeDef 级 = 7.1.0、6.0.0、5.4.0；
   仅基础产物 = 4.8.0 与 5.x/6.x 若干；未开始 = 4.2-4.7（按目标最后处理）。
3. constants-index.md 同步更新 6.4 状态（PARTIALLY VALIDATED）并引用 version-status.md。

## 137. R66 6.4 字段/属性访问器公式（候选未验证）（2026-10-18）

1. 从 6.4 cipher 解码调用点 0x14047A735 反推 10 字节行访问器（函数 0x14047A400）：base =
   hdr[0x98]^0x2FEB120C、stride 10；mask(n)=((((n*0x6E84+0x133D8A7A)^0x238CC4C0)*0x67F700C3)>>8
   +0x439ECF62)^0x1D01444C；name=(raw32[0]^0x0492A370)-mask；getter=((raw16[8]^0x581C)-mask)&0xFFFF；
   setter=((raw16[4]-mask)+0xFFFF8C73)&0xFFFF；+6 另有 attrs 类列。
2. 数据验收失败：99,320 行只有 300 个名字是标识符（0.3%），getter/setter 值越界 ⇒ 行索引或表身份
   （属性 vs 字段）仍不对。常数写入 candidate JSON 的 field_or_property_accessor_candidate 段，
   标记 CANDIDATE - NOT VALIDATED。

## 138. R67 最终完成度报告（第 40 轮，2026-10-18）

1. 写出 docs/re/objective-final-report.md：结论、已完成证据表、可自动化管线组件、剩余工作优先级、
   经验教训。结论：7.0.0/6.7.0 完整达成样例；6.4.0 部分完成；6.0/5.4/7.1 typeDef 级；5.x/6.1–6.3/
   6.5–6.6 仅 derive；4.2–4.7 未开始 ⇒ 目标未全部完成，goal 保持 active。
2. 最终自检：verify_70.py 13 项 PASS；6.7 oracle 对照字段 100%/返回 100%/参数 100%/属性 96.3%；
   status_matrix.py 重新生成 26 版本覆盖矩阵。

## 139. 追问：静态字段偏移的载体与 6.4 对照实验（2026-10-18）

1. 新增 tools/version-triage/check_field_offsets_cross.py：解析 6.4Dump.cs 的 instance 偏移序列，在
   6.4 exe 全量搜索每类型 fieldOffsets 数组。
2. 结果：2,738 个候选序列抽样 200，只命中 0x70/0x78/0x80/0x88 这类通用小偏移的平凡序列（与 7.1
   的误报相同），无真实数组 ⇒ 6.4 的偏移（含 30,587 个静态偏移）同样不是文件里的静态数组，而是
   运行时辅助 dump 的值。这补强了 remaining-static-limits.md A 的结论：7.1 无运行时快照 + 文件
   无载体 ⇒ 静态不可得。
3. 顺藤摸瓜法已用于本会话多数关键发现（属性构建器、字段/方法/参数解码器、6.7 事件/属性分支）；
   静态偏移这条线摸到 image 表 loader（无 typeStart/count）、exe 数组搜索（0 命中）两个有证据的
   终点；尚未摸的藤：loader per-image 注册 sub_14051e390 的 typeStart 来源、0x188/0x118 大表、
   VMP 初始化器仿真。

## R68–R70（2026-10-25）：通用解法落地——符号执行提常数 + 数据验收求解器 + 零接触战役

**不是需求（方案记录，需求见 REQUIREMENTS）**

### R68 symwalk.py（L4a 核心件）
- builder 函数窗口线性符号执行：hdr 锚点/掩码链（含 mask2=mask*K 派生）/行列公式全自动提取，表达式树 JSON 为唯一接口；exprvm.py numpy 求值。
- 关键修复：寄存器别名表 base[1:] 截断 bug（32 位名从未映射到 64 位规范名）、位宽统一 bits（调用处误 ×8）、lo 嵌套折叠、x*A±x*B 分配律折叠（mod 2^64 sound）、行标记广义线性化（shl/sub stride 惯用语，lea 5×5+1 折成 26i）、递归死循环（x+A+x*B 分支重建自身输入）、PE 字节按路径共享（多 walker 不再各拷 450MB，曾 OOM）。
- 多起点 top-3 质量合并（resolved<body 锚点/大乘数链/列数评分）。
- 回归 12 目标（7.0/6.7/7.1 方法/参数/字段/属性/事件锚点）：掩码链 11/12 组全常数复现；7.0 参数表/属性表整组 PASS；残缺=16 位访问器列与兄弟函数列（设计上由多锚点合并+数据求解覆盖）。提交 f376f6b。

### R69 rowtable_solve.py
- name 列：堆枚举（mhydump strings）已知明文反解 C；**fam_invert 修 XorCSubMask 逆推 bug（C=raw^((idx+mask)&M)，此前漏了外层 xor 导致 6.6 全灭）**；验收=堆命中率≥45%×4000 且标识符率（可解行中）≥95%。
- count 列：u8 众数钉 C（sub-88 ≡ add-168 mod 256 族自动归一）。
- start 列：哨兵 0xFFFFFFFF 钉 C + 非哨兵行=累计参数数全表校验（修正连续差分判据——哨兵行不参与链）；32 位域截断（fam_value dom 参数）修 64 位回绕假象。
- **6.7 方法表端到端回归全绿：name off8 XorCSubMask 0x6bbf48d / count off24 +0xA8 / start off0 0xd62b555 链 0 违例 哨兵 385952/385952 / flags off20 —— 与人工逆向常数全部一致。**
- 链求值坑：人工注入测试树多加了 lo32(i*mul1)（真代码 64 位 imul）——symwalk 记录即正确；教训=注入测试必须与代码记录逐位对齐。提交 0b8f3e5。
- 6.6 方法链未定位（open）：锚点密集区 0x40 步长密扫无 stride-26+大乘链共存窗口；解码器 52 调用点定向只覆盖惰性访问器外围；全 .text imul 簇 23807 头（3s）但 walk 不可行（未 ranking）。chain_hunt.py 留优化。

### R70 auto_tables.py + 零接触战役
- 6.7 多表种子（数据文件）→ shape_transfer → symwalk → 落盘 ~/gire/out/zero-touch/。
- **6.6/6.5 参数表零接触全解**（见 zero-touch-report.md §2，解码验证标识符率 100%）；6.3 方法 builder 定位（0x140467bc8，stride+链同函数）；6.2/6.1 链已提取、验收未过。
- oracle（6.1–6.5 官方 dump 已解压 ~/gire/out/oracle/，6.0=59,629/6.1=72,832/6.2=73,951/6.3=76,397/6.4=77,260/6.5=80,166 类型）逐名比对留下一步。提交 2cd4400。

## R71（2026-10-25）：模拟执行链提取（用户提议，验证成功）

**不是需求（方案记录）**：用户问「可否通过模拟执行寻找？」+ 指令「最终要移植到 Rust」（后者已录入 REQUIREMENTS R39）。

- `emu_chain.py`：unicorn 静态模拟（映射真实 exe+metadata、植入 hdr_global/body_global、寄存器播种、fetch-unmapped 时栈顶合法则模拟 ret）。执行流 mini-tracker 重建链表达式（symwalk 同款 JSON）。
- **为什么窗口法找不到 6.6 方法链**：链以 `movabs rax,imm64 + imul r11,rax` 形态存在（symwalk 的 imm 匹配/密扫判据都没覆盖），且该函数早段就有运行时指针间接调用断掉一切回看。模拟执行 30 条指令直接拿到完整链+列公式（+0x10 flags 型 `(raw16+0x1EEA)^mask32`、+0x12 slot 型）。
- 7.1 ground truth 一次过（链+mask2 逐位）；6.6 方法表全解（name/count/start，链 0 违例）；6.5/6.1 方法链提取+name 验证 idrate 1.0。6.3/6.2 断在首段间接调用，待 ret-forest（把指针寄存器指向填满 ret 桩的页）。
- Rust 移植映射已记 docs/TOOLS.md 与记忆：symwalk→iced-x86、emu→unicorn crate、exprvm/rowtable_solve→ndarray/裸切片；表达式 JSON 保持 serde 中立。

## R72（2026-10-25）：oracle 全绿 + 6.2/6.3 链 + 6.4 根因（不是需求，方案记录）

- oracle 逐名比对：**6.1/6.2/6.5 方法名 vs 官方 dump 全部 100%**（5151/5232/5250 零失配）。比对坑：oracle 的 RVA 注释与签名分行（解析器要抓含 `) { }` 的行）；跳过己方不可解码行时必须同步跳过 oracle 行，否则错位全失配（首版比对 0.3% 即此假象）。
- emu_chain 修复：imul reg,reg 追踪（dst=gete(dst)*gete(src)，此前双侧取 movabs imm 折叠成常数——6.6 链一直手工注入的根因）；ret-forest 会改变分支走向 → 改 zero/forest 双策略自动重试合并。
- 6.2 方法表 name 解出（off0 XorCSubMask 0x614fcedd）；6.3 链提取但 builder 不读 name（惰性访问器边界，同 7.0 字段名模式）。
- **6.4 三轮悬案根因**：name 公式正确；第二解密器 0x140474480（splitmix64：0x9E3779B185EBCA87×idx ^0x27D4EB2F165667C9 rol 0x17 ×0xC2B2AE3D27D4EB4F +0x165667B19E3779F9，shr 0x21/0x1d/0x20 三轮 finalize；位切片查表 r10[（h>>6）<<5]）；密钥表由 0x1404B78AC/0x1404B7B6C 区域在加载期构建（写 0x144EEAC08/28/30）。模拟路线已通到最后一步（喂 idx→查表→解密），缺建表。提交 28dbfd5。

## R73（2026-10-25）：Rust 移植第一步 + 6.4 二号堆前缀实证（不是需求，方案记录）

- **6.4 补充证据**：strings 枚举证明 6.4 heap 前缀无 .ctor/GetText/Format（<Module> 后直接 resourceFormat）——方法名字符串不在 derive 堆，第二字符串空间实锤；GetTextInfoData/GetTextureStreamingEnabled 等长名仍在（属其它表）。6.4 方法名恢复需模拟 C++ 初始化（0x1404B72B0，CRT/TLS 重）或运行时 dump，战略价值低（7.x 无此架构），维持 timebox。
- **expr.rs 落地**（R39 首块）：Expr/eval + Fam/fam_value/fam_invert + 8 测试。两个坑：① serde 1.0.229 元组变体序列化为 {"imm":v} 而非 ["imm",v]——手写 impl 保数组 wire format（跨语言工件稳定性优先）；② 测试常数手抄十进制两度错（27083628349962≠27554674704714 等）——与「JSON 存十进制人看十六进制」同一族坑，规则=测试常数必须脚本换算注入。
- 会话环境：cargo 被 AppImage 代理劫持，`env -u RUSTC_WRAPPER /usr/bin/cargo` 绕过（记入 TOOLS.md 与记忆）。

## R74（2026-10-25）：rowtable Rust 化 + CLI + auto_tables emu 合流（不是需求，方案记录）

- src/rowtable.rs（name/count/start 三求解器）+ `mhydump rowtable` 子命令 + assets/prior_method_names.json（先验名数据文件）。
- **验证等级**：6.7 实弹 CLI 输出与 Python 求解器逐字段一致（含 ok_rows 2565/idrate 1.0/哨兵 385952/sum_counts 513345）；门控样本测试全绿（508s）。
- **移植期新发现（回灌 Python 语义）**：均匀堆偏移下「错 C 恒定位移」可通过标识符率验收（合成测试抓到）——Python 的 exact-prior 校验（_verify_name ≥5 精确命中）此前漏移植，已补齐；该类 alias 在真实非均匀堆上本就难成立（oracle 100% 佐证），但判据应显式化。
- 进制坑两连：sub 族 C=88 ≡ add 族 +0xA8（mod 256 同变换）；断言/文档写常数必须注明进制。
- auto_tables emu 合流：method_defs 12→24 链（emu 贡献 movabs 形态 3 条）。
- dev/release 构建混淆：裸 `cargo build` 只出 dev profile，target/release/mhydump 不更新——统一 `env -u RUSTC_WRAPPER /usr/bin/cargo build --release`。

## R75（2026-10-25）：symwalk Rust 化 11/11 全绿（不是需求，方案记录）

- src/symwalk.rs + `mhydump symwalk` 子命令；门控回归 symwalk_regression 11/11 站点常数逐位复现（等价 Python 的 11/12 组，第 12 个是兄弟站点设计性排除）。
- 调试方法论：构造隔离微测试（mov eax,edi+imul3 / 行标记+disp4 / movabs+imul2）把「全站缺」收敛到单指令路径，再回真实站点验证——比全站调试快一个量级。
- 四根因（Rust 移植特有，Python 无）：iced OpKind::Immediate32to64（imul r64,r64,imm32 的立即数形态，imm_of 曾静默 None）；lin_terms 对 Lo/Ext 不穿透（32 位循环变量→行标记全灭；对 <2^32 索引穿透精确）；caller-saved 表 SysV/Win64 混淆（rsi/rdi 被误清，getter 列全在 call 后）；reg_info 裸 r8-r15 无后缀名解析（"R13" 的 rest[..len-1] 剥掉数字）。
- 设计差异（有意）：候选全量合并（Python top-3）——错起点垃圾由下游数据验收过滤；合并回扫 289 起点，链 cap 400。

## R76（2026-10-25）：emu_chain Rust 化 6/6 全绿（不是需求，方案记录）

- src/emu_chain.rs + `mhydump emu-chain`。unicorn crate API 与 Python 版差异：Prot/HookType::MEM_INVALID（无 add_mem_invalid_hook，走 add_mem_hook）；emu_start count 参数 usize；hook 闭包借用 D=() 的 Unicorn；共享态用 Rc<RefCell>（hooks 持弱引用，emu 结束后 Rc::try_unwrap/swap 取回）。
- 链接：unicorn qemu 后端引 __atomic_compare_exchange_16（GCC 内建），rust-lld 不从 libgcc 提供——`.cargo/config.toml` rustflags `-C link-arg=-latomic`。
- 结果：6/6 版本（7.1/6.6/6.5/6.3/6.2/6.1）链常数逐位复现；6.3/6.2 优于 Python（栈返回恢复穿过首段间接调用，stop=clean）。全量 cargo test 31 passed。

## R77（2026-10-25）：R39 收官——auto-tables 编排子命令（不是需求，方案记录）

- src/shape_transfer.rs + `mhydump auto-tables`；纯 Rust 全链：6.7 种子（数据 JSON）→ 指纹转移（trigram Jaccard top-3）→ 匹配函数 symwalk(全起点合并)+emu(zero/forest) 链合流 → rowtable 方法表求解（--solve-method）。
- **验收**：6.6（方法链须模拟执行的 hardest case）方法表 name/count/start 三列常数与 Python 战役（R71）逐字段一致；method/param/prop/event 四语义 slot 与 Python 逐位同。已知分歧：field_names（score 0.084 弱匹配）序数选取 Rust→slot 0x4 vs Python→slot 0xDC，显式记录待核（该语义基址在 Python 靠 derive 侧独立互证过）。
- 移植期两根因：iced `memory_displacement64()` 对 RIP 相对寻址返回绝对目标地址（capstone 返回位移，加 next_ip 双重偏移致锚点扫描全空）；种子 op 词（add/xor）与 AnchorOp 符号（+ /^）表示不一致致序数匹配恒败（归一化 parse_op 修复）。
- R39 五件套完成度：expr(449d1f6)/rowtable(5cf4207)/symwalk(f03ba6f)/emu_chain(185fffc)/shape_transfer+编排(8415cdb)，各带门控回归；Python 原型仍在 tools/version-triage 作为参考实现。

## R78（2026-10-25）：改进①——auto-tables → Profile → dump-gen 接线（不是需求，方案记录）

**目标（改进计划第 1 项）**：把零接触管线输出接成 dump-gen 可吃的 Profile，使「新版本 → auto-tables → dump-gen」闭环。质量分级：solved/partial/inherited 由 `_splice` manifest 显式携带。

- src/profile_splice.rs：种子 Profile（默认内置 71 布局）+ TransferReport + TableReport + 目标 derive_build → 拼接 Profile。cipher/strsec 恒取目标自身 derive（strsec_direct 直写，str 槽位换算 `str_sub=-imm mod 2^32` 且与 derive 互证）；24 语义表基座映射到 Profile 的 TableBase 字段；方法表切片（stride+通用链+name/param_start/param_count 三列）。
- Profile 扩展（数据字段，老 JSON 兼容）：`md_mask_expr: Option<Expr>`（通用逐行掩码链，取代 md_pmask——固定 MaskChain 形状装不下 6.6 的 46 位乘子）、`strsec_direct`、ColKind 新增 8 个 Gen* 变体（fam_value u32 域 ×5 + count u8 域 ×3，统一走 `gen_col_value` 单点求值，杜绝换算与求值漂移）。engine md_col/find_header/strsec 消费点接入。
- `auto-tables --profile-out --seed-profile --verify-rows`：拼接后**用 dump-gen 同款引擎路径**（Meta::md_col+decode_str）解码前 N 行验证。
- **6.6 实弹（全链 6:22，其中 solve 5 分钟）**：256/256 行命名、标识符率 100%、样本=corelib 前缀（.ctor/GetText/GetText/Format/mono_runtime_install_handlers/...）。dump-gen 冒烟 exit 0（cipher 校验过、md=0x794924 正确），0 types=如实现状（typedef 仍种子继承，等改进③）。
- **实弹捉到并修复的真 bug**：转移成功后 `rec.op` 是符号形式（"+"，shape_transfer.rs:375 `a.op.name()`），splice 首版只认词形式（"add"）→ method_defs 的 imm 静默丢失 → 引擎验证乱码暴露。parse_op 双形式归一化修复+回归测试（`params` 符号 op 用例）。又一例「op 表示不一致」家族（R77 已踩过同根）。
- **勘误（R77/TOOLS.md）**：6.6 name 列记为 XorCSubMask 0xA6C26AFF——本轮同链实测 len=181 乱码；本轮解 AddCXorMask c=0xA6BBF48D（idrate 1.0、2580 行、exact-prior 门过、引擎路径 100%+精确 corelib 前缀）。旧记录疑为转写误差，以本轮可复现证据为准（auto.json/profile.json 在 ~/gire/out/zero-touch/）。
- 未验证项：`--seed-profile` 外部 JSON 路径未实弹（默认 gen71 路径已验）；startup-metadata 表 partial 接线（表基座可换、掩码仍种子）未验——掩码属改进③。

## R79（2026-10-26）：改进③-td——typeDef 表结构化求解 + 引擎通用列（不是需求，方案记录）

- `profile_splice::solve_typedef`：**不靠种子语义**——candidate_bases（代码自带 base+index*stride 位点→锚点兜底，抽到 tables.rs 公共函数）→ tables::find 平铺谓词（start/count 对）→ 字符串列发现器选 name → 回锚 TableBase（含 td_size 探测）。两对按 max_index 排序：大者=methodStart 对，小者=fieldStart 对（6.6: +4 add c=0x565FC12F max 671950；+0x20 xor c=0x9A2F3E83 max 404882）。IndexTransform Add→ColKind::AddC 带负 c 换算（profile 用 raw+c，IndexTable 用 raw-c）。
- engine 通用化：td_name/td_ns/td_method_start/td_field_start/td_field_count 消费点全部改走 `profile::col_value32/16`（kind 化）；新增 `td_method_start` 访问器。
- Profile 新数据字段：`td_rows_direct`/`md_rows_direct`（无 size 锚时的行数来源：td 结构走查行数 / maxMethodIdx+1）。**两处种子残留教训**：splice 清了 td_rows_direct 但没清种子 td_size——engine 优先 td_size → 6.6 解析出 144714 垃圾行；md_size 同理。修复=求解成功而 size 槽未转移时显式 `p.td_size=None`/`p.md_size=None`。
- dump_gen 分组：decl 列在范围内照旧（7.1 逐字节不变，`cmp ~/gire/out/71/dump.cs` 实证），出界才回退 methodStart 区间推导 decl——拼接 profile（decl 是种子乱码）的方法靠区间救回。
- **6.6 实弹**：td 引擎验证 82222 行 256/256 标识符（corelib 序）；dump-gen exit 0：**82222 types / 404886 fields / 671951 methods**（世代规模）；方法名+RVA 正确（GetText/InstallSignalHandlers/.ctor），参数名/namespace/flags 仍种子乱码（inherited，待 ③ 后续）。
- 事故记录：/tmp 被 host 清空一次+配额写满一次——战役产物一律走 ~/gire/out/zero-touch/battle/（持久盘）；tmpfs 只放临时。

## R80（2026-10-26）：改进⑤——loadsites.py 移植，全链单二进制（不是需求，方案记录）

- src/loadsites.rs + `mhydump loadsites`：rip 扫描（逐字节推进匹配 numpy 掩码含重叠假阳性，site 集与 Python 逐位同）、hdr_global（lea→store 双 rip 模式）、iced 指纹。
- **指纹逐字节对齐 capstone**（与既有 Python 种子文件混用前提），六轮迭代：①IntelFormatter 排版选项（hex_prefix/大小写/逗号空格/内存 +- 空格/rip_relatives/MemorySizeOptions::Always）；②负立即数符号规则——capstone 实测真值表：原生宽度恒无符号，符号扩展编码（imm8→16/32/64、imm32→64）仅 add/adc/sub/sbb/cmp 有符号、or/and/xor 无符号（按助记符+OpKind 双条件逐指令切换 set_signed_immediate_operands）；③段前缀仅非默认时注入（iced 自动显示 fs/gs，会双写）；④movabs（mov r64,imm64）/imul 三操作数补显式 dst/0x90→nop（iced 记 Nop+0 操作数但格式器印 xchg ax,ax）；⑤零操作数尾随空格（capstone 恒 `mnemonic + ' '`）；⑥**无效字节：capstone 停止、iced 印 `(bad)`——is_invalid() 即停**（此条曾致 3192/4254 site 差 1 token，是最大单项）。
- **验收**：6.6 指纹 4253/4254 site 逐 token 全同（99.98%）；唯一分歧=1 个 `sal r8d` vs `shl r8d`（capstone 在该处编码上的命名怪癖，探针复现不了，对 Jaccard 无影响）。`mhydump derive` 输出 schema 与 Python derive.json 逐键同（首锚逐字段同）。
- 至此六个子命令全链无 Python：loadsites → derive → strings → auto-tables → dump-gen（+tables/rowtable 调试面）。battle_rust.sh 改为自产 sites/derive。
- 方法论沉淀：跨反汇编器指纹对齐必须「首分歧 token」聚合统计——zip 对比在 token 数不同时整体错位，会把后续无关 token 当分歧（`sal` 假象浪费一轮）。

## R81b（2026-10-26）：首轮战役结果 + name-only 拼接（不是需求，方案记录）

- **HeapIndex.starts_with 平方黑洞**（2992ca3）：原实现每次调用全量 sort 47 万条目，pin 循环内被调数万次——可解版本侥幸早停（6.6 solve ~3min 真凶也是它），不可解版本穷举 59min+。预排序 by_text + 二分前缀扫描：6.0 solve 59min→4s。
- **L5 derive 互证门**（2992ca3）：弱匹配（score<0.3）须目标 derive 锚含同 (slot,op,imm) 才拼接；否则拒。6.6 field_names 实证：Rust 弱选 0x4^0x46E79FE3 无锚被拒（此前会拼进垃圾基座），Python 侧 0xDC+0x9623F4C7 有 confirmed 锚。
- **name-only 拼接**：count/start 未解（6.2 疑 mask2 变体）时仅拼 stride+链+name 列——dump 方法名即可正确，参数列留种子。6.2 实弹 20s：引擎 256 行 100%。
- **战役 6.0–6.6 结果**（旧 binary、heap 修复后）：
  - typeDef 结构解 **6/6 全对**（行数与 oracle 类型数吻合：6.3 76399≈76397、6.5 80164≈80166、6.6 82222；样本全部 corelib 正确序）。
  - 方法表：6.5/6.6 全解（引擎 100%）；6.2 name-only；6.0/6.1/6.3 链池无解（转移分 0.01–0.4，函数定位是弱环——Python 时代 6.1 是 emu 在已知函数地址解的，零接触转移到不了那里）。
  - **6.5 oracle 13.75% 定性**：非解码错误——第 83676 行起 oracle 显示 BeeByte 去混淆名（JDIOCKICHNB→get_txtTitle，oracle 目录有 BeeByte-6.0/ 映射），前 89924 行 lockstep 逐位全同；R72 时代只比前 5k 行才全绿。后续 oracle 比对应过滤映射名或用 raw dump。

## R82（2026-10-27）：7.1 独立 dump 达成——layout71 退役 + 四门补全（不是需求，方案记录）

**用户设计判据**：dumper 二进制零常数；常数只允许 Profile 数据文件携带；7.1 全程自主求解出 dump。**验收：7.1 零接触 dump 与内置 oracle dump 2,417,104 行 100% 逐行一致。**

- **layout71 退役**：全部常数移 `assets/profile-7.1.0.json`（gen71 改 include_str+serde；默认 dump 路径逐字节回归一致；36 测试全绿）。代码里不再有任何版本常数（prior 名单也是 assets）。
- **count 候选迭代**：solve_start_column 此前只对 counts[0] 验证——伪列在前则 start 全灭（7.1 实弹）。改为迭代前 4 个候选取首个非空 starts。
- **start 链违例比例门**：绝对门 bad>8 在 73 万行下把正确解拒了——7.1 真实数据有 39 行不规则（隐藏/包装方法 paramStart≠累计和；哨兵 411465/411467 全对、c 与 oracle 逐位同实证）。改 `bad > rows/1000+16`。
- **md_size 结构锚探**：行数下界=td 平铺 maxMethodIdx+1，扫 derive 锚找 byte size ∈ [lo, lo+512)×stride——7.1 命中 slot 0x134+0x8EEFDB56=oracle 精确。
- **td_ns**：字符串列发现器的第二列=namespace（7.1 off24 XorC 0x666769B5 与 oracle 逐位同）。
- **L6 基座解码门（field_names）**：L5（锚存在）在 7.1 放行了错锚——转移选了 0xDC=typeDef 槽（真锚、错表）。L6=候基座用种子链解码字段名，标识符率≥0.98 才收，不过则扫 derive 锚全量找过验者。7.1：转移基 0x48f3fd8(TD表) 被拒，锚基 0x4580d78 率 1.00 → slot 76（与 oracle 同槽、add/sub 写法等价）。
- 7.1 零接触 34s 全链：机器解出 cipher/strsec/td 全套+ns/方法表四列+md_size/field_names 基座，全部与 oracle 语义等价；种子继承列（7.1 场景下=oracle）由 manifest 如实标注。**跨版本时继承列=种子值（会错），属已知边界——关闭它需要 fields/param/prop/event 列求解（下轮）。**

## R83（2026-10-27）：param_defs 表零接触求解（跨版本继承列第一块）（不是需求，方案记录）

- **行数**=方法求解的 sum_counts（精确）；**链**=param 转移池（7.1 全 7 常数链在池内，数值验证=oracle mask 逐位同）；**name 列**=solve_name_column 复用（engine `param_name` 公式 `(raw^xor)-mask` 恰=XorCSubMask 族）。
- **短串盲区根因**：参数名 msg/fmt/args（3 字节）后跟非打印间隙，run<8 不入堆枚举（strings --out 只录 run≥8 起点）→ pin/exact 门全灭。修法三件：①`strings --min-len N`（string_starts_min，printable_prefix_len 参数化；7.1 min3 堆 67万→158万条）；②solve_name_column pin 行**按先验名长度降序**（长名钉常数更锐且短名恰是堆缺失区）；③Profile `param_def_name_off/type_off` 数据化（6.6 实测 name 列在 +0 与 7.1 的 +4 换位——engine 硬编码 +4 是 6.6 dump 乱码的直接原因）。
- **先验资产**：assets/prior_param_names.json（48 个 corelib 参数名，7.1 oracle 常数提取：msg/fmt/args/resourceFormat/exception/flag/obj/klass/ptr...）。
- **验收**：7.1 name_xor=1804988680=oracle、零接触 dump 仍 2,417,104 行 100%；**6.6 跨版本实弹：`private object GetText(object fmt, object args)`——参数名正确**（name 列 +0 c=0x37C37EA 482602 行；类型列仍种子=object，type 列求解留下轮）。默认 7.1 dump 逐字节回归一致。

## R84（2026-10-28）：field 切片脚手架 + 全战役回归（不是需求，方案记录）

- field 切片接线完成（field_mask_expr/列偏移数据化、TdSolve.field_rows_total=平铺计数和、prior_field_names.json 资产、XorCXorMask 门）——**但 7.1 实测链池无真链**：字段访问器函数的 symwalk 产物全是 r13^r13 自消常数伪影（链对每个 i 恒定），oracle 六常数只以伪影形式共现。**缺口在提取层不在求解层**：需要该函数的循环变量追踪修复或 emu 定点。代码保留（门控自动激活，无副作用）。
- 全战役回归（min3 堆+param 切片）：td 6/6、6.5/6.6 方法全解、6.2 name-only（ok 2585→3670 提升）、oracle 前缀一致——无回退。**param 切片跨版落地：6.6 ✓（name@+0，482602 行）；6.5 链池无解；6.2 方法 name-only 无 sum_counts 不触发**（门正确）。
- L6 门跨版行为如设计：6.5/6.6 种子 field_mask（7.1 的）在目标上解不出字段名 → 全候选拒 → 保种子基座+显式 note。
- 遗留清单（按优先级）：①字段链提取修复（r13 追踪）→字段名跨版；②6.5/6.2 param 链提取；③prop/event 表；④转移弱环 6.0/6.1/6.3（chain_hunt 移植或全镜像找链）；⑤param type 列（typearr 上界区间交集）。

## R85（2026-10-28）：字段链提取修复——7.1 字段名零接触解出（不是需求，方案记录）

三层根因逐个修掉，7.1 字段表（440172 行）零接触解出，dump 保持 2,417,104 行 100%：

1. **fold 缺自消规则**：`xor r13d,r13d`（循环变量清零惯用法）被记为 `Xor(Sym,Sym)` 而非 0——下游一切经 r13 的表达式变成双符号且 r13 出现两次，任何坍缩/纯度门都过不了（R84 的「r13 伪影」确切成因）。fold 加 `X^X→0 / A-A→0`（Expr derive PartialEq）。
2. **emu 不处理 Lea**：`lea edx,[r14+r13]`（行地址惯用法）直接跳过，rdx 保持陈旧值——整个掩码链建立在错的输入上。emu_tracker 补 Lea 符号求值（base+index×scale+disp）。修复后 emu 一次产出完整 oracle 六常数链＋含 `^0x48e6373` 的整列公式。
3. **链内烘焙列常数**：池里 `mask^nameC` 变体让 name 求解给出 c=0（解码等价）但类型列共用掩码被连坐（`MonoClass* value`→`object value`，3.31% 崩）。拼接处拆分：顶层（穿透 Lo 包裹）`Xor(inner,imm)` → mask=inner、C^=imm。修后 field_name_xor=0x48E6373=oracle 逐位同、7.1 dump 回 100%。
- 附：expr::collapse_index_sum（base+counter 双符号求和节点坍缩为 Sym("i")，symwalk/emu 两处 record 门接入）+ 单测；本轮它未成为主修复路径（Lea+fold 已让链单符号化）但作为通用保险保留。
- **6.6 字段**：联合基座+链求解（匹配函数窗口内 derive 锚 ×链池）已实现，但 6.6 链形态不同（movabs-imul 家族 `×0x4f0c708494a8>>0x12`，与其方法链同族），name 列族也非 XorCXorMask——需要 engine 字段列 Gen* 化（照 md 列模式）＝下轮。参数名 6.6 已全对（fmt/args/obj/parser 实证）。

## R86（2026-10-28）：engine 字段列 Gen* 化——6.6 六切片全解（不是需求，方案记录）

- Profile `field_name_kind: Option<ColKind>`（None=legacy 三重 xor 形式；Gen* 走 gen_col_value 单点求值）；engine field_name_idx 按类型分派。splice 字段切片放开族限制（任意 fam→from_fam 映射），XorCXorMask 保留烘焙常数拆分，其余族直取。
- **6.6 实弹：field_names.slice（base 0x325aed0=Python 时代实证锚 0xDC+0x9623F4C7、name@+0 GenXorCSubMask c=0x3E3F44FB、404886 行）**——联合基座+链求解（R85 脚手架）在列族放开后直接命中。**6.6 共 6 个机器切片**：cipher/strsec/method/td/field/param，dump 字段名（value…）、参数名（fmt/args）、方法名全部正确。
- 7.1 双路径回归：零接触 dump 2,417,104 行 100%；默认 dump 逐字节一致（cmp 实证）。from_fam→Gen* 映射核对无误（虚惊一场的 legacy 同名坑：from_fam 全部落 Gen 前缀变体）。
- 全战役矩阵不变：6.2/6.5 field/param 卡各自世代的链池覆盖（提取层），6.0/6.1/6.3 卡转移——均为已记录缺口。

## R87 补遗（2026-10-28，提交 7edc2fd）：6.5 param 解出与两处回归修复

- **6.5 param 破解路径**：asm 直读 `idx=(raw+r14)+0x92A9143C`（r14=(((i×0x2E45)^0x54D26629)×0x27CF5FCE)^0xCF047B35）。三个缺口逐个补：①族缺失——AddMaskAddC（`raw+mask+C`，mask 符号不能折进常数）进 Fam/gen_col_value/from_fam/rowtable fams 数组；②变体生成器补 **negated 链**（`raw+chain+C ≡ raw-(-chain)+C`，同一 SubMaskAddC 反演不变）；③**短名验收门** short_name_column_ok——参数名 msg/fmt/args(3B) 在 min3 堆里 4000 行只有 9 行可确认，方法表的 ok_rows≥1800 地板必拒正确解；改 exact-prior 证据（exact+1≥min(6,len-1)）。
- **基座来源修正**：6.5 param 真基座 0x19D8E6C=hdr[0x60]^0x2580119A（代码形态，非 confirmed 锚也参与 sweep）。
- **两处回归（都是本轮新代码引入）**：①engine param_name 把 legacy None 路由进 gen_col_value(XorCSubMask2)——该 kind 无分支、静默返回 raw 列（7.1 崩到 2.67%）；修=None 直接算 (raw^xor)-mask。②splice 设 param_def_name_kind（AddMaskAddC 需 Gen 路径，否则同样静默 raw）。教训：**新增 kind 分发时必须核对所有 unwrap_or 回退族的分支覆盖**。
- 终态：7.1 零接触 2,417,104 行 100%；6.5 field(396,634 行 c=0x2DD43D8D)+param(552,886 行 AddMaskAddC c=0x92A9143C)、GetText(msg/fmt/args) 全对；6.6 不回退。37 测试全绿。

## R88（2026-10-28）：6.2 field+paramCount 解出——差分定位法+基座邻域+xorsub 族

- **差分不变量定位法（本轮方法论核心）**：六族列变换的行间差分均与族常数 C 无关（线性族 add-diff、Xor* 族 xor-diff），用 oracle packed 序列做 v[]、链池 eval 做 mask[]，全 body u32 域搜差分模式即可 1 秒定位列（diag62_field2.py）——不依赖锚集、不依赖函数定位。对比：chain_hunt 全镜像形状扫跑 5h43m/6.7GB 未完成（被杀），差分法快 4 个数量级。
- **6.2 field 真因与修复**：转移 resolved=0x18E58F4 与真表起点 0x18E58F0 差 4 字节（游戏访问器 `rcx=hdr[0x184]+imm+body_ptr`，body 指针贡献 0x41C 而 resolve 只见 hdr+imm）。修=splice 基座候选加 ±4/±8 邻域（exact 优先+邻域殿后两轮，快路径零回退）。命中：base 0x18E58EC+name_off 4、XorCSubMask c=0x372DF988、368293 行（diag 验证 24/24 oracle 行逐位同）。
- **6.2 paramCount 新族 xorsub**：`(raw8 ^ C) - mask`——xor 常数在前、减链在后（xor/sub 混合，原 count_decode 三 op 均不覆盖）。count_decode/solve_count_column/ColKind::GenCountXorSub8/gen_col_value/from_count_op/engine md_col 全链接入。命中：off 16、C=0xBF（diag 512/512）、count_sum=453660。TableReport 加 count_sum（start 未解时 param 切片的行数来源），method PARTIAL 分支拼 count、param 切片触发条件用 count_sum 兜底。
- **提取层认知**：①6.2 strsec 字符串无分隔符紧贴（default_vtable@762 与 xdomain_vtable@776 重叠），堆 text exact→off 有系统盲区（52/192 行 missing）——Rust solve_name_column 的 off→前缀方向不受影响（proxy_class@0x316 精确可解）。②6.2 method 访问器实测（0x14044a5c1 群）：count 链=`(((i×0x1A70E038E08A)>>8)^0x700A03C7)+0x4455DC19` 与池内 chain2/52 等价；name C=0x614FCEDD。
- **未解清单（6.2）**：param name（40 分钟全锚 sweep 无命中——链池疑缺真链，下轮差分诊断）；paramStart（6 fam×62 链×全 offset 0 命中——布局在假设空间外，疑行号语义或 mask2 形态）；dump-gen 未解列种子继承使 paramCount 乱码放大成 12GB dump（乱码串直写+255 参数/方法），待 param 解出自然消，引擎 clamp 防御暂未加。
- **回归**：7.1 零接触 dump 与 oracle 2,417,104 行 BYTE-IDENTICAL（cmp 实证）；6.6/6.5 六切片逐值一致（field/param 基座与常数同 R86/R87）；37 测试全绿。
- **性能债**：6.2 全程 40 分钟（param sweep 全锚×邻域×87 链）——差分定位法移植 Rust 是下轮第一优先（枚举法换数据驱动定位）。

## R89（2026-10-29）：差分定位法移植 Rust——field/param 切片快路径全链（不是需求，方案记录）

- **locator（rowtable::locate_name_column_differential）**：C-free 行差分全 body 扫描。四族类（线性-add、add-mask、xor-sub、xor-xor）；锚行=连续已知对按候选积排序；命中=所有已知先行行解码落堆候选≥6。单测×2（XorCSubMask/AddMaskAddC 合成列）。
- **池探针**：零命中=该池在所有可扫族下无解 → param sweep 直接跳过（6.2 param 40min 枚举→52s 全程）。相位设计：xor 族先扫原始 mask（多数池携带真掩码），零命中再扫 ±KS/取负变体（**xor 族差分对 mask 平移不变量不成立**——6.5 field 真掩码=池链∓0x847bfc89，phase-2 命中；DiffHit 带 (shift,negated) 供快路径复现并烘焙进 profile 链）。
- **三个真 bug（都是本轮新代码引入，各有教训）**：
  ①scan 闭包单元素切片使 chain_idx 恒 0——快路径拿 chains[0] 验证必败。教训：索引映射要显式传参（重构为 item fn 顺带解决借用冲突）。
  ②(TableBase,off) 二义：定位器给列位置，(base,0)/(base-4,4) 名字解码相同但**类型列相反**且锚定不同。修=双解释评估+锚定优先+TableBase 加 `direct` 字段（无锚可落时以数据携带绝对偏移；6.2 field 因此拿到**真行起点 0x18E58F0**——比 R88 sweep 的 0x18E58EC+4 更准）。sweep 路径同修（无锚落 direct，不再留转移基座=R88 的 6.2 潜在错位）。
  ③**烘焙拆分条件**：7.1 param 的池链顶层 Xor 是链自身结构，被当 R85 烘焙常数拆掉——验证用 (原链,hit.c) 通过、profile 记 (inner,c^k) 破损对。教训：**验证与记录必须用同一 (mask,C) 对；等价变换才可拆**（XorCXorMask 的 XOR 交换拆分等价；XorCSubMask 不等价）。修=拆分限定 field+XorCXorMask+未平移未取负；param 不拆。
- **验证矩阵**：7.1 零接触 dump **BYTE-IDENTICAL**（field c=0x48E6373=oracle、param c=0x6B95F108=oracle，全走差分快路径）；6.5 field/param anchored 双解逐值同 R87；6.6 双解逐值同 R86；6.2 field direct 真基座+param 探针跳 sweep。39 测试全绿。性能：6.2 全程 40min→52s；6.5 42s。
- 遗留：phase-2（平移/取负）命中时共享类型列可能错（manifest 已注记）——未在已解版本出现；6.2 param 真链仍缺（提取层，下轮反汇编 param 访问器）。

## R89 补遗（2026-10-29）：6.2 param 访问器搜索——五路排查与意外收获（不是需求，方案记录）

param 差分零命中后对提取层做了系统排查，param 访问器仍未定位，但收获三个**其他表**的 6.2 访问器常数（后续接线素材）：

- **gp 访问器 ×2**（0x14044DC30 / 0x1404476E7）：gp 表基座 = hdr[0x1E0]^0x728D450D+body、**stride 16**（7.1 是 14）；gpStart = td 行+0x32 的 u16 ^0x28EA（哨兵 0xFFFF）；gp 链 = (((i×0x5C2890877728+0xB4A21FAA8FC8545)>>0x16)×0x6F41175D+0x23155180D3C03C76)^0x21E06262（一个 64 位版一个 32 位版）。→ engine gp/gc 硬编码的 6.2 修正素材。
- **event 访问器**（0x14044AAF6 区）：基座 = hdr[0x204]+0x9B8EE445（与转移锚一致！）、stride 14、name@0 = (raw ^ mask)^C1（哨兵 -1）、type@4 同 mask ^C2，mask = (((i×0x1594F54A3868+0x18A1ED1E5C6D3B09)^0x3E56E4CD)×0x500002EC)>>0x16（64 位域取低 32）。堆解码验证未过（4 行可解非标识符）——常数抄录或 64 位域细节待复核。
- **field 运行时路径互证**（0x14045247B）：真公式 = (raw^0x372DF988) + lo64(链×0xD27214C8) + 0xD878151F ≡ (raw^C) − chain0（代数等价）——差分解 XorCSubMask c=0x372DF988 与游戏实现逐位一致，独立佐证。
- **decode_str 调用点普查**：全镜像 27 处（.text；il2cpp section 零调用）。已归因：field(0x4486AA)/method(0x44A67D,0x44A76B)/event(0x44AB86)/prop(0x44AFAD)/gp 邻域/0x452-0x453 运行时区/0x47B 区（0x47BD71 带 kind byte 表+stride8+链，疑似 defaults/attributes）。**param 名不经过独立 decode_str 调用点**——或为内联、或 param 表访问器结构不同（可能 GetParameterName 不走字符串缓存路径）。
- 工具改进：symwalk.pe_map 加按路径缓存（chain_hunt 每 Walker 重读 450MB 的 5h43m 根因）；chain_hunt 62min 仍未完（逐簇 python Walker 仍慢）——Rust 化 chain_hunt 列入待办。diag62_param.py 支持 --chains 直读 chain_hunt 池。
- 6.2 param 现状：链池缺真链（差分探针已实锤）+ 访问器未定位 = 提取层双缺口。param/paramStart 列保持种子数据（探针跳 sweep 已使其零开销）。

## R89c（2026-10-29）：6.2 event 常数复核——两处符号扩展修正+结构预接线（不是需求，方案记录）

- **64 位域复核（逐字节核对原始机器码）**：event 链两处 imm32 符号扩展此前遗漏——①`xor rcx, 0x3E56E4CD` 是 xor r64,imm32 → **符号扩展** 0xFFFFFFFF3E56E4CD；②`imul rbx, rcx, 0x500002EC` 是 imul r64,r64,imm32 → **符号扩展** 0xFFFFFFFF500002EC。另纠正列归属：decode_str 的输入是 **+4 列**（name，C=0x2C9FF31D），+0 是 type 列（typearr 索引、哨兵 0xFFFFFFFF，C=0x6DD83F38）——7.1 profile 的 name@0/type@4 在 6.2 **互换**（与 param 的 +0/+4 换位同款）。
- **mask-free 行内信号（新工具）**：event 行 type/name 两列共用 mask → 行内 xor (u32@0 ^ u32@4) 消去 mask；其 byte1 恒 0x7D（16/16 行）证明**基座 0x3489918 行对齐、14 字节行结构、两列共享 mask**——不依赖任何链常数。此前我误读为 byte2 恒定（已纠正）。
- **堆验证仍未通过**：修正符号扩展+列交换后 6 行可解（含真实事件名 `RemoveDynami…` 截断 12 字符）但仅 6/3000——行号语义仍缺一环。已排除：行号偏移 k∈[0,32000)（esi=td klass 结构 u16@0x34+0x5260 的绝对行号假设）、C 低 24 位暴力交集（1178 候选×len 聚类失败）、len 聚类。链公式与机器码语义逐位一致——剩余未知=esi→链输入的某一环（可能 u16@0x34 解读或 0x5260 组合方式）。
- **event 结构预接线（常数还原后的接入点）**：Profile 加 `event_mask_expr`（Gen 链优先于固定形式 EventMaskChain）+ `event_name_off`/`event_type_off`（数据化 6.2 布局互换）；engine.event_row 按此分派，accessor 列（+8..14）不随 name/type 换位移动。7.1 BYTE-IDENTICAL 保持；39 测试全绿。
- 教训：**imul/xor 的 r64,imm32 形式一律符号扩展**——抄常数时必须核对操作数位宽；行内 mask-free 信号（共 mask 列的 xor）是表结构验证的通用工具，值得在 prop/event 接线时复用。

- **dummy 路径回归补充**：event 结构改动后 7.1 dummy 导出（dummy_export.rs 是 event_row 的唯一消费者）与内置 oracle **224MB 逐字节一致**——event_mask_expr/offsets 数据化双路径验证完成（dump.cs BYTE-IDENTICAL + dummy.jsonl IDENTICAL）。

## R90（2026-10-29）：Rust 化 chain-hunt 落地——62 分钟超时→3 秒；6.2 param/event 差分终局否定（不是需求，方案记录）

- **chain-hunt 子命令**（symwalk::chain_hunt）：全镜像形状驱动链提取。双通道锚（0x69 imm32 直接形式+movabs imm64 间接形式——python 版只扫 0x69，**漏掉 movabs-imul reg,reg 家族=6.6/6.2 method 链形态**）；从簇锚点起步 walk（锚=movabs/0x69 指令边界，固定 back 偏移会撞指令错位）；共享 Image。**性能：6.2 全镜像 3-6 秒**（python 62 分钟未完）。
- **三个新 bug 的教训**：①base_va_of 公式错减 raw_pointer（差 0x400→全部访问器区 walk 打偏）；②锚扫描 else 分支把 d[i] 当 modrm 误判——**790 万假锚**（真 3 万）→ 簇结构全坏；③**符号表达式无界膨胀**是 chain_hunt python 版 62 分钟+8GB 的真根因——record_chain 加 512 节点上限、寄存器传播加 4096 上限（超限折为 RUNAWAY_sym 占位）。**json.dumps 里查十六进制 imm 串是无效的**（serde 输出十进制）——假阴性差点误判链池为空。
- **池内容（6.2）**：7240 链，field K1（2026086125534）×12、method count K ×4、**param 0xD45D ×3**（R89b 手工反汇编常数）都在；event K1/gp K1 不在（0x449f1b/0x44dc30 簇 walk 未出链，待查）。
- **6.2 param/event 差分终局否定**：7180 链×6 族×全 body——param name（prior 名锚定）与 paramStart（count 桥接 prefix 和，纯数据驱动零 oracle）都零命中；行内 byte3 信号判别力不足（随机基线 4.3%）。**结论：6.2 的 param/event mask 不在任何可符号执行提取的产物中**——剩余路径=手工 RE param/event 访问器（0x452-0x453 区 7 个未细查的 decode_str 调用点）或 emu 定点（待 emu_chain 支持该函数形态）。
- 回归：7.1 BYTE-IDENTICAL、39 测试全绿。

- **decode_str 调用点普查终局（R90 补）**：0x452-0x453 区 7 个未细查点全部归因为 td/namespace 运行时消费（0x140453090 区实证：0x1F1AE728=td name 哨兵、0xAD869451=td_name C、0x7B7C9EC4^td@0x24=ns 列）。**27/27 调用点归因完毕，param/event 名不经过任何独立 decode_str 调用**——其访问器为内联或运行时组装形态。6.2 param/event 的 mask 语义到达本轮静态框架的推进边界；剩余路径=emu_chain 定点（需先定位访问器）或运行时调试。
