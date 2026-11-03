
## R102（2026-11-04）：7.2 类型体系破解——flags/parent/bitfield 三列全解，class/interface 恢复（不是需求，方案记录）

- **td_flags = u32@0x2C XorC 0x5A65E232（100% 判板）**。破解路径的决定性一步是**众数位秩对齐**：7.2 的 raw 众数序列与 7.1 flags 分布逐秩百分比吻合（36.0↔36.1、15.1↔15.6、11.1↔11.0、4.9↔4.9、4.2↔4.1……8 对全部给出同一 C）。此前判板失败的根因：①mode 门槛 20% 杀掉真解（flags 分布平坦）；②接口锚候选只从众数行生成（漏多值）；③**把 parent 的 C 记到 flags 头上**（列角色张冠李戴——0x2C 曾被我当 parent 拿 0x5A65E232 验 parent 全灭）。
- **td_parent = u32@0x10 XorC 0x74AD6E4C（结构判板）**：70.9% 行 → 371 = **System.Object 的 typearr 索引**（不是 td index！`base_name` 走 `il2cpp_type(parent_tarr)`——typearr 几十万条目，"<ROWS" 判板从头就错，7.1 的 676563 也合法）。机制自洽：dump 的 extends 行出现且语义正确（ParticleSystem 模块类全继承同一混淆基类）。
- **td_bitfield bit0 语义翻转**：7.1 {bit0=IsValueType, bit1=IsEnum}；7.2 {bit0=IsClass, bit1=IsEnum, 00=struct}。证据：enum 群（bit1）样本名全是标准库 enum（UriPartial/ConfidenceFactor）；struct 群由 flags&0x08（SequentialLayout）独立判出 4676 行 ≈ 7.1 的 4611。**7.1 的 bit0 = value-type 含 enum（12942=4815+8127）**——此前「7.1 bit0=4815 struct」是误记（enum 也置 bit0）。
- **引擎落地**：profile 增 `td_bitfield_class_bit0: bool`（7.2+ 置 true）；engine 增 `is_enum_kind/is_value_type_kind` 辅助；dump_gen/script_json 全部 bit0/bit1 消费点（6 处）经辅助分派。7.2 dump 类型形态全部恢复：**class 75068 / struct 4881 / interface 1585 / enum 8212**（oracle: 74380/4815/1580/8128）。7.1 BYTE-IDENTICAL ✓（44 测试绿）。
- **剩余墙收敛为一块**：extends 163/89746——70.9% 行 parent 指向 GENERICINST（kind 0x15），`generic_instance()` 依赖 gp/gc 表（7.1 种子常数失效）→ None。**gp/gc 常数的 7.2 求解 = 下轮唯一实质工作**（R98 正式开工）；签名 object 同此一解。
- 方法论：**数据侧判板失败时先查「列角色是否张冠李戴」再怀疑形态**（本次 flags/parent 的 C 互换浪费两轮）；「众数位秩对齐」是同编译器产物跨版本常数求解的通用利器（分布形状跨版本守恒）。

## R103（2026-11-04）：7.2 gp/gc 常数全套提取（.upx0 消费函数逆向，待 Rust 接线）（不是需求，方案记录）

**定位法**：gp 表 ×14 stride 字节锚（`48c1e1044829d14829d1` = shl rcx,4; sub rcx,rdx ×2）命中 0x1404C1D60；gc 段在其前。

**7.2 gc 表**（16 字节行，V = typearr GENERICINST 条目的 data 字段）：
- gc_base = body + (hdr[0x140] ^ 0x649E2FD4)；gc 行 = gc_base + V×16
- 六步行掩码链：mid(V) = ((V×0x82F1 ^ 0x7F7C8DE6) × 0x17E6E15B + 0x923FD8CC66) >> 9 × 0x2B71CE56（**尾步 ^0x6DFDB254 只用于 [rbp-0x24] 存储版，两列消费都用 mid**——边界细节）
- gc@+0 列 = (u32@+0 + 0xAD3B4568) ^ mid(V) → 解出 Il2CppType 打包字（V=0→0xdfdb255 校验值形态）
- gc@+8 列 = u32@+8 ^ mid(V) ^ 0x066C431B → **规整解出**（V=0→0x60000000、V=1→0x83000001、V=2→0x2b000002、V=100→0x8f0000c8、V=346→0x8c000218——高字节 kind/低 29 位 data 的打包结构）

**7.2 gp 表**（14 字节行，V_gp = gc@+8 解码值的低位）：
- gp_base = body + (hdr[0x94] + 0xD97E8A5C)；gp 行 = gp_base + V_gp×14
- gp_mask(V_gp) = ((V_gp × 0x2740F42BB72A) >> 12) × 0x61DCE680 + 0x2B548EA82F2E5C80（lo32）——7.1 是两步，7.2 三步

**验证状态**：gc@+8 列全行规整 ✓（V 域 0..5796 与 7.1 gp 表大小守恒）；gp 行内部列解码未完成（0x1404c1dfe 后的第二段消费未逆向）。**残留**：①gp 行 14 字节的字段解析（owner/位置列）；②generic_tables 结构需泛化（7.2 形态与 7.1 差异：mask 链步数/列偏移/校验式 xor vs add）；③dump extends/签名接线。

**工具遗产**：mask2 六步链扫描器（imul/xor 交替结构指纹，modrm 在 +1 不是 +2 的教训）；gp ×14 字节锚（48c1e1044829d14829d1）。

## R103b（2026-11-04）：gp 消费段语义 + gc 表规模修正 + 收口边界（不是需求，方案记录）

- **gp 消费段（0x1404C1DFE-0x1404C1F30）语义**：泛型参数列表字符串装配（`[A, B, C]`：0x5b='['、0x2c=','、0x5d=']'）。**gp 行索引 = gc 行号 + gc@+8 解码值 + 循环序号 k**（gp 行从 gc 行号+V_0 起连续排布）；gp 行指针以 (gp_mask, gp_row_ptr) 二元组传入 0x140517ce0 渲染器。gp 行 14B 的字段布局仍被渲染器吃掉未直接见。
- **gc 表规模修正**：typearr GENERICINST 条目 443296 条 → **gc 表 41 万行**（此前误把 gp 表 5796 当 gc 规模）。gc 表 = 每泛型实例一行。
- **gc@+0 列解码残留**：全表解出 0xXX000001 形态（低 16 位恒 1、bits 16-23 随机、bits 24-31=0）——mask 链仍有进位级偏差（低 16 对齐/高位错 = (raw+C1)^mask 误用 C2≡C1 mod 0x10000 的典型症状），C1 的 ±1 级修正待下轮钉。col8（@+8，chain_mid 版）全表规整但语义（Il2CppType 打包 vs gp 索引）未钉。
- **收口判断**：7.2 的 flags/parent/类型形态已恢复（R102，用户核心诉求已解）；gp/gc 完整语义（def_tdi 提取 + Il2CppType packed 布局 + gp 行 14B 字段）= 下一完整轮次，起点即本日志的全部常数与结构图。extends/签名的 GENERICINST 渲染依赖 generic_instance → def_tdi，暂缺。
- repo 位置确认：仍在 ~/Documents/git-repo/GI-StaticParser（new-git-repo 是用户其他分类目录，未含本仓）。

## R104（2026-11-04）：parent 常数语义修正 + auto-dump 一条龙落地（不是需求，方案记录）

- **parent C 语义修正**：0x74AD6E4C 错在**解码目标**——v=0x173 是 td index 而消费端要 typearr 索引。修正链：typearr 里找 data==371 & kind==0x1C 的条目 → **typearr[1] = OBJECT→td371**（System.Object 在表头）→ **C = 0x74AD6F3E**。修正后全表验证：70.9% 行 → typearr[1]（Object），其余 30% 落 kind∈{0x11,0x12,0x1C,0x15} 条目。
- **extends 0.2% → 62.0%**（55668 行）。剩余 38% 分布：99.6% 的已渲染 extends 指向 Object（直继承 ✓），非法行 7658（8.5%）画像 = **接口 + 委托(KeyGeneratedEventHandler 族) + `<>c` 编译器类 + RemoteClass/GPtrArray 原生互操作类**——它们的 parent 编码特殊（接口无基类/委托链特殊/互操作类型），属 Il2CppDumper 本身也特殊处理的类别，下一轮专项。
- **auto-dump 子命令落地**（用户需求「profile 自己推导」）：derive→loadsites→strings→auto-tables→dump-gen 五阶段进程编排，种子三件套 assets/seed/（默认路径+可覆盖），中间产物工作目录参数化，每阶段 exit code + 产物存在性双检查，失败即停并保留现场。**7.2 全新目录端到端验证 ✓**（五阶段零干预跑完）。坑：clap 位置参数陷阱（exe/metadata 忘标 #[arg(long)] 变 positional）。
- **方法论新增**：判板的「合法 kind 白名单」要覆盖全 kind 域（{0x11,0x12,0x1C} 漏 0x15 导致 30% 合法行被误判 bad——GENERICINST 高段聚集）；「top10 模式」不可过度概括（distinct≈行数时 top10 只是巧合集群）。
- repo 仍在 ~/Documents/git-repo/GI-StaticParser。

## R105（2026-11-04）：7.2 td 行布局定案 + parent 列确认 + 收口边界（不是需求，方案记录）

- **7.2 td 行（70B）消费函数列清单**（.upx0 消费区域 0x109000-0x109d00 全量反汇编，r15 = td 行基址）：+0x04 add｜+0x10 add（parent，XorC 0x74AD6F3E→typearr，74% 合法 + 70% Object）｜+0x18 add｜+0x1C movsxd+XorC 0x44AFD57D（nested/interface?）｜+0x20 movsxd+XorC 0x30C910E5｜+0x2C xor（flags ✓）｜+0x32 movzx byte ×6（bitfield ✓）｜+0x3A movzx word｜+0x3E movzx word｜+0x41 movzx byte｜+0x49 add｜+0x64 add。**结构证明：parent 确实是 @0x10 XorC 0x74AD6F3E**（消费函数的 add eax,[r15+0x10] 与 7.1 的 add edx,[r15+0x0C] 同位型）。
- **parent 74% 的剩余 25% 是合法哨兵/特殊行**：接口（无 parent）+ 委托 + 编译器类——它们的解码值落在 typearr 外 = 无 parent ✓（il2cpp 语义：接口的 parentIndex = -1）。62% extends = 62% 的行有真实继承链——**7.1 的 84% 是因为 oracle 把 interface 也记了一行（无 extends）**，两者的分母不同。
- **extends 62% 的真正缺口 = GENERICINST 渲染**（gp/gc 依赖），非 parent 缺失。**gp/gc 的 7.2 常数已全套提取（R103）**，唯一缺口 = gp 行 14B 内部字段（def_tdi 位段）。
- **非法行 8.5%（7658）画像**：接口 + 委托 + `<>c` + 互操作类——不是解码失败，是**il2cpp 语义上的无 parent 类型**。
- 方法论：消费函数的列读清单（[r15+disp] 全量反汇编）是 td 行布局的 ground truth——数据判板无法区分「解码错」和「语义上就无值」。

## R106（2026-11-04）：gc72 Rust 接线——extends 62%→90.8%（不是需求，方案记录）

- **gc@+0 64-bit 修正破局**：7.2 gc mask 链的 step 3（×0x17E6E15B）和 step 4（+0x923FD8CC66）是 **64 位运算**（`imul rdx, rbx` 的 rbx 是 64 位）——此前截断到 32 位导致链输出全错。修正后 gc@+0 解出**小的 td 索引**（V=0→1, V=2→2...）= **def_tdi** ✓。
- **Rust 落地**：profile 增 `Gc72` 结构（slot/xor/stride/data_add + 7 步 mask 链常数）+ `gc72: Option<Gc72>`；engine `generic_instance` 加 7.2 回退路径（当 `gc72` present 时从 body 嵌入的 gc 表读 def_tdi，无需 startup-metadata）。
- **验证**：extends **62%→90.8%**（81534/89746，甚至超过 7.1 oracle 的 84%——因为 7.2 新增了更多带 extends 的类型）；class/struct/interface/enum 不变；**7.1 BYTE-IDENTICAL ✓**（44 测试绿）。
- **签名仍 99.5% object**：gp 表（泛型参数名/位置）和 typearr 的完整 Il2CppType 表仍未解——这是独立的下一轮（签名走的是 type_name→il2cpp_type→typearr 路径，不走 gc 表）。泛型类名已开始出现（Dictionary`2、IList`1 等 4933 处）但参数渲染为 Locale<> 占位——gp 表接线后可修复。
- **方法论**：64 位混淆链的位宽是关键判据（`imul rdx, rbx` 的 64 位乘法 vs `imul r15d, ebx` 的 32 位截断，capstone 的 op_str 直接告诉你位宽）；gc@+0 解出小 td 索引 = def_tdi 的语义自洽（泛型定义的 typeDef 索引必然小，因为在 metadata 前段的 mscorlib/System 程序集里）。

## R107（2026-11-04）：flags/parent/bitfield 求解器机械化——auto-tables 管线闭环（不是需求，方案记录）

- **solve_td_flags_parent 加入 events_solve.rs + auto_tables_cmd 管线**：td solve 后自动扫 td 行全部 u32 offset，**flags 板**（值域 ≤ 0x12000A + interface 1-3% + seq 4-7%）+ **parent 板**（全部解码值 < typearr_len + kind 合法 + data < td_rows + obj_distance ≤ 0.70）。解出的列自动 splice 进 profile（td_flags/td_parent_off/td_parent_xor/td_bitfield_class_bit0）。
- **7.2 端到端验证**：flags@0x2C ^0x5A65E232 ✓、parent@0x10 ^0x74AD6F3E ✓、class_bit0=true ✓——与 R102 手工 RE 逐位一致。extends 62%（无 gc72 时）。
- **判板演化教训**：①parent 板的 `parent_col.is_none()` 条件阻止了更优候选的更新——必须移除；②obj_rate 单独不可靠（假阳性 89% > 真值 70.9%）——**obj_distance ≤ 0.70** 才是正确判据；③typearr data < td_rows 校验不区分真假（两者的 typearr data 都 < ROWS）；④distinct count 也不行（假阳性反而更高）。
- **auto-dump 当前限制**：extends 62%（gc72 常数不在 auto-tables 产出中，需 .upx0 逆向提取——下一轮通过 ×14 stride 字节锚自动化）。

## R107b（2026-11-04）：extends 62%→90.8% 根因 + auto-dump gc72 carry-forward（不是需求，方案记录）

- **extends 62% vs 90.8% 根因**：auto-dump profile 从 seed 继承了 `generic_tables`（7.1 gp/gc 常数），与 `gc72`（7.2 常数）**共存导致引擎用 7.1 基址做泛型查找 → extends 渲染断**。修复 = `gc72` 存在时 splice 清除 `generic_tables`。验证：去掉 generic_tables 后 extends 62%→90.8%。
- **auto-dump gc72 carry-forward**：二次运行时从 `work_dir/profile.prev.json` 继承 gc72 常数。首次运行 62% extends（无 gc72），用户手动/脚本添加 gc72 后二次运行 90.8%。
- **方法论**：多世代常数共存 = 隐性炸弹——profile 的 `generic_tables`（7.1）和 `gc72`（7.2）结构相似但常数完全不同，引擎按优先级选择但未选的那个仍在影响其他路径（gp_row 等）。

## R107b 状态（2026-11-04）：gc72 自动推导尝试 + 收口（不是需求，方案记录）

- **derive_gc72 实现**（events_solve.rs）：扫 .upx0 找 ×16 stride 标记 → capstone 反汇编窗口 → 按指令模式提取 gc slot/xor/mask 链/gp 常数。**当前返回 None**——.upx0 混淆代码的指令序列与模式匹配不完全对应（寄存器分配变化、垃圾指令插入、×16 标记可能不在 gc 函数附近）。
- **已验证的替代路径**：R103 的手工 .upx0 逆向已提取全套 gc72 常数（gc_base=hdr[0x140]^0x649E2FD4、七步 mask 链），通过 profile.prev.json carry-forward 机制注入 auto-dump。二次运行 extends 90.8%。
- **当前 auto-dump 产出**（无 gc72）：extends 62%，类型判定 ✓，名字 ✓。gc72 需要 .upx0 消费函数的精确逆向（已有完整常数）。
- **下轮入口**：①改进 derive_gc72 的模式匹配（用 ×14 而非 ×16 锚、放宽寄存器约束、用指令序列而非单条匹配）；②或接受 gc72 为半自动步骤（.upx0 分析脚本 + profile 注入）。
