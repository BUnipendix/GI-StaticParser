# 原神 7.1.0 metadata 加载流程 —— 逆向知识库（防复研）

> 生成：2026-10-14（第二轮代码驱动逆向）。**全部结论来自指令级证据**（capstone 窗口扫描 + kuna 反编译 + Ghidra 边界），
> 证据原文见仓库 IMPLEMENTATION_LOG.md §26/§27 与 artifacts-7.1.0/ 目录。
> 样本：/home/yangsanyi/kuna_in/710/YuanShen.exe（md5 51d3263ca7c0cddde468278142d9ec51，445,006,744 B，与 VMP壳 工作区同文件）。
> 镜像基址 0x140000000；段表：.text 0x140001000 / .rdata 0x1421AB000 / .data 0x1454B4000 / il2cpp 0x146C05000 / .upx0 0x159E5B000(vsz 0xE921B8)。

## 0. 一页结论

1. **头部不在文件里**：真正的 0x210 字节头是 .rdata 静态 blob（0x1427D5CB0，开头 "MHY\0"），
   由 CRT 初始化器 0x1402F3730 在 main 之前写入全局 0x145AD62B8。global-metadata.dat 自己的前 0x210 字节是假头，直接丢弃。
2. **身体**：加载器 FUN_1405359e0 调 sub_140523f70("global-metadata.dat") 拿文件镜像，+0x210 后存入 0x145AD62C0。
   第二个文件 "startup-metadata.dat" 存 0x145AD62C8（metadataUsage 对表在这边，槽 0x120）。
3. **取表统一成语**：`表基址 = body + (hdr[槽] OP 常数)`，OP ∈ {xor, add, sub, shr+xor}。全 .text 共 45+ 张表、702 个读取点（见 §3 与 slotrec4.json）。
4. **typeDef 行 0x46 字节 / 方法行 0x1A 字节**，列清单见 §4/§5；方法行走每行掩码 mask2(i)（公式在 §5）。
5. **flags 在壳里**：行→klass 转换器是 sub_14051db00 → 一条 jmp 0x159F63C4D 落在 .upx0（VMProtect）。
   该 RVA 在 VMP壳/work/vmenters.txt 91 个入口清单中（第 2 个）。klass 侧 flags 被重打包：[klass+0xAC] 低 3 位=可见性、[klass+0xC9] bit5=interface。
6. **数组/指针类绑定占位行 (typeCount-2)**：表末尾行是合成类型占位，导出时须排除。

## 1. 关键全局（.data 0x145AD6200–0x145AD6480 区）

| 全局 | 指向 | 写入者 | 语义 |
|---|---|---|---|
| 0x145AD62B8 | 0x1427D5CB0 (.rdata) | CRT init 0x1402F376F | 头部（HDRGLOBAL），356 个读点 |
| 0x145AD62C0 | 文件镜像+0x210 | 加载器 0x1405361B0 | 身体（BODYBASE），343 个读点 |
| 0x145AD62C8 | startup-metadata.dat | 加载器 0x1405361B7 | 第二文件 |
| 0x145AD6298 | 0x1422DF450 (.rdata) | CRT init 0x1402F3737 | 静态代码注册：+0x8 invoker 数组、+0x28 方法指针数组、+0x78 泛型方法数组 |
| 0x145AD62A0 | 0x142871B68 (.rdata) | CRT init 0x1402F3745 | 静态注册：+0x28 Il2CppType 数组指针、+0x30 ^0x28A0FA2D=计数、+0x50=模块基址（1035 读点）|
| 0x145AD62A8 | 0x142871C08 (.rdata) | CRT init 0x1402F3753 | 结构 A（+0x60 校验 ^0x56B6352C）|
| 0x145AD62B0 | 0x1422DF4F8 (.rdata) | CRT init 0x1402F3761 | 版本描述（+4=7 → 0x145AD6350）|
| 0x145AD62D0/D8/E0/E8 | 运行时分配 | 加载器 | 缓存数组（D8=typeDef 相关、E0=klass-by-typeDefIndex、E8=泛型实例缓存，411 读点）|
| 0x145AD62F8 | 运行时分配 | 加载器 | image 表（88B/行）|
| 0x145AD6308 | 运行时分配 | 加载器 | assembly 表（80B/行）|

## 2. 启动序列（加载器 FUN_1405359e0 [0x1405359E0..0x14053BD29]，唯一调用者 FUN_1404b1f30）

1. 解析自身 PE 段表，按名字匹配 "il2cpp" 段 → dat_145ad4900/4908 = 段 VA 范围（sub_141c2fae0）。
2. sub_140523f70 两次：文件名参数是**明文字符串**（"global-metadata.dat" / "startup-metadata.dat"，前缀 "Metadata"，错误日志 "ERROR: Could not open %s"，IAT=CloseHandle/GetLastError）。
3. 依次按头部槽分配并清零缓存数组（alloc=sub_1405002f0，memset=sub_141fc84c0）：
   - 62D0：62A0[6]^0x28A0FA2D ×8
   - 62D8：hdr[0x60]^0x15335474 ÷0x46 ×8（typeCount）
   - 62E0：方法表规模（hdr[0x134]+0x8EEFDB56 ÷0x1A）
   - 62E8：(hdr[0xAC]^0x6F3B0AC0) ÷3 ×8（配 0x188 表索引）
   - 62F8：(hdr[0xA4]^0x1496B860) ÷0x28 ×88B，哨兵初始化（11 个加密零常量，即 image 各字段的解密常数：+4=0x7B236BA..、+0x18=0x7362B478、+0x20=0x6AFF73A46C9233D6、+0x50=0x4FBFA07B 等）
   - 6308：(hdr[0x170]>>4 ^0x28D714C) ×80B，哨兵 9 常量
4. metadataUsage 初始化：对表在 startup-metadata 的 (hdr[0x120]^0x1C3F68EA)+62C8 处，{u32 idx,u32 typeIdx} 对 → typearr[typeIdx×0x10] 建指针。
5. 注册 mscorlib："mscorlib.dll" / "__Generated"（sub_14050d4c0 按名找 image），System.Object / 各 SByteEnum..UInt64Enum 等（sub_140516680(ns,name)）。
6. 遍历 image 的 typeStart/exportedTypes 注册每个类型：sub_14051e390(image, row) 处理嵌套类型（见 §4）。

## 3. 完整槽清单（机器生成自 slotrec4.json：702 条读取、45+ 组）

高置信（多站点/身体加法确认）：

| 槽 | OP | 常数 | 站点 | 语义 |
|---|---|---|---|---|
| 0x5C | ^ | 0x6B2B3963 | 3 | 导出类型索引 u32（-1=无）|
| 0x60 | ^ | 0x15335474 | 4 | typeDef 表字节数（÷0x46=行数）|
| 0x64 | + | 0xE6130C67 | 1 | **eventDefs 表（14B 行）**；运行时 EventInfo 构建器 0x140515AE0 读它（§85）|
| 0x74 | ^ | 0x245177E0 | 3 | 泛型方法索引表 stride 6 {i32,u16}，大小=hdr[0x110]^0x1AB6109A ÷6 |
| 0x98 | ^ | 0x76A06155 | 203 | 打包表 (类别3位|索引29位)；类别=6 → 查 0x188 |
| 0xA4 | ^ | 0x1496B860 | 2 | image 表偏移（÷0x28=行数，88B/行）|
| 0xAC | ^ | 0x6F3B0AC0 | 2 | ÷3 = 0x188 表行数 |
| 0xC8 | ^ | 0x8D701A3 | 11 | Il2CppType 数组（16B/元素；静态副本=62A0[5]）|
| 0xDC | ^ | 0x5278CA3B | 56 | typeDef 表（0x46/行）|
| 0x110 | ^ | 0x1AB6109A | 3 | 0x74 表字节数 |
| 0x118 | ^ | 0x4009A6BF | 26 | 大表（语义待定）|
| 0x134 | + | 0x8EEFDB56 | 3 | 方法表字节数（÷0x1A=行数）|
| 0x158 | − | 0x1D545CCC | 1 | **propertyDefs 表（10B 行）**；运行时 PropertyInfo 构建器 0x140515FC0 直接读该槽 ⇒ 此槽是属性表锚点（2026-10-18，§83）|
| 0x170 | >>4,^ | 0x28D714C | 1 | assembly 行数 |
| 0x188 | ^ | 0x57DD5CA8 | 207 | 泛型实例表 12B/行 {i32,i32(-1=无),i32} |
| 0x1B8 | ^ | 0x586ABAF1 | 2 | 嵌套类型 u32 索引表 |
| 0x1E0 | ^ | 0x2EE480FB | 11 | 方法表（0x1A/行）|
| 0x200 | − | 0x4BC1F14F | 1 | u32/方法（-1=无）→ 6298[+0x8] 索引 |
| 0x70 | − | 0x6EA5B3FD | (repo) | iface 表（layout71 既有；本扫形式未覆盖）|

（单点槽全表见下方机器生成节；注意单点 add 形态存在误绑可能，用前先到 slotrec4.json 按 va 核对现场。）

## 4. typeDef 行（stride 0x46，base=hdr[0xDC]^0x5278CA3B+body）

| 偏移 | 宽 | 解码 | 列 | 证据 |
|---|---|---|---|---|
| 0x00 | u32 | ^0x72628007 | fieldStart | 加载器+layout71 |
| 0x08 | u32 | ^0x0478AF59 | methodStart | 加载器+sub_1405153f0（三处）|
| 0x14 | u32 | +0xE811F779（≡−0x17EE0887）| nameIndex | sub_14051e390 负数形式互证 |
| 0x18 | u32 | ^0x666769B5 | namespaceIndex | sub_14051e390 |
| 0x1C | u32 | ^0x2145AFB6（-1=无，-1 的密文=0xDEBA5049）| elementTypeIndex（"tag"即其哨兵！）| 壳内 0x159F645D2 |
| 0x04 | u32 | +0x89DE8E6E | 接口相关列（count/start，待终判）| 壳内 0x159F646C9 |
| 0x0C | u32 | −0x205F6070 | **flags**（→klass+0xAC）| 壳内 0x159F6436A，统计验证 ✓ |
| 0x10 | u32 | ^0x37EEAE45 | byvalTypeIndex（u32 形态，16B 拷贝→klass+0x68）| 壳内 0x159F641B7 |
| 0x28 | u32 | ^0x1B7494B5 | this/element 类型索引（→klass+0x10）| 壳内 0x159F641FD |
| 0x32 | u16 | ^0x8BA4 | **bitfield**（bit0=IsValueType、bit1=IsEnum；低字节位再散到 klass 0xC7/0xC9/0xCA）| 壳内 0x159F63DC2/0x159F64372，统计验证 ✓ |
| 0x40 | u8 | ^0x06 | 小列（→klass+0xBE）| 壳内 0x159F63DAC |
| 0x42 | u8 | +0xA2 | 小列（→klass+0xC2）| 壳内 0x159F645AE |
| 0x20 | u32 | ^0x6C9A5100 | interfacesStart | FUN_1400010f0+加载器 |
| 0x30 | u16 | ^0x9A6B | fieldCount | layout71 |
| 0x36 | u16 | ^0xC87C | nestedTypesStart（索引 0x1B8 表）| sub_14051e390 |
| 0x3C | u16 | ^0x8811 | methodCount | 加载器 |
| 0x3E | u16 | −0x1398（0xFFFF=无）| byvalTypeIndex | 3 处 |
| 0x45 | u8 | ^0xAB | nestedTypesCount | sub_14051e390+加载器 |
| 0x24 | u32 | +0xCE2141CC | **propertyStart**（propertyDefs 行号）| 0x1405162B0（PropertyInfo 构建器），2026-10-18 |
| 0x43 | u8 | ^0x86 | **propertyCount** | 0x1405161A4 同上（全量铺瓦 115,596 行，0 不规则）|
| 0x38 | u16 | +0xFFFFD6AB | **eventStart**（eventDefs 行号；0xFFFF=无）| 0x140515E0F（EventInfo 构建器），2026-10-18 |
| 0x44 | u8 | ^0xB5 | **eventCount** | 0x140515B42 同上（全量铺瓦 628 行，0 不规则）|
| 0x2C | u32 | ^0x8177D738 混 tag | parent | layout71（旧）|
| 0x3A | u16 | ^0x4BCE | ？（与 0x20 冲突，待重验）| layout71（旧）|
| ? | u32 | ? | bitfield / token（未定位）| |

## 4b. eventDefs 行（stride 14，base=hdr[0x64]+0xE6130C67+body）

| 偏移 | 宽 | 解码 | 列 |
|---|---|---|---|
| 0x00 | u32 | ^mask ^0x05C273ED | nameIndex（packed 字符串索引）|
| 0x04 | u32 | (+0x979C7DA9) ^mask | typeIndex（typearr；0xFFFFFFFF=无）|
| 0x08 | u16 | ((raw+0x38EB) ^mask)&0xFFFF | remove（0xFFFF=无）|
| 0x0A | u16 | ((raw+0xFFFFE40A) ^mask)&0xFFFF | raise（0xFFFF=无）|
| 0x0C | u16 | ((raw^mask)^0x7D45)&0xFFFF | add（0xFFFF=无）|

mask(i) = ((i*0x9C54 ^ 0x1F0DA79F) * 0x1BF89D8B64959BB7 + 0x295EE0EBA6CAFAEA) >> 15（64-bit 乘法）。
来源：0x140515AE0 的 EventInfo 缓存构建器（写入 klass+0x38，元素 0x30）。全量 628 行精确铺瓦 [0,628)，
type 索引全部合法，未混淆类型的 add/remove 落到 add_*/remove_* 方法（详见 IMPLEMENTATION_LOG §85）。

## 5. 方法行（stride 0x1A，base=hdr[0x1E0]^0x2EE480FB+body）

mask2(i) = ((i×0x4E94 ^ 0x62D8B7B8)×0x7572748A + 0x1F4D9EEA ^ 0x6E8931D6) × 0x39036375 （mod 2^32，按列宽截断）

| 偏移 | 宽 | 解码 | 列 |
|---|---|---|---|
| 0x0C | u16 | ^0x1E2A − mask2 | slot（-1=无）|
| 0x0E | u32 | ^0x394729C + 每行项 | declaringType（typeDef 索引）|
| 0x12 | u16 | − mask2 − 0x7269 | parameterCount |
| 0x14 | 2×u16 | − mask2 + dat_143909610/612 | 两列（名字/返回类型候选）|
| 0x18 | u8 | − mask2 + 0x8C | flags 字节 |
| 0x19 | u8 | ^0xB1 − mask2 | attrs 位（参与静态位重打包）|

每行项（declaringType 用）：((i×0x4E94 ^ 0x62D8B7B8)×0x7572748A + 0x1F4D9EEA ^ 0x6E8931D6)×0x39036375 的负形式。
方法信息结构 0x38B（7 qword）：+0x00 klass、+0x08 invoker/generic、+0x10 索引、+0x18 slot、+0x20 signature、+0x28 paramCount、+0x2A.. attrs。

## 6. 运行时结构

klass（0xD0 字节，分配于 sub_1405002f0）：
- +0x58 methods 数组（methodinfo 0x38B/个）
- +0x60 **typeDef 行指针**（数组/指针类=占位行 typeCount−2）
- +0xAC 重打包 flags（**低 3 位=可见性**，FUN_140518030: ((uint4*)v9)[0x2b]=a0&7）
- +0xC0 (u16) methodCount；+0xC8&0xE、+0xCA bit5=含泛型方法
- +0xC9 bit5=interface、bit6=?（0x40 分支走 vtable）
缓存：62E0=klass-by-typeDefIndex（sub_14051e0f0 填）、62E8=泛型实例（配 0x188 表）。
FUN_140518030=数组/指针 klass 工厂（0xD0B，名字来自 0x143A724CC 串）。
sub_1405153f0=klass 方法表构建器（含泛型方法二分：0x74 表按 method 索引查）。
sub_14051e0f0(typeDefIndex)=按索引取 klass：方法行[0xE] 解 declaringType → 父 klass → sub_1405153f0 → 从嵌套数组取。
sub_14051db00=统一解析器 → **jmp 0x159F63C4D（.upx0 壳内）→ 行→klass 转换（flags 解包）在这里**。

## 7. 负结果与坑（别再走）

1. FUN_1406bb570 / 0x1406BC080 的 [r10+rcx+8] = .rdata 0x1439206E0 静态二分表（12B/行），与 typeDef 无关。
2. 全量 capstone detail 存 9.5M 指令 → OOM；用字节定位 + 小窗（idiom4.py）。
3. 自造寄存器号 ≠ capstone 枚举（X86_REG_RDX=40 非 2）；REX.R 是 0x4 位。
4. 变换有两方向：dst,imm 与 dst,[mem]（mov reg,K 预装）。
5. kuna 后台需绝对路径 ~/Documents/git-repo/kuna/decompiler/target/release/kuna，CWD=/tmp，单实例（内存）。
6. Ghidra 工具名带连字符（run-script）；大函数 get-decompilation 会超时，用 kuna。
7. dat 文件前 0x210 字节与 .rdata 头 blob 不相等（假头，勿当头解析）。

## 8. 复现

- 扫描器：artifacts-7.1.0/idiom5.py（扩展版，含反向操作数形态）；hdrrefs.py（全局引用扫描）。
- kuna 反编译：artifacts-7.1.0/kuna_*.txt（5 个关键函数）+ kuna_loader.txt（加载器全文）。
- 槽清单数据：artifacts-7.1.0/slotrec4.json（702 条含 va）；slotfn.json（256 个函数映射）。
- NoVmp 脱壳（flags 用）：见 VMP壳/交接-给下一个agent.md；入口 0x19f63c4d。

## 9. 下一步（按优先级）

1. NoVmp 脱 0x19f63c4d → 读 flags/bitfield 列与变换 → 回填 layout71 → 修 dump71 type_kind。
2. 0x118 表语义（26 站点）；0x3A 列重验；token 列。
3. 单点槽逐个用现场核对（slotrec4.json 按 va 回读指令）。
4. field offsets：62A0 静态注册里找 fieldOffsets 数组（Il2CppMetadataRegistration 等价）。

## 10. 附录：全部 (槽,OP,常数) 机器生成表（n=站点数，body+=身体加法确认数，first=首个读取点 VA）

| 槽 | OP | 常数 | n | body+ | stride | first VA |
|---|---|---|---|---|---|---|
| 0x0 | - | None | 33 | 9 | [] | 0x1404CA14F |
| 0x0 | add | -0x-F3887255 | 1 | 0 | [] | 0x14052821D |
| 0x0 | add | -0x-E5EE4081 | 1 | 0 | [] | 0x1405294A4 |
| 0x0 | add | -0x-8EDEA6E9 | 1 | 0 | [] | 0x140547371 |
| 0x0 | xor | 0x72628007 | 6 | 1 | [] | 0x1404CA006 |
| 0x0 | xor | -0x-E5D249BF | 1 | 0 | [] | 0x14051DA1A |
| 0x4 | - | None | 11 | 0 | [] | 0x1404E58DE |
| 0x4 | xor | 0x613ace3 | 1 | 0 | [] | 0x140529183 |
| 0x6 | xor | 0x8fd52d1 | 1 | 0 | [] | 0x1404CA130 |
| 0x8 | - | None | 9 | 0 | [] | 0x1404E58DA |
| 0x8 | add | -0x-A0B8D7F1 | 2 | 0 | [] | 0x1405350B9 |
| 0x8 | xor | 0xdb1 | 1 | 0 | [] | 0x140516347 |
| 0x8 | xor | -0x-FB8750A6 | 1 | 0 | [] | 0x14051E1CA |
| 0xC | xor | 0x2a5fba | 2 | 1 | [] | 0x140514945 |
| 0xC | xor | 0x5c56350b | 1 | 0 | [] | 0x14054739C |
| 0xE | xor | 0x394729c | 1 | 0 | [] | 0x14051E16F |
| 0x10 | - | None | 3 | 1 | [] | 0x1405350D8 |
| 0x10 | xor | 0xbbfca3a | 1 | 1 | [] | 0x140538E20 |
| 0x14 | add | -0x-816CE90C | 1 | 0 | [] | 0x1404E6B1E |
| 0x18 | add | 0x297576 | 1 | 0 | [] | 0x1404B27D5 |
| 0x18 | add | -0x-A1C835BE | 1 | 0 | [] | 0x1405287EB |
| 0x1C | xor | 0x49ccbad1 | 3 | 2 | [] | 0x14051495A |
| 0x20 | - | None | 1 | 0 | [] | 0x1405166AB |
| 0x20 | add | -0x-A5D24562 | 1 | 0 | [] | 0x14052601E |
| 0x20 | xor | 0x6c9a5100 | 2 | 1 | [] | 0x140514CFA |
| 0x24 | - | None | 2 | 2 | [] | 0x140534F4E |
| 0x28 | - | None | 1 | 0 | [] | 0x1404B8FB5 |
| 0x2C | add | -0x-E412B6A9 | 1 | 0 | [] | 0x14053711F |
| 0x2E | - | None | 1 | 0 | [] | 0x1404B2D45 |
| 0x30 | - | None | 4 | 0 | [] | 0x1404B2D4F |
| 0x34 | xor | 0x698901c | 3 | 3 | [] | 0x140548026 |
| 0x38 | add | -0x-929CF336 | 2 | 0 | [] | 0x1404E594B |
| 0x38 | add | -0x-FFFFD6AB | 2 | 2 | [] | 0x14053500F |
| 0x3C | xor | 0x6bd889c8 | 1 | 1 | [] | 0x1404D979C |
| 0x40 | - | None | 1 | 0 | [] | 0x1405375F3 |
| 0x44 | xor | 0x32ea0436 | 2 | 2 | [] | 0x140516574 |
| 0x45 | - | None | 1 | 0 | [] | 0x1405486D3 |
| 0x4C | - | None | 1 | 0 | [] | 0x14051394E |
| 0x4C | add | -0x-E5D249BF | 1 | 0 | [] | 0x14051D9E1 |
| 0x50 | - | None | 1 | 0 | [] | 0x140528214 |
| 0x58 | - | None | 1 | 0 | [] | 0x14051E1BD |
| 0x5C | xor | 0x6b2b3963 | 3 | 2 | [70] | 0x14051687F |
| 0x60 | - | None | 10 | 8 | [] | 0x1404CA002 |
| 0x60 | add | 0xa | 1 | 1 | [] | 0x1404CA114 |
| 0x60 | xor | 0x15335474 | 4 | 3 | [70] | 0x1404E17D2 |
| 0x60 | xor | 0x76a06155 | 1 | 1 | [] | 0x140517529 |
| 0x64 | - | None | 1 | 1 | [] | 0x140515E49 |
| 0x68 | xor | 0x146be503 | 1 | 1 | [] | 0x140529807 |
| 0x6C | add | -0x-E028E1F0 | 1 | 0 | [] | 0x14053712A |
| 0x70 | - | None | 2 | 2 | [] | 0x140513D6B |
| 0x74 | xor | 0x245177e0 | 3 | 1 | [] | 0x140514D3C |
| 0x78 | xor | 0x70c36cac | 1 | 1 | [] | 0x140538DD8 |
| 0x80 | xor | 0xa989fac | 2 | 0 | [] | 0x1405389A1 |
| 0x84 | xor | 0x582f3633 | 1 | 0 | [] | 0x140536D9E |
| 0x8C | add | -0x-D7BBE415 | 2 | 0 | [] | 0x140538D11 |
| 0x90 | - | None | 2 | 0 | [] | 0x14051301A |
| 0x94 | add | -0x-F15F5122 | 1 | 0 | [] | 0x14052C433 |
| 0x98 | xor | 0x76a06155 | 203 | 199 | [] | 0x1400011D1 |
| 0xA0 | add | -0x-E2AC71C1 | 1 | 0 | [] | 0x140536565 |
| 0xA4 | xor | 0x1496b860 | 2 | 0 | [88] | 0x140536347 |
| 0xAC | xor | 0x6f3b0ac0 | 2 | 0 | [] | 0x1405362DC |
| 0xBE | - | None | 1 | 0 | [] | 0x1405175BD |
| 0xC8 | xor | 0x8d701a3 | 11 | 8 | [] | 0x1404B8D51 |
| 0xD0 | - | None | 1 | 0 | [] | 0x1405175C7 |
| 0xD0 | add | -0x-901B547D | 1 | 0 | [] | 0x1404E6B31 |
| 0xD4 | add | -0x-E292EFE6 | 1 | 0 | [] | 0x140514AAB |
| 0xDC | xor | 0x5278ca3b | 56 | 48 | [70] | 0x1404B2418 |
| 0xE8 | - | None | 1 | 0 | [] | 0x1405376B3 |
| 0xEC | - | None | 2 | 0 | [] | 0x1404C9FC8 |
| 0x110 | xor | 0x1ab6109a | 3 | 0 | [] | 0x140514D4A |
| 0x118 | xor | 0x4009a6bf | 26 | 25 | [] | 0x1404B2442 |
| 0x120 | xor | 0x1c3f68ea | 2 | 0 | [] | 0x1405365C5 |
| 0x124 | add | -0x-C45F877B | 4 | 0 | [] | 0x1405146B3 |
| 0x128 | xor | 0x371354a2 | 2 | 2 | [] | 0x14051CD0D |
| 0x12C | xor | 0x24898706 | 1 | 1 | [] | 0x14052C419 |
| 0x134 | add | -0x-8EEFDB56 | 3 | 0 | [] | 0x140536280 |
| 0x144 | add | -0x-D1F800F2 | 5 | 0 | [] | 0x1404C7C72 |
| 0x14C | xor | 0x2f249c2f | 1 | 1 | [] | 0x140524356 |
| 0x150 | add | -0x-C8542DD2 | 1 | 0 | [] | 0x140510F01 |
| 0x158 | - | None | 1 | 1 | [] | 0x1405162B0 |
| 0x15C | xor | 0xa282eb | 2 | 1 | [] | 0x140538DB9 |
| 0x160 | - | None | 5 | 5 | [] | 0x140547FE0 |
| 0x164 | xor | 0x3893506 | 5 | 5 | [] | 0x1404C7CB0 |
| 0x170 | xor | 0x28d714c | 1 | 0 | [] | 0x140536459 |
| 0x174 | - | None | 8 | 8 | [] | 0x1404B8F4E |
| 0x174 | add | -0x-CED1EDB1 | 8 | 0 | [] | 0x1404B8DD2 |
| 0x178 | - | None | 2 | 0 | [] | 0x1404C9FB8 |
| 0x188 | xor | 0x57dd5ca8 | 207 | 5 | [] | 0x140001214 |
| 0x18C | xor | 0xa6dd06f | 1 | 1 | [] | 0x1404C6B76 |
| 0x194 | xor | 0x35506cf3 | 1 | 1 | [] | 0x140514A90 |
| 0x198 | xor | 0x5303f399 | 1 | 0 | [] | 0x1405138C1 |
| 0x19C | xor | 0x159fbc84 | 1 | 1 | [] | 0x140524274 |
| 0x1A0 | add | -0x-80130D0F | 1 | 0 | [] | 0x1405281EA |
| 0x1A4 | xor | 0xd8c5d0a | 2 | 1 | [] | 0x1405138B0 |
| 0x1A8 | - | None | 3 | 3 | [] | 0x1405269A7 |
| 0x1B0 | xor | 0x7f990d7f | 2 | 1 | [] | 0x140538985 |
| 0x1B8 | xor | 0x586abaf1 | 2 | 2 | [] | 0x140512117 |
| 0x1D0 | xor | 0x7d0bbf9 | 1 | 1 | [] | 0x14052886C |
| 0x1DC | xor | 0x5ac819b | 2 | 0 | [] | 0x14053760D |
| 0x1E0 | xor | 0x2ee480fb | 11 | 11 | [] | 0x1405155FC |
| 0x1E4 | xor | 0x67102427 | 2 | 2 | [] | 0x140513794 |
| 0x1E8 | xor | 0x74314ec | 1 | 1 | [] | 0x140526007 |
| 0x1F4 | xor | 0x7a3b781e | 3 | 0 | [] | 0x1404E6B8F |
