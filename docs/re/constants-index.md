# 关键常数与算法索引（跨版本）

本文件是"每个关键常数/算法在哪里、怎么解出来的、验证数字是多少"的快速索引。
详细推导与证据在 `generalize-method.md` 的 §3.2x 小节；每轮实现细节在 `IMPLEMENTATION_LOG.md`。
所有布局都是**纯数据 JSON**（`docs/re/artifacts-*/`），工具不硬编码版本常数。

## 0. 经验：每一类常数是怎么找到的

| 常数/算法类别 | 方法 | 教训 |
|---|---|---|
| 字符串密码（cipher） | mhydump derive 从镜像自解（schedule/strsec） | 不能跨版本搬运，必须每版重跑 |
| 表基址（table base） | 代码 slot 惯用法 hdr[slot] OP imm，锚点扫描；或形态转移后读常数 | 7.0 属性构建器指纹在 6.7 命中的是事件构建器——必须用行数/数据验收区分 |
| 行 stride | 反汇编 imul reg,idx,imm / lea x5 组合 | 每版常量（7.0 方法 26、6.7 方法 26、6.7 事件 14、6.7 属性 10） |
| 行掩码链 | 反汇编 imul/add/xor/shr 链 | 链形状稳定、常数每版不同；抄成 JSON |
| 列常数（无已知明文） | 窗口性质：解码值必须落在一段连续窗口内 | 7.0 字段 type 窗口解 0xA90E9923 错，已知明文重钉 0xA9152807 |
| 列常数（有已知明文） | 用 oracle/corelib 已知字段/方法反解常数 | 15 种族 x 偏移；0 越界 + 分布可解释才算解出 |
| 自反关系求解 | byvalTypeIndex：typearr 条目 data == typeDefIndex | 无需已知明文，交集求解 |
| 索引语义 | 代码循环起点来源 + 数据验收 | 6.7 属性用线性属性索引（通过）；6.7 事件必须行数=617 验收 |
| 判别表类型 | 行数：属性 108,747 / 事件 617 / 字段 413,644 / 方法 687,467 | 同族构建器指纹相似，行数是第一判别器 |
| 类型分类 | byval kind + parent sentinel + value__ 字段 | 无 flags 表也能 100% 分类（114/114） |
| 泛型实例表 | 16B/24B/32B、body、exe .data 多轮结构扫描 | 全部 0 候选；在加密指针区，需先找全局指针解密例程 |

## 1. 7.0.0

| 项 | 值 | 来源/验证 |
|---|---|---|
| typeDef 表 | base 17522200 stride 70 rows 86932 | tables-7.0.0.json |
| typeDef name 列 | off 16 Xor 0x616B619D | 256/256 行可解 |
| typeDef ns 列 | off 24 Xor 0x7351490A | 55/256 |
| typeDef 方法范围 | start off 32 w4 add 0xCC54A508; cnt off 60 w1 xor 0xE5 | R30（end 713956） |
| typeDef 字段范围 | start off 0 w4 add 0xDF8B643E; cnt off 50 w1 xor 0x9B | R30（end 430290） |
| typeDef 属性范围 | start off 28 w4 add 0xF6929062; cnt off 69 w1 add 0xDB | R30（end 112949） |
| typeDef 事件范围 | start off 62 w2 xor 0x66AD; cnt off 68 w1 add 0x3A | R30（end 625） |
| typeDef byvalTypeIndex | off 12, raw ^ 0x1253E298 | 自反关系 86,905/86,932 |
| typeDef parentIndex | off 4, raw ^ 0x149B1F48 | 接口=0xFFFFFFFF |
| 类型分类 | parent sentinel->interface；kind 0x11->struct；value__->enum；否则 class | 114/114 |
| 方法表 | slot 0x138 add 0xD37E9675 stride 26 rows 713956 | R32 |
| 方法行掩码 | mul 0x3639B538F896 add 0xCC49CF2E948F28F shr 13 mul 0x3209B9A2 add 0x066E3EE5EEBB7B78 | R32 |
| 方法列 | param_start off 4 (raw+C-mask C=0xAC706A39)；name off 8 (raw^C-mask C=0x997E86CD)；flags off 0x0E；return_type off 0 (raw^C-mask C=0x215FCCB1)；param_count off 0x18 | R33/R39；ret Void 61.2% |
| 参数表 | slot 0x1FC add 0xFC3EC0CE stride 8 | R32 |
| 参数行掩码 | {'mul1': '0x2F64C993DFFE', 'add1': '0xAB42C68E0D4A', 'shr': 17, 'mul2': '0x272E941C', 'xor2': '0x705880A8'} | R32 |
| 参数列 | name off 4 (raw+0xDA14EDA6)^mask；type off 0 (raw+0x8FE5701B)^mask | 532,361 行全解 |
| 属性表 | slot 0x15C xor 0x368C9997 stride 10 rows 112949 | R34 |
| 属性行掩码 | {'mul1': '0xE0F8', 'xor1': '0x22F6DA00', 'mul2': '0x3AA8EE62', 'add1': '0x49880E3C', 'xor2': '0x3E17E98E', 'add2': '0x7EC31F32'} | R34 |
| 属性列 | name off 0 ((raw^C)-mask C=0x5DC2119E)；getter off 8；setter off 6（16 位，§3.2q.1） | 名字 99.94%，访问器越界 0 |
| 字段表 | slot 0x1D0 add 0xB98BE77F stride 8 rows 430290 | R36 |
| 字段行掩码 | {'mul1': '0x1147E475DFA9', 'shr1': 18, 'mul2': '0x2CD0F4EE', 'add1': '0xC16316113B52', 'shr2': 16} | R36 |
| 字段列 | name off 4 ((raw^C)-mask C=0x6040B64C)；type off 0 ((raw+C)-mask C=0xA9152807) | 名字 99.77%；149,852 primitive 行 |
| Il2CppType 数组 | file_off 0x2D3C7F0 va 0x142D3DFF0 count 662534 | R39；参数 type max=count-1 |
| 类型渲染 | PRIM + CLASS/VALUETYPE data=typeDefIndex + PTR/SZARRAY/ARRAY data=typearr VA + byref bit6 | 方法签名 99.6%/98.1% |
| 回归门禁 | tools/version-triage/verify_70.py 13 项 | 全 PASS |

## 2. 6.7.0

| 项 | 值 | 来源/验证 |
|---|---|---|
| typeDef 表 | base 35616688 stride 70 rows 83775 | tables-6.7.0.json |
| typeDef name 列 | off 24 Xor 0x17FB1577 | 256/256 |
| typeDef ns 列 | off 44 Xor 0x4AAC4BAB | 40/256 |
| typeDef 方法范围 | start off 12 w4 xor 0x4DFA3BEC; cnt off 48 w1 add 0x13 | R30（end 687467） |
| typeDef 字段范围 | start off 20 w4 xor 0x1D37F888; cnt off 56 w1 xor 0x4C | R30（end 413644） |
| typeDef 属性范围 | start off 0 w4 add 0xF43F5BDC; cnt off 68 w1 add 0x7C | R30（end 108747） |
| typeDef 事件范围 | start off 52 w2 add 0xFD33; cnt off 64 w1 xor 0x10 | R30（end 617） |
| 方法表 | slot 0x38 add 0xD515CAA3 stride 26 rows 687452 | R47 |
| 方法行掩码 | {'mul1': '0xCB87', 'xor0': '0x1D9A1A7A', 'mul2': '0x38036D18', 'shr': 8, 'add1': '0x7964C76C', 'xor1': '0x324CAF19'} | R47 |
| 方法列 | param_start off 0 (raw^0xD62B555-mask)；param_count off 0x18 (raw+0xA8-mask&0xFF)；name off 8 (raw^0x6BBF48D-mask)；flags off 0x14 (raw^3-mask)；return_type off 4 (raw^0x546F8F09-mask) | 名字 99.82%，ret Void 61.2% |
| 参数表 | slot 0x14C xor 0x12C9258B stride 8 | R47 |
| 参数行掩码 | {'mul': '0x2A2E98A6', 'add': '0x59887B45'} | name=raw^mask^0x3CBE0533，type=raw^mask^0x5A301FB |
| Il2CppType 数组 | file_off 0x29F9200 va 0x1429FA400 count 633862 | R49 |
| 事件表 | slot 0x140 add 0xB8765480 stride 14 rows 617 | R51；617/617 |
| 事件行掩码 | {'mul1': '0xFDA4FDC7922E20A0', 'add1': '0x52ED0039DCB14F2E'} | R51 |
| 事件列 | type off 0 (raw+0xE2CC29CA)^mask；name off 4 (raw+0xA16DD35B)^mask；raise off 8 ^0xC054；remove off 0xA ^0xC0EE；add off 0xC +0x5B99 | R51 |
| 字段表 | slot 0xC add 0xD34ADB03 stride 8 rows 413644 | R52 |
| 字段行掩码 | {'mul1': '0x1BB4F2A67161', 'add1': '0x251BA412D3BC6', 'shr': 18, 'extra_add': '0x2C7618B2', 'extra_xor': '0x14BDA7A6', 'extra_mul': '0xC9B392C3'} | R52 |
| 字段列 | name off 0: ((raw^0x70F1D209)+extra)&32, extra=((((m+0x2C7618B2)&32)^0x14BDA7A6)*0xC9B392C3)&32；type off 4: ((raw-extra2)+0xF94BD493)&32, extra2=((((m+0x2C7618B2)&32)^0x14BDA7A6)*0x364C6D3D)&32 | 名字 99.76%，type 13 行越界 |
| 属性表 | slot 0x1E8 add 0xE9FF5F7F stride 10 rows 108747 | R55；名字 108,464/108,747=99.74% |
| 属性行掩码 | {'mul1': '0x137D', 'xor0': '0x70B05CB7', 'mul2': '0x42639239', 'shr1': 13, 'mul3': '0x525521B3', 'shr2': 13, 'add1': '0x5F17108D'} | R55 |
| 属性列 | name off 0 (raw^mask^0x2BFBE794)；getter off 8 ((raw^mask16)^0x5D18)；setter off 4 ((raw^mask16)^0xD662) | get_ 56,483 / set_ 8,584 |
| 端到端清单 | dump67_partial.py -> dump67-partial.txt（83,775/413,644/687,467） | R53/R54 |

## 3. 7.1.0（早期参考，已固化）

| 项 | 位置 |
|---|---|
| 形态种子（25 个语义） | docs/re/artifacts-7.1.0/shape-seed.json |
| slot 惯用法脚本 | docs/re/artifacts-7.1.0/{slotfn,slotrec4,idiom4,idiom5,hdrrefs}.py |
| 7.1 表布局 | generalize-method.md §3.2 及更早 + MEMORY §70-§90 |
| oracle dumps | ~/gire/out/71/dump.cs；6.4Dump.cs |

## 4. 负结果与未决（避免重复踩坑）

| 项 | 结论 | 出处 |
|---|---|---|
| GENERICINST 泛型实例表 | 多轮结构扫描 0 候选；疑在加密指针区 | §3.2r.1/§3.2x |
| 7.0 方法 slot 列 | 未解（+0x10 不是返回值，已移除） | §3.2m |
| 6.7 属性列 +6 | 不是访问器；公式未定 | §3.2ac |
| 6.7 字段 attrs | 未解 | §3.2z |
| 6.7 方法 flags 完整语义 | 仅 static 位验证 | §3.2v |
| 7.0 参数 type 列 | 值全在界内，ret 已修正 | §3.2l/§3.2m |

## 5. 复现命令

`mhydump derive --exe <game.exe> --metadata <global-metadata.dat> --out derive.json`
`python3 tools/version-triage/decode_params.py <ver> <derive> <sites> <layout> [typearr]`
`python3 tools/version-triage/dump70_partial.py / dump67_partial.py`
`python3 tools/version-triage/verify_70.py`
