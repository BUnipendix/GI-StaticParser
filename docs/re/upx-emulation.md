# `.upx0` 静态模拟路线（VMProtect 变形代码）

> 2026-10-17 第 35 轮（round 27 后首次推进）。不是需求，是证据与方法记录。

## 1. 结论：它是 VMProtect 式「变形原生代码」，不是加密数据

| 证据 | 值 |
|---|---|
| `.upx0` 段 | VA `0x159E5B000`，vsz `0xE921B8`（14.6 MB）|
| 熵（64KB 块） | **6.8**（代码级；加密数据应≈8.0）|
| `0x159F63C4D`（flags 解包入口）字节 | 合法 x86-64：`push rbp; ... push r15/r14/r13/r12/rsi/rdi/rbx` + 大量只作用于 `bp/ebp` 的 junk 变形 |
| 重定位指向 `.upx0` | **20 / 1,658,208**（DIR64）⇒ 位置无关，无 handler 指针表 |
| `.text → .upx0` 入口 | **206 个**（109 `call` + 97 `jmp`，目标全不同）|
| `.upx0` 内部 call/jmp 目标 | 27,139 个 / 34,953 处 ⇒ 大量函数被逐函数变形/虚拟化 |

⇒ 每函数 = 保存全部寄存器的 stub + 变形后的原生代码（junk 指令可识别、真语义可读）。
**反调试不构成本路线的障碍**：静态反汇编与 Unicorn 模拟都不启动游戏进程，不触发 VMP 的反调试检查。

## 2. 模拟器（`tools/emu_upx.py`，已验证可执行）

设计：

- 按 preferred base 映射所有 PE 段（ASLR delta = 0 ⇒ 段内绝对指针无需重定位）；
- 映射我们重建的 global-metadata body（`0x300000000`）、startup（`0x320000000`）、0x210 header（`0x310000000`）；
- 设置 loader 全局：`0x145AD62B8`→header、`0x145AD62C0`→body、`0x145AD62C8`→startup；
- 自建运行时缓存表 `0x145AD62D8[typeDefIndex]` = 指向 body 中真实 typeDef 行（base `0x48F3FD8`、stride `0x46`）的指针数组；
- TEB/GS 基础映射，栈 + 哨兵返回地址；
- hook：metadata 内所有读操作、执行指令环形缓冲、非法访问/中断打印。

实测：`python3 tools/emu_upx.py`（entry=0x14051DB00，rcx=293）**完整返回到哨兵**，
返回 `rax=0x3048F8FF6`（body 内指针）；执行轨迹 `0x159F63C4D → 0x159F647C7(ret)`。

## 3. 模拟揭示的 flags/klass 解析器内部（与静态公式互相印证）

```
rax = [0x145AD62D8][index]            ; 运行时 klass 缓存；非空 ⇒ 直接返回（我们喂了非空指针）
r12 = [0x145AD62C0]  (body)
r11 = [0x145AD62B8]  (header)
r15 = (hdr[0xDC] ^ 0x5278CA3B) + body ; = typeDef 表 base（已解，profile td table）
rsi = index * 0x46                    ; stride 70
rcx = (hdr[0x198] ^ 0x5303F399) + body
r13 = dword [rcx + index*4]           ; ★ 按 typeDefIndex 索引的 u32 表（值域 0..23150 稠密）
r8  = [ [0x145AD62A0] + 0x18 ]        ; registration 字段
r10 = byte [rsi + r15 + 0x40]         ; typeDef 行 +0x40 字节列
```

- `hdr[0x198]^0x5303F399` = body **0x10500E0**，88,902 条 u32、值稠密覆盖 0..23,150（= 另一数组的索引，语义未定）。
  这是**新发现的候选表**（可能对应容器/属性/泛型相关映射），已列入待解。
- 缓存非空 ⇒ 走快路径、不读 metadata（所以本轮 `metadata reads: 0`）；缓存为空则会走构建路径，
  在 `0x159F63CFD` 调用一个经 `.rdata` 槽（`0x143B4B248`）的初始化函数，该槽需运行时填充 —— 下一步补初始化即可观察完整构建过程。

## 4. 下一步（模拟路线执行计划）

1. **打通 cache-miss 构建路径**：初始化 `.rdata` 函数指针槽与 registration 结构（`0x145AD62A0` 链），让函数真正读 typeDef 行；
2. **批量跑 206 个入口**：对每入口用若干输入（索引 0/1/293/最后一个、指针参数）执行，日志记录 header/body/startup 读地址 ⇒ 生成「入口 → 表」映射；
3. 把映射与已知表比对，剩余未归属的即 **propertyDefs / genericParameters / attribute-args** 候选读取器；
4. 对候选函数用黑盒差分（改变输入，观察读到的行偏移与返回值）反推行布局/掩码，再按现有 profile 机制接进 `mhydump`。

预计：步骤 1–2 一轮内可完成；步骤 3–4 视函数复杂度 1–3 轮。
