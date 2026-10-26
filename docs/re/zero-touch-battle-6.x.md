# 零接触管线 6.x 战役报告（R78–R81，2026-10-26）

单二进制链：`loadsites → derive → strings → auto-tables --solve-method --solve-td --profile-out → dump-gen --profile-in`。
种子=6.7（5 语义 JSON，纯数据）。全部命令与产物见 `~/gire/out/zero-touch/battle/`。

## 结果矩阵

| 版本 | typeDef 结构解 | 方法表 name | 方法表 param_start/count | oracle 逐名 |
|---|---|---|---|---|
| 6.0.0 | ✅ 59629 行 corelib 正确 | ✗（链池无解） | ✗ | —（方法未解） |
| 6.1.0 | ✅ 72834 | ✗（链池无解） | ✗ | — |
| 6.2.0 | ✅ 73954 | ✅ 100%（name-only） | ✗（疑 mask2 变体） | 前 81342 行逐位全同，之后 oracle=BeeByte 映射名 |
| 6.3.0 | ✅ 76399（oracle 类型数 76397） | ✗（链池无解） | ✗ | — |
| 6.5.0 | ✅ 80164（oracle 80166） | ✅ 100% | ✅ bad=0 sum=492684 | 前 83676 行逐位全同，之后同上 |
| 6.6.0 | ✅ 82222 | ✅ 100% | ✅ bad=0 sum=482602 | —（无 oracle） |

typeDef 行数与官方 oracle 的类型数吻合（差 ≤2 行为尾部 padding 修剪语义），是跨版本最稳的一环——
**不需要种子、不需要转移**，纯结构（平铺谓词+字符串列+锚定）。

## 已定性事项

- **oracle 13.75%/14.48% 不是解码错误**：第 ~81–84k 行起 oracle dump 显示 BeeByte 去混淆名
  （`JDIOCKICHNB→get_txtTitle`；oracle 目录带 `BeeByte-6.0/` 映射），此前 R72 只比前 5k 行所以全绿。
  前缀段（81342/83676 行）lockstep 逐位全同=解码正确性的直接证据。后续比对应过滤映射名。
- **6.0/6.1/6.3 方法链无解的根因是转移不是求解**：指纹分 0.01–0.4（世代差大，函数定位失败），
  symwalk/emu 在错误函数上提链。Python 时代 6.1 曾 100% 是因为 emu 跑在**已知**函数地址（非零接触）。
  补法：chain_hunt（imul 簇扫描）移植，或按不变量直接全镜像找链（不走函数定位）。
- **6.2 count/start 未解**：u8/u32 单链求解器不覆盖二级掩码（mask2 = pmid×mul 变体，7.1 同款）。
  name-only 拼接兜底已上（方法名正确，参数列留种子）。

## 新版本 runbook（两条命令出 dump 的最短路径）

```bash
# 目标版本 X（种子 sites/derive/semantics 一次制备，长期复用）
mhydump strings  --exe X/YuanShen.exe --metadata X/.../global-metadata.dat --out X.strings.txt
mhydump auto-tables --exe X/YuanShen.exe --metadata X/.../global-metadata.dat \
  --sites X.sites.json --seed seed.json --seed-sites seed.sites.json --seed-derive seed.derive.json \
  --strings X.strings.txt --solve-method --solve-td --rows 700000 \
  --profile-out X.profile.json --verify-rows 256        # verify<90% 即报警
mhydump dump-gen --exe X/YuanShen.exe --metadata X/.../global-metadata.dat \
  --profile-in X.profile.json --out X/dump.cs
# X.sites.json 由 `mhydump loadsites --exe X/YuanShen.exe --out X.sites.json` 自产
```

拼接质量分级内嵌在 profile 的 `_splice` manifest（solved/partial/inherited/notes）——
消费方永远知道哪些字段是机器验证过的目标数据、哪些是种子遗留。
