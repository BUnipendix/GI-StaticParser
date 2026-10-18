# 跨版本 profile 差异：7.0.0 vs 6.7.0

## method.method

| 项 | 7.0.0 | 6.7.0 | 差异 |
|---|---|---|---|
| table | imm=0xD37E9675 op=add slot=0x138 | imm=0xD515CAA3 op=add slot=0x38 | **异** |
| stride | 26 | 26 | 同 |
| rows | 713956 | 687452 | **异** |
| mask | add1=0xCC49CF2E948F28F add2=0x066E3EE5EEBB7B78 mul1=0x3639B538F896 mul2=0x3209B9A2 shr=13 | add1=0x7964C76C mul1=0xCB87 mul2=0x38036D18 shr=8 xor0=0x1D9A1A7A xor1=0x324CAF19 | **异** |
| col:flags | {'off': 14, 'kind': 'SubMaskAddC16', 'c': '0x13'} | {'off': 20, 'kind': 'XorCSubMask16', 'c': '0x3'} | **异** |
| col:flags_note | None | decoded as ((raw16 ^ 3) - mask) & 0xFFFF; bit 0x10 = static (80,860 methods). Full MethodAttributes semantics still tentative: distinct values 992 with unexpected high bits, needs a cross-check against dump modifiers. | **异** |
| col:name | {'off': 8, 'kind': 'SubMaskAddC32', 'c': '0x997E86CD'} | {'off': 8, 'kind': 'XorCSubMask32', 'c': '0x06BBF48D'} | **异** |
| col:param_count | {'off': 24, 'kind': 'XorCSubMask8', 'c': '0x5B'} | {'off': 24, 'kind': 'AddCSubMask8', 'c': '0xA8'} | **异** |
| col:param_start | {'off': 4, 'kind': 'AddCSubMask32', 'c': '0xAC706A39'} | {'off': 0, 'kind': 'XorCSubMask32', 'c': '0xD62B555'} | **异** |
| col:return_type | {'off': 0, 'kind': 'XorCSubMask32', 'c': '0x215FCCB1'} | {'off': 4, 'kind': 'XorCSubMask32', 'c': '0x546F8F09'} | **异** |

## method.param

| 项 | 7.0.0 | 6.7.0 | 差异 |
|---|---|---|---|
| table | imm=0xFC3EC0CE op=add slot=0x1FC | imm=0x12C9258B op=xor slot=0x14C | **异** |
| stride | 8 | 8 | 同 |
| rows | None | None | 同 |
| mask | add1=0xAB42C68E0D4A mul1=0x2F64C993DFFE mul2=0x272E941C shr=17 xor2=0x705880A8 | add=0x59887B45 mul=0x2A2E98A6 | **异** |
| col:name | {'off': 4, 'kind': 'AddCXorMask32', 'c': '0xDA14EDA6'} | {'off': 0, 'kind': 'XorMaskXorC32', 'c': '0x3CBE0533'} | **异** |
| col:type | {'off': 0, 'kind': 'AddCXorMask32', 'c': '0x8FE5701B'} | {'off': 4, 'kind': 'XorMaskXorC32', 'c': '0x5A301FB'} | **异** |

## field

| 项 | 7.0.0 | 6.7.0 | 差异 |
|---|---|---|---|
| table | imm=0xB98BE77F op=add slot=0x1D0 | imm=0xD34ADB03 op=add slot=0xC | **异** |
| stride | 8 | 8 | 同 |
| rows | 430290 | 413644 | **异** |
| mask | add1=0xC16316113B52 mul1=0x1147E475DFA9 mul2=0x2CD0F4EE shr1=18 shr2=16 | add1=0x251BA412D3BC6 extra_add=0x2C7618B2 extra_mul=0xC9B392C3 extra_xor=0x14BDA7A6 mul1=0x1BB4F2A67161 shr=18 | **异** |
| col:name | 4 | 0 | **异** |
| col:type | 0 | 4 | **异** |

## property

| 项 | 7.0.0 | 6.7.0 | 差异 |
|---|---|---|---|
| table | imm=0x368C9997 op=xor slot=0x15C | imm=0xE9FF5F7F op=add slot=0x1E8 | **异** |
| stride | 10 | 10 | 同 |
| rows | 112949 | 108747 | **异** |
| mask | add1=0x49880E3C add2=0x7EC31F32 mul1=0xE0F8 mul2=0x3AA8EE62 xor1=0x22F6DA00 xor2=0x3E17E98E | add1=0x5F17108D mul1=0x137D mul2=0x42639239 mul3=0x525521B3 shr1=13 shr2=13 xor0=0x70B05CB7 | **异** |
| col:getter | 8 | 8 | 同 |
| col:name | 0 | 0 | 同 |
| col:setter | 6 | 4 | **异** |
| col:unknown_6 | None | 6 | **异** |

## event

- 7.0.0: 缺失 / 6.7.0: 有

## typearr

| 项 | 7.0.0 | 6.7.0 | 差异 |
|---|---|---|---|
| va | 0x142D3DFF0 | 0x1429FA400 | **异** |
| count | 662534 | 633862 | **异** |
