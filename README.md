# static-dumper

A static IL2CPP metadata dumper. It reads the custom-encrypted `global-metadata.dat` and the
main program module (the one holding the IL2CPP/GameAssembly code and metadata tables) directly —
with **no live process** — and emits an [Il2CppDumper](https://github.com/Perfare/Il2CppDumper)-style
`dump.cs`.

## How it works

`global-metadata.dat` is encrypted on disk. Instead of running the target, this tool reproduces the
decryption statically: the metadata body is the raw `.dat` from offset `0x210`, the header is an
embedded blob in the main module's `.rdata` (located by a self-validating scan), and all tables are
decoded with constant-keyed recipes recovered by reverse-engineering. Full details in
[`RECIPE.md`](RECIPE.md). Tool inventory, cross-version workflows and pitfalls:
[`docs/TOOLS.md`](docs/TOOLS.md).

## Build

```sh
cargo build --release
```

Rust (edition 2021); dependencies are pinned in `Cargo.lock`.

## Usage

```sh
mhydump dump --exe <main-module> --metadata <global-metadata.dat> --out dump.cs
```

`dump-gen` additionally auto-loads the sibling **`startup-metadata.dat`** (same directory as
`global-metadata.dat`) — it holds the generic-class rows, so `GENERICINST` types render as
`System.Collections.Generic.List<System.String>` instead of `System.Object`. Without that file the
tool warns and falls back (nothing is silently faked).

| Command | Purpose |
|---|---|
| `derive --exe <m> --metadata <d> [--out art.json]` | **分析提取模块（R10）**：一次性导出全部可机推数据（字符串密码/表槽锚点/表基址+stride）为 JSON 工件，含 mscorlib 自检 |
| `dump-gen --exe <m> --metadata <d> [--out dump.cs] [--profile-in p.json]` | 世代通用 dump 管线（profile 驱动；默认 profile 为 7.1 实测 layout71）。`dump71` 为过渡别名，多版本 profile 推导落地后移除（R9） |
| `pe-validate --exe <m>` | Parse the PE, print sections, flag BSS globals |
| `decode-one --exe <m> --metadata <d> --idx <packed>` | Decode a single string by packed index |
| `header-dump --exe <m> --metadata <d>` | Load metadata, print resolved table offsets |
| `dump --exe <m> --metadata <d> [--only 28,42,...] [--out dump.cs]` | Emit `dump.cs` |

A full dump produces 88,902 types / 440,172 fields / 733,442 methods (~112 MB) in a few seconds
on the 7.1.0 sample. Row counts come from the table-size header slots, not from the structural
chain walk or the code-pointer array (both undercount; see `docs/re/gap-inventory.md` §0).
Field offsets are reconstructed by sequential layout (the dat has no offset table): 321,796 of
440,172 fields carry a `// 0x…` comment; static fields have no derivable offset statically.
Method signatures carry real parameter names and types (parameter-definition table at
`hdr[0x68]^0x146BE503`, 8-byte rows), and const fields / enum members carry their values
(field default-value table at `hdr[0x164]^0x03893506`).

## Layout

```
src/
  pe.rs            PE32+ parsing
  mem.rs           the Memory trait + byte-buffer backing
  decrypt/         header location + table resolution
  decode_str.rs    string decryption
  metadata.rs      resolved table-base view
  class_model.rs   typeDef reconstruction
  typenames.rs     Il2CppType -> C# name + modifiers
  field_meta.rs    field decoding
  method_meta.rs   method decoding
  default_values.rs  default-value literals
  dump.rs          the full dump walk
RECIPE.md          the decryption recipe
```

## Disclaimer

For educational and interoperability research on software you own or are authorized to analyze. Constants for the 7.x generation are consolidated in `src/derive/layout71.rs`
and re-derivable per build (`derive` framework); see `REQUIREMENTS.md` R2 for
the adaptation policy and `IMPLEMENTATION_LOG.md` for what is auto-derived vs
pending.

## License

[GPL-3.0](LICENSE).

## Ghidra integration

`mhydump dump` writes `dump.cs` plus an Il2CppDumper-compatible `script.json`
(beside it). To apply names inside Ghidra:

1. import the game executable, run auto-analysis (or skip it);
2. Script Manager -> run `ghidra/apply_mhy_dump.py`, select the `script.json`;
3. every method address gets its fully-qualified managed name
   (`Namespace.Class.Method`); functions are created where missing.

Any Il2CppDumper-compatible Ghidra plugin can consume the same `script.json`.
