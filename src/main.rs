//! CLI entry point. One subcommand per milestone (see the plan).
//!
//! Milestone (a): `mhydump pe-validate <exe>` — parse and print the PE section table + flag BSS.

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mhydump", about = "Static IL2CPP 'MHY' metadata dumper")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Constant-free: locate the embedded MHY header and recover every header-slot
    /// anchor from the code, then report each resolved body offset.
    Anchors {
        #[arg(short, long)]
        exe: String,
        /// Optional global-metadata.dat, used only to range-check resolved offsets.
        #[arg(long)]
        metadata: Option<String>,
        /// Emit the recovered anchors as JSON.
        #[arg(long)]
        json: bool,
        /// Debug: only scan the header-pointer load at this VA (hex).
        #[arg(long, value_parser = parse_u64_hex)]
        site: Option<u64>,
    },
    /// Constant-free: derive the string cipher (M1/X1/X2 + strsec) from the image.
    Cipher {
        #[arg(short, long)]
        exe: String,
        #[arg(long)]
        metadata: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Constant-free: decrypt the whole string heap and enumerate every entry.
    Strings {
        #[arg(short, long)]
        exe: String,
        #[arg(long)]
        metadata: String,
        /// Write every entry as `offset<TAB>text`.
        #[arg(short, long)]
        out: Option<String>,
        /// How many leading entries to print.
        #[arg(long, default_value_t = 16)]
        head: usize,
    },
    /// Constant-free: locate metadata row tables from structure alone (no constant,
    /// no address, no column name).
    Tables {
        #[arg(short, long)]
        exe: String,
        #[arg(long)]
        metadata: String,
        /// Restrict the scan to this body offset (hex). Default: every offset the
        /// anchor recovery found in the code.
        #[arg(long, value_parser = parse_u64_hex)]
        base: Option<u64>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Milestone (a): parse a PE image, print its section table, ImageBase, and flag BSS globals.
    PeValidate {
        /// Path to GenshinImpact.exe (or any PE32+ image).
        #[arg(short, long)]
        exe: String,
    },
    /// Milestone (c): decode a single string by packed index from the metadata.
    DecodeOne {
        #[arg(long)]
        exe: String,
        #[arg(long)]
        metadata: String,
        /// Packed string index (offset in low 24 bits, length in next 8). Hex (0x..) or decimal.
        #[arg(long, value_parser = parse_u32)]
        idx: u32,
    },
    /// Milestone (d): load metadata and print every resolved table base.
    HeaderDump {
        #[arg(long)]
        exe: String,
        #[arg(long)]
        metadata: String,
    },
    /// Walk the TypeDefinition table and dump type names.
    TypesDump {
        #[arg(long)]
        exe: String,
        #[arg(long)]
        metadata: String,
        /// Output path.
        #[arg(short, long, default_value = "typedefs.txt")]
        out: String,
    },
    /// Locate il2cpp runtime API functions (il2cpp_init & friends) via anchor strings + call graph.
    Il2CppFns {
        /// Path to the main PE image (the game executable).
        #[arg(short, long)]
        exe: String,
    },
    /// R10 "constant/algorithm analysis-extract" module: one-shot constant-free
    /// derivation of everything machine-derivable (string cipher, header-slot
    /// anchors, table bases incl. strides), exported as a JSON artifact.
    /// The unpack module (`dump-gen --profile-in`) consumes exported data;
    /// `dump-gen --profile-out` is the same contract for a full profile.
    Derive {
        #[arg(short, long)]
        exe: String,
        #[arg(long)]
        metadata: String,
        /// Write the derivation artifact here (default: print JSON to stdout).
        #[arg(short, long)]
        out: Option<String>,
    },
    /// Generation dump pipeline: full dump.cs + script.json via the derived profile.
    /// Version-generic: behaviour is fully profile-driven; the shipped default profile
    /// is the 7.1-measured one (layout71). `dump71` stays as a deprecated alias until
    /// the multi-version profile derivation lands (REQUIREMENTS R9).
    #[clap(name = "dump-gen", alias = "dump71")]
    DumpGen {
        #[arg(long)]
        exe: String,
        #[arg(long)]
        metadata: String,
        #[arg(short, long, default_value = "dump.cs")]
        out: String,
        /// Load the whole profile from JSON instead of the built-in 7.1 layout.
        #[arg(long)]
        profile_in: Option<String>,
        /// Write the effective profile as JSON.
        #[arg(long)]
        profile_out: Option<String>,
        /// Skip the constant-free cipher cross-check against the binary.
        #[arg(long)]
        no_cipher_check: bool,
        /// Write the recovered image / assembly name tables (from startup-metadata) as JSON.
        #[arg(long)]
        images_out: Option<String>,
        /// Write every recovered custom-attribute instance (class + member identity) as JSON.
        #[arg(long)]
        attributes_out: Option<String>,
        /// Export structured type/field/method data (JSONL) for the DummyDll generator.
        #[arg(long)]
        dummy_out: Option<String>,
    },
    /// Milestones (e)/(f): emit dump.cs. With --only, restrict to given TypeDefIndices.
    Dump {
        #[arg(long)]
        exe: String,
        #[arg(long)]
        metadata: String,
        /// Output path for dump.cs.
        #[arg(short, long, default_value = "dump.cs")]
        out: String,
        /// Comma-separated TypeDefIndices to emit (milestone e). Omit for the full dump (f).
        #[arg(long, value_delimiter = ',')]
        only: Option<Vec<usize>>,
    },
}

fn parse_u32(s: &str) -> Result<u32, std::num::ParseIntError> {
    if let Some(h) = s.strip_prefix("0x") {
        u32::from_str_radix(h, 16)
    } else {
        s.parse()
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("mhydump=info".parse()?))
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Anchors { exe, metadata, json, site } => anchors_cmd(&exe, metadata.as_deref(), json, site),
        Cmd::Cipher { exe, metadata, json } => cipher_cmd(&exe, &metadata, json),
        Cmd::Strings { exe, metadata, out, head } => strings_cmd(&exe, &metadata, out.as_deref(), head),
        Cmd::Tables { exe, metadata, base, json } => tables_cmd(&exe, &metadata, base, json),
        Cmd::PeValidate { exe } => pe_validate(&exe),
        Cmd::DecodeOne { exe, metadata, idx } => decode_one(&exe, &metadata, idx),
        Cmd::HeaderDump { exe, metadata } => header_dump(&exe, &metadata),
        Cmd::TypesDump { exe, metadata, out } => types_dump(&exe, &metadata, &out),
        Cmd::Derive { exe, metadata, out } => derive_cmd(&exe, &metadata, out.as_deref()),
        Cmd::Il2CppFns { exe } => il2cpp_fns(&exe),
        Cmd::DumpGen { exe, metadata, out, profile_in, profile_out, no_cipher_check, images_out, attributes_out, dummy_out } =>
            dump_gen_cmd(
                &exe,
                &metadata,
                &out,
                profile_in.as_deref(),
                profile_out.as_deref(),
                no_cipher_check,
                images_out.as_deref(),
                attributes_out.as_deref(),
                dummy_out.as_deref(),
            ),
        Cmd::Dump { exe, metadata, out, only } => dump_cmd(&exe, &metadata, &out, only.as_deref()),
    }
}

/// Constant-free string-cipher derivation.
fn cipher_cmd(exe: &str, metadata: &str, json: bool) -> Result<()> {
    let ga = std::fs::read(exe)?;
    let gm = std::fs::read(metadata)?;
    let body = gm.get(0x210..).unwrap_or(&[]);
    let found = static_mhy_dumper::derive::cipher::derive(&ga, body)?;
    let tables = static_mhy_dumper::derive::cipher::find_key_step_tables(&ga)?;
    let build = static_mhy_dumper::derive::cipher::derive_build(&ga, &gm)?;
    let sched = build.as_ref().and_then(|b| b.cipher.clone());
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ciphers": found,
                "key_step_tables": tables,
                "schedule": sched,
            }))?
        );
        return Ok(());
    }
    for t in &tables {
        println!("key-step table @0x{:X}  M4=0x{:016X}", t.va, t.m4);
    }
    // Schedule-agnostic pass: the decoder that references a key-step table, with
    // its key schedule traced out of the instructions and reported as data.
    match &sched {
        Some(c) => {
            println!(
                "schedule-derived cipher: decoder@0x{:X} mask@0x{:X} strsec=0x{:X} score={}",
                c.site, c.mask_site, c.strsec, c.score
            );
            println!("  step-table @0x{:X}  step=0x{:016X}", c.step_table, c.schedule.step);
            println!("  key(off) = {}", c.schedule.formula());
        }
        None => println!("schedule-derived cipher: none (no key-step table / no straight-line schedule)"),
    }
    if found.is_empty() {
        println!("no 3-constant string cipher derived (expected on the 5-constant generations)");
        return Ok(());
    }
    for c in &found {
        println!(
            "site=0x{:X}  M1=0x{:016X} X1=0x{:016X} X2=0x{:016X}  strsec=0x{:X}  score={}",
            c.site, c.m1, c.x1, c.x2, c.strsec, c.score
        );
    }
    Ok(())
}

/// Constant-free: decrypt the whole string heap and report what it contains.
///
/// This is the end-to-end check on the cipher that needs no table constants at
/// all: entry 0 must be `mscorlib`, every entry must terminate, and the walk must
/// reach the end of the heap. A wrong schedule stops after a handful of entries.
fn strings_cmd(exe: &str, metadata: &str, out: Option<&str>, head: usize) -> Result<()> {
    let ga = std::fs::read(exe)?;
    let gm = std::fs::read(metadata)?;
    let body = gm.get(0x210..).unwrap_or(&[]);
    let build = static_mhy_dumper::derive::cipher::derive_build(&ga, &gm)?
        .ok_or_else(|| anyhow::anyhow!("no embedded MHY header located"))?;
    let c = build
        .cipher
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no string cipher derived from this image"))?;
    let t0 = std::time::Instant::now();
    let limit = body.len().saturating_sub(c.strsec as usize);
    let heap = static_mhy_dumper::decode_str::string_starts(body, c.strsec as usize, &c.schedule, limit);
    println!("strsec=0x{:X}  step=0x{:016X}  key(off) = {}", c.strsec, c.schedule.step, c.schedule.formula());
    println!("scanned=0x{:X} bytes of heap, found {} offsets that start a string of length >= 8 (+ ~0.04% noise)",
        limit, heap.len());
    println!("in {:.2}s   (noise floor for the same predicate is 20..100 per 256 KiB)", t0.elapsed().as_secs_f64());
    match heap.first() {
        Some(h) if h.text.starts_with("mscorlib") => {
            println!("first entry OK: offset 0 -> {:?}", h.text)
        }
        Some(h) => println!("first entry WRONG: offset 0 -> {:?} (expected \"mscorlib\")", h.text),
        None => println!("nothing decodes at all -- schedule is wrong"),
    }
    for h in heap.iter().take(head) {
        println!("  0x{:06X}  {}", h.off, h.text);
    }
    println!("NOTE: `text` is the exact string followed by further printable bytes, because the");
    println!("      heap stores no terminators and no lengths. Exact strings come from decoding a");
    println!("      real index with the metadata table that holds it.");
    if let Some(p) = out {
        let mut s = String::new();
        for h in &heap {
            s.push_str(&format!("0x{:06X}\t{}\n", h.off, h.text));
        }
        std::fs::write(p, s)?;
        println!("wrote {} entries to {p}", heap.len());
    }
    Ok(())
}
/// Constant-free table location: structure only, no constant and no address.
///
/// Candidate bases default to every body offset the anchor recovery read out of the
/// code, so the whole command needs nothing but the exe and the encrypted metadata.
fn tables_cmd(exe: &str, metadata: &str, base: Option<u64>, json: bool) -> Result<()> {
    let ga = std::fs::read(exe)?;
    let gm = std::fs::read(metadata)?;
    let body = gm.get(0x210..).unwrap_or(&[]);
    let build = static_mhy_dumper::derive::cipher::derive_build(&ga, &gm)?;
    let bases: Vec<usize> = match base {
        Some(b) => vec![b as usize],
        None => {
            let b = build
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("no embedded MHY header located"))?;
            // R8 (a): the primary candidate set is what the code itself computes.
            // `recover_tables` returns only the sites where a header slot and a
            // stride are combined into a row address, so the set is a handful of
            // entries instead of every slot the game ever reads.
            let code = static_mhy_dumper::derive::anchor::recover(&ga)
                .ok()
                .and_then(|r| {
                    static_mhy_dumper::derive::anchor::recover_tables(&ga, r.hdr_global)
                        .ok()
                        .map(|t| {
                            let mut v: Vec<usize> = t
                                .iter()
                                .filter_map(|d| d.resolve(&r.header))
                                .filter(|o| *o > 0)
                                .map(|o| o as usize)
                                .collect();
                            v.sort_unstable();
                            v.dedup();
                            v
                        })
                });
            match code.filter(|v| !v.is_empty()) {
                Some(v) => {
                    tracing::info!(
                        "{} candidate bases from the code's own base+index*stride sites",
                        v.len()
                    );
                    v
                }
                None => {
                    let v: Vec<usize> = b.body_offsets().into_iter().map(|o| o as usize).collect();
                    tracing::info!(
                        "{} candidate bases from the anchor recovery (no code-defined table site matched)",
                        v.len()
                    );
                    v
                }
            }
        }
    };
    let found = static_mhy_dumper::derive::tables::find(body, &bases);
    // Ask EVERY candidate table which of its columns decode to string indices, not just
    // the first. A version can describe the same physical column under two models (6.4.0
    // does), and the description that yields a name column is the typeDef one -- so the
    // name column doubles as the arbiter between competing descriptions.
    let mut cols: Vec<static_mhy_dumper::derive::tables::StringColumn> = Vec::new();
    let mut col_table: Option<usize> = None;
    if let Some(c) = build.as_ref().and_then(|b| b.cipher.as_ref()) {
        for (i, t) in found.iter().enumerate() {
            let mut cand = static_mhy_dumper::derive::tables::find_additive_string_columns(
                body, c.strsec as usize, &c.schedule, t.base, t.stride, t.rows,
            );
            if cand.is_empty() {
                // The two families flip together: 7.0.0 has an ADD index column and an
                // XOR name column, the opposite of 7.1.0. Try both before giving up.
                cand = static_mhy_dumper::derive::tables::find_xor_string_columns(
                    body, c.strsec as usize, &c.schedule, t.base, t.stride, t.rows,
                );
            }
            if !cand.is_empty() {
                cols = cand;
                col_table = Some(i);
                break;
            }
        }
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "tables": found, "string_columns": cols }))?);
        return Ok(());
    }
    if found.is_empty() {
        println!("no row table found by the structural predicate");
        return Ok(());
    }
    println!("{:>10} {:>6} {:>4} {:>6} {:>9} {:>10} {:>4} {:>6} {:>4} {:>6} {:>6} {:>8} {:>7}",
        "base", "stride", "op", "idx_off", "idx_c", "sentinel", "cntop", "cnt_off", "cnt_c", "rows", "real", "max_idx", "trans");
    for t in &found {
        let op = match t.transform {
            static_mhy_dumper::derive::tables::IndexTransform::Xor => "xor",
            static_mhy_dumper::derive::tables::IndexTransform::Add => "add",
        };
        let cop = match t.cnt_transform {
            static_mhy_dumper::derive::tables::IndexTransform::Xor => "xor",
            static_mhy_dumper::derive::tables::IndexTransform::Add => "add",
        };
        let sent = t.sentinel_raw.map(|s| format!("0x{s:08X}")).unwrap_or_else(|| "-".into());
        println!("0x{:08X} 0x{:04X} {:>4} 0x{:04X} 0x{:08X} {:>10} {:>4} 0x{:04X} 0x{:04X} {:>6} {:>6} {:>8} {:>7}",
            t.base, t.stride, op, t.idx_off, t.idx_c, sent, cop, t.cnt_off, t.cnt_c, t.rows, t.real_rows, t.max_index, t.transitions);
    }
    if !cols.is_empty() {
        println!();
        match col_table {
            Some(i) => println!("string-index columns of table #{i} above:"),
            None => println!("string-index columns:"),
        }
        for c in &cols {
            println!("  col_off=0x{:02X}  +0x{:08X}  ok {}/{}", c.off, c.c, c.rows_ok, c.rows_tested);
        }
    }
    Ok(())
}

/// Constant-free header location + anchor recovery.
fn parse_u64_hex(s: &str) -> Result<u64, std::num::ParseIntError> {
    let t = s.trim_start_matches("0x");
    u64::from_str_radix(t, 16)
}

fn anchors_cmd(exe: &str, metadata: Option<&str>, json: bool, site: Option<u64>) -> Result<()> {
    let ga = std::fs::read(exe)?;
    if let Some(site) = site {
        let img = static_mhy_dumper::pe::Image::parse(&ga)?;
        let blobs = static_mhy_dumper::derive::anchor::find_header_blobs(&ga)?;
        let hg = static_mhy_dumper::derive::anchor::find_hdr_global(&ga, blobs[0].va)?;
        println!("site 0x{site:X} hdr_global 0x{hg:X}");
        for a in static_mhy_dumper::derive::anchor::scan_site_debug(&img, &ga, site, hg, hg + 8) {
            println!("  {a:?}");
        }
        return Ok(());
    }
    let rec = static_mhy_dumper::derive::anchor::recover(&ga)?;
    let tdefs = static_mhy_dumper::derive::anchor::recover_tables(&ga, rec.hdr_global)?;
    let body_len = match metadata {
        Some(p) => std::fs::read(p)?.len().saturating_sub(0x210),
        None => usize::MAX,
    };
    if json {
        let unique = rec.unique();
        let rows: Vec<_> = unique
            .iter()
            .map(|a| {
                serde_json::json!({
                    "hdr_off": a.hdr_off,
                    "op": a.op,
                    "imm": a.imm,
                    "site": format!("0x{:X}", a.site),
                    "confirmed": a.confirmed,
                    "resolved": a.resolve(&rec.header),
                })
            })
            .collect();
        let trows: Vec<_> = tdefs
            .iter()
            .map(|t| {
                serde_json::json!({
                    "hdr_off": t.hdr_off,
                    "op": t.op,
                    "imm": t.imm,
                    "stride": t.stride,
                    "site": format!("0x{:X}", t.site),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "blob_va": format!("0x{:X}", rec.blob.va),
                "blob_file_off": format!("0x{:X}", rec.blob.file_off),
                "hdr_global": format!("0x{:X}", rec.hdr_global),
                "body_len": (body_len != usize::MAX).then(|| format!("0x{body_len:X}")),
                "anchors": rows,
                "tables_from_code": trows,
            }))?
        );
        return Ok(());
    }
    println!(
        "MHY blob at file 0x{:X} (VA 0x{:X}); header global 0x{:X}",
        rec.blob.file_off, rec.blob.va, rec.hdr_global
    );
    if body_len != usize::MAX {
        println!("body length 0x{body_len:X}");
    }
    println!("{:<6} {:<5} {:<12} {:<12} {:<10} {}", "slot", "op", "imm", "resolved", "confirmed", "site");
    for a in rec.unique() {
        let v = a.resolve(&rec.header);
        let in_range = match v {
            Some(v) if body_len != usize::MAX => {
                if v > 0 && (v as usize) < body_len { "in-range" } else { "OUT-OF-RANGE" }
            }
            Some(_) => "?",
            None => "truncated",
        };
        println!(
            "0x{:<4X} {:<5} 0x{:<10X} {:<12} {:<10} 0x{:X}  {}",
            a.hdr_off,
            match a.op {
                static_mhy_dumper::derive::anchor::AnchorOp::Add => "add",
                static_mhy_dumper::derive::anchor::AnchorOp::Sub => "sub",
                static_mhy_dumper::derive::anchor::AnchorOp::Xor => "xor",
            },
            a.imm,
            v.map(|x| format!("0x{x:X}")).unwrap_or_default(),
            a.confirmed,
            a.site,
            in_range,
        );
    }
    if !tdefs.is_empty() {
        println!();
        println!("{:<6} {:<5} {:<12} {:>7}  {}", "slot", "op", "imm", "stride", "site  (base + index * stride)");
        for t in &tdefs {
            println!(
                "0x{:<4X} {:<5} 0x{:<10X} 0x{:<5X} 0x{:X}",
                t.hdr_off,
                match t.op {
                    static_mhy_dumper::derive::anchor::AnchorOp::Add => "add",
                    static_mhy_dumper::derive::anchor::AnchorOp::Sub => "sub",
                    static_mhy_dumper::derive::anchor::AnchorOp::Xor => "xor",
                },
                t.imm,
                t.stride,
                t.site,
            );
        }
    }
    Ok(())
}

/// Walk the TypeDefinition table (current-generation layout).
fn types_dump(exe: &str, metadata: &str, out: &str) -> Result<()> {
    let ga = std::fs::read(exe)?;
    let gm = std::fs::read(metadata)?;
    let md = static_mhy_dumper::decrypt::file::load(&ga, &gm)?;
    use std::io::Write;
    let f = std::fs::File::create(out)?;
    let mut w = std::io::BufWriter::new(f);
    let (nt, nh) = static_mhy_dumper::td_dump::dump_types(&md, &mut w)?;
    w.flush()?;
    println!("wrote {out}: {nt} visible types, {nh} hidden-marker records skipped");
    Ok(())
}

/// Locate il2cpp runtime API functions by anchor strings + direct-call graph.
fn il2cpp_fns(exe: &str) -> Result<()> {
    let ga = std::fs::read(exe)?;
    let img = static_mhy_dumper::pe::Image::parse(&ga)?;
    let report = static_mhy_dumper::il2cpp_api::analyze(&img)?;
    print!("{report}");
    Ok(())
}

/// R10 analysis-extract module: one-shot, constant-free export of every
/// machine-derivable fact (string cipher, header-slot anchors, table bases with
/// strides) as a JSON artifact. The artifact is data only — the unpack module
/// (`dump-gen --profile-in`) never re-derives and never carries these constants
/// in code.
fn derive_cmd(exe: &str, metadata: &str, out: Option<&str>) -> Result<()> {
    let ga = std::fs::read(exe)?;
    let gm = std::fs::read(metadata)?;
    let body = gm.get(0x210..).unwrap_or(&[]);
    let build = static_mhy_dumper::derive::cipher::derive_build(&ga, &gm)?
        .ok_or_else(|| anyhow::anyhow!("no embedded MHY header located"))?;
    let tdefs = static_mhy_dumper::derive::anchor::recover_tables(
        &ga,
        static_mhy_dumper::derive::anchor::find_hdr_global(&ga, build.blob_va)?,
    )?;

    // Dedup anchors by (hdr_off, op, imm); resolved against the embedded header.
    let mut rows: Vec<serde_json::Value> = Vec::new();
    for a in &build.anchors {
        let key = serde_json::json!([a.hdr_off, format!("{:?}", a.op), a.imm]);
        if rows.iter().any(|r| {
            r.get("key") == Some(&key)
        }) {
            continue;
        }
        rows.push(serde_json::json!({
            "key": key,
            "hdr_off": a.hdr_off,
            "op": format!("{:?}", a.op),
            "imm": a.imm,
            "site": format!("0x{:X}", a.site),
            "confirmed": a.confirmed,
            "resolved": a.resolve(&build.header),
        }));
    }
    rows.retain(|r| r.get("key").is_some());
    for r in &mut rows {
        let obj = r.as_object_mut().unwrap();
        obj.remove("key");
    }
    let trows: Vec<_> = tdefs
        .iter()
        .map(|t| {
            serde_json::json!({
                "hdr_off": t.hdr_off,
                "op": format!("{:?}", t.op),
                "imm": t.imm,
                "stride": t.stride,
                "site": format!("0x{:X}", t.site),
            })
        })
        .collect();

    // Sanity: the derived schedule must decode heap entry 0 to "mscorlib".
    // A wrong schedule would emit a plausible-looking artifact with garbage keys.
    let heap0 = build
        .cipher
        .as_ref()
        .map(|c| {
            static_mhy_dumper::decode_str::decode_str_sched(
                &static_mhy_dumper::mem::Buffer::new(body),
                c.strsec as usize,
                0x0800_0000, // offset 0, length 8
                &c.schedule,
            )
        })
        .unwrap_or_default();
    if heap0 != "mscorlib" {
        anyhow::bail!(
            "derived cipher failed the mscorlib sanity check (got {:?}) — refusing to export",
            heap0
        );
    }

    let artifact = serde_json::json!({
        "artifact": "mhydump-derive",
        "artifact_version": 1,
        "module": "constant-algorithm-analysis-extract (REQUIREMENTS R10)",
        "blob_va": format!("0x{:X}", build.blob_va),
        "cipher": build.cipher,
        "anchors": rows,
        "tables": trows,
        "sanity": {
            "heap0": heap0,
            "body_len": body.len(),
        },
    });
    let text = serde_json::to_string_pretty(&artifact)?;
    match out {
        Some(p) => {
            std::fs::write(p, &text)?;
            println!("derivation artifact written to {p}");
        }
        None => println!("{text}"),
    }
    Ok(())
}

fn dump_gen_cmd(
    exe: &str,
    metadata: &str,
    out: &str,
    profile_in: Option<&str>,
    profile_out: Option<&str>,
    no_cipher_check: bool,
    images_out: Option<&str>,
    attributes_out: Option<&str>,
    dummy_out: Option<&str>,
) -> Result<()> {
    use static_mhy_dumper::derive::profile::Profile;
    let ga = std::fs::read(exe)?;
    let gm = std::fs::read(metadata)?;
    let mut profile: Profile = match profile_in {
        Some(p) => serde_json::from_str(&std::fs::read_to_string(p)?)?,
        None => static_mhy_dumper::derive::layout71::gen71(),
    };

    // Constant-free cipher cross-check. The profile's table constants are only valid
    // for the build they were derived from; if the binary on hand carries a different
    // key schedule, every decoded string would be garbage, so refuse instead of
    // emitting a plausible-looking dump (REQUIREMENTS R2.4 / R4.2).
    let derived = static_mhy_dumper::derive::cipher::derive_build(&ga, &gm)?
        .and_then(|b| b.cipher);
    match (&derived, no_cipher_check) {
        (Some(d), false) => {
            let effective = profile.schedule();
            let same = effective.ops == d.schedule.ops && effective.step == d.schedule.step;
            if same {
                tracing::info!("cipher cross-check OK: {}", d.schedule.formula());
            } else {
                tracing::warn!(
                    "cipher MISMATCH: profile key(off) = {} ; binary key(off) = {} (step 0x{:X} vs 0x{:X})",
                    effective.formula(),
                    d.schedule.formula(),
                    effective.step,
                    d.schedule.step
                );
                anyhow::bail!(
                    "profile does not match this binary (strings would decode to garbage); \
                     pass --profile-in for this build, or --no-cipher-check to force"
                );
            }
            // Carry the *derived* schedule as data, so `--profile-out` emits a
            // self-describing profile instead of a constant triple.
            profile.cipher = Some(d.schedule.clone());
        }
        (None, false) => tracing::warn!("no cipher derived from the binary; using the profile as-is"),
        _ => {}
    }

    // The generic-class rows live in the sibling startup-metadata.dat (same directory as
    // global-metadata.dat). Missing file = GENERICINST types fall back to System.Object with an
    // explicit warning; nothing is silently faked. The bytes must outlive `m` (borrowed).
    let startup_bytes: Option<Vec<u8>> = {
        let startup_path = std::path::Path::new(metadata)
            .parent()
            .map(|d| d.join("startup-metadata.dat"))
            .filter(|p| p.exists());
        match &startup_path {
            Some(p) => Some(std::fs::read(p)?),
            None => {
                tracing::warn!("startup-metadata.dat not found next to the metadata; \
                                GENERICINST types will render as System.Object");
                None
            }
        }
    };
    let m = static_mhy_dumper::derive::engine::Meta::load_with_startup(
        &ga,
        &gm,
        startup_bytes.as_deref(),
        profile,
    )?;
    tracing::info!(
        "header OK: strsec=0x{:X} td=0x{:X} md=0x{:X} fd=0x{:X} params=0x{:X} typearr=0x{:X}({}) mptrs=0x{:X}({})",
        m.strsec, m.td_base, m.md_base, m.fd_base, m.param_base,
        m.typearr, m.typearr_len, m.methodptrs, m.methodptrs_len
    );
    if let Some(p) = profile_out {
        std::fs::write(p, serde_json::to_string_pretty(&m.profile)?)?;
        println!("wrote profile {p}");
    }
    if let Some(p) = images_out {
        let images = m.startup_image_names();
        let assemblies = m.startup_assembly_names();
        if images.is_empty() || assemblies.is_empty() {
            tracing::warn!(
                "image/assembly name tables not resolved ({} images, {} assemblies); 
                 the profile needs startup_images / startup_assemblies",
                images.len(),
                assemblies.len()
            );
        }
        // The two tables are index-aligned (verified: image name minus `.dll` equals the
        // assembly name for every row). Only emit the pairing when that invariant holds,
        // otherwise report the mismatch instead of inventing a mapping.
        let pairs: Vec<serde_json::Value> = if images.len() == assemblies.len() {
            images
                .iter()
                .zip(assemblies.iter())
                .enumerate()
                .map(|(i, (img, asm))| {
                    serde_json::json!({"Index": i, "Image": img, "Assembly": asm})
                })
                .collect()
        } else {
            tracing::warn!(
                "image count {} != assembly count {}; AssemblyImages pairing omitted",
                images.len(),
                assemblies.len()
            );
            Vec::new()
        };
        let doc = serde_json::json!({
            "Images": images,
            "Assemblies": assemblies,
            "AssemblyImages": pairs,
        });
        std::fs::write(p, serde_json::to_string_pretty(&doc)?)?;
        println!(
            "wrote {p}: {} images, {} assemblies",
            doc["Images"].as_array().map(|a| a.len()).unwrap_or(0),
            doc["Assemblies"].as_array().map(|a| a.len()).unwrap_or(0)
        );
    }
    if let Some(p) = attributes_out {
        let n = static_mhy_dumper::dump_gen::write_attributes_json(&m, p)?;
        println!("wrote {p}: {n} attribute instances");
    }
    if let Some(p) = dummy_out {
        let (nt, nf, nm) = static_mhy_dumper::dummy_export::export_dummy(&m, p)?;
        println!("wrote {p}: {nt} types, {nf} fields, {nm} methods (DummyDll input)");
    }
    let json_path = match out.rfind('/') {
        Some(p) => format!("{}script.json", &out[..=p]),
        None => "script.json".to_string(),
    };
    let f = std::fs::File::create(out)?;
    let mut w = std::io::BufWriter::new(f);
    let fj = std::fs::File::create(&json_path)?;
    let mut wj = std::io::BufWriter::new(fj);
    let (nt, nf, nm) = static_mhy_dumper::dump_gen::dump(&m, &mut w, &mut wj)?;
    use std::io::Write;
    w.flush()?;
    wj.flush()?;
    println!("wrote {out} + {json_path}: {nt} types, {nf} fields, {nm} methods");
    Ok(())
}

/// Milestones (e)/(f): emit dump.cs.
fn dump_cmd(exe: &str, metadata: &str, out: &str, only: Option<&[usize]>) -> Result<()> {
    let ga = std::fs::read(exe)?;
    let gm = std::fs::read(metadata)?;
    let md = static_mhy_dumper::decrypt::file::load(&ga, &gm)?;
    if !md.tables.tables_ok {
        // current-generation path: MethodDefinition table + method-pointer array
        let json_path = match out.rfind('/') {
            Some(p) => format!("{}script.json", &out[..=p]),
            None => "script.json".to_string(),
        };
        let f = std::fs::File::create(out)?;
        let mut w = std::io::BufWriter::new(f);
        let fj = std::fs::File::create(&json_path)?;
        let mut wj = std::io::BufWriter::new(fj);
        let (nt, nm_out, nm_total) = static_mhy_dumper::methods_71::dump_full(&md, &mut w, &mut wj)?;
        w.flush()?;
        wj.flush()?;
        println!("wrote {out} + {json_path}: {nt} types, {nm_out} methods emitted (of {nm_total})");
        return Ok(());
    }
    let dm = static_mhy_dumper::metadata::DecodedMetadata::new(&md);
    let f = std::fs::File::create(out)?;
    let mut w = std::io::BufWriter::new(f);
    let (nt, nf, nm) = static_mhy_dumper::dump::dump_all(&dm, &mut w, only)?;
    use std::io::Write;
    w.flush()?;
    println!("wrote {out}: {nt} types, {nf} fields, {nm} methods");
    Ok(())
}

/// Milestone (c): decode one string by packed index.
fn decode_one(exe: &str, metadata: &str, idx: u32) -> Result<()> {
    let ga = std::fs::read(exe)?;
    let gm = std::fs::read(metadata)?;
    let md = static_mhy_dumper::decrypt::file::load(&ga, &gm)?;
    let dm = static_mhy_dumper::metadata::DecodedMetadata::new(&md);
    let off = idx & 0xFF_FFFF;
    let len = (idx >> 24) & 0xFF;
    println!("idx=0x{idx:08X} (offset=0x{off:X}, len={len}) -> {:?}", dm.string(idx));
    Ok(())
}

/// Milestone (d): print every resolved table base.
fn header_dump(exe: &str, metadata: &str) -> Result<()> {
    let ga = std::fs::read(exe)?;
    let gm = std::fs::read(metadata)?;
    let md = static_mhy_dumper::decrypt::file::load(&ga, &gm)?;
    if !md.tables.tables_ok {
        anyhow::bail!("header-dump reports the old-generation table set; runtime-table anchors for this build are not ported yet (see types-dump / decode-one)");
    }
    let dm = static_mhy_dumper::metadata::DecodedMetadata::new(&md);
    println!("Metadata loaded:");
    println!("  header (f418): {} bytes (embedded .rdata MHY blob)", md.header.len());
    println!("  body   (f420): {} bytes (global-metadata.dat[0x210..])", md.body.len());
    println!("\nBody-relative table offsets:");
    for (name, off) in [
        ("strings", dm.strings),
        ("method_defs", dm.method_defs),
        ("params", dm.params),
        ("field_defs", dm.field_defs),
        ("field_offsets", dm.field_offsets),
        ("generic_params", dm.generic_params),
        ("field_off_table_b", dm.field_off_table_b),
        ("foff_v43base", dm.foff_v43base),
        ("default_value_blob", dm.default_value_blob),
        ("field_default_values", dm.field_default_values),
    ] {
        let ok = if off < md.body.len() { "OK" } else { "OOB" };
        println!("  {name:22} body+0x{off:08X}  [{ok}]");
    }
    println!("\nGenshinImpact .rdata table file-offsets:");
    println!("  {:22} 0x{:08X}", "typearr", md.tables.typearr);
    println!("  {:22} 0x{:08X}", "methodptrs", md.tables.methodptrs);
    println!("  {:22} 0x{:08X}", "generic_classes", md.tables.generic_classes);
    println!("\nOracle: string idx (len=8, off=0) = {:?}", dm.string((8 << 24) | 0));
    Ok(())
}

/// Milestone (a). Parses the PE, prints sections + ImageBase, and confirms the metadata globals
/// `f418`/`f420` resolve as BSS (in-`.data`-range but beyond RawSize).
fn pe_validate(path: &str) -> Result<()> {
    let bytes = std::fs::read(path)?;
    let img = static_mhy_dumper::pe::Image::parse(&bytes)?;

    println!("ImageBase: 0x{:016X}", img.image_base());
    println!("Sections ({}):", img.sections().len());
    println!(
        "  {:<10} {:<12} {:<12} {:<12} {:<12} flags",
        "name", "VA", "VSize", "raw@file", "rawSize"
    );
    for s in img.sections() {
        println!(
            "  {:<10} VA=0x{:08X} VS=0x{:08X} raw@0x{:08X} rs=0x{:08X} 0x{:08X}{}{}",
            s.name,
            s.virtual_address,
            s.virtual_size,
            s.raw_pointer,
            s.raw_size,
            s.characteristics,
            if s.is_executable() { " X" } else { "" },
            if s.is_writable() { " W" } else { "" },
        );
    }

    // The load-bearing correctness check: f418/f420 are BSS.
    for (name, rva) in [("f418 (header)", 0x521F418u32), ("f420 (body)", 0x521F420u32)] {
        let bss = img.is_bss(rva);
        let file = img.rva_to_file(rva);
        println!(
            "\n{name}: RVA=0x{rva:08X}  BSS={bss}  file_offset={}",
            match file {
                Some(o) => format!("0x{o:X}"),
                None => "<none — BSS/unmapped>".to_string(),
            }
        );
    }

    // IAT: report any file/read APIs (used by the Phase-1 loader RE).
    let io: Vec<_> = img
        .imports()
        .into_iter()
        .filter(|(_, n, _)| {
            n.as_deref().map_or(false, |x| {
                x.eq_ignore_ascii_case("ReadFile")
                    || x.eq_ignore_ascii_case("CreateFileA")
                    || x.eq_ignore_ascii_case("CreateFileW")
            })
        })
        .collect();
    println!("\nFile-IO imports ({}):", io.len());
    for (dll, name, va) in &io {
        println!("  {dll}!{:<14} IAT slot VA=0x{va:016X}", name.as_deref().unwrap_or("?"));
    }
    Ok(())
}
