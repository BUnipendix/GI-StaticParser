//! Locate il2cpp runtime API functions (il2cpp_init & friends) by anchor strings.
//!
//! The vendor strips the usual exports, but the runtime keeps its tell-tale
//! plaintext strings, and their call chains are fixed by upstream structure:
//!
//! ```text
//! engine (.text) ──> il2cpp_init(domain) ──> Runtime::Init ──┬─> Domain::Create <─── "IL2CPP Root Domain"
//!                                                            └─> MetadataCache::Initialize
//!                                                                  └─> MetadataLoader::LoadMetadataFile <─── "global-metadata.dat"
//! ```
//!
//! Version-agnostic procedure:
//! 1. find the anchor strings in read-only data, convert to VAs;
//! 2. scan every executable section for rip-relative references (`lea/mov r64, [rip+disp32]`)
//!    targeting those VAs → the referencing functions;
//! 3. approximate function starts from `int3` padding boundaries (MSVC layout) and build a
//!    deduplicated direct-call edge list (`E8 rel32`) as compact `(callee_idx, caller_idx)`
//!    pairs — memory stays proportional to the edge count, not to path counts;
//! 4. walk callers upward from each anchor function with a visited-set BFS (parent pointers,
//!    never path enumeration — a naive all-paths walk explodes on high fan-in nodes) and
//!    report one representative chain per anchor.
//!    `il2cpp_init` is expected as an ancestor whose callers live in the engine section
//!    (cross-module boundary = the C-API surface).
//!
//! Known limitations: indirect (register-indirect) calls are invisible to the E8 graph; the
//! upstream chains above are compiled C++ and resolve through direct calls in practice, but a
//! link may be missing on some builds — the report prints the raw referencing sites so the gap
//! can be closed by hand in a disassembler.

use anyhow::{bail, Result};


use crate::pe::Image;

const ANCHORS: &[(&str, &[u8])] = &[
    ("Domain::Create (Runtime::Init callee)", b"IL2CPP Root Domain"),
    ("MetadataLoader::LoadMetadataFile", b"global-metadata.dat"),
];

const MAX_DEPTH: usize = 6;
const MAX_EDGES: usize = 96_000_000; // ~768 MB as (u32,u32) pairs; hard safety cap

struct Graph {
    starts: Vec<u64>,              // sorted fn starts (VA)
    rev_edges: Vec<(u32, u32)>,    // sorted+deduped (callee_idx, caller_idx)
}

impl Graph {
    fn fn_idx(&self, va: u64) -> Option<u32> {
        let i = self.starts.partition_point(|&s| s <= va);
        if i == 0 { None } else { Some((i - 1) as u32) }
    }
    /// all (callee=self, caller) edges for fn index f (edges sorted by callee)
    fn caller_band(&self, f: u32) -> &[(u32, u32)] {
        let lo = self.rev_edges.partition_point(|e| e.0 < f);
        let hi = self.rev_edges.partition_point(|e| e.0 <= f);
        &self.rev_edges[lo..hi]
    }
}

/// Approximate function starts from int3 (0xCC) padding runs inside executable sections.
fn collect_fn_starts(img: &Image) -> Vec<u64> {
    let mut starts = Vec::new();
    for s in img.sections().iter().filter(|s| s.is_executable()) {
        let base = img.image_base() + s.virtual_address as u64;
        let Some(bytes) = img.file_slice(s.raw_pointer as u64, s.raw_size as usize) else { continue };
        starts.push(base);
        let mut run = 0usize;
        for (i, &b) in bytes.iter().enumerate() {
            if b == 0xCC {
                run += 1;
            } else {
                if run >= 4 { starts.push(base + i as u64); }
                run = 0;
            }
        }
    }
    starts.sort_unstable();
    starts.dedup();
    starts
}

fn fn_containing(starts: &[u64], va: u64) -> Option<u32> {
    let i = starts.partition_point(|&s| s <= va);
    if i == 0 { None } else { Some((i - 1) as u32) }
}

/// Build the deduplicated direct-call edge list (E8 rel32 only), memory-compact.
fn collect_edges(img: &Image, starts: &[u64]) -> Result<Vec<(u32, u32)>> {
    let mut edges: Vec<(u32, u32)> = Vec::new();
    for s in img.sections().iter().filter(|s| s.is_executable()) {
        let base = img.image_base() + s.virtual_address as u64;
        let Some(bytes) = img.file_slice(s.raw_pointer as u64, s.raw_size as usize) else { continue };
        for i in 0..bytes.len().saturating_sub(5) {
            if bytes[i] != 0xE8 { continue; }
            let rel = i32::from_le_bytes(bytes[i + 1..i + 5].try_into().unwrap());
            let site = base + i as u64;
            let target = (site as i64 + 5 + rel as i64) as u64;
            let (Some(tf), Some(cf)) = (fn_containing(starts, target), fn_containing(starts, site)) else { continue };
            if tf != cf { edges.push((tf, cf)); }
            if edges.len() > MAX_EDGES { bail!("call edges exceed safety cap ({MAX_EDGES})"); }
        }
    }
    edges.sort_unstable();
    edges.dedup();
    Ok(edges)
}

/// Find rip-relative references (lea/mov r64, [rip+disp32]) to `target_va`.
fn find_rip_refs(img: &Image, target_va: u64) -> Vec<u64> {
    let mut sites = Vec::new();
    for s in img.sections().iter().filter(|s| s.is_executable()) {
        let base = img.image_base() + s.virtual_address as u64;
        let Some(bytes) = img.file_slice(s.raw_pointer as u64, s.raw_size as usize) else { continue };
        for i in 0..bytes.len().saturating_sub(7) {
            let b0 = bytes[i];
            if b0 != 0x48 && b0 != 0x4C { continue; }
            let b1 = bytes[i + 1];
            if b1 != 0x8D && b1 != 0x8B { continue; }
            let b2 = bytes[i + 2];
            if b2 & 0xC7 != 0x05 { continue; }
            let disp = i32::from_le_bytes(bytes[i + 3..i + 7].try_into().unwrap());
            let next = base + i as u64 + 7;
            if (next as i64 + disp as i64) as u64 == target_va { sites.push(next - 7); }
        }
    }
    sites
}

fn string_vas(img: &Image, pat: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    for s in img.sections().iter() {
        let Some(bytes) = img.file_slice(s.raw_pointer as u64, s.raw_size as usize) else { continue };
        let mut pos = 0usize;
        while let Some(rel) = find_sub(&bytes[pos..], pat) {
            let off = pos + rel;
            out.push(img.image_base() + s.virtual_address as u64 + off as u64);
            pos = off + 1;
        }
    }
    out
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() { return None; }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Depth-limited reverse BFS from `start_fn` (fn index): visited set + parent pointers,
/// one representative chain reconstructed at print time. Never enumerates paths.
fn reverse_bfs(graph: &Graph, start: u32) -> (Vec<u32>, Vec<u32>) {
    let n = graph.starts.len() as u32;
    let mut parent: Vec<u32> = vec![u32::MAX; n as usize];
    let mut depth: Vec<u32> = vec![u32::MAX; n as usize];
    parent[start as usize] = start;
    depth[start as usize] = 0;
    let mut frontier = vec![start];
    let mut d = 0u32;
    while !frontier.is_empty() && (d as usize) < MAX_DEPTH {
        let mut next: Vec<u32> = Vec::new();
        for &f in &frontier {
            for &(_c, caller) in graph.caller_band(f) {
                let cu = caller as usize;
                if depth[cu] == u32::MAX {
                    depth[cu] = d + 1;
                    parent[cu] = f;
                    next.push(caller);
                }
            }
        }
        next.sort_unstable();
        next.dedup();
        frontier = next;
        d += 1;
    }
    (parent, depth)
}

fn chain_to(graph: &Graph, parents: &[u32], depth: &[u32], node: u32) -> Vec<u64> {
    let mut chain = Vec::new();
    let mut cur = node;
    loop {
        chain.push(graph.starts[cur as usize]);
        let p = parents[cur as usize];
        if p == cur || p == u32::MAX || depth[cur as usize] == 0 { break; }
        cur = p;
    }
    chain
}

/// Run the full analysis; returns a printable report.
pub fn analyze(img: &Image) -> Result<String> {
    let starts = collect_fn_starts(img);
    if starts.is_empty() { bail!("no executable sections / no function boundaries found"); }
    eprintln!("[*] approximated {} function starts; building call edges…", starts.len());
    let edges = collect_edges(img, &starts)?;
    eprintln!("[*] {} deduped direct-call edges", edges.len());
    let graph = Graph { starts, rev_edges: edges };

    let mut report = String::new();
    for (label, pat) in ANCHORS {
        let vas = string_vas(img, pat);
        report.push_str(&format!("\n== anchor {label:?} (\"{}\") ==\n", String::from_utf8_lossy(pat)));
        if vas.is_empty() {
            report.push_str("  string not found\n");
            continue;
        }
        for sva in &vas {
            report.push_str(&format!("  string VA {sva:#x}\n"));
            for site in find_rip_refs(img, *sva) {
                let Some(f) = graph.fn_idx(site) else { continue };
                report.push_str(&format!("  referenced at {site:#x} (fn {:#x})\n", graph.starts[f as usize]));
                let (parents, depth) = reverse_bfs(&graph, f);
                // representative chains: deepest few reached nodes with no further callers
                let mut leaves: Vec<u32> = (0..graph.starts.len() as u32)
                    .filter(|&i| depth[i as usize] != u32::MAX && graph.caller_band(i).is_empty())
                    .collect();
                leaves.sort_by_key(|&i| std::cmp::Reverse(depth[i as usize]));
                for leaf in leaves.iter().take(4) {
                    let ch = chain_to(&graph, &parents, &depth, *leaf);
                    report.push_str(&format!(
                        "    chain (depth {}): {}\n",
                        ch.len() - 1,
                        ch.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>().join(" <- ")
                    ));
                }
            }
        }
    }
    Ok(report)
}

impl Graph {
    /// number of distinct callers of fn index i (0 = leaf in the reverse graph)
    fn callers_of_leaf(&self, i: u32, edges: &[(u32, u32)]) -> usize {
        let lo = edges.partition_point(|e| e.0 < i);
        let mut n = 0usize;
        for e in &edges[lo..] {
            if e.0 != i { break; }
            n += 1;
        }
        n
    }
}
