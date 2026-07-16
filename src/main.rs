#[cfg(not(windows))]
compile_error!("wechat-vault-poc currently supports Windows only");

mod export;
mod process;
mod sqlcipher;

use anyhow::{bail, Context, Result};
use clap::Parser;
use process::{find_main_weixin_pid, ProcessReader};
use rayon::prelude::*;
use sqlcipher::{verify_derived_candidate, verify_raw_candidate, MatchKind};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const PUBLIC_KEY_MARKER: &[u8] = b"-----BEGIN PUBLIC KEY-----";
const PRIVATE_KEY_MARKERS: [&[u8]; 3] = [
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
];

#[derive(Parser, Debug)]
#[command(version, about = "Read-only WeChat 4.x database-key feasibility PoC")]
struct Args {
    /// Inspect this process instead of auto-detecting the main Weixin.exe.
    #[arg(long)]
    pid: Option<u32>,

    /// Validate against this encrypted database instead of auto-detecting message_0.db.
    #[arg(long)]
    db: Option<PathBuf>,

    /// Bytes to inspect on each side of a public-key reference.
    #[arg(long, default_value_t = 4096)]
    context_radius: usize,

    /// Upper bound for expensive SQLCipher candidate checks.
    #[arg(long, default_value_t = 512)]
    max_candidates: usize,

    /// Export all decrypted databases to this directory as JSON.
    #[arg(long)]
    export: Option<PathBuf>,
}

#[derive(Default)]
struct CandidateSet {
    prioritized: Vec<[u8; 32]>,
    fallback: Vec<[u8; 32]>,
    seen: HashSet<[u8; 32]>,
}

impl CandidateSet {
    fn add_prioritized(&mut self, bytes: &[u8]) {
        self.add(bytes, true);
    }

    fn add_fallback(&mut self, bytes: &[u8]) {
        self.add(bytes, false);
    }

    fn add(&mut self, bytes: &[u8], prioritized: bool) {
        if bytes.len() < 32 {
            return;
        }
        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&bytes[..32]);
        if !looks_like_key(&candidate) || !self.seen.insert(candidate) {
            candidate.zeroize();
            return;
        }
        if prioritized {
            self.prioritized.push(candidate);
        } else {
            self.fallback.push(candidate);
        }
    }

    fn into_bounded(mut self, limit: usize) -> Vec<[u8; 32]> {
        self.prioritized.append(&mut self.fallback);
        self.prioritized.truncate(limit);
        self.prioritized
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    if !(256..=65_536).contains(&args.context_radius) {
        bail!("--context-radius must be between 256 and 65536");
    }
    if !(1..=8192).contains(&args.max_candidates) {
        bail!("--max-candidates must be between 1 and 8192");
    }
    let pid = args.pid.map(Ok).unwrap_or_else(find_main_weixin_pid)?;
    let db_path = args.db.map(Ok).unwrap_or_else(find_message_database)?;
    let page = read_database_page(&db_path)?;

    println!("WechatVault feasibility PoC");
    println!("  process: Weixin.exe (pid {pid})");
    println!("  database: {}", db_path.display());
    println!("  access: read-only; secrets are never printed or saved");

    let reader = ProcessReader::open(pid)?;
    let scanned_bytes: u64 = reader
        .regions()
        .iter()
        .map(|region| region.size as u64)
        .sum();
    println!(
        "  readable memory: {} regions / {:.1} MiB",
        reader.regions().len(),
        scanned_bytes as f64 / 1024.0 / 1024.0
    );

    let mut marker_needles = vec![PUBLIC_KEY_MARKER.to_vec()];
    marker_needles.extend(PRIVATE_KEY_MARKERS.iter().map(|marker| marker.to_vec()));
    let marker_matches = reader.scan(&marker_needles, 256);
    let public_markers = &marker_matches[0];
    let private_marker_count: usize = marker_matches[1..].iter().map(Vec::len).sum();
    println!("  public-key markers: {}", public_markers.len());
    println!("  private-key markers: {private_marker_count}");
    if public_markers.is_empty() {
        bail!("no public-key memory anchor was found");
    }

    let mut anchor_addresses = public_markers.clone();
    for matches in &marker_matches[1..] {
        anchor_addresses.extend(matches.iter().copied());
    }

    let canonical_db_path = db_path.canonicalize().unwrap_or_else(|_| db_path.clone());
    let db_path_text = canonical_db_path.to_string_lossy();
    let db_needles = vec![
        page[..16].to_vec(),
        b"message_0.db".to_vec(),
        utf16_bytes("message_0.db"),
        db_path_text.as_bytes().to_vec(),
        utf16_bytes(&db_path_text),
    ];
    let db_anchor_matches = reader.scan(&db_needles, 512);
    let salt_matches = db_anchor_matches[0].len();
    let path_matches: usize = db_anchor_matches[1..].iter().map(Vec::len).sum();
    println!("  SQLCipher salt anchors: {salt_matches}");
    println!("  database-path anchors: {path_matches}");
    for matches in &db_anchor_matches {
        anchor_addresses.extend(matches.iter().copied());
    }
    anchor_addresses.sort_unstable();
    anchor_addresses.dedup();

    let pointer_needles: Vec<Vec<u8>> = anchor_addresses
        .iter()
        .map(|address| address.to_le_bytes().to_vec())
        .collect();
    let reference_matches = reader.scan(&pointer_needles, 4096);
    let references: Vec<usize> = reference_matches.into_iter().flatten().collect();
    println!("  x64 anchor references: {}", references.len());
    if references.is_empty() {
        bail!("public-key anchors were found, but no 64-bit references point to them");
    }

    let mut candidate_set = CandidateSet::default();
    let mut derived_candidates = HashSet::new();
    for reference in references {
        collect_candidates(&reader, reference, args.context_radius, &mut candidate_set);
        collect_dense_candidates(&reader, reference, 512, &mut derived_candidates);
    }
    for matches in &db_anchor_matches {
        for &anchor in matches {
            collect_dense_candidates(&reader, anchor, 1024, &mut derived_candidates);
        }
    }
    let prioritized_count = candidate_set.prioritized.len();
    let fallback_count = candidate_set.fallback.len();
    let mut candidates = candidate_set.into_bounded(args.max_candidates);
    println!(
        "  raw candidates: {} prioritized + {} fallback; validating {}",
        prioritized_count,
        fallback_count,
        candidates.len()
    );
    let mut derived_candidates: Vec<[u8; 32]> = derived_candidates.into_iter().collect();
    println!("  derived-key candidates: {}", derived_candidates.len());

    let matched = derived_candidates
        .par_iter()
        .find_map_any(|candidate| verify_derived_candidate(candidate, &page))
        .or_else(|| {
            candidates
                .par_iter()
                .find_map_any(|candidate| verify_raw_candidate(candidate, &page))
        });

    for candidate in &mut candidates {
        candidate.zeroize();
    }
    for candidate in &mut derived_candidates {
        candidate.zeroize();
    }

    match matched {
        Some((kind, mut key_bytes)) => {
            println!("RESULT: MATCH ({})", match_label(kind));

            if let Some(export_dir) = &args.export {
                let databases = export::discover_databases(&db_path)?;
                let db_storage = db_path
                    .parent()
                    .and_then(|p| p.parent())
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "?".to_string());
                println!();
                println!("EXPORT");
                println!("  db_storage: {db_storage}");
                println!("  databases found: {}", databases.len());
                println!("  output: {}", export_dir.display());

                export::export_all(&databases, &key_bytes, kind, export_dir)?;
                println!();
                println!("RESULT: EXPORT COMPLETE -> {}", export_dir.display());
            } else {
                println!("The exact database key was found and authenticated; no key was disclosed.");
            }

            key_bytes.zeroize();
            Ok(())
        }
        None => {
            println!("RESULT: NO MATCH (anchor-based)");
            println!("  attempting broad memory scan as fallback…");

            let max_broad = args.max_candidates.saturating_mul(4).min(8192);
            let broad_candidates =
                reader.broad_scan(looks_like_key, max_broad);
            println!("  broad scan candidates: {}", broad_candidates.len());

            if broad_candidates.is_empty() {
                println!("RESULT: NO MATCH");
                println!("No key-like sequences were found anywhere in readable memory.");
                std::process::exit(2);
            }

            let broad_matched = broad_candidates
                .par_iter()
                .find_map_any(|candidate| {
                    verify_raw_candidate(candidate, &page)
                        .or_else(|| verify_derived_candidate(candidate, &page))
                });

            // Zeroize broad candidates regardless of outcome.
            for mut candidate in broad_candidates {
                candidate.zeroize();
            }

            match broad_matched {
                Some((kind, mut key_bytes)) => {
                    println!("RESULT: MATCH ({}) via broad scan", match_label(kind));

                    if let Some(export_dir) = &args.export {
                        let databases = export::discover_databases(&db_path)?;
                        let db_storage = db_path
                            .parent()
                            .and_then(|p| p.parent())
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "?".to_string());
                        println!();
                        println!("EXPORT");
                        println!("  db_storage: {db_storage}");
                        println!("  databases found: {}", databases.len());
                        println!("  output: {}", export_dir.display());

                        export::export_all(&databases, &key_bytes, kind, export_dir)?;
                        println!();
                        println!("RESULT: EXPORT COMPLETE -> {}", export_dir.display());
                    } else {
                        println!("The exact database key was found and authenticated; no key was disclosed.");
                    }

                    key_bytes.zeroize();
                    Ok(())
                }
                None => {
                    println!("RESULT: NO MATCH");
                    println!(
                        "Neither the anchor-based approach nor the broad memory scan found the database key."
                    );
                    std::process::exit(2);
                }
            }
        }
    }
}

fn collect_dense_candidates(
    reader: &ProcessReader,
    anchor: usize,
    radius: usize,
    candidates: &mut HashSet<[u8; 32]>,
) {
    let start = anchor.saturating_sub(radius);
    let size = radius.saturating_mul(2);
    let Some(context) = reader.read(start, size) else {
        return;
    };

    for offset in (0..context.len().saturating_sub(32)).step_by(8) {
        let mut inline = [0u8; 32];
        inline.copy_from_slice(&context[offset..offset + 32]);
        if looks_like_key(&inline) {
            candidates.insert(inline);
        } else {
            inline.zeroize();
        }

        let pointer = read_u64(&context, offset).unwrap_or(0) as usize;
        if pointer != 0 && reader.contains_range(pointer, 32) {
            if let Some(target) = reader.read(pointer, 32) {
                let mut pointed = [0u8; 32];
                pointed.copy_from_slice(&target);
                if looks_like_key(&pointed) {
                    candidates.insert(pointed);
                } else {
                    pointed.zeroize();
                }
            }
        }
    }
}

fn collect_candidates(
    reader: &ProcessReader,
    reference: usize,
    radius: usize,
    candidates: &mut CandidateSet,
) {
    let start = reference.saturating_sub(radius);
    let size = radius.saturating_mul(2);
    let Some(context) = reader.read(start, size) else {
        return;
    };

    // Look for the common x64 layouts used by byte buffers and std::string:
    // pointer+length, pointer+padding+length, and inline data+size+capacity.
    for offset in (0..context.len().saturating_sub(32)).step_by(8) {
        let pointer = read_u64(&context, offset).unwrap_or(0) as usize;
        let len_at_8 = read_u64(&context, offset + 8);
        let len32_at_8 = read_u32(&context, offset + 8).map(u64::from);
        let len_at_16 = read_u64(&context, offset + 16);
        let len32_at_16 = read_u32(&context, offset + 16).map(u64::from);
        let tagged_length = [len_at_8, len32_at_8, len_at_16, len32_at_16]
            .into_iter()
            .flatten()
            .any(|length| length == 32 || length == 64 || length == 66);

        if pointer != 0 && reader.contains_range(pointer, 32) {
            if let Some(target) = reader.read(pointer, 66) {
                if tagged_length {
                    add_target_candidates(candidates, &target, true);
                } else {
                    add_target_candidates(candidates, &target, false);
                }
            } else if let Some(target) = reader.read(pointer, 32) {
                if tagged_length {
                    candidates.add_prioritized(&target);
                } else {
                    candidates.add_fallback(&target);
                }
            }
        }

        if len_at_16 == Some(32) || len32_at_16 == Some(32) {
            candidates.add_prioritized(&context[offset..]);
        }
    }
}

fn add_target_candidates(candidates: &mut CandidateSet, target: &[u8], prioritized: bool) {
    let add = |candidates: &mut CandidateSet, value: &[u8]| {
        if prioritized {
            candidates.add_prioritized(value);
        } else {
            candidates.add_fallback(value);
        }
    };

    add(candidates, target);
    if target.len() >= 64 {
        if let Ok(text) = std::str::from_utf8(&target[..64]) {
            if text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                if let Ok(decoded) = hex::decode(text) {
                    add(candidates, &decoded);
                }
            }
        }
    }
}

fn looks_like_key(candidate: &[u8; 32]) -> bool {
    let distinct: HashSet<u8> = candidate.iter().copied().collect();
    distinct.len() >= 12
        && !candidate.iter().all(|byte| byte.is_ascii_whitespace())
        && !candidate.starts_with(b"-----BEGIN")
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let value: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(value))
}

fn utf16_bytes(value: &str) -> Vec<u8> {
    value.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn read_database_page(path: &Path) -> Result<Vec<u8>> {
    let mut file =
        File::open(path).with_context(|| format!("cannot open database {}", path.display()))?;
    let mut page = vec![0u8; 4096];
    file.read_exact(&mut page)
        .with_context(|| format!("cannot read database first page from {}", path.display()))?;
    if page.starts_with(b"SQLite format 3\0") {
        bail!(
            "{} is already an unencrypted SQLite database",
            path.display()
        );
    }
    Ok(page)
}

fn find_message_database() -> Result<PathBuf> {
    let app_data = std::env::var_os("APPDATA").context("APPDATA is not set")?;
    let config_dir = PathBuf::from(app_data).join("Tencent/xwechat/config");
    let mut roots = Vec::new();

    for entry in std::fs::read_dir(&config_dir)
        .with_context(|| format!("cannot read {}", config_dir.display()))?
    {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("ini") {
            continue;
        }
        let bytes = std::fs::read(entry.path())?;
        if bytes.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes)
            .trim_matches(char::from(0))
            .trim()
            .to_string();
        let root = PathBuf::from(text);
        if root.is_dir() {
            roots.push(root.join("xwechat_files"));
        }
    }

    let mut databases = Vec::new();
    for root in roots {
        if !root.is_dir() {
            continue;
        }
        for account in std::fs::read_dir(root)? {
            let account = account?;
            let candidate = account.path().join("db_storage/message/message_0.db");
            if candidate.is_file() {
                let modified = candidate.metadata()?.modified().ok();
                databases.push((modified, candidate));
            }
        }
    }

    databases.sort_by_key(|(modified, _)| *modified);
    databases
        .pop()
        .map(|(_, path)| path)
        .context("could not auto-detect xwechat_files/.../message_0.db; pass --db")
}

fn match_label(kind: MatchKind) -> &'static str {
    match kind {
        MatchKind::SqlCipher4Raw => "SQLCipher 4 raw key",
        MatchKind::SqlCipher4Derived => "SQLCipher 4 derived key",
        MatchKind::SqlCipher3Raw => "SQLCipher 3 raw key",
        MatchKind::SqlCipher3Derived => "SQLCipher 3 derived key",
        MatchKind::SqlCipherHeaderRaw => "SQLCipher raw key (SQLite header verified)",
        MatchKind::SqlCipherHeaderDerived => "SQLCipher derived key (SQLite header verified)",
    }
}
