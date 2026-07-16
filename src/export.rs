use anyhow::{bail, Context, Result};
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use pbkdf2::pbkdf2_hmac;
use rusqlite::{Connection, OpenFlags};
use rusqlite::types::ValueRef;
use serde_json::{json, Map, Value};
use sha1::Sha1;
use sha2::Sha512;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::sqlcipher::MatchKind;

// ── SQLCipher 4 constants ───────────────────────────────────────────────────

const PAGE_SIZE: usize = 4096;
const SALT_LEN: usize = 16;
const SQLCIPHER4_ITERATIONS: u32 = 256_000;
const SQLCIPHER3_ITERATIONS: u32 = 64_000;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

// ── Database discovery ──────────────────────────────────────────────────────

/// Walk `db_storage/` recursively and return every `*.db` file found.
pub fn discover_databases(message_db: &Path) -> Result<Vec<PathBuf>> {
    let db_storage = message_db
        .parent()
        .and_then(|p| p.parent())
        .with_context(|| {
            format!(
                "cannot locate db_storage directory from {}",
                message_db.display()
            )
        })?;

    let mut databases = Vec::new();
    collect_dbs(db_storage, &mut databases)?;
    databases.sort();
    Ok(databases)
}

fn collect_dbs(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_dbs(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("db") {
            out.push(path);
        }
    }
    Ok(())
}

// ── Key derivation ──────────────────────────────────────────────────────────

/// Return the AES‑256 key that should be used for page decryption.
fn derive_aes_key(candidate: &[u8; 32], salt: &[u8], kind: MatchKind) -> [u8; 32] {
    match kind {
        // Derived candidate ➜ already the encryption key.
        MatchKind::SqlCipher4Derived | MatchKind::SqlCipherHeaderDerived => *candidate,
        // Raw candidate ➜ needs PBKDF2‑HMAC‑SHA512 (64 000 iterations for v3, 256 000 for v4).
        MatchKind::SqlCipher4Raw | MatchKind::SqlCipherHeaderRaw => {
            let mut key = [0u8; 32];
            pbkdf2_hmac::<Sha512>(candidate, salt, SQLCIPHER4_ITERATIONS, &mut key);
            key
        }
        MatchKind::SqlCipher3Derived => *candidate,
        MatchKind::SqlCipher3Raw => {
            let mut key = [0u8; 32];
            pbkdf2_hmac::<Sha1>(candidate, salt, SQLCIPHER3_ITERATIONS, &mut key);
            key
        }
    }
}

// ── Page‑level decryption ───────────────────────────────────────────────────

/// Build the 16‑byte IV for SQLCipher page decryption.
/// SQLCipher stores the page number as a 4‑byte **little‑endian** integer
/// followed by 12 zero bytes (the host byte order on x86 / ARM).
fn make_iv(page_number: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&page_number.to_le_bytes());
    iv
}

/// Decrypt a raw ciphertext buffer in AES‑256‑CBC.  Returns the plaintext.
fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let mut cipher = Aes256CbcDec::new(key.into(), iv.into());
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        let mut block = aes::Block::clone_from_slice(chunk);
        cipher.decrypt_block_mut(&mut block);
        plaintext.extend_from_slice(&block);
    }
    plaintext
}

/// One complete, correct page‑layout description discovered from page 1.
struct PageLayout {
    /// How many bytes of ciphertext follow the salt on page 1.
    ct_len_1: usize,
    /// How many bytes of ciphertext are there on pages ≥ 2.
    ct_len_n: usize,
    /// Total decrypted size for each page (the SQLite page size).
    sqlite_page_size: usize,
}

/// Attempt to decrypt page 1 of a SQLCipher database and discover the
/// correct page layout.  Returns `Some(layout)` when the decrypted content
/// starts with the SQLite magic header.
fn probe_page_layout(page1: &[u8; PAGE_SIZE], key: &[u8; 32]) -> Option<PageLayout> {
    // The ciphertext for page 1 always starts right after the salt.
    for &ct_len_1 in &[4016usize /* v4 with 64‑B HMAC */] {
        let ct_end = SALT_LEN + ct_len_1;
        if ct_end > PAGE_SIZE {
            continue;
        }

        let ciphertext = &page1[SALT_LEN..ct_end];
        let iv = make_iv(1);
        let plain = aes_cbc_decrypt(key, &iv, ciphertext);

        if plain.len() >= 16 && &plain[..16] == b"SQLite format 3\x00" {
            // Read the SQLite page size (big‑endian u16 at byte 16).
            let sqlite_page_size =
                u16::from_be_bytes([plain[16], plain[17]]) as usize;

            // For pages ≥ 2 the ciphertext starts at offset 0 (no salt).
            let ct_len_n = sqlite_page_size.min(PAGE_SIZE);

            return Some(PageLayout {
                ct_len_1,
                ct_len_n,
                sqlite_page_size,
            });
        }
    }
    None
}

/// Decrypt a complete SQLCipher database into `out_path`.
fn decrypt_to_plain(
    in_path: &Path,
    out_path: &Path,
    key: &[u8; 32],
) -> Result<()> {
    let mut input = File::open(in_path)
        .with_context(|| format!("cannot open {}", in_path.display()))?;

    let file_len = input.metadata()?.len() as usize;
    if file_len < PAGE_SIZE {
        bail!("{} is too small to be a SQLCipher database", in_path.display());
    }

    let mut page1 = [0u8; PAGE_SIZE];
    input.read_exact(&mut page1)?;

    let layout = probe_page_layout(&page1, key)
        .context("page 1 decryption failed — key is wrong or database format is unsupported")?;

    let mut output = File::create(out_path)
        .with_context(|| format!("cannot create {}", out_path.display()))?;

    // ── Decrypt page 1 ───────────────────────────────────────────────
    let ciphertext = &page1[SALT_LEN..SALT_LEN + layout.ct_len_1];
    let plain1 = aes_cbc_decrypt(key, &make_iv(1), ciphertext);

    // Write the decrypted SQLite page, padded to sqlite_page_size.
    if plain1.len() < layout.sqlite_page_size {
        output.write_all(&plain1)?;
        let pad = vec![0u8; layout.sqlite_page_size - plain1.len()];
        output.write_all(&pad)?;
    } else {
        output.write_all(&plain1[..layout.sqlite_page_size])?;
    }

    // ── Decrypt remaining pages ──────────────────────────────────────
    let mut page_buf = vec![0u8; PAGE_SIZE];
    for page_no in 2u32.. {
        match input.read_exact(&mut page_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let ct_len = layout.ct_len_n.min(page_buf.len());
        let ciphertext = &page_buf[..ct_len];
        let plain = aes_cbc_decrypt(key, &make_iv(page_no), ciphertext);

        if plain.len() < layout.sqlite_page_size {
            output.write_all(&plain)?;
            let pad = vec![0u8; layout.sqlite_page_size - plain.len()];
            output.write_all(&pad)?;
        } else {
            output.write_all(&plain[..layout.sqlite_page_size])?;
        }

        page_buf.zeroize();
    }

    Ok(())
}

// ── Table export ─────────────────────────────────────────────────────────────

/// List user tables (exclude SQLite / WCDB internal tables).
fn list_tables(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT name FROM sqlite_master \
         WHERE type = 'table'  \
           AND name NOT LIKE 'sqlite_%' \
           AND name NOT LIKE 'webview_%' \
           AND name NOT LIKE 'fts_%' \
           AND tbl_name NOT LIKE 'FTS%' \
           AND tbl_name NOT LIKE 'sqlite_%' \
         ORDER BY name",
    )?;
    let tables: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .filter_map(Result::ok)
        .collect();
    Ok(tables)
}

/// Export every user table in the database into a map keyed by table name.
fn export_database(conn: &Connection) -> Result<BTreeMap<String, Vec<Value>>> {
    let tables = list_tables(conn)?;
    let mut data = BTreeMap::new();
    for table in &tables {
        match export_table(conn, table) {
            Ok(rows) => {
                data.insert(table.clone(), rows);
            }
            Err(err) => {
                eprintln!("  warning: cannot read table \"{table}\": {err}");
            }
        }
    }
    Ok(data)
}

fn export_table(conn: &Connection, table: &str) -> Result<Vec<Value>> {
    let mut stmt = conn.prepare(&format!("SELECT * FROM \"{table}\""))?;
    let column_count = stmt.column_count();
    let column_names: Vec<String> = (0..column_count)
        .map(|i| stmt.column_name(i).unwrap_or("?").to_string())
        .collect();

    let mut rows_out = Vec::new();
    let mut cursor = stmt.query([])?;
    while let Some(row) = cursor.next()? {
        let mut record = Map::new();
        for (i, name) in column_names.iter().enumerate() {
            record.insert(name.clone(), sql_value_to_json(row.get_ref(i)?, name));
        }
        rows_out.push(Value::Object(record));
    }
    Ok(rows_out)
}

// ── Value conversion ─────────────────────────────────────────────────────────

fn sql_value_to_json(val: ValueRef, column: &str) -> Value {
    match val {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(n) => {
            if let Some(iso) = try_timestamp(n, column) {
                return json!({ "raw": n, "iso": iso });
            }
            Value::from(n)
        }
        ValueRef::Real(f) => Value::from(f),
        ValueRef::Text(bytes) => Value::from(String::from_utf8_lossy(bytes).into_owned()),
        ValueRef::Blob(bytes) => {
            if bytes.is_empty() {
                return Value::Null;
            }
            if bytes.len() <= 256 {
                Value::from(hex::encode(bytes))
            } else {
                Value::from(format!("<blob {} bytes>", bytes.len()))
            }
        }
    }
}

/// Heuristically detect a WeChat timestamp column and convert to ISO‑8601.
fn try_timestamp(n: i64, column: &str) -> Option<String> {
    let lower = column.to_ascii_lowercase();

    // WeChat uses Unix‑seconds for msgCreateTime / msgSvrId‑related fields,
    // and Unix‑milliseconds for createTime and most other time columns.
    let seconds_col = lower.contains("msgt")
        || lower == "createtime"
        || lower.contains("msgcreatetime")
        || lower.contains("_createtime");

    let value = if seconds_col && n < 9_999_999_999 {
        n as i64 // already seconds — keep as-is
    } else if n > 9_999_999_999 {
        n // milliseconds → convert
    } else {
        return None; // too small to be a real timestamp
    };

    let secs = if value > 9_999_999_999 {
        value / 1000
    } else {
        value
    };

    // 2000‑01‑01 … 2100‑01‑01
    if !(946_684_800..=4_102_444_800).contains(&secs) {
        return None;
    }
    chrono::DateTime::from_timestamp(secs, 0).map(|dt| dt.to_rfc3339())
}

// ── Main export entry‑point ──────────────────────────────────────────────────

/// Export every discovered database into `output_dir`.
/// Each database file produces a `<stem>.json` containing all its tables.
pub fn export_all(
    databases: &[PathBuf],
    candidate: &[u8; 32],
    kind: MatchKind,
    output_dir: &Path,
) -> Result<()> {
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("cannot create output directory {}", output_dir.display()))?;

    let mut summary = Vec::new();
    let mut used_names = HashSet::new();
    let temp_dir = tempfile::tempdir()?;

    for db_path in databases {
        let stem = db_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("database");

        let mut output_name = format!("{stem}.json");
        let mut counter = 1;
        while !used_names.insert(output_name.clone()) {
            output_name = format!("{stem}_{counter}.json");
            counter += 1;
        }
        let output_file = output_dir.join(&output_name);

        // ── Read salt from page 1 to derive the AES key ──────────────
        let mut raw_file = File::open(db_path)
            .with_context(|| format!("cannot open {}", db_path.display()))?;
        let mut salt = [0u8; SALT_LEN];
        raw_file.read_exact(&mut salt)
            .with_context(|| format!("cannot read salt from {}", db_path.display()))?;
        drop(raw_file);

        let mut aes_key = derive_aes_key(candidate, &salt, kind);

        // ── Decrypt to a temporary plain‑SQLite file ────────────────
        let plain_path = temp_dir.path().join(format!("{stem}.plain.db"));
        if let Err(err) = decrypt_to_plain(db_path, &plain_path, &aes_key) {
            eprintln!("  skip {} — {err}", db_path.display());
            aes_key.zeroize();
            continue;
        }
        aes_key.zeroize();

        // ── Open plain SQLite and export ────────────────────────────
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = match Connection::open_with_flags(&plain_path, flags) {
            Ok(c) => c,
            Err(err) => {
                eprintln!("  skip {} — cannot open: {err}", db_path.display());
                continue;
            }
        };

        let data = match export_database(&conn) {
            Ok(data) => data,
            Err(err) => {
                eprintln!("  skip {} — {err}", db_path.display());
                continue;
            }
        };

        let total_rows: usize = data.values().map(Vec::len).sum();
        let table_summary: Vec<Value> = data
            .iter()
            .map(|(name, rows)| json!({"name": name, "rows": rows.len()}))
            .collect();
        let json_text = serde_json::to_string_pretty(&data)?;
        std::fs::write(&output_file, json_text)
            .with_context(|| format!("cannot write {}", output_file.display()))?;

        println!(
            "  {} -> {} ({} tables, {} rows)",
            db_path.file_name().unwrap_or_default().to_string_lossy(),
            output_file.display(),
            table_summary.len(),
            total_rows,
        );
        summary.push(json!({
            "database": db_path.display().to_string(),
            "output": output_file.display().to_string(),
            "tables": table_summary,
            "total_rows": total_rows,
        }));

        // Drop the connection so the OS can delete the temp file.
        drop(conn);
    }

    // temp_dir is dropped here, automatically cleaning up plain‑SQLite files.

    let summary_path = output_dir.join("_summary.json");
    let summary_doc = json!({
        "exported_at": chrono::Local::now().to_rfc3339(),
        "databases": summary,
    });
    std::fs::write(&summary_path, serde_json::to_string_pretty(&summary_doc)?)?;
    println!("  summary -> {}", summary_path.display());
    Ok(())
}
