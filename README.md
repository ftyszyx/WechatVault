# WechatVault

Windows WeChat 4.x local-data export tool.

## Quick start

Build and run from PowerShell / Git Bash:

```powershell
# Verify key recovery only (read-only, no data exported)
cargo run --release

# Export all local databases to JSON
cargo run --release -- --export ./wechat_export
```

The tool reads the SQLCipher database key from the running `Weixin.exe`
process, decrypts every `*.db` file under `xwechat_files/<account>/db_storage/`,
and exports all tables to plain JSON.

## What gets exported

| Source | Content |
|--------|---------|
| `message/message_0.db`, `message_1.db`, … | All your chat history |
| `contact/contact.db` | All friend / contact information |
| `group/group.db` | Group metadata and member information |
| `session/session.db` | Session list |
| Other `*.db` files under `db_storage/` | Everything else the client stores locally |

Each database becomes a `<stem>.json` file. Timestamps are converted to
human-readable ISO‑8601 where detected.

The output directory also contains `_summary.json` — a manifest listing every
exported database, its tables, and row counts.

## Safety

- The process is opened with **query + read only** permissions.
- The database key is zeroised after use and never written to disk.
- Exported JSON **may contain personal content** — keep it private.
- This project is **not affiliated with Tencent or WeChat**.

## Optional arguments

```powershell
cargo run --release -- --pid 1234                           # specific PID
cargo run --release -- --db "E:\wechat\...\message_0.db"    # specific DB
cargo run --release -- --context-radius 4096 --max-candidates 1024
cargo run --release -- --export ./out                       # export mode
```

## Current PoC (verify-only mode)

Without `--export`, the tool performs a read-only feasibility check:

1. Locate the main Weixin process and the local `message_0.db`.
2. Find PEM public-key markers in readable process memory.
3. Find 64-bit references to those markers.
4. Collect a bounded set of likely 32-byte key buffers near the references.
5. Validate candidates against the encrypted database first-page HMAC.

A success means a memory candidate passed SQLCipher page authentication. A
failure only means this bounded locator did not find the key; it does not prove
that the database is undecryptable.

## License

This project is for research & personal use only.
