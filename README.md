# Vault-Boy

A local-first password manager for Windows 11. Your passwords live in an encrypted
vault on your own machine. No account, no cloud, no telemetry.

> **Early development, not independently audited.** Don't store real passwords in it yet.

## Features

- Master-password encrypted vault, with a device key bound via Windows DPAPI
- Add, edit, and search entries; dark/light theme follows Windows
- Clipboard auto-clear and exclusion from Windows clipboard history
- Screenshot and screen-recording exclusion
- Locked-down vault folder permissions, atomic writes, tamper-evident unlock backoff
- Hardened Windows build (ASLR, DEP, CFG) with tests that check it

## Built with

Rust, Tauri 2, React 19, Vite, Tailwind.

## Build

Needs Rust (MSVC), Node.js 20+, and WebView2.

```powershell
npm ci
npm run dev                 # dev window
cargo build --release --locked
cargo test --locked
```

Verification scripts: `tools\verify\run-all.ps1`

The Exe file will be in target\release\vaultly.exe



## Limits

Protects your vault if someone gets the file. It can't protect against malware
running as you, keyloggers, or a compromised Windows install.

## License

MIT
