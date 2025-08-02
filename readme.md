# 🦀 passcan

> A fast, Rust-powered CLI tool to scan your codebase for secrets before deployment.

## ⚡ Overview

`passcan` is a high-performance command-line tool written in **Rust**, designed to detect sensitive information in your files before pushing to production.

It scans for:

- API keys (OpenAI, AWS, etc.)
- Hardcoded passwords and secrets
- Slack webhooks, tokens, and more

Perfect for developers who care about shipping safe code 🚀

## 🔧 Built With

- 🦀 **Rust** for speed and reliability
- 📁 `walkdir` for directory traversal
- 🎨 `colored` for styled output
- 🔍 Regex-powered pattern detection

## 📦 Installation

### 🚀 Install via Cargo (Local Dev)

```bash
git clone https://github.com/yourusername/passcan.git
cd passcan
cargo install --path .


### Manual Build
cargo build --release
./target/release/passcan /path/to/scan

###  Usage
passcan .
