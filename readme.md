# 🛡️ passcan

> A fast CLI tool built with Rust to detect secrets in your code before pushing to production.

---

## ✨ What is passcan?

`passcan` is a lightweight command-line scanner that helps you **catch hardcoded secrets** like:

- 🔑 API keys (OpenAI, AWS, etc.)
- 🔒 Passwords in `.env` or source files
- 🧵 Tokens (Slack, generic auth tokens)

Use it before every commit or deployment to keep your codebase clean and secure.

---

## ⚙️ How it works

- Scans common code and config files in the directory you provide
- Uses `regex` patterns to match known secret formats
- Shows live progress and a summary of what it finds
- Works super fast — thanks to Rust!

---



### 🧰 Built With
🦀 Rust — fast and memory-safe

📂 walkdir — recursive file traversal

🎨 colored — styled terminal output

🔎 regex — pattern detection

⌚ notify — optional file change watching

#####   💡 Why You Should Use It
Even one leaked key can cost a lot. passcan helps you:

Catch secrets before committing

Protect your production environment

Improve team security hygiene

🙌 Contributing
Pull requests are welcome! If you have ideas or suggestions, feel free to open an issue or PR.



## 📦 Installation

### 🧪 Local Development (for testing or contributing)

```bash
git clone https://github.com/max5010cs/Passcan.git
cd Passcan
cargo install --path .
passcan .
### Run passcan . anwywhere after proper installation

# Scan another folder
passcan /your/project/path

# Watch mode (auto-scan on changes)
passcan --watch .





