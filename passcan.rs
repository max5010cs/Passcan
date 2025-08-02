use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::io::{Write, stdout};

use walkdir::{DirEntry, WalkDir};
use regex::Regex;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use tabwriter::TabWriter;

/// Ignore these files and directories
const IGNORED_FILES: &[&str] = &[
    "package-lock.json", "yarn.lock", "Cargo.lock", ".gitignore", "README.md",
];
const IGNORED_EXTENSIONS: &[&str] = &[
    ".log", ".min.js", ".lock", ".html", ".json"
];
const IGNORED_DIRS: &[&str] = &[
    "node_modules", ".git", ".vscode", "__pycache__", "target", "build", ".idea",
];

fn is_ignored(entry: &DirEntry) -> bool {
    let path = entry.path();
    // Ignore directories
    if path.is_dir() {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            return IGNORED_DIRS.iter().any(|d| name.eq_ignore_ascii_case(d));
        }
    }
    // Ignore files by name
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if IGNORED_FILES.contains(&name) {
            return true;
        }
        for ext in IGNORED_EXTENSIONS {
            if name.ends_with(ext) {
                return true;
            }
        }
    }
    false
}

// Only include files likely authored by devs (exclude .json, .lock, .html, etc.)
fn is_code_file(file_path: &str) -> bool {
    let code_extensions = [
        ".env", ".py", ".js", ".ts", ".rs", ".go", ".sh", ".java", ".yml", ".yaml", ".toml", ".md",
    ];
    code_extensions.iter().any(|ext| file_path.ends_with(ext))
}

/// Try to avoid scanning binary files (simple heuristic)
fn is_binary_file(path: &Path) -> bool {
    if let Ok(data) = fs::read(path) {
        // If there's a null byte, likely binary
        data.iter().take(8000).any(|&b| b == 0)
    } else {
        false
    }
}

fn contains_secret(content: &str) -> Vec<&'static str> {
    let patterns: Vec<(&str, Regex)> = vec![
        ("AWS Access Key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
        ("OpenAI Key", Regex::new(r"sk-[a-zA-Z0-9]{48}").unwrap()),
        ("Slack Token", Regex::new(r"xox[baprs]-[a-zA-Z0-9-]{10,48}").unwrap()),
        ("Generic Token", Regex::new(r"[a-zA-Z0-9_-]{32,}").unwrap()),
        ("Password", Regex::new(r#"(?i)password\s*=\s*["']?.+?["']?"#).unwrap()),
    ];

    patterns
        .iter()
        .filter_map(|(name, regex)| if regex.is_match(content) { Some(*name) } else { None })
        .collect()
}

fn collect_files(root: &str) -> Vec<PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|entry| {
            let path = entry.path();
            !is_ignored(entry)
                && path.is_file()
                && path.to_str().map_or(false, |p| is_code_file(p))
                && !is_binary_file(path)
        })
        .map(|entry| entry.path().to_path_buf())
        .collect()
}

struct ScanResult {
    path: String,
    status: String,
    secrets: Vec<&'static str>,
}

fn scan_file(file_path: &Path) -> ScanResult {
    let path_str = file_path.display().to_string();
    match fs::read_to_string(file_path) {
        Ok(content) => {
            let matches = contains_secret(&content);
            if !matches.is_empty() {
                ScanResult {
                    path: path_str,
                    status: "❗ Alert".red().bold().to_string(),
                    secrets: matches,
                }
            } else {
                ScanResult {
                    path: path_str,
                    status: "✅ Clean".green().to_string(),
                    secrets: vec![],
                }
            }
        }
        Err(_) => ScanResult {
            path: path_str,
            status: "⚠️ Error".yellow().to_string(),
            secrets: vec![],
        },
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = args.get(1).expect("⚠️  Please provide a directory to scan.");

    println!(
        "\n{} Scanning directory: {}\n",
        "🔍".blue().bold(),
        path.bold()
    );

    let start = Instant::now();
    let files = collect_files(path);
    let total_files = files.len();

    let pb = ProgressBar::new(total_files as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} files ({percent}%)"
        )
        .unwrap()
        .progress_chars("#>-"),
    );

    let mut results: Vec<ScanResult> = Vec::new();
    let mut files_with_secrets = 0;
    let mut total_secrets = 0;

    for file_path in &files {
        pb.set_message(format!("Scanning: {}", file_path.display()));
        let result = scan_file(file_path);
        if !result.secrets.is_empty() {
            files_with_secrets += 1;
            total_secrets += result.secrets.len();
        }
        results.push(result);
        pb.inc(1);
    }
    pb.finish_and_clear();

    // Print table
    let mut tw = TabWriter::new(stdout()).padding(2);
    writeln!(
        &mut tw,
        "{}\t{}\t{}",
        "File Path".bold(),
        "Status".bold(),
        "Secrets Found".bold()
    ).unwrap();
    writeln!(
        &mut tw,
        "{}\t{}\t{}",
        "---------------------".blue(),
        "-----------".blue(),
        "---------------------".blue()
    ).unwrap();

    for r in &results {
        let secrets = if r.secrets.is_empty() {
            "-".to_string()
        } else {
            r.secrets.join(", ")
        };
        writeln!(
            &mut tw,
            "{}\t{}\t{}",
            r.path.cyan(),
            r.status,
            secrets.yellow()
        ).unwrap();
    }
    tw.flush().unwrap();

    let duration = start.elapsed();
    println!("\n{}", "📦 Scan Summary".bold().underline().blue());
    println!(
        "{} {}",
        "Total files scanned:".bold(),
        total_files.to_string().cyan()
    );
    println!(
        "{} {}",
        "Files with secrets:".bold(),
        files_with_secrets.to_string().red().bold()
    );
    println!(
        "{} {}",
        "Total secrets found:".bold(),
        total_secrets.to_string().yellow().bold()
    );
    println!(
        "{} {}",
        "Time taken:".bold(),
        format!("{:.2?}", duration).magenta()
    );
    println!("\n{}", "✅ Scan completed.".green().bold());
}

// Add to Cargo.toml dependencies if not present:
// indicatif = "0.17"
// colored = "2"
// walkdir = "2"
// regex = "1"
// tabwriter = "1"
