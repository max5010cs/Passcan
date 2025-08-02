use std::env;
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::time::{Instant, Duration};

use walkdir::{DirEntry, WalkDir};
use regex::Regex;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use prettytable::{Table, row};
use rayon::prelude::*;
use notify::{RecommendedWatcher, RecursiveMode, Watcher, EventKind};

const BANNER: &str = r#"
 ____                               
|  _ \ __ _ ___ ___  ___ __ _ _ __  
| |_) / _` / __/ __|/ __/ _` | '_ \ 
|  __/ (_| \__ \__ \ (_| (_| | | | |
|_|   \__,_|___/___/\___\__,_|_| |_|
Passcan - Scan your codebase for secrets before pushing!
"#;

const GITHUB_LINK: &str = "https://github.com/max5010cs/passcan";

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
    if path.is_dir() {
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            return IGNORED_DIRS.iter().any(|d| name.eq_ignore_ascii_case(d));
        }
    }
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

fn is_code_file(file_path: &str) -> bool {
    let code_extensions = [
        ".env", ".py", ".js", ".ts", ".rs", ".go", ".sh", ".java", ".yml", ".yaml", ".toml", ".md",
    ];
    code_extensions.iter().any(|ext| file_path.ends_with(ext))
}

fn is_binary_file(path: &Path) -> bool {
    if let Ok(data) = std::fs::read(path) {
        data.iter().take(8000).any(|&b| b == 0)
    } else {
        false
    }
}

fn contains_secret_stream<R: BufRead>(reader: R) -> Vec<&'static str> {
    let patterns: Vec<(&str, Regex)> = vec![
        ("AWS Access Key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
        ("OpenAI Key", Regex::new(r"sk-[a-zA-Z0-9]{48}").unwrap()),
        ("Slack Token", Regex::new(r"xox[baprs]-[a-zA-Z0-9-]{10,48}").unwrap()),
        ("Generic Token", Regex::new(r"[a-zA-Z0-9_-]{32,}").unwrap()),
        ("Password", Regex::new(r#"(?i)password\s*=\s*["']?.+?["']?"#).unwrap()),
    ];
    let mut found = vec![];
    for line in reader.lines().flatten() {
        for (name, regex) in &patterns {
            if regex.is_match(&line) && !found.contains(name) {
                found.push(*name);
            }
        }
    }
    found
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
    match File::open(file_path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            let matches = contains_secret_stream(reader);
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

fn print_table(results: &[ScanResult]) {
    let mut table = Table::new();
    table.add_row(row![
        "File Path".bold(),
        "Status".bold(),
        "Secrets Found".bold()
    ]);
    for r in results {
        let secrets = if r.secrets.is_empty() {
            "-".to_string()
        } else {
            r.secrets.join(", ")
        };
        table.add_row(row![
            r.path.cyan(),
            r.status.clone(),
            secrets.yellow()
        ]);
    }
    table.printstd();
}

fn run_scan(path: &str, verbose: bool) {
    println!("{}", BANNER.bright_blue().bold());
    println!(
        "{} {}\n",
        "Welcome to Passcan!".bold(),
        "Scan your codebase for secrets before pushing.".yellow()
    );
    println!(
        "{} {}\n",
        "🔍 Scanning directory:".blue().bold(),
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

    let results: Vec<ScanResult> = files
        .par_iter()
        .map(|file_path| {
            pb.set_message(format!("Scanning: {}", file_path.display()));
            let result = scan_file(file_path);
            if verbose {
                println!("{} {}", "📄".cyan(), file_path.display());
            }
            pb.inc(1);
            result
        })
        .collect();
    pb.finish_and_clear();

    print_table(&results);

    let files_with_secrets = results.iter().filter(|r| !r.secrets.is_empty()).count();
    let total_secrets = results.iter().map(|r| r.secrets.len()).sum::<usize>();
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
    println!(
        "\n{} {}\n{}",
        "🔗".blue(),
        GITHUB_LINK.underline().bright_blue(),
        "✅ Scan completed. Stay safe!".green().bold()
    );
}

fn watch_mode(path: &str, verbose: bool) {
    println!("{}", BANNER.bright_blue().bold());
    println!(
        "{} {}\n",
        "PASSCAN Watch Mode".bold(),
        "Watching for file changes...".yellow()
    );
    println!(
        "{} {}\n",
        "🔍 Watching directory:".blue().bold(),
        path.bold()
    );

    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(
        move |res| {
            tx.send(res).unwrap();
        },
        notify::Config::default(),
    ).unwrap();

    watcher.watch(Path::new(path), RecursiveMode::Recursive).unwrap();

    loop {
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(Ok(event)) => {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)) {
                    println!("{}", "🔄 Change detected, rescanning...".yellow());
                    run_scan(path, verbose);
                }
            }
            Ok(Err(e)) => {
                println!("Watch error: {:?}", e);
                break;
            }
            Err(_) => {} // timeout, continue
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut path = ".";
    let mut watch = false;
    let mut verbose = false;

    for arg in &args[1..] {
        match arg.as_str() {
            "--watch" => watch = true,
            "--verbose" => verbose = true,
            _ => path = arg,
        }
    }

    if watch {
        watch_mode(path, verbose);
    } else {
        run_scan(path, verbose);
    }
}

// Add to Cargo.toml dependencies:
// rayon = "1.8"
// notify = "6"
// prettytable = "0.12"
// indicatif = "0.17"
// colored = "2"
// walkdir = "2"
// regex = "1"
// tabwriter = "1"
