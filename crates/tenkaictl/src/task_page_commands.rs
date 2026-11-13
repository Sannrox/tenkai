//! Docs check: every `tenkaictl` invocation in `docs/tasks/` parses.

use std::fs;
use std::path::{Path, PathBuf};

use clap::Parser;

use crate::args::{Cli, Target};
use crate::output::command_name;

#[test]
fn task_page_commands_parse() {
    let dir = task_pages_dir();
    let mut pages = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            (path.extension()? == "md").then_some(path)
        })
        .collect::<Vec<_>>();
    pages.sort();
    assert!(
        !pages.is_empty(),
        "expected markdown task pages under {}",
        dir.display()
    );

    let mut commands = 0;
    for page in &pages {
        let markdown = fs::read_to_string(page)
            .unwrap_or_else(|error| panic!("read {}: {error}", page.display()));
        for (line_no, argv) in extract_tenkaictl_commands(&markdown) {
            commands += 1;
            let cli = Cli::try_parse_from(&argv).unwrap_or_else(|error| {
                panic!(
                    "{}:{line_no}: command does not parse: {}\n{error}",
                    page.display(),
                    argv.join(" ")
                )
            });
            if requests_json_v1(&argv)
                && command_name(&cli.command, cli.target.unwrap_or(Target::Embedded)).is_none()
            {
                panic!(
                    "{}:{line_no}: --output json-v1 is unsupported for: {}",
                    page.display(),
                    argv.join(" ")
                );
            }
        }
    }
    assert!(
        commands > 0,
        "expected at least one tenkaictl command in {}",
        dir.display()
    );
}

fn task_pages_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/tasks")
}

fn extract_tenkaictl_commands(markdown: &str) -> Vec<(usize, Vec<String>)> {
    let mut commands = Vec::new();
    let mut fence: Option<&str> = None;
    let mut pending = String::new();
    let mut pending_line = 0;
    let mut in_shell = false;

    for (idx, raw) in markdown.lines().enumerate() {
        let line_no = idx + 1;
        if let Some(marker) = fence {
            if raw.trim_start().starts_with(marker) {
                if in_shell && !pending.is_empty() {
                    if looks_like_tenkaictl(&pending) {
                        commands.push((pending_line, parse_command_line(&pending, pending_line)));
                    }
                    pending.clear();
                }
                fence = None;
                in_shell = false;
                continue;
            }
            if !in_shell {
                continue;
            }
            let trimmed = raw.trim_end();
            if trimmed.ends_with('\\') {
                if pending.is_empty() {
                    pending_line = line_no;
                }
                pending.push_str(trimmed.trim_end_matches('\\').trim_end());
                pending.push(' ');
                continue;
            }
            pending.push_str(trimmed);
            let complete = std::mem::take(&mut pending);
            let start = if pending_line == 0 {
                line_no
            } else {
                pending_line
            };
            pending_line = 0;
            if looks_like_tenkaictl(&complete) {
                commands.push((start, parse_command_line(&complete, start)));
            }
            continue;
        }
        let opened = raw.trim_start();
        if let Some(rest) = opened.strip_prefix("```") {
            fence = Some("```");
            let lang = rest
                .trim()
                .split(|c: char| c.is_whitespace() || c == ',')
                .next()
                .unwrap_or("");
            in_shell = matches!(lang, "sh" | "bash" | "shell");
        }
    }
    commands
}

fn requests_json_v1(argv: &[String]) -> bool {
    argv.windows(2)
        .any(|pair| pair[0] == "--output" && pair[1] == "json-v1")
        || argv.iter().any(|arg| arg == "--output=json-v1")
}

fn looks_like_tenkaictl(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }
    trimmed == "tenkaictl"
        || trimmed.starts_with("tenkaictl ")
        || trimmed == "./tenkaictl"
        || trimmed.starts_with("./tenkaictl ")
}

fn parse_command_line(line: &str, line_no: usize) -> Vec<String> {
    let trimmed = line.trim();
    if trimmed.contains('|') || trimmed.contains("$(") || trimmed.contains('`') {
        panic!(
            "task page line {line_no} must be a single tenkaictl invocation, not a pipeline: {trimmed}"
        );
    }
    let argv = split_argv(trimmed).unwrap_or_else(|error| {
        panic!("task page line {line_no}: {error}: {trimmed}");
    });
    let mut argv = argv;
    if argv.first().is_some_and(|arg| arg == "./tenkaictl") {
        argv[0] = "tenkaictl".into();
    }
    argv
}

fn split_argv(line: &str) -> Result<Vec<String>, &'static str> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for ch in line.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => current.push(c),
            (None, c) if c == '"' || c == '\'' => quote = Some(c),
            (None, c) if c.is_whitespace() => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            (None, c) => current.push(c),
        }
    }
    if quote.is_some() {
        return Err("unclosed quote");
    }
    if !current.is_empty() {
        args.push(current);
    }
    if args.is_empty() {
        return Err("empty command");
    }
    Ok(args)
}
