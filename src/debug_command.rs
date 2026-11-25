//! Debug commands on an instance: reads (ADR 0061 §4, #1559) and the writes an elevation unlocks (§5, #1560).
//!
//! An operator sends one command line per `command` control on a debug
//! stream. The runtime splits it into an argv, without a shell, and asks the
//! instance's executor whether it only reads. Each executor names the few
//! commands it treats as read ([`crate::software_executor::SoftwareExecutor::debug_commands`]);
//! every other argv is [`DebugAccess::Write`] and is refused in a `read`
//! session. An elevated session (#1560) also runs the few write commands the
//! executor names ([`crate::software_executor::SoftwareExecutor::debug_write_commands`]);
//! any argv that is neither is refused in every session. A command runs
//! through the executor's own credentials and scoping, never as a shell.

use std::io::Read as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

/// Whether a command only reads the instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugAccess {
    Read,
    Write,
}

impl DebugAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// What one read command printed, capped at [`MAX_OUTPUT`], and its exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugOutput {
    pub output: Vec<u8>,
    pub exit_code: i32,
}

/// The most output one command returns; later bytes are dropped.
pub const MAX_OUTPUT: usize = 1 << 20;
/// The longest one command may run.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// The most arguments, and bytes of one command line, accepted.
pub const MAX_ARGS: usize = 16;
pub const MAX_LINE: usize = 1024;
/// The default and largest `--tail` of a `logs` command.
pub const DEFAULT_TAIL: u32 = 200;
pub const MAX_TAIL: u32 = 5000;

/// Split `line` into an argv the way a POSIX shell splits words, with single
/// and double quotes and backslash escapes, and nothing else: no expansion,
/// no pipes, no redirection. Those characters are plain argument text.
pub fn split_command(line: &str) -> Result<Vec<String>> {
    if line.len() > MAX_LINE {
        bail!("a command line is at most {MAX_LINE} bytes");
    }
    let mut argv = Vec::new();
    let mut word: Option<String> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if let Some(done) = word.take() {
                    argv.push(done);
                }
            }
            '\'' => {
                let word = word.get_or_insert_with(String::new);
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => word.push(c),
                        None => bail!("unterminated single quote"),
                    }
                }
            }
            '"' => {
                let word = word.get_or_insert_with(String::new);
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(c @ ('"' | '\\')) => word.push(c),
                            Some(c) => {
                                word.push('\\');
                                word.push(c);
                            }
                            None => bail!("unterminated double quote"),
                        },
                        Some(c) => word.push(c),
                        None => bail!("unterminated double quote"),
                    }
                }
            }
            '\\' => match chars.next() {
                Some(c) => word.get_or_insert_with(String::new).push(c),
                None => bail!("a trailing backslash escapes nothing"),
            },
            c => word.get_or_insert_with(String::new).push(c),
        }
    }
    argv.extend(word);
    if argv.len() > MAX_ARGS {
        bail!("a command has at most {MAX_ARGS} arguments");
    }
    Ok(argv)
}

/// The tail of `logs` or `logs --tail N`; `None` for any other argv
/// after `logs`.
pub fn logs_tail(rest: &[String]) -> Option<u32> {
    match rest {
        [] => Some(DEFAULT_TAIL),
        [flag, count] if flag == "--tail" => count
            .parse::<u32>()
            .ok()
            .filter(|count| (1..=MAX_TAIL).contains(count)),
        _ => None,
    }
}

/// The read commands of the cluster executors (`kubernetes`,
/// `kubernetes-inprocess`), each scoped to the pods and workloads carrying
/// the instance's `tenkai.product` and `tenkai.instance` labels in its
/// namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterQuery {
    /// The instance's pods and workloads, one line each.
    Get,
    /// Each of the instance's pods and its status, never its spec, which
    /// can carry literal secrets.
    Describe,
    /// The last lines of every container of the instance's pods.
    Logs { tail: u32 },
}

/// Usage lines of [`ClusterQuery`].
pub const CLUSTER_COMMANDS: &[&str] = &["get", "describe", "logs [--tail N]"];

impl ClusterQuery {
    /// The query `argv` names, when it is exactly one of [`CLUSTER_COMMANDS`].
    pub fn parse(argv: &[String]) -> Option<Self> {
        let (verb, rest) = argv.split_first()?;
        match (verb.as_str(), rest) {
            ("get", []) => Some(Self::Get),
            ("describe", []) => Some(Self::Describe),
            ("logs", rest) => logs_tail(rest).map(|tail| Self::Logs { tail }),
            _ => None,
        }
    }
}

/// The one write command: restart the instance's running workloads in place,
/// with the release they already run.
pub const RESTART: &str = "restart";

/// Whether `argv` is exactly a write command of `offered`. Write commands
/// take no arguments, so the usage line is the verb.
pub fn names_write(offered: &[&str], argv: &[String]) -> bool {
    matches!(argv, [verb] if offered.contains(&verb.as_str()))
}

/// What a debug session reads through: an executor's own reads, or the host
/// executor's, which reads the applier's records rather than a workload.
#[derive(Clone)]
pub enum DebugReader {
    Executor(std::sync::Arc<dyn crate::software_executor::SoftwareExecutor>),
    Host(std::sync::Arc<crate::host_executor::HostExecutor>),
}

impl DebugReader {
    /// Usage lines of the read commands; empty when there are none.
    pub fn commands(&self) -> &'static [&'static str] {
        match self {
            Self::Executor(executor) => executor.debug_commands(),
            Self::Host(_) => crate::host_executor::HOST_DEBUG_COMMANDS,
        }
    }

    /// Whether `argv` only reads; anything not exactly a read is a write.
    pub fn access(&self, argv: &[String]) -> DebugAccess {
        let read = match self {
            Self::Executor(executor) => return executor.debug_access(argv),
            Self::Host(_) => crate::host_executor::HostDebugQuery::parse(argv).is_some(),
        };
        if read {
            DebugAccess::Read
        } else {
            DebugAccess::Write
        }
    }

    /// Usage lines of the write commands an elevated session may run.
    pub fn write_commands(&self) -> &'static [&'static str] {
        match self {
            Self::Executor(executor) => executor.debug_write_commands(),
            Self::Host(_) => &[],
        }
    }

    /// Whether `argv` is exactly one of [`Self::write_commands`].
    pub fn is_write(&self, argv: &[String]) -> bool {
        names_write(self.write_commands(), argv)
    }

    /// Run write `argv` against `request`'s instance.
    pub fn write(
        &self,
        request: &crate::software_executor::SoftwareApplyRequest,
        argv: &[String],
    ) -> Result<DebugOutput> {
        match self {
            Self::Executor(executor) if names_write(executor.debug_write_commands(), argv) => {
                executor.debug_write(request, argv)
            }
            _ => bail!("not a write command of this executor"),
        }
    }

    /// Run read `argv` against `request`'s instance.
    pub fn read(
        &self,
        request: &crate::software_executor::SoftwareApplyRequest,
        argv: &[String],
    ) -> Result<DebugOutput> {
        match self {
            Self::Executor(executor) => executor.debug_read(request, argv),
            Self::Host(host) => {
                let Some(query) = crate::host_executor::HostDebugQuery::parse(argv) else {
                    bail!("only read commands run in a debug session");
                };
                host.debug_read(&request.environment, &request.product, query)
            }
        }
    }
}

/// Run `command` with no stdin, stdout and stderr together, capped at
/// [`MAX_OUTPUT`] and killed after [`COMMAND_TIMEOUT`].
pub fn run_capped(mut command: Command) -> Result<DebugOutput> {
    let program = command.get_program().to_string_lossy().into_owned();
    let (reader, writer) = std::io::pipe().context("opening an output pipe")?;
    command
        .stdin(Stdio::null())
        .stdout(writer.try_clone().context("sharing the output pipe")?)
        .stderr(writer);
    let mut child = command
        .spawn()
        .with_context(|| format!("running {program}"))?;
    // Drop the parent's copies so the read ends when the child exits.
    drop(command);
    let collect = std::thread::spawn(move || {
        let mut output = Vec::new();
        let _ = reader.take(MAX_OUTPUT as u64).read_to_end(&mut output);
        output
    });
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut output = collect.join().unwrap_or_default();
    let exit_code = match status {
        Some(status) => status.code().unwrap_or(-1),
        None => {
            output.extend_from_slice(b"\r\n[tenkai: the command timed out]\r\n");
            -1
        }
    };
    Ok(DebugOutput { output, exit_code })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_split_like_shell_words_without_expansion() {
        assert_eq!(
            split_command(r#"logs  --tail 50"#).unwrap(),
            ["logs", "--tail", "50"]
        );
        assert_eq!(
            split_command(r#"a 'b c' "d \"e\"" f\ g $(rm) |x"#).unwrap(),
            ["a", "b c", r#"d "e""#, "f g", "$(rm)", "|x"]
        );
        assert_eq!(split_command("  ").unwrap(), Vec::<String>::new());
        assert!(split_command("'open").is_err());
        assert!(split_command(&"a ".repeat(17)).is_err());
    }

    #[test]
    fn logs_tail_is_bounded() {
        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(logs_tail(&[]), Some(DEFAULT_TAIL));
        assert_eq!(logs_tail(&args(&["--tail", "10"])), Some(10));
        assert_eq!(logs_tail(&args(&["--tail", "0"])), None);
        assert_eq!(logs_tail(&args(&["--tail", "5001"])), None);
        assert_eq!(logs_tail(&args(&["-f"])), None);
    }

    #[test]
    fn only_exact_cluster_queries_read() {
        let argv = |line: &str| split_command(line).unwrap();
        assert_eq!(ClusterQuery::parse(&argv("get")), Some(ClusterQuery::Get));
        assert_eq!(
            ClusterQuery::parse(&argv("logs --tail 5")),
            Some(ClusterQuery::Logs { tail: 5 })
        );
        for write in [
            "get pods",
            "delete pod x",
            "exec -it x sh",
            "logs -f",
            "",
            "scale",
        ] {
            assert_eq!(ClusterQuery::parse(&argv(write)), None, "{write}");
        }
    }

    #[test]
    fn output_is_captured_with_the_exit_code() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "echo out; echo err >&2; exit 3"]);
        let ran = run_capped(command).unwrap();
        assert_eq!(ran.exit_code, 3);
        assert_eq!(String::from_utf8_lossy(&ran.output), "out\nerr\n");
    }
}
