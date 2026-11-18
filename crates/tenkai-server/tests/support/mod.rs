//! Spawned-server helpers for the integration tests: every wait has a
//! deadline and the child is killed on drop, so a stuck server fails its test
//! instead of hanging the run (#1314).
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

/// How long a server may take to report ready, exit, or print an expected
/// line. Generous for loaded debug builds; a hang still fails.
pub const DEADLINE: Duration = Duration::from_secs(120);

/// A spawned server. Threads drain stdout and stderr line by line into
/// channels, so the child never blocks on a full pipe and every read can
/// time out. Dropping it kills and reaps the child.
pub struct Spawned {
    child: Child,
    stdout: Receiver<String>,
    stderr: Receiver<String>,
}

fn drain(pipe: impl Read + Send + 'static) -> Receiver<String> {
    let (send, receive) = channel();
    std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines().map_while(Result::ok) {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    receive
}

/// The first line on `lines` that matches, or `None` once the stream ends or
/// `deadline` passes.
fn first(
    lines: &Receiver<String>,
    deadline: Instant,
    matches: impl Fn(&str) -> bool,
) -> Option<String> {
    loop {
        let left = deadline.checked_duration_since(Instant::now())?;
        match lines.recv_timeout(left) {
            Ok(line) if matches(&line) => return Some(line),
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => return None,
        }
    }
}

impl Spawned {
    /// Spawns `command` with both output streams piped.
    pub fn spawn(command: &mut Command) -> Self {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = drain(child.stdout.take().unwrap());
        let stderr = drain(child.stderr.take().unwrap());
        Self {
            child,
            stdout,
            stderr,
        }
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// The first stdout line that matches within [`DEADLINE`].
    pub fn stdout_line(&self, matches: impl Fn(&str) -> bool) -> Option<String> {
        first(&self.stdout, Instant::now() + DEADLINE, matches)
    }

    /// The first stderr line that matches within `within`.
    pub fn stderr_line(&self, within: Duration, matches: impl Fn(&str) -> bool) -> Option<String> {
        first(&self.stderr, Instant::now() + within, matches)
    }

    /// Waits for the `tenkai-server ready` line; panics past [`DEADLINE`].
    pub fn ready(&self) {
        self.stdout_line(|line| line.starts_with("tenkai-server ready"))
            .expect("server reported ready before the deadline");
    }

    /// Waits for the child to exit within `within`, killing it and panicking
    /// otherwise.
    pub fn wait(&mut self, within: Duration) -> ExitStatus {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("server did not exit within {within:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Kills the child and returns the stderr lines nobody read yet.
    pub fn stop(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.rest_of_stderr()
    }

    /// Stderr lines not read yet, up to the end of the stream. Call after the
    /// child has exited.
    pub fn rest_of_stderr(&self) -> String {
        let deadline = Instant::now() + DEADLINE;
        let mut lines = Vec::new();
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.stderr.recv_timeout(left) {
                Ok(line) => lines.push(line),
                Err(_) => break,
            }
        }
        lines.join("\n")
    }

    /// Stdout lines not read yet, up to the end of the stream. Call after the
    /// child has exited.
    pub fn rest_of_stdout(&self) -> String {
        let deadline = Instant::now() + DEADLINE;
        let mut lines = Vec::new();
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.stdout.recv_timeout(left) {
                Ok(line) => lines.push(line),
                Err(_) => break,
            }
        }
        lines.join("\n")
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Runs `command` to completion like [`Command::output`], but kills it and
/// panics if it has not exited within [`DEADLINE`].
pub fn output(command: &mut Command) -> Output {
    let mut spawned = Spawned::spawn(command);
    let status = spawned.wait(DEADLINE);
    Output {
        status,
        stdout: spawned.rest_of_stdout().into_bytes(),
        stderr: spawned.rest_of_stderr().into_bytes(),
    }
}
