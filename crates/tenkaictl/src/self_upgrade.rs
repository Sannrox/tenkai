//! `tenkaictl self-upgrade`: a verified swap of this host's Tenkai server
//! binaries with readiness-gated, automatic rollback (#678). Local only: it
//! acts on a server home and its SQLite store, never through the API.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use clap::Subcommand;
use tenkai::server_self_upgrade::{Home, StoreCheck};

#[derive(Subcommand)]
pub(crate) enum SelfUpgradeCommand {
    /// Verify the bundle's host binaries and run the candidate's store
    /// check. Changes nothing.
    Plan {
        #[command(flatten)]
        source: Source,
    },
    /// Verify, check the store, back it up, switch `current`, then (with
    /// `--ready-url`) wait for readiness and roll back if it does not come.
    /// Arguments after `--` restart the service, for example
    /// `-- systemctl restart tenkai-server`.
    Apply {
        #[command(flatten)]
        source: Source,
        #[command(flatten)]
        settle: Settle,
    },
    /// Wait for readiness after the service was restarted by hand; confirm
    /// the switch, or roll it back if readiness does not come.
    Confirm {
        #[arg(long)]
        home: PathBuf,
        #[command(flatten)]
        settle: Settle,
    },
    /// Roll the last switch back by hand. When the new version migrated the
    /// store, stop the server first and pass `--restore-backup`: the backup
    /// taken before the switch replaces the store, and what was written since
    /// is given up.
    Rollback {
        #[arg(long)]
        home: PathBuf,
        #[arg(long)]
        restore_backup: bool,
        /// Restarts the service after the rollback.
        #[arg(last = true)]
        restart: Vec<String>,
    },
}

#[derive(clap::Args)]
pub(crate) struct Source {
    /// The server home holding `versions/`, `current` and `previous`.
    #[arg(long)]
    home: PathBuf,
    /// A `tenkai.offline-bundle.v1` archive carrying signed host binaries.
    #[arg(long)]
    bundle: PathBuf,
    /// Trust roots that must authenticate the bundle exporter.
    #[arg(long)]
    trust_roots: PathBuf,
    /// The environment the bundle is scoped to.
    #[arg(long)]
    env: String,
    /// The server's SQLite store.
    #[arg(long, env = "TENKAI_DATABASE")]
    database: PathBuf,
    /// Packaged host platform; defaults to this process's.
    #[arg(long)]
    platform: Option<String>,
    /// How long the candidate's store check may take; it copies and
    /// migrates the whole store.
    #[arg(long, default_value_t = 1800)]
    check_timeout_secs: u64,
}

#[derive(clap::Args)]
pub(crate) struct Settle {
    /// The new server's `/readyz`, for example `http://127.0.0.1:8080/readyz`.
    #[arg(long)]
    ready_url: Option<String>,
    #[arg(long, default_value_t = 120)]
    ready_timeout_secs: u64,
    /// Restarts the service, run after a switch and after a rollback.
    #[arg(last = true)]
    restart: Vec<String>,
}

pub(crate) async fn run(command: SelfUpgradeCommand) -> Result<()> {
    match command {
        SelfUpgradeCommand::Plan { source } => {
            let home = Home::new(&source.home);
            let _held = home.lock()?;
            let (id, check) = candidate(&home, &source)?;
            println!("candidate {id} {}", describe(&check));
            Ok(())
        }
        SelfUpgradeCommand::Apply { source, settle } => {
            let home = Home::new(&source.home);
            let _held = home.lock()?;
            let (id, check) = candidate(&home, &source)?;
            println!("candidate {id} {}", describe(&check));
            let record = home.switch(&id, &source.database, tenkai::now_millis())?;
            println!("{}", serde_json::to_string_pretty(&record)?);
            if settle.restart.is_empty() {
                // The old server still answers readiness: only a restart
                // makes it the candidate's, so confirming waits for one.
                println!(
                    "switched to {}; restart the service, then run `tenkaictl self-upgrade confirm --home <home> --ready-url <url>`",
                    record.to
                );
                return Ok(());
            }
            settle_switch(&home, &settle).await
        }
        SelfUpgradeCommand::Confirm { home, settle } => {
            let home = Home::new(home);
            let _held = home.lock()?;
            settle_switch(&home, &settle).await
        }
        SelfUpgradeCommand::Rollback {
            home,
            restore_backup,
            restart,
        } => {
            let home = Home::new(home);
            let _held = home.lock()?;
            let reverted = home.revert(restore_backup)?;
            println!("{}", serde_json::to_string_pretty(&reverted)?);
            restart_service(&restart)
        }
    }
}

/// Verify the bundle's binaries for this host into a scratch directory,
/// stage them, and run their store check. The scratch copy is removed.
fn candidate(home: &Home, source: &Source) -> Result<(String, StoreCheck)> {
    let envelope = tenkai::offline_bundle::BundleEnvelope::load(&source.bundle)?;
    let roots = tenkai::release_signing::TrustRoots::load(&source.trust_roots)?;
    let platform = match &source.platform {
        Some(platform) => platform.clone(),
        None => tenkai::offline_host_binaries::detect_platform()?.to_string(),
    };
    let scratch = home.scratch()?;
    let staged = (|| {
        tenkai::offline_host_binaries::verify_and_install(
            &envelope,
            &roots,
            tenkai::ontology::NS,
            &source.env,
            tenkai::now_millis(),
            &scratch,
            &platform,
        )?;
        home.stage(&scratch)
    })();
    let _ = std::fs::remove_dir_all(&scratch);
    let id = staged?;
    let check = home.check_candidate(
        &id,
        &source.database,
        Duration::from_secs(source.check_timeout_secs),
    )?;
    Ok((id, check))
}

fn describe(check: &StoreCheck) -> String {
    if check.migrates() {
        format!(
            "migrates the store from schema {} to {}; a rollback then needs the backup restored",
            check.stored, check.supported
        )
    } else {
        format!(
            "opens the store at schema {}",
            check.stored.max(check.supported)
        )
    }
}

/// Restart (when asked), wait for readiness, and confirm the switch; when
/// readiness does not come, roll back and restart again. A store the new
/// version migrated cannot be rolled back while it may still run: that is
/// reported for the operator instead.
async fn settle_switch(home: &Home, settle: &Settle) -> Result<()> {
    let record = home.record()?.context("no server switch to settle")?;
    let Some(url) = &settle.ready_url else {
        restart_service(&settle.restart)?;
        println!(
            "switched to {}; once the service runs it, run `tenkaictl self-upgrade confirm --home <home> --ready-url <url>`",
            record.to
        );
        return Ok(());
    };
    let timeout = Duration::from_secs(settle.ready_timeout_secs);
    // A restart that fails is handled as readiness that did not come.
    let started = match restart_service(&settle.restart) {
        Ok(()) => wait_ready(url, timeout).await,
        Err(error) => Err(error),
    };
    match started {
        Ok(()) => {
            let confirmed = home.confirm()?;
            println!("{}", serde_json::to_string_pretty(&confirmed)?);
            Ok(())
        }
        Err(error) => {
            if home.store_migrated(&record)? {
                bail!(
                    "server version {} did not become ready ({error:#}) and migrated the store; stop the server, run `tenkaictl self-upgrade rollback --home <home> --restore-backup`, then start it",
                    record.to
                );
            }
            let reverted = home.revert(false)?;
            println!("{}", serde_json::to_string_pretty(&reverted)?);
            let restarted = restart_service(&settle.restart);
            // The candidate may have migrated the store while it was still
            // starting; the older binary cannot open such a store, and its
            // restart may fail for that reason.
            if home.store_migrated(&record)? {
                bail!(
                    "server version {} migrated the store while it was rolled back to {}; stop the server, run `tenkaictl self-upgrade rollback --home <home> --restore-backup`, then start it",
                    record.to,
                    reverted.to
                );
            }
            restarted?;
            let back = if settle.restart.is_empty() {
                "restart the service".to_string()
            } else {
                match wait_ready(url, timeout).await {
                    Ok(()) => "it is ready".into(),
                    Err(error) => format!("it is not ready either: {error:#}"),
                }
            };
            bail!(
                "server version {} did not become ready ({error:#}); rolled back to {}, {back}",
                record.to,
                reverted.to
            )
        }
    }
}

/// How long a restart command may run before it is killed and counted as
/// failed.
const RESTART_DEADLINE: Duration = Duration::from_secs(300);

/// Run the operator's restart command, if one was given, within
/// [`RESTART_DEADLINE`]. No shell is involved: the arguments are the
/// command line.
fn restart_service(command: &[String]) -> Result<()> {
    let Some((program, args)) = command.split_first() else {
        return Ok(());
    };
    use std::os::unix::process::CommandExt as _;
    // Its own process group, so a timeout stops whatever it started too.
    let mut child = std::process::Command::new(program)
        .args(args)
        .process_group(0)
        .spawn()
        .with_context(|| format!("running {program}"))?;
    let group = child.id() as i32;
    let deadline = std::time::Instant::now() + RESTART_DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            // SAFETY: signalling our own child's process group.
            unsafe { libc::killpg(group, libc::SIGKILL) };
            let _ = child.wait();
            bail!(
                "{} did not finish within {}s",
                command.join(" "),
                RESTART_DEADLINE.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    if !status.success() {
        bail!("{} exited with {status}", command.join(" "));
    }
    Ok(())
}

/// Poll `url` until it answers 200 or `timeout` passes.
async fn wait_ready(url: &str, timeout: Duration) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let last = match client.get(url).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => format!("{url} answered {}", response.status()),
            Err(error) => format!("{url}: {error}"),
        };
        if tokio::time::Instant::now() >= deadline {
            bail!("{last} after {}s", timeout.as_secs());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home_with_switch(root: &std::path::Path) -> (Home, String, String) {
        tenkai::storage::SqliteStore::open(root.join("tenkai.db")).unwrap();
        let schema = tenkai::storage::SCHEMA_VERSION;
        let home = Home::new(root.join("home"));
        let mut ids = Vec::new();
        for marker in ["a", "b"] {
            let dir = root.join(marker);
            std::fs::create_dir_all(&dir).unwrap();
            for name in tenkai::server_self_upgrade::BINARIES {
                let script = format!(
                    "#!/bin/sh\n# {marker}\nif [ \"$1\" = --check-store ]; then echo '{{\"stored\":{schema},\"supported\":{schema}}}'; exit 0; fi\necho {name}\n"
                );
                std::fs::write(dir.join(name), script).unwrap();
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
            ids.push(home.stage(&dir).unwrap());
        }
        home.switch(&ids[0], &root.join("tenkai.db"), 1).unwrap();
        home.confirm().unwrap();
        home.switch(&ids[1], &root.join("tenkai.db"), 2).unwrap();
        let b = ids.pop().unwrap();
        (home, ids.pop().unwrap(), b)
    }

    /// Readiness that never comes rolls the switch back, and the restart
    /// command runs again; readiness that comes confirms it.
    #[tokio::test]
    async fn readiness_confirms_or_rolls_back_the_switch() {
        let root = std::env::temp_dir().join(format!(
            "tenkaictl-self-upgrade-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let (home, a, b) = home_with_switch(&root);
        let restarts = root.join("restarts");
        let restart = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("echo x >> {}", restarts.display()),
        ];
        // Nothing listens on this port: readiness never comes.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/readyz", closed.local_addr().unwrap());
        drop(closed);
        let error = settle_switch(
            &home,
            &Settle {
                ready_url: Some(url),
                ready_timeout_secs: 0,
                restart: restart.clone(),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("rolled back to"), "{error}");
        assert_eq!(home.current().unwrap().as_deref(), Some(a.as_str()));
        assert_eq!(
            std::fs::read_to_string(&restarts).unwrap().lines().count(),
            2
        );

        // A ready server confirms the next switch.
        home.switch(&b, &root.join("tenkai.db"), 3).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ready = format!("http://{}/readyz", listener.local_addr().unwrap());
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = [0_u8; 1024];
                let _ = stream.read(&mut request).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
            }
        });
        settle_switch(
            &home,
            &Settle {
                ready_url: Some(ready),
                ready_timeout_secs: 5,
                restart: Vec::new(),
            },
        )
        .await
        .unwrap();
        assert!(home.record().unwrap().unwrap().confirmed);
        assert_eq!(home.current().unwrap().as_deref(), Some(b.as_str()));
        let _ = std::fs::remove_dir_all(root);
    }
}
