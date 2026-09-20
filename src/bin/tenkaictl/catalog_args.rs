use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum CanaryCommand {
    /// Mark an environment as eligible for canary cohorts.
    Designate {
        env: String,
        /// Remove the explicit canary designation.
        #[arg(long)]
        remove: bool,
    },
    /// Require successful evidence from every named environment before promotion.
    Policy {
        spec: String,
        channel: String,
        /// Required canary environment; repeat for the complete cohort.
        #[arg(long = "env", required = true)]
        cohort: Vec<String>,
        /// Start a fresh activation; prior evidence remains audited but no longer applies.
        #[arg(long)]
        reactivate: bool,
    },
    /// Rebuild durable canary outcomes for a completed apply.
    Repair { plan_id: String },
    /// Remove an abandoned promotion lock after verifying no operation is running.
    Unlock { product: String, channel: String },
}

#[derive(Subcommand)]
pub(crate) enum ReleaseCommand {
    /// Show stored release verification evidence as JSON.
    Inspect { spec: String },
    /// Reverify stored release content and evidence against current trust roots.
    Verify {
        spec: String,
        #[arg(long)]
        trust_roots: PathBuf,
    },
    /// Recall a published release so lookup and planning fail closed.
    Recall { spec: String },
}

#[derive(Subcommand)]
pub(crate) enum ApprovalCommand {
    /// Show signer, policy, scope, expiry, and bypass evidence without credentials.
    Inspect { plan_id: String },
    /// Record signed approval evidence without executing the plan.
    Submit {
        plan_id: String,
        #[arg(long, default_value = "local")]
        env: String,
        #[arg(long)]
        approval: PathBuf,
        #[arg(long)]
        approval_trust_roots: PathBuf,
        /// Current fencing generation; required with --target remote.
        #[arg(long)]
        generation: Option<u64>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{Cli, Command};
    use clap::Parser;

    #[test]
    fn parses_canary_policy_cohort_and_reactivation() {
        let cli = Cli::try_parse_from([
            "tenkaictl",
            "canary",
            "policy",
            "api@1.2.3",
            "stable",
            "--env",
            "canary-a",
            "--env",
            "canary-b",
            "--reactivate",
        ])
        .unwrap();
        let Command::Canary {
            command:
                CanaryCommand::Policy {
                    spec,
                    channel,
                    cohort,
                    reactivate,
                },
        } = cli.command
        else {
            panic!("expected canary policy command");
        };
        assert_eq!(spec, "api@1.2.3");
        assert_eq!(channel, "stable");
        assert_eq!(cohort, ["canary-a", "canary-b"]);
        assert!(reactivate);
    }

    #[test]
    fn parses_signed_and_explicit_unsigned_publication() {
        let signed = Cli::try_parse_from([
            "tenkaictl",
            "publish",
            "tenkai.toml",
            "--signature",
            "tenkai.sig.json",
            "--trust-roots",
            "release-trust.toml",
        ])
        .unwrap();
        let Command::Publish {
            signature,
            trust_roots,
            allow_unsigned_development,
            provenance,
            ..
        } = signed.command
        else {
            panic!("expected publish command");
        };
        assert_eq!(signature, Some(PathBuf::from("tenkai.sig.json")));
        assert_eq!(trust_roots, Some(PathBuf::from("release-trust.toml")));
        assert!(!allow_unsigned_development);
        assert!(provenance.is_empty());

        let unsigned = Cli::try_parse_from([
            "tenkaictl",
            "publish",
            "tenkai.toml",
            "--allow-unsigned-development",
            "--provenance",
            "subject.json",
            "--provenance",
            "build.json",
            "--provenance-trust-roots",
            "provenance-trust.toml",
            "--change-set-evidence",
            "closure.json",
        ])
        .unwrap();
        assert!(matches!(
            unsigned.command,
            Command::Publish {
                allow_unsigned_development: true,
                provenance,
                change_set_evidence,
                ..
            } if provenance == [PathBuf::from("subject.json"), PathBuf::from("build.json")]
                && change_set_evidence == Some(PathBuf::from("closure.json"))
        ));
    }

    #[test]
    fn parses_release_inspection_and_reverification() {
        let inspect =
            Cli::try_parse_from(["tenkaictl", "release", "inspect", "api@1.2.3"]).unwrap();
        assert!(matches!(
            inspect.command,
            Command::Release {
                command: ReleaseCommand::Inspect { spec }
            } if spec == "api@1.2.3"
        ));

        let verify = Cli::try_parse_from([
            "tenkaictl",
            "release",
            "verify",
            "api@1.2.3",
            "--trust-roots",
            "release-trust.toml",
        ])
        .unwrap();
        assert!(matches!(
            verify.command,
            Command::Release {
                command: ReleaseCommand::Verify { spec, trust_roots }
            } if spec == "api@1.2.3" && trust_roots == std::path::Path::new("release-trust.toml")
        ));
    }
}
