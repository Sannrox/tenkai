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
    /// Free a promotion lock now instead of waiting a minute for it to expire.
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
    /// Pin version and artifact digests, then validate the manifest to sign.
    Render {
        manifest: PathBuf,
        /// Set `product.version`.
        #[arg(long)]
        version: Option<String>,
        /// Set the digest of the `[[artifacts]]` entry with this repository.
        #[arg(long = "artifact", value_name = "REPOSITORY=DIGEST")]
        artifacts: Vec<String>,
        /// Set that entry's SBOM digest and keep its declared media type.
        #[arg(long = "sbom", value_name = "REPOSITORY=DIGEST")]
        sboms: Vec<String>,
        /// Write the rendered manifest here. Without it, validate only.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum ChannelCommand {
    /// Pause delivery to every environment subscribed to this channel.
    Hold {
        product: String,
        channel: String,
        #[command(subcommand)]
        action: crate::env_args::HoldAction,
    },
    /// Stop this channel delivering the product. Installed instances stay
    /// until their environments unsubscribe.
    Remove {
        product: String,
        channel: String,
        /// Refuse unless the channel still heads this `<product>@<version>`.
        #[arg(long)]
        expected_head: Option<String>,
    },
    /// Declare, pause, or resume automatic promotion into this channel.
    Policy {
        product: String,
        channel: String,
        /// Source channel whose head is promoted.
        #[arg(long = "from")]
        source: Option<String>,
        /// Minimum soak (`30`, `250ms`, `2m`, `24h`). A bare number is seconds.
        #[arg(long)]
        soak: Option<String>,
        /// Require a passing canary cohort for the target channel.
        #[arg(long)]
        require_canary: bool,
        /// Require passing health/SLO gate evidence.
        #[arg(long)]
        require_health_slo: bool,
        /// Require published evaluation evidence.
        #[arg(long)]
        require_evaluation: bool,
        /// Pause the policy without deleting soak state.
        #[arg(long, conflicts_with = "resume")]
        pause: bool,
        /// Resume a paused policy.
        #[arg(long, conflicts_with = "pause")]
        resume: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum EvalEvidenceCommand {
    /// Install trusted Ed25519 signers for Chisei model-evaluation records.
    Trust {
        /// Versioned TOML file containing trusted evaluation signers.
        #[arg(long)]
        trust_roots: PathBuf,
    },
    /// Record a signed chisei.model_evaluation_evidence.v1 JSON document.
    Record { evidence: PathBuf },
}

#[derive(Subcommand)]
pub(crate) enum ApprovalCommand {
    /// Show signer, policy, scope, expiry, and bypass evidence without credentials.
    Inspect { plan_id: String },
    /// Record signed approval evidence without executing the plan.
    Submit {
        plan_id: String,
        #[arg(long, env = "TENKAI_ENVIRONMENT")]
        env: Option<String>,
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
    fn parses_channel_promotion_policy() {
        let cli = Cli::try_parse_from([
            "tenkaictl",
            "channel",
            "policy",
            "api",
            "stable",
            "--from",
            "candidate",
            "--soak",
            "24h",
            "--require-canary",
        ])
        .unwrap();
        let Command::Channel {
            command:
                ChannelCommand::Policy {
                    product,
                    channel,
                    source,
                    soak,
                    require_canary,
                    require_health_slo,
                    require_evaluation,
                    pause,
                    resume,
                },
        } = cli.command
        else {
            panic!("expected channel policy command");
        };
        assert_eq!(product, "api");
        assert_eq!(channel, "stable");
        assert_eq!(source.as_deref(), Some("candidate"));
        assert_eq!(soak.as_deref(), Some("24h"));
        assert!(require_canary);
        assert!(!require_health_slo);
        assert!(!require_evaluation);
        assert!(!pause);
        assert!(!resume);
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

    #[test]
    fn parses_release_render_pins_and_output() {
        let cli = Cli::try_parse_from([
            "tenkaictl",
            "release",
            "render",
            "deploy/tenkai.toml",
            "--version",
            "1.4.0",
            "--artifact",
            "edge/app=sha256:aaa",
            "--sbom",
            "edge/app=sha256:bbb",
            "--out",
            "out/tenkai.toml",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Release {
                command: ReleaseCommand::Render {
                    ref manifest,
                    ref version,
                    ref artifacts,
                    ref sboms,
                    ref out,
                }
            } if manifest == std::path::Path::new("deploy/tenkai.toml")
                && version.as_deref() == Some("1.4.0")
                && artifacts == &["edge/app=sha256:aaa".to_string()]
                && sboms == &["edge/app=sha256:bbb".to_string()]
                && out.as_deref() == Some(std::path::Path::new("out/tenkai.toml"))
        ));
    }

    #[test]
    fn parses_eval_evidence_trust_and_record() {
        let trust = Cli::try_parse_from([
            "tenkaictl",
            "eval-evidence",
            "trust",
            "--trust-roots",
            "eval-trust.toml",
        ])
        .unwrap();
        assert!(matches!(
            trust.command,
            Command::EvalEvidence {
                command: EvalEvidenceCommand::Trust { trust_roots }
            } if trust_roots == std::path::Path::new("eval-trust.toml")
        ));

        let record = Cli::try_parse_from([
            "tenkaictl",
            "eval-evidence",
            "record",
            "evaluation-result.json",
        ])
        .unwrap();
        assert!(matches!(
            record.command,
            Command::EvalEvidence {
                command: EvalEvidenceCommand::Record { evidence }
            } if evidence == std::path::Path::new("evaluation-result.json")
        ));
    }
}
