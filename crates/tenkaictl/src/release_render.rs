//! Render a release manifest for signing: version and digest pins, same
//! validation `publish` uses for structure, no catalog or registry.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, bail};
use toml_edit::{DocumentMut, Item, Value};

use crate::catalog_args::ReleaseCommand;

pub(crate) fn run(command: ReleaseCommand) -> Result<()> {
    let ReleaseCommand::Render {
        manifest,
        version,
        artifacts,
        sboms,
        out,
    } = command
    else {
        unreachable!("release render dispatcher received a non-render command");
    };
    let raw = std::fs::read_to_string(&manifest)
        .with_context(|| format!("reading manifest {}", manifest.display()))?;
    let rendered = render_text(
        &raw,
        version.as_deref(),
        &parse_assignments("--artifact", &artifacts)?,
        &parse_assignments("--sbom", &sboms)?,
    )?;
    let Some(out) = out else {
        return Ok(());
    };
    tenkai::atomic_state::write_file(&out, rendered.as_bytes(), None)
        .with_context(|| format!("writing {}", out.display()))?;
    println!("wrote {}", out.display());
    Ok(())
}

fn render_text(
    raw: &str,
    version: Option<&str>,
    artifacts: &BTreeMap<String, String>,
    sboms: &BTreeMap<String, String>,
) -> Result<String> {
    validate_manifest(raw)?;
    if version.is_none() && artifacts.is_empty() && sboms.is_empty() {
        return Ok(raw.to_string());
    }
    let mut document = raw
        .parse::<DocumentMut>()
        .context("parsing manifest for edit")?;
    if let Some(version) = version {
        set_string_keeping_decor(&mut document["product"]["version"], version);
    }
    for (repository, digest) in artifacts {
        set_artifact_digest(&mut document, repository, digest)?;
    }
    for (repository, digest) in sboms {
        set_sbom_digest(&mut document, repository, digest)?;
    }
    let rendered = document.to_string();
    validate_manifest(&rendered)?;
    Ok(rendered)
}

fn validate_manifest(raw: &str) -> Result<tenkai::manifest::Manifest> {
    let manifest = tenkai::manifest::parse_raw(raw)?;
    tenkai::manifest::validate_declared(&manifest)?;
    tenkai::oci_artifact::validate_all(&manifest.artifacts)?;
    Ok(manifest)
}

fn parse_assignments(flag: &str, values: &[String]) -> Result<BTreeMap<String, String>> {
    let mut assignments = BTreeMap::new();
    for value in values {
        let Some((repository, digest)) = value.split_once('=') else {
            bail!("{flag} must be <repository>=<digest>");
        };
        if repository.is_empty() {
            bail!("{flag} names no repository");
        }
        if digest.is_empty() {
            bail!("{flag} names no digest");
        }
        if assignments
            .insert(repository.to_string(), digest.to_string())
            .is_some()
        {
            bail!("{flag} names repository {repository:?} more than once");
        }
    }
    Ok(assignments)
}

fn artifact_table<'a>(
    document: &'a mut DocumentMut,
    flag: &str,
    repository: &str,
) -> Result<&'a mut toml_edit::Table> {
    let Some(item) = document.get_mut("artifacts") else {
        bail!("{flag} names repository {repository:?} the manifest does not declare");
    };
    let Some(tables) = item.as_array_of_tables_mut() else {
        bail!("{flag} names repository {repository:?} the manifest does not declare");
    };
    let mut found = None;
    for (index, table) in tables.iter().enumerate() {
        if table.get("repository").and_then(Item::as_str) == Some(repository) {
            if found.is_some() {
                bail!("repository {repository:?} is declared more than once");
            }
            found = Some(index);
        }
    }
    let Some(index) = found else {
        bail!("{flag} names repository {repository:?} the manifest does not declare");
    };
    tables.get_mut(index).ok_or_else(|| {
        anyhow::anyhow!("{flag} names repository {repository:?} the manifest does not declare")
    })
}

fn set_artifact_digest(document: &mut DocumentMut, repository: &str, digest: &str) -> Result<()> {
    let table = artifact_table(document, "--artifact", repository)?;
    set_string_keeping_decor(&mut table["digest"], digest);
    Ok(())
}

fn set_sbom_digest(document: &mut DocumentMut, repository: &str, digest: &str) -> Result<()> {
    let table = artifact_table(document, "--sbom", repository)?;
    match table.get_mut("sbom") {
        Some(Item::Value(Value::InlineTable(sbom))) => {
            let mut next = Value::from(digest);
            if let Some(old) = sbom.get("digest") {
                *next.decor_mut() = old.decor().clone();
            }
            sbom.insert("digest", next);
        }
        Some(Item::Table(sbom)) => {
            set_string_keeping_decor(&mut sbom["digest"], digest);
        }
        _ => {
            bail!("artifact {repository:?} declares no SBOM");
        }
    }
    Ok(())
}

fn set_string_keeping_decor(item: &mut Item, value: &str) {
    let mut next = toml_edit::value(value);
    if let (Some(old), Some(new)) = (item.as_value(), next.as_value_mut()) {
        *new.decor_mut() = old.decor().clone();
    }
    *item = next;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const IMAGE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const IMAGE_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SBOM: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const SBOM_B: &str = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn artifact_manifest() -> String {
        format!(
            "# keep this comment\n\
             [product]\n\
             name = \"app\"\n\
             version = \"0.0.0\" # placeholder\n\
             [deploy]\n\
             install = \"true\"\n\
             [[artifacts]]\n\
             registry = \"registry.example.com\"\n\
             repository = \"edge/app\"\n\
             digest = \"{IMAGE}\"\n\
             media_type = \"application/vnd.oci.image.manifest.v1+json\"\n\
             sbom = {{ digest = \"{SBOM}\", media_type = \"application/spdx+json\" }}\n"
        )
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tenkai-release-render-{name}-{}-{}",
            std::process::id(),
            tenkai::now_millis()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn same_inputs_are_byte_identical_and_keep_comments() {
        let raw = artifact_manifest();
        let artifacts = BTreeMap::from([("edge/app".into(), IMAGE_B.into())]);
        let sboms = BTreeMap::from([("edge/app".into(), SBOM_B.into())]);
        let first = render_text(&raw, Some("1.4.0"), &artifacts, &sboms).unwrap();
        let second = render_text(&raw, Some("1.4.0"), &artifacts, &sboms).unwrap();
        assert_eq!(first, second);
        assert!(first.contains("# keep this comment"));
        assert!(
            first.contains("version = \"1.4.0\" # placeholder"),
            "comments on edited lines must be kept:\n{first}"
        );
        assert!(first.contains("version = \"1.4.0\""));
        assert!(first.contains(IMAGE_B));
        assert!(first.contains(SBOM_B));
        assert!(first.contains("application/spdx+json"));
        assert!(!first.contains(IMAGE));
        assert!(!first.contains("0.0.0"));
    }

    #[test]
    fn undeclared_repository_is_named_and_does_not_write() {
        let dir = temp_dir("undeclared");
        let input = dir.join("tenkai.toml");
        let output = dir.join("out.toml");
        fs::write(&input, artifact_manifest()).unwrap();
        fs::write(&output, "preserve me\n").unwrap();
        let err = run(ReleaseCommand::Render {
            manifest: input,
            version: None,
            artifacts: vec!["missing/app=sha256:dead".into()],
            sboms: Vec::new(),
            out: Some(output.clone()),
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("missing/app"),
            "undeclared repository must be named: {err}"
        );
        assert_eq!(fs::read_to_string(&output).unwrap(), "preserve me\n");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn sbom_without_declaration_is_named() {
        let raw = format!(
            "[product]\nname = \"app\"\nversion = \"1.0.0\"\n[deploy]\ninstall = \"true\"\n\
             [[artifacts]]\nregistry = \"registry.example.com\"\nrepository = \"edge/app\"\n\
             digest = \"{IMAGE}\"\nmedia_type = \"application/vnd.oci.image.manifest.v1+json\"\n"
        );
        let err = render_text(
            &raw,
            None,
            &BTreeMap::new(),
            &BTreeMap::from([("edge/app".into(), SBOM.into())]),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("edge/app") && err.to_ascii_lowercase().contains("sbom"),
            "missing SBOM must name the repository: {err}"
        );
    }

    #[test]
    fn unknown_key_is_named_with_and_without_output() {
        let dir = temp_dir("unknown-key");
        let input = dir.join("tenkai.toml");
        let output = dir.join("out.toml");
        fs::write(
            &input,
            "[product]\nname = \"app\"\nversion = \"1.0.0\"\nnope = true\n[deploy]\ninstall = \"true\"\n",
        )
        .unwrap();
        fs::write(&output, "preserve me\n").unwrap();
        let with_output = run(ReleaseCommand::Render {
            manifest: input.clone(),
            version: None,
            artifacts: Vec::new(),
            sboms: Vec::new(),
            out: Some(output.clone()),
        })
        .unwrap_err()
        .to_string();
        let without_output = run(ReleaseCommand::Render {
            manifest: input,
            version: None,
            artifacts: Vec::new(),
            sboms: Vec::new(),
            out: None,
        })
        .unwrap_err()
        .to_string();
        for err in [&with_output, &without_output] {
            assert!(err.contains("nope"), "unknown key must be named: {err}");
        }
        assert_eq!(fs::read_to_string(&output).unwrap(), "preserve me\n");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_digest_is_named() {
        let raw = artifact_manifest();
        let err = render_text(
            &raw,
            None,
            &BTreeMap::from([("edge/app".into(), "sha256:not-a-digest".into())]),
            &BTreeMap::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("artifact digest"),
            "malformed digest must name the field: {err}"
        );
    }

    #[test]
    fn malformed_sbom_digest_is_named() {
        let raw = artifact_manifest();
        let err = render_text(
            &raw,
            None,
            &BTreeMap::new(),
            &BTreeMap::from([("edge/app".into(), "sha256:not-a-digest".into())]),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("SBOM digest"),
            "malformed SBOM digest must name the field: {err}"
        );
    }

    #[test]
    fn empty_version_is_refused() {
        let raw = artifact_manifest();
        let err = render_text(&raw, Some(""), &BTreeMap::new(), &BTreeMap::new())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("product.version") || err.contains("product.name and product.version"),
            "empty version must be named: {err}"
        );
    }

    #[test]
    fn software_without_install_is_refused() {
        let raw = "[product]\nname = \"app\"\nversion = \"1.0.0\"\n";
        let err = render_text(raw, None, &BTreeMap::new(), &BTreeMap::new())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("deploy.install"),
            "missing install must be named: {err}"
        );
    }
}
