#[cfg(feature = "ui")]
#[path = "../../ui/pin.rs"]
mod console_pin;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "ui")]
    embed_console()?;
    Ok(())
}

/// Embed the pinned web-console bundle (feature `ui`, ADR 0031).
///
/// Downloads the release zip named in `ui/console.pin`, or reads
/// `TENKAI_UI_BUNDLE` for offline builds, and refuses it unless its SHA-256
/// matches the pin. Default builds never reach this code or the network.
#[cfg(feature = "ui")]
fn embed_console() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Cursor, Read};
    use std::path::{Component, PathBuf};

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let pin_file = manifest_dir.join("../../ui/console.pin");
    let pin_rs = manifest_dir.join("../../ui/pin.rs");
    println!("cargo:rerun-if-changed={}", pin_file.display());
    println!("cargo:rerun-if-changed={}", pin_rs.display());
    println!("cargo:rerun-if-env-changed=TENKAI_UI_BUNDLE");
    let pin = console_pin::ConsolePin::parse(&std::fs::read_to_string(&pin_file)?)?;
    let bundle = match std::env::var_os("TENKAI_UI_BUNDLE") {
        Some(path) => {
            println!("cargo:rerun-if-changed={}", PathBuf::from(&path).display());
            std::fs::read(&path)?
        }
        None => reqwest::blocking::get(pin.url())?
            .error_for_status()?
            .bytes()?
            .to_vec(),
    };
    pin.verify(&bundle)?;

    let root = PathBuf::from(std::env::var("OUT_DIR")?).join("console");
    if root.exists() {
        std::fs::remove_dir_all(&root)?;
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(bundle))?;
    let mut files = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry.is_dir() {
            continue;
        }
        let relative = entry
            .enclosed_name()
            .filter(|path| {
                path.components()
                    .all(|part| matches!(part, Component::Normal(_)))
            })
            .ok_or_else(|| format!("console bundle entry {:?} has an unsafe path", entry.name()))?;
        let name = relative
            .components()
            .map(|part| {
                part.as_os_str()
                    .to_str()
                    .ok_or("console bundle path is not UTF-8")
            })
            .collect::<Result<Vec<_>, _>>()?
            .join("/");
        let target = root.join(&relative);
        std::fs::create_dir_all(target.parent().ok_or("console bundle path has no parent")?)?;
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;
        std::fs::write(&target, contents)?;
        files.push((name, target));
    }
    files.sort();
    if !files.iter().any(|(name, _)| name == "index.html") {
        return Err("console bundle has no index.html".into());
    }
    let mut generated = format!(
        "pub const TAG: &str = {:?};\npub static FILES: &[(&str, &[u8])] = &[\n",
        pin.tag
    );
    for (name, path) in &files {
        let path = path.to_str().ok_or("OUT_DIR is not UTF-8")?;
        generated.push_str(&format!("    ({name:?}, include_bytes!({path:?})),\n"));
    }
    generated.push_str("];\n");
    std::fs::write(root.with_file_name("console_bundle.rs"), generated)?;
    Ok(())
}
