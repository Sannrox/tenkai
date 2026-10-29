//! Embeds `docs/` so an offline bundle carries the docs of the exact Tenkai
//! version that built it (#646). Generates `$OUT_DIR/embedded_docs.rs`: one
//! `(path, bytes)` pair per file, sorted, paths relative to `docs/` with `/`.

use std::path::{Path, PathBuf};

fn main() {
    let root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let docs = root.join("docs");
    println!("cargo:rerun-if-changed=docs");
    let mut files = Vec::new();
    collect(&docs, &docs, &mut files);
    files.sort();
    let mut source = String::from("pub static DOCS: &[(&str, &[u8])] = &[\n");
    for (relative, absolute) in files {
        source.push_str(&format!(
            "    ({relative:?}, include_bytes!({:?})),\n",
            absolute.display().to_string()
        ));
    }
    source.push_str("];\n");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("out dir"));
    std::fs::write(out.join("embedded_docs.rs"), source).expect("writing embedded docs");
}

fn collect(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            collect(root, &path, files);
        } else if kind.is_file() {
            let relative = path
                .strip_prefix(root)
                .expect("under docs")
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            files.push((relative, path));
        }
    }
}
