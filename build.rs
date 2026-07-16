use sha2::{Digest, Sha256};

const VENDORED_PROTOS: [(&str, &str); 2] = [
    (
        "proto/vendor/sekai.proto",
        "ae62da7bba6fe9e00e5ec8f6f682f547d829c36f4f5865d1708de1a72880af91",
    ),
    (
        "proto/vendor/chisei.proto",
        "fe6578641d4d1e74e8f57368eb52f151ccc038ccbbebbfc734cfcc3bc2499fcd",
    ),
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    verify_vendored_protos()?;
    println!("cargo:rerun-if-changed=proto/tenkai/agent/v1/agent.proto");

    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &[
                "proto/vendor/sekai.proto",
                "proto/vendor/chisei.proto",
                "proto/tenkai/agent/v1/agent.proto",
            ],
            &["proto/vendor/", "proto/"],
        )?;
    Ok(())
}

fn verify_vendored_protos() -> Result<(), Box<dyn std::error::Error>> {
    for (path, expected) in VENDORED_PROTOS {
        println!("cargo:rerun-if-changed={path}");
        let contents = std::fs::read(path)?;
        let normalized = contents
            .split(|byte| *byte == b'\n')
            .flat_map(|line| {
                line.strip_suffix(b"\r")
                    .unwrap_or(line)
                    .iter()
                    .copied()
                    .chain([b'\n'])
            })
            .collect::<Vec<_>>();
        let normalized = normalized.strip_suffix(b"\n").unwrap_or(&normalized);
        let actual = format!("{:x}", Sha256::digest(normalized));
        if actual != expected {
            return Err(format!(
                "vendored proto drift detected in {path}: expected {expected}, got {actual}; \
                 review the upstream change and update the pinned digest in build.rs"
            )
            .into());
        }
    }

    Ok(())
}
