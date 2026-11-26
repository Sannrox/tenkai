use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?).join("../../proto");
    let graph_action = proto_root.join("tenkai/graph_action.proto");
    let record = proto_root.join("tenkai/record.proto");
    let runtime = proto_root.join("tenkai/runtime/v1/runtime.proto");
    println!("cargo:rerun-if-changed={}", graph_action.display());
    println!("cargo:rerun-if-changed={}", record.display());
    println!("cargo:rerun-if-changed={}", runtime.display());
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // No caller uses the generated `connect`; skipping it keeps tonic transport optional.
        .build_transport(false)
        .compile_protos(
            &[
                graph_action.to_str().ok_or("proto path is not UTF-8")?,
                record.to_str().ok_or("proto path is not UTF-8")?,
                runtime.to_str().ok_or("proto path is not UTF-8")?,
            ],
            &[proto_root.to_str().ok_or("proto root is not UTF-8")?],
        )?;
    Ok(())
}
