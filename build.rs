fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/vendor/sekai.proto");
    println!("cargo:rerun-if-changed=proto/vendor/chisei.proto");
    println!("cargo:rerun-if-changed=proto/tenkai/runtime/v1/runtime.proto");
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "proto/vendor/sekai.proto",
                "proto/vendor/chisei.proto",
                "proto/tenkai/runtime/v1/runtime.proto",
            ],
            &["proto/vendor/", "proto/"],
        )?;
    Ok(())
}
