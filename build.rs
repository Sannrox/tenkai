fn main() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &["proto/vendor/sekai.proto", "proto/vendor/chisei.proto"],
            &["proto/vendor/"],
        )?;
    Ok(())
}
