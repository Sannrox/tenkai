fn main() -> Result<(), Box<dyn std::error::Error>> {
    let report = tenkai::delivery_conformance::run_from_env();
    println!("{}", serde_json::to_string(&report)?);
    report
        .passed
        .then_some(())
        .ok_or_else(|| "delivery conformance failed".into())
}
