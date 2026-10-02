//! The web-console pin (ADR 0031): one place, one line, checksum enforced.

#[path = "../ui/pin.rs"]
mod pin;

use pin::ConsolePin;

#[test]
fn checked_in_pin_parses_and_names_a_release_asset() {
    let text = std::fs::read_to_string(pin::PIN_FILE).unwrap();
    assert_eq!(text.trim_end().lines().count(), 1, "the pin is one line");
    let pin = ConsolePin::parse(&text).unwrap();
    assert!(
        pin.url()
            .starts_with("https://github.com/Sannrox/tenkai-console/releases/download/")
    );
    assert!(
        pin.url()
            .ends_with(&format!("tenkai-console-{}.zip", pin.tag))
    );
}

#[test]
fn checksum_mismatch_is_refused() {
    let pin = ConsolePin::parse(
        "v1.2.3 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    .unwrap();
    pin.verify(b"").expect("sha256 of empty input matches");
    let error = pin.verify(b"tampered").unwrap_err();
    assert!(error.contains("checksum mismatch"), "{error}");
}

#[test]
fn malformed_pins_are_refused() {
    let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    for text in [
        String::new(),
        format!("1.2.3 {sha}"),
        format!("v1.2 {sha}"),
        format!("v1.2.3 {}", sha.to_uppercase()),
        "v1.2.3 abc".to_string(),
        format!("v1.2.3 {sha} extra"),
    ] {
        assert!(ConsolePin::parse(&text).is_err(), "{text:?}");
    }
}
