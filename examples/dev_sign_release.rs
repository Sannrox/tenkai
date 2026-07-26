//! Thin wrapper around `tenkaictl dev sign-release` (#149).
//! Prefer: `tenkaictl dev init-keys` then `tenkaictl dev sign-release …`.

fn main() {
    eprintln!(
        "deprecated example: use `tenkaictl dev init-keys` and `tenkaictl dev sign-release` instead"
    );
    std::process::exit(2);
}
