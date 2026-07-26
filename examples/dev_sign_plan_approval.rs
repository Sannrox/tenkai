//! Thin wrapper around `tenkaictl dev sign-approval` (#149).
//! Prefer: `tenkaictl dev init-keys` then `tenkaictl dev sign-approval …`.

fn main() {
    eprintln!(
        "deprecated example: use `tenkaictl dev init-keys` and `tenkaictl dev sign-approval` instead"
    );
    std::process::exit(2);
}
