use std::path::PathBuf;

pub fn workspace_bin(name: &str) -> PathBuf {
    let key = format!("CARGO_BIN_EXE_{name}");
    if let Ok(path) = std::env::var(&key) {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(deps) = exe.parent()
        && deps.file_name().is_some_and(|n| n == "deps")
        && let Some(profile_dir) = deps.parent()
    {
        let candidate = profile_dir.join(name);
        if candidate.is_file() {
            return candidate;
        }
    }
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let mut dirs = Vec::new();
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        dirs.push(PathBuf::from(target_dir).join(profile).join(name));
    }
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..5 {
        dirs.push(dir.join("target").join(profile).join(name));
        if !dir.pop() {
            break;
        }
    }
    if let Some(found) = dirs.into_iter().find(|candidate| candidate.is_file()) {
        return found;
    }
    panic!("workspace binary {name} not found under target/{profile}")
}
