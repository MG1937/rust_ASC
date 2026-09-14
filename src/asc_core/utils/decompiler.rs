// Auth: MG1937

// NOTE: Androguard DAD decompiler is Python-only. This stub shells out to
// the Python helper script (rust_ASC/scripts/asc_decompile.py) when available.
// Set ASC_DECOMPILE env var to override the script path.

use std::process::Command;

fn find_script() -> Option<String> {
    // 1. Check env var
    if let Ok(path) = std::env::var("ASC_DECOMPILE") {
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }
    // 2. Relative to project dir
    let cwd = std::env::current_dir().ok()?;
    for candidate in &[
        cwd.join("scripts").join("asc_decompile.py"),
        cwd.join("..").join("scripts").join("asc_decompile.py"),
    ] {
        if candidate.exists() {
            return Some(candidate.to_string_lossy().to_string());
        }
    }
    None
}

/// Take DEX bytes and a target class format, decompile it using Androguard DAD
/// and return the source code.
///
/// Falls back to an error message with recovery instructions when androguard
/// is not available. The extraction pipeline runs regardless.
pub fn decompile_dex_bytes(dex_bytes: &[u8], dalvik_class_fmt: &str) -> String {
    let script = match find_script() {
        Some(s) => s,
        None => {
            return format!(
                "/* === DEX Extraction Succeeded ===\n \
                 * Rebuilt DEX: {} bytes\n \
                 * Class: {}\n \
                 *\n \
                 * To decompile, set ASC_DECOMPILE env var to:\n \
                 *   rust_ASC/scripts/asc_decompile.py\n \
                 *\n \
                 * Requirements: Python + androguard\n \
                 *   pip install androguard\n \
                 */\n",
                dex_bytes.len(),
                dalvik_class_fmt,
            );
        }
    };

    // Write the rebuilt DEX to a temp file
    let tmp_path = std::env::temp_dir().join(format!("asc_rebuilt_{}.dex", std::process::id()));
    if std::fs::write(&tmp_path, dex_bytes).is_err() {
        return format!("/* Error: Failed to write temp DEX */\n");
    }

    let output = Command::new("py")
        .args([&script, tmp_path.to_str().unwrap(), dalvik_class_fmt])
        .output();

    let _ = std::fs::remove_file(&tmp_path);

    match output {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).to_string()
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            format!("/* Python ASC error: {} */\n", stderr.trim())
        }
        Err(e) => {
            format!("/* Failed to run Python: {} */\n", e)
        }
    }
}