// Auth: MG1937

// NOTE: Androguard DAD decompiler is Python-only. This shells out to
// the Python helper script (rust_ASC/scripts/asc_decompile.py).
// Set ASC_DECOMPILE env var to override the script path.
// Set ASC_PYTHON env var to override the python executable.

use std::process::Command;

fn find_python() -> Option<String> {
    // 1. Check env var
    if let Ok(path) = std::env::var("ASC_PYTHON") {
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }
    // 2. Common Windows install paths (check known-good first)
    for base in &[
        r"C:\Users\Admin\AppData\Local\Programs\Python\Python312",
        r"C:\Users\Admin\AppData\Local\Programs\Python\Python311",
        r"C:\Python312",
        r"C:\Python311",
    ] {
        let candidate = format!(r"{}\python.exe", base);
        if std::path::Path::new(&candidate).exists() {
            if let Ok(out) = Command::new(&candidate)
                .args(["-c", "import androguard; print('ok')"])
                .output()
            {
                if out.status.success() {
                    return Some(candidate);
                }
            }
        }
    }
    // 3. Try PATH names as last resort
    for name in &["python3", "python", "py"] {
        if let Ok(out) = Command::new(name)
            .args(["-c", "import androguard; print('ok')"])
            .output()
        {
            if out.status.success() {
                return Some(name.to_string());
            }
        }
    }
    None
}

fn find_script() -> Option<String> {
    // 1. Check env var
    if let Ok(path) = std::env::var("ASC_DECOMPILE") {
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }
    // 2. Relative to executable (target/release/ -> ../../scripts/)
    if let Ok(exe) = std::env::current_exe() {
        let exe_dir = exe.parent()?;
        // Try: target/release/../../scripts/asc_decompile.py
        let candidate = exe_dir.join("..").join("..").join("scripts").join("asc_decompile.py");
        if candidate.exists() {
            return Some(candidate.to_string_lossy().to_string());
        }
    }
    // 3. Relative to cwd
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
pub fn decompile_dex_bytes(dex_bytes: &[u8], dalvik_class_fmt: &str) -> String {
    let python = match find_python() {
        Some(p) => p,
        None => {
            return format!(
                "/* === DEX Extraction Succeeded ===\n \
                 * Rebuilt DEX: {} bytes\n \
                 * Class: {}\n \
                 *\n \
                 * Python + androguard not found. Install:\n \
                 *   pip install androguard\n \
                 * Set ASC_PYTHON env var to your python executable.\n \
                 * Set ASC_DECOMPILE env var to the script path.\n \
                 */\n",
                dex_bytes.len(),
                dalvik_class_fmt,
            );
        }
    };

    let script = match find_script() {
        Some(s) => s,
        None => {
            return format!(
                "/* === DEX Extraction Succeeded ===\n \
                 * Rebuilt DEX: {} bytes\n \
                 * Class: {}\n \
                 *\n \
                 * Decompile script not found at expected paths.\n \
                 * Set ASC_DECOMPILE env var to scripts/asc_decompile.py\n \
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

    let output = Command::new(&python)
        .args([&script, tmp_path.to_str().unwrap(), dalvik_class_fmt])
        .output();

    let _ = std::fs::remove_file(&tmp_path);

    match output {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).to_string()
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            // If stdout has content (partial decompile), return it
            let trimmed_stdout = stdout.trim();
            if !trimmed_stdout.is_empty() {
                trimmed_stdout.to_string()
            } else {
                format!("/* Decompilation failed: {} */\n", stderr.trim())
            }
        }
        Err(e) => {
            format!("/* Failed to run Python: {} */\n", e)
        }
    }
}