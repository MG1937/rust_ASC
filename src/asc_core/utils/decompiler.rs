// Auth: MG1937

use std::str::FromStr;

use dexdec::{DecompileOptions, Decompiler, JavaDecompilerConfig, SourceLanguage};
pub use radguard::writer::{MemberKind, MemberReference};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompilerEngine {
    Dexdec,
    Radguard,
}

impl FromStr for DecompilerEngine {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "dexdec" => Ok(Self::Dexdec),
            "radguard" => Ok(Self::Radguard),
            _ => Err(format!(
                "unsupported decompiler engine '{value}'; expected dexdec or radguard"
            )),
        }
    }
}

/// Decompile a target class from an in-memory DEX using DexDec.
pub fn decompile_dex_bytes(dex_bytes: &[u8], dalvik_class_fmt: &str) -> String {
    decompile_dex_bytes_with_engine(dex_bytes, dalvik_class_fmt, DecompilerEngine::Dexdec)
}

pub fn decompile_dex_bytes_with_engine(
    dex_bytes: &[u8],
    dalvik_class_fmt: &str,
    engine: DecompilerEngine,
) -> String {
    match engine {
        DecompilerEngine::Dexdec => decompile_with_dexdec(dex_bytes, dalvik_class_fmt),
        DecompilerEngine::Radguard => decompile_with_radguard(dex_bytes, dalvik_class_fmt),
    }
}

fn decompile_with_dexdec(dex_bytes: &[u8], dalvik_class_fmt: &str) -> String {
    let mut decompiler = match Decompiler::from_bytes(dex_bytes) {
        Ok(decompiler) => decompiler.with_options(
            DecompileOptions::default()
                .with_language(SourceLanguage::Java)
                .with_java(JavaDecompilerConfig::default().with_preserved_dex_names(true)),
        ),
        Err(error) => return format!("/* DexDec decompiler error: {error} */\n"),
    };
    decompiler
        .class(dalvik_class_fmt)
        .map(|unit| unit.source)
        .unwrap_or_else(|error| format!("/* DexDec decompiler error: {error} */\n"))
}

fn decompile_with_radguard(dex_bytes: &[u8], dalvik_class_fmt: &str) -> String {
    radguard::decompile_dex_bytes(dex_bytes, dalvik_class_fmt)
        .map(|output| output.source)
        .unwrap_or_else(|error| format!("/* RadGuard decompiler error: {error} */\n"))
}

/// Decompile a target class and its member references using RadGuard.
pub fn decompile_dex_bytes_with_metadata(
    dex_bytes: &[u8],
    dalvik_class_fmt: &str,
) -> (String, Vec<MemberReference>) {
    radguard::decompile_dex_bytes(dex_bytes, dalvik_class_fmt)
        .map(|output| (output.source, output.member_references))
        .unwrap_or_else(|error| {
            (
                format!("/* RadGuard decompiler error: {error} */\n"),
                Vec::new(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::{
        DecompilerEngine, decompile_dex_bytes, decompile_dex_bytes_with_engine,
        decompile_dex_bytes_with_metadata,
    };

    #[test]
    fn dexdec_reports_invalid_dex_without_panicking() {
        let source = decompile_dex_bytes(b"not a dex", "Lexample/Test;");
        assert!(source.starts_with("/* DexDec decompiler error:"));
    }

    #[test]
    fn radguard_reports_invalid_dex_without_panicking() {
        let source = decompile_dex_bytes_with_engine(
            b"not a dex",
            "Lexample/Test;",
            DecompilerEngine::Radguard,
        );
        assert!(source.starts_with("/* RadGuard decompiler error:"));
    }

    #[test]
    fn metadata_errors_do_not_panic() {
        let (source, references) =
            decompile_dex_bytes_with_metadata(b"not a dex", "Lexample/Test;");
        assert!(source.starts_with("/* RadGuard decompiler error:"));
        assert!(references.is_empty());
    }
}
