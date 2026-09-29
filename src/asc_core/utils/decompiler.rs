// Auth: MG1937

pub use radguard::writer::{MemberKind, MemberReference};

/// Decompile a target class from an in-memory DEX using RadGuard.
pub fn decompile_dex_bytes(dex_bytes: &[u8], dalvik_class_fmt: &str) -> String {
    radguard::decompile_dex_bytes(dex_bytes, dalvik_class_fmt)
        .unwrap_or_else(|error| format!("/* RadGuard decompiler error: {error} */\n"))
}

pub fn decompile_dex_bytes_with_metadata(
    dex_bytes: &[u8],
    dalvik_class_fmt: &str,
) -> (String, Vec<MemberReference>) {
    radguard::decompile_dex_bytes_with_metadata(dex_bytes, dalvik_class_fmt).unwrap_or_else(
        |error| {
            (
                format!("/* RadGuard decompiler error: {error} */\n"),
                Vec::new(),
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{decompile_dex_bytes, decompile_dex_bytes_with_metadata};

    #[test]
    fn decompiles_with_radguard() {
        let dex = include_bytes!("../../../radguard/tests/fixtures/sample.dex");
        let source = decompile_dex_bytes(dex, "Lkotlinx/coroutines/flow/AbstractFlow$collect$1;");
        assert!(source.contains("class AbstractFlow$collect$1"));
    }

    #[test]
    fn reports_invalid_dex_without_panicking() {
        let source = decompile_dex_bytes(b"not a dex", "Lexample/Test;");
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
