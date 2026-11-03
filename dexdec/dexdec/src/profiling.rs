// Keep the upstream scope macro as a no-op so decompilation bodies stay intact.
#[macro_export]
macro_rules! profile_scope {
    ($label:literal, $body:block) => {{
        let _ = $label;
        let mut __dexdec_profile_run = || $body;
        __dexdec_profile_run()
    }};
    ($label:literal, $body:expr) => {{
        let _ = $label;
        $body
    }};
}
