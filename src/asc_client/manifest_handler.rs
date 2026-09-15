// Auth: MG1937
// Strict 1:1 translation from Python manifest_handler.py

use std::fs::File;
use std::io::Read;

use apk_info_axml::AXML;
use quick_xml::events::Event;
use quick_xml::{Reader, Writer};
use zip::ZipArchive;

fn _quiet_loguru() {
    // No-op in Rust: there is no loguru/androguard to silence.
}

fn _format_xml(xml: &str, pretty: bool) -> Result<String, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut writer = if pretty {
        Writer::new_with_indent(Vec::new(), b' ', 2)
    } else {
        Writer::new(Vec::new())
    };
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Text(text))
                if text.iter().all(|byte| byte.is_ascii_whitespace()) => {}
            Ok(event) => writer
                .write_event(event)
                .map_err(|e| format!("cannot format AndroidManifest.xml: {}", e))?,
            Err(e) => {
                return Err(format!("cannot format AndroidManifest.xml: {}", e));
            }
        }
        buf.clear();
    }

    String::from_utf8(writer.into_inner())
        .map_err(|e| format!("cannot format AndroidManifest.xml as UTF-8: {}", e))
}

/// 从APK中获取AndroidManifest.xml的文本表示
pub fn get_manifest_xml(apk_path: &str, pretty: bool) -> Result<String, String> {
    let fp = File::open(apk_path)
        .map_err(|e| format!("cannot open APK: {}", e))?;
    let mut zf = ZipArchive::new(fp)
        .map_err(|e| format!("cannot read APK as ZIP: {}", e))?;
    let mut manifest = zf.by_name("AndroidManifest.xml")
        .map_err(|e| format!("AndroidManifest.xml not found in APK: {}", e))?;
    let mut manifest_data = Vec::new();
    manifest.read_to_end(&mut manifest_data)
        .map_err(|e| format!("cannot read AndroidManifest.xml: {}", e))?;

    _quiet_loguru();
    let mut input = manifest_data.as_slice();
    let axml = AXML::new(&mut input, None)
        .map_err(|e| format!("AndroidManifest.xml is not a valid binary XML: {}", e))?;
    _format_xml(&axml.get_xml_string(), pretty)
}
