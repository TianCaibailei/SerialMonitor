// Text codec: byte-stream decoding for the display / search / filter / export paths.
//
// Historically the UI rendered payload bytes one by one with `escape_text`, which meant
// a GBK Chinese character (D6 D0) was shown as `\xD6\xD0` and switching 编码方式 had no
// visible effect at all — the encoding fields only ever drove the *export* file encoding.
// This module is the single place where bytes become text. Every consumer (Table 数据列,
// 终端视图, 选中行详情, 查找, 过滤, 复制, 导出) goes through it, so the user's encoding
// choice is honoured consistently.

/// Display encoding for captured byte streams.
///
/// Index order is shared by the menu (设置→编码方式), the auto-save dialog and config.ini,
/// so `as_index`/`from_index` are the single source of truth for that mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DisplayEncoding {
    /// UTF-8. Also auto-detects a UTF-16 BOM so mislabeled streams still read correctly.
    #[default]
    Utf8,
    /// Windows ANSI code page 936 (GBK), used by most Chinese serial devices.
    Gbk,
    /// UTF-16 little-endian, two bytes per code unit.
    Utf16Le,
}

impl DisplayEncoding {
    pub const ALL: [DisplayEncoding; 3] = [
        DisplayEncoding::Utf8,
        DisplayEncoding::Gbk,
        DisplayEncoding::Utf16Le,
    ];

    pub fn label(self) -> &'static str {
        match self {
            DisplayEncoding::Utf8 => "UTF-8",
            DisplayEncoding::Gbk => "ANSI(GBK)",
            DisplayEncoding::Utf16Le => "Unicode(UTF-16LE)",
        }
    }

    pub fn as_index(self) -> usize {
        match self {
            DisplayEncoding::Utf8 => 0,
            DisplayEncoding::Gbk => 1,
            DisplayEncoding::Utf16Le => 2,
        }
    }

    /// Never panics on an out-of-range index (config.ini is user-editable).
    pub fn from_index(i: usize) -> Self {
        match i {
            1 => DisplayEncoding::Gbk,
            2 => DisplayEncoding::Utf16Le,
            _ => DisplayEncoding::Utf8,
        }
    }

    /// Short hint shown in the UI so the two encoding controls are not confused.
    pub fn hint(self) -> &'static str {
        match self {
            DisplayEncoding::Utf8 => "按 UTF-8 解码显示（自动识别 UTF-16 BOM）",
            DisplayEncoding::Gbk => "按 GBK/ANSI 解码显示，适用于中文串口设备",
            DisplayEncoding::Utf16Le => "按 UTF-16LE 双字节码元解码显示",
        }
    }
}

/// Decode captured bytes into display text. Invalid sequences become U+FFFD rather than
/// being silently dropped, and BOMs are honoured even when the user picked UTF-8.
pub fn decode(data: &[u8], enc: DisplayEncoding) -> String {
    // BOM detection wins over the selected encoding: a stream that *starts* with a UTF-16
    // BOM is UTF-16, and showing it byte-by-byte was one of the worst symptoms of the old
    // implementation. Skip the BOM bytes themselves so they do not render as a character.
    if data.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(&data[2..], true);
    }
    if data.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(&data[2..], false);
    }
    let body = if data.starts_with(&[0xEF, 0xBB, 0xBF]) { &data[3..] } else { data };
    match enc {
        DisplayEncoding::Utf8 => String::from_utf8_lossy(body).into_owned(),
        DisplayEncoding::Gbk => {
            // decode_without_bom_handling returns (Cow<str>, had_errors); the replacement
            // characters inside the Cow already mark undecodable bytes, so the flag is
            // informational only.
            let (cow, _had_errors) = encoding_rs::GBK.decode_without_bom_handling(body);
            cow.into_owned()
        }
        DisplayEncoding::Utf16Le => decode_utf16(body, true),
    }
}

fn decode_utf16(data: &[u8], little_endian: bool) -> String {
    // An odd trailing byte cannot form a code unit; decode what we can and mark the rest.
    let usable = data.len() & !1;
    let mut units = Vec::with_capacity(usable / 2);
    for pair in data[..usable].chunks_exact(2) {
        units.push(if little_endian {
            u16::from_le_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], pair[1]])
        });
    }
    let mut s = String::from_utf16_lossy(&units);
    if usable != data.len() {
        s.push('\u{FFFD}');
    }
    s
}

/// Encode a text string for a log file. UTF-16LE gets a BOM (see `bom()`), because without
/// one editors misread the file as ANSI — a real bug in the old `save_log`.
pub fn encode(text: &str, enc: DisplayEncoding) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(bom(enc));
    match enc {
        DisplayEncoding::Utf8 => out.extend_from_slice(text.as_bytes()),
        DisplayEncoding::Gbk => {
            let (b, _, _) = encoding_rs::GBK.encode(text);
            out.extend_from_slice(&b);
        }
        DisplayEncoding::Utf16Le => {
            let (b, _, _) = encoding_rs::UTF_16LE.encode(text);
            out.extend_from_slice(&b);
        }
    }
    out
}

/// BOM for a *new* file. For append-style auto-save only call this on the first chunk,
/// otherwise a BOM would be injected in the middle of the file.
pub fn bom(enc: DisplayEncoding) -> &'static [u8] {
    match enc {
        DisplayEncoding::Utf16Le => &[0xFF, 0xFE],
        _ => &[],
    }
}

/// Render decoded text for the UI.
///
/// Unlike the old byte-wise implementation, printable characters — including CJK — are
/// kept as-is. Only CR/LF/TAB get escaped and only genuinely non-printable characters
/// become `\xNN` (or `?` when escaping is disabled). The undecodable replacement char
/// U+FFFD is shown as `\xFD`-style marker so binary payloads still look like bytes.
pub fn escape_decoded(text: &str, escape: bool) -> String {
    let mut s = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\r' => s.push_str("\\r"),
            '\n' => s.push_str("\\n"),
            '\t' => s.push_str("\\t"),
            '\u{FFFD}' => {
                if escape {
                    s.push_str("\\xFD");
                } else {
                    s.push('?');
                }
            }
            c if is_printable(c) => s.push(c),
            c => {
                if escape {
                    let cp = c as u32;
                    if cp <= 0xFF {
                        s.push_str(&format!("\\x{cp:02X}"));
                    } else if cp <= 0xFFFF {
                        s.push_str(&format!("\\u{cp:04X}"));
                    } else {
                        s.push_str(&format!("\\U{cp:08X}"));
                    }
                } else {
                    s.push('?');
                }
            }
        }
    }
    s
}

fn is_printable(c: char) -> bool {
    // C0/C1 controls, DEL, and Unicode line/paragraph separators are not printable.
    // Everything else (Latin, CJK, symbols, emoji) is rendered verbatim.
    !c.is_control() && c != '\u{2028}' && c != '\u{2029}'
}

/// Convenience wrapper used by every view: decode then escape in one call.
pub fn escape_text(data: &[u8], escape: bool, enc: DisplayEncoding) -> String {
    escape_decoded(&decode(data, enc), escape)
}

/// Plain decoded text for searching / filtering (no escaping applied).
pub fn decoded_text(data: &[u8], enc: DisplayEncoding) -> String {
    decode(data, enc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gbk_chinese_is_readable() {
        // "中文" in GBK
        let data = [0xD6, 0xD0, 0xCE, 0xC4];
        assert_eq!(escape_text(&data, true, DisplayEncoding::Gbk), "中文");
        // With the wrong encoding it must NOT pretend to be readable text.
        let wrong = escape_text(&data, true, DisplayEncoding::Utf8);
        assert!(!wrong.contains("中文"));
    }

    #[test]
    fn utf8_chinese_is_readable() {
        let data = "中文".as_bytes();
        assert_eq!(escape_text(data, true, DisplayEncoding::Utf8), "中文");
    }

    #[test]
    fn utf16le_is_decoded_by_code_unit_not_byte() {
        let mut data = vec![0xFF, 0xFE]; // BOM
        for u in "A中".encode_utf16() {
            data.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(escape_text(&data, true, DisplayEncoding::Utf16Le), "A中");
        // Even when UTF-8 is selected, the BOM must win.
        assert_eq!(escape_text(&data, true, DisplayEncoding::Utf8), "A中");
    }

    #[test]
    fn control_bytes_still_escape() {
        assert_eq!(escape_text(&[0x01, 0x03, b'A', b'\r'], true, DisplayEncoding::Utf8), "\\x01\\x03A\\r");
        assert_eq!(escape_text(&[0x01, 0x03, b'A', b'\r'], false, DisplayEncoding::Utf8), "??A\\r");
    }

    #[test]
    fn utf16_export_has_bom() {
        let bytes = encode("中文", DisplayEncoding::Utf16Le);
        assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
        assert!(bytes.len() > 2);
        assert!(bom(DisplayEncoding::Utf8).is_empty());
    }

    #[test]
    fn index_roundtrip_is_total() {
        for e in DisplayEncoding::ALL {
            assert_eq!(DisplayEncoding::from_index(e.as_index()), e);
        }
        assert_eq!(DisplayEncoding::from_index(999), DisplayEncoding::Utf8);
    }
}
