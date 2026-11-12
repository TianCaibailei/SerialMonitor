// Protocol layer: CRC-16/MODBUS, LRC, frame parsing (RTU / ASCII / TCP-MBAP), preset library.
// Preset rows replicate modbus/modbus-request.bdp and modbus-response.bdp from the original.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameKind {
    Req,
    Resp,
    Except,
    Failed,
    Raw,
}

impl FrameKind {
    pub fn name(self) -> &'static str {
        match self {
            FrameKind::Req => "请求",
            FrameKind::Resp => "响应",
            FrameKind::Except => "异常",
            FrameKind::Failed => "校验失败",
            FrameKind::Raw => "数据",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ModbusParsed {
    pub id: u8,
    pub function: u8,
    pub address: Option<u16>,
    pub quantity: Option<u16>,
    pub values: Option<Vec<u8>>,
    pub checksum: String,
    pub checksum_ok: Option<bool>,
    pub kind: FrameKind,
    pub remark: String,
}

/// Standard CRC-16/MODBUS: poly 0xA001 (reflected 0x8005), init 0xFFFF.
/// The original computes this per-bit (no lookup table embedded — byte scan ev_33b2cf2c),
/// and its preset rows carry crctype 77 / crcBit 0.
pub fn crc16_modbus(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Modbus ASCII LRC: two's complement of the sum of all bytes.
pub fn lrc(data: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    for &b in data {
        sum = sum.wrapping_add(b);
    }
    (!sum).wrapping_add(1)
}

pub fn fc_name(fc: u8) -> &'static str {
    match fc {
        0x01 => "Read Coils",
        0x02 => "Read Discrete Inputs",
        0x03 => "Read Holding Registers",
        0x04 => "Read Input Registers",
        0x05 => "Write Single Coil",
        0x06 => "Write Single Register",
        0x07 => "Read Exception Status",
        0x08 => "Diagnostics",
        0x0B => "Get Comm Event Counter",
        0x0C => "Get Comm Event Log",
        0x0F => "Write Multiple Coils",
        0x10 => "Write Multiple Registers",
        0x11 => "Report Server ID",
        0x14 => "Read File Record",
        0x15 => "Write File Record",
        0x16 => "Mask Write Register",
        0x17 => "Read/Write Multiple Registers",
        0x18 => "Read FIFO Queue",
        0x2B => "Encapsulated Interface Transport",
        _ => "Unknown",
    }
}

fn base(id: u8, fc: u8, dir_tx: bool, checksum_ok: bool, crc_text: String) -> ModbusParsed {
    let kind = if fc & 0x80 != 0 {
        FrameKind::Except
    } else if !checksum_ok {
        FrameKind::Failed
    } else if dir_tx {
        FrameKind::Req
    } else {
        FrameKind::Resp
    };
    ModbusParsed {
        id,
        function: fc,
        address: None,
        quantity: None,
        values: None,
        checksum: crc_text,
        checksum_ok: Some(checksum_ok),
        kind,
        remark: fc_name(fc).to_string(),
    }
}

/// Best-effort parse of a raw RTU frame (addr fc ... crc_lo crc_hi).
pub fn parse_rtu(frame: &[u8], dir_tx: bool) -> Option<ModbusParsed> {
    if frame.len() < 4 {
        return None;
    }
    let id = frame[0];
    let fc = frame[1];
    let (payload, crc_bytes) = frame.split_at(frame.len() - 2);
    let calc = crc16_modbus(payload);
    let got = crc_bytes[0] as u16 | ((crc_bytes[1] as u16) << 8);
    let mut p = base(id, fc, dir_tx, got == calc, format!("{:04X}", calc));
    if fc & 0x80 != 0 {
        if payload.len() >= 3 {
            p.quantity = Some(payload[2] as u16);
        }
        p.remark = format!("异常码 0x{:02X}", payload.get(2).copied().unwrap_or(0));
        return Some(p);
    }
    let body = &payload[2..];
    match fc {
        0x01..=0x06 => {
            if body.len() >= 4 {
                p.address = Some(u16::from_be_bytes([body[0], body[1]]));
                p.quantity = Some(u16::from_be_bytes([body[2], body[3]]));
                if body.len() > 4 {
                    p.values = Some(body[4..].to_vec());
                }
            }
        }
        0x0F | 0x10 => {
            if body.len() >= 5 {
                p.address = Some(u16::from_be_bytes([body[0], body[1]]));
                p.quantity = Some(u16::from_be_bytes([body[2], body[3]]));
                p.values = Some(body[5..].to_vec());
            }
        }
        _ => {
            if !body.is_empty() {
                p.values = Some(body.to_vec());
            }
        }
    }
    Some(p)
}

/// Modbus ASCII frame: ':' hex ... LRC CRLF. Input excludes ':' and CRLF (text form).
pub fn parse_ascii_text(text: &[u8], dir_tx: bool) -> Option<ModbusParsed> {
    let s = String::from_utf8_lossy(text);
    let hex_part: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex_part.len() < 6 || hex_part.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex_part.len() / 2);
    let hx = hex_part.as_bytes();
    for i in (0..hx.len()).step_by(2) {
        bytes.push(((hex_val(hx[i]) << 4) | hex_val(hx[i + 1])) as u8);
    }
    if bytes.len() < 3 {
        return None;
    }
    let id = bytes[0];
    let fc = bytes[1];
    let (payload, lrc_b) = bytes.split_at(bytes.len() - 1);
    let calc = lrc(payload);
    let mut p = base(id, fc, dir_tx, calc == lrc_b[0], format!("{:02X}", calc));
    let body = &payload[2..];
    if !body.is_empty() {
        p.values = Some(body.to_vec());
    }
    Some(p)
}

fn hex_val(c: u8) -> u32 {
    match c {
        b'0'..=b'9' => (c - b'0') as u32,
        b'a'..=b'f' => (c - b'a' + 10) as u32,
        _ => (c - b'A' + 10) as u32,
    }
}

/// Modbus TCP MBAP: tid(2) pid(2) len(2) uid(1) fc(1)... Returns parsed frame + total bytes consumed.
pub fn parse_mbap(buf: &[u8], dir_tx: bool) -> Option<(ModbusParsed, usize)> {
    if buf.len() < 8 {
        return None;
    }
    let len = u16::from_be_bytes([buf[4], buf[5]]) as usize; // bytes after this field
    let total = 6 + len;
    if buf.len() < total {
        return None;
    }
    let pid = u16::from_be_bytes([buf[2], buf[3]]);
    if pid != 0 {
        return None; // not Modbus TCP
    }
    let id = buf[6];
    let fc = buf[7];
    let body = &buf[8..total];
    let mut p = base(id, fc, dir_tx, true, "-".to_string());
    p.checksum_ok = None;
    p.remark = format!("MBAP tid={} pid={}", u16::from_be_bytes([buf[0], buf[1]]), pid);
    match fc {
        0x01..=0x06 => {
            if body.len() >= 4 {
                p.address = Some(u16::from_be_bytes([body[0], body[1]]));
                p.quantity = Some(u16::from_be_bytes([body[2], body[3]]));
                if body.len() > 4 {
                    p.values = Some(body[4..].to_vec());
                }
            }
        }
        0x0F | 0x10 => {
            if body.len() >= 5 {
                p.address = Some(u16::from_be_bytes([body[0], body[1]]));
                p.quantity = Some(u16::from_be_bytes([body[2], body[3]]));
                p.values = Some(body[5..].to_vec());
            }
        }
        _ => {
            if !body.is_empty() {
                p.values = Some(body.to_vec());
            }
        }
    }
    Some((p, total))
}

/// Append CRC-16/MODBUS (low byte first) to a request frame.
pub fn append_crc(frame: &[u8]) -> Vec<u8> {
    let c = crc16_modbus(frame);
    let mut out = frame.to_vec();
    out.push((c & 0xFF) as u8);
    out.push((c >> 8) as u8);
    out
}

/// Wrap a PDU (unit id + function code + data) in a Modbus TCP MBAP header.
///
/// MBAP `len` counts the bytes that follow it — i.e. **unit id + PDU data** — which is
/// exactly `pdu.len()`, because `pdu` already starts with the unit id. The previous
/// implementation wrote `pdu.len() + 1`, so every frame the "发送预设" button produced
/// carried a length one byte too large and `parse_mbap` (which computes `total = 6 + len`)
/// would wait for a byte that never arrives. Send and receive must agree on this layout:
/// `[tid][pid][len][uid][fc][data]`.
pub fn wrap_mbap(pdu: &[u8], tid: u16) -> Vec<u8> {
    let len = pdu.len() as u16;
    let mut out = Vec::with_capacity(6 + pdu.len());
    out.extend_from_slice(&tid.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(pdu);
    out
}

/// Build the on-wire frame for a PDU according to the session's protocol.
///
/// Single source of truth for the send paths (manual send and 发送预设). It used to be
/// duplicated in the UI, where the ASCII branch appended the LRC twice — once as a
/// decimal string and once as hex — producing frames the receiver always rejected.
pub fn build_frame(pdu: &[u8], proto: crate::session::ProtoType, tid: u16) -> Vec<u8> {
    use crate::session::ProtoType;
    match proto {
        ProtoType::Rtu => append_crc(pdu),
        ProtoType::Ascii => {
            let mut v = Vec::with_capacity(pdu.len() * 2 + 5);
            v.push(b':');
            for b in pdu {
                v.extend_from_slice(format!("{b:02X}").as_bytes());
            }
            v.extend_from_slice(format!("{:02X}", lrc(pdu)).as_bytes());
            v.extend_from_slice(b"\r\n");
            v
        }
        ProtoType::Tcp => wrap_mbap(pdu, tid),
        ProtoType::None => pdu.to_vec(),
    }
}

pub struct Preset {
    pub name: &'static str,
    pub data: &'static str,
}

/// Rows copied from modbus/modbus-request.bdp (23 presets).
pub const REQUEST_PRESETS: &[Preset] = &[
    Preset { name: "01 (0x01) Read Coils-req", data: "01 01 00 13 00 13" },
    Preset { name: "02 (0x02) Read Discrete Inputs-req", data: "01 02 00 C4 00 16" },
    Preset { name: "03 (0x03) Read Holding Registers-req", data: "01 03 00 6B 00 03" },
    Preset { name: "04 (0x04) Read Input Registers-req", data: "01 04 00 08 00 01" },
    Preset { name: "05 (0x05) Write Single Coil-req", data: "01 05 00 AC FF 00" },
    Preset { name: "06 (0x06) Write Single Register-req", data: "01 06 00 01 00 03" },
    Preset { name: "15 (0x0F) Write Multiple Coils-req", data: "01 0F 00 13 00 0A 02 CD 01" },
    Preset { name: "16 (0x10) Write Multiple registers-req", data: "01 10 00 01 00 02 04 00 0A 01 02" },
    Preset { name: "22 (0x16) Mask Write Register-req", data: "01 16 00 04 00 F2 00 25" },
    Preset { name: "23 (0x17) Read/Write Multiple registers-req", data: "01 17 00 03 00 06 00 0E 00 03 06 00 FF 00 FF 00 FF" },
    Preset { name: "24 (0x18) Read FIFO Queue-req", data: "01 18 04 DE" },
    Preset { name: "21 (0x15) Write File Record-req-1", data: "01 15 11 06 00 04 00 07 00 05 06 AF 04 BE 10 0D FF DD CC EE" },
    Preset { name: "21 (0x15) Write File Record-req", data: "01 15 0D 06 00 04 00 07 00 03 06 AF 04 BE 10 0D" },
    Preset { name: "20 (0x14) Read File Record-req", data: "01 14 0E 06 00 04 00 01 00 02 06 00 03 00 09 00 02" },
    Preset { name: "17 (0x11) Report Server ID-req", data: "01 11" },
    Preset { name: "07 (0x07) Read Exception Status-req", data: "01 07" },
    Preset { name: "11 (0x0B) Get Comm Event Counter-req", data: "01 0B" },
    Preset { name: "12 (0x0C) Get Comm Event Log-req", data: "01 0C" },
    Preset { name: "43 (0x2B) Encapsulated Interface Transport-0D-req", data: "01 2B 0D 00 01 02 03" },
    Preset { name: "43 (0x2B) Encapsulated Interface Transport-0D-req1", data: "01 2B 0D 00 01 01 02" },
    Preset { name: "43 (0x2B) Encapsulated Interface Transport-0E-req", data: "01 2B 0E 01 00" },
    Preset { name: "08 (0x08) Diagnostics-SubFunc-15-3-req", data: "01 08 00 15 00 03" },
    Preset { name: "08 (0x08) Diagnostics-SubFunc-15-4-req", data: "01 08 00 15 00 04" },
];

/// Response presets recovered from the original's modbus/modbus-response.bdp.
///
/// The count is **38**, not the 43 claimed by earlier comments/docs — the table is the
/// authority and `preset_counts_match_code` keeps it honest.
pub const RESPONSE_PRESETS: &[Preset] = &[
    Preset { name: "01 (0x01) Read Coils-resp", data: "01 01 03 CD 6B 05" },
    Preset { name: "02 (0x02) Read Discrete Inputs-resp", data: "01 02 03 AC DB 35" },
    Preset { name: "03 (0x03) Read Holding Registers-resp", data: "01 03 06 02 2B 00 00 00 64" },
    Preset { name: "04 (0x04) Read Input Registers-resp", data: "01 04 02 00 0A" },
    Preset { name: "05 (0x05) Write Single Coil-resp", data: "01 05 00 AC FF 00" },
    Preset { name: "06 (0x06) Write Single Register-resp", data: "01 06 00 01 00 03" },
    Preset { name: "15 (0x0F) Write Multiple Coils-resp", data: "01 0F 00 13 00 0A" },
    Preset { name: "16 (0x10) Write Multiple registers-resp", data: "01 10 00 01 00 02" },
    Preset { name: "17 (0x11) Report Server ID-resp", data: "01 11 04 ff 00 AA BB" },
    Preset { name: "20 (0x14) Read File Record-resp", data: "01 14 0C 05 06 0D FE 00 20 05 06 33 CD 00 40" },
    Preset { name: "21 (0x15) Write File Record-resp", data: "01 15 11 06 00 04 00 07 00 05 06 AF 04 BE 10 0D FF DD CC EE" },
    Preset { name: "22 (0x16) Mask Write Register-resp", data: "01 16 00 04 00 F2 00 25" },
    Preset { name: "23 (0x17) Read/Write Multiple registers-resp", data: "01 17 0C 00 FE 0A CD 00 01 00 03 00 0D 00 FF" },
    Preset { name: "24 (0x18) Read FIFO Queue-Resp", data: "01 18 00 0A 00 04 01 B8 12 84 FF 00 00 AA" },
    Preset { name: "07 (0x07) Read Exception Status-resp", data: "01 07 6D" },
    Preset { name: "11 (0x0B) Get Comm Event Counter-resp", data: "01 0B FF FF 01 08" },
    Preset { name: "12 (0x0C) Get Comm Event Log-resp", data: "01 0C 08 00 00 01 08 01 21 20 00" },
    Preset { name: "08 (0x08) Diagnostics-SubFunc-00-resp", data: "01 08 00 00 A5 37" },
    Preset { name: "08 (0x08) Diagnostics-01-resp", data: "01 08 00 01 ff 00" },
    Preset { name: "08 (0x08) Diagnostics-02-resp", data: "01 08 00 02 FF DD" },
    Preset { name: "08 (0x08) Diagnostics-03-resp", data: "01 08 00 03 AA FF" },
    Preset { name: "08 (0x08) Diagnostics-04-resp", data: "01 08 00 04 00 00" },
    Preset { name: "08 (0x08) Diagnostics-0A-resp", data: "01 08 00 0A 00 11" },
    Preset { name: "08 (0x08) Diagnostics-0B-resp", data: "01 08 00 0B 00 22" },
    Preset { name: "08 (0x08) Diagnostics-0C-resp", data: "01 08 00 0C 00 33" },
    Preset { name: "08 (0x08) Diagnostics-0D-resp", data: "01 08 00 0D 22 33" },
    Preset { name: "08 (0x08) Diagnostics-0E-resp", data: "01 08 00 0E 00 02" },
    Preset { name: "08 (0x08) Diagnostics-0F-resp", data: "01 08 00 0F CC 1A" },
    Preset { name: "08 (0x08) Diagnostics-10-resp", data: "01 08 00 10 01 22" },
    Preset { name: "08 (0x08) Diagnostics-11-resp", data: "01 08 00 11 44 55" },
    Preset { name: "08 (0x08) Diagnostics-12-resp", data: "01 08 00 12 22 55" },
    Preset { name: "08 (0x08) Diagnostics-13-resp", data: "01 08 00 13 77 01" },
    Preset { name: "08 (0x08) Diagnostics-14-resp", data: "01 08 00 14 00 11" },
    Preset { name: "08 (0x08) Diagnostics-15-3resp", data: "01 08 00 15 00 03 00 06 01 02 03 04 05 06" },
    Preset { name: "08 (0x08) Diagnostics-15-4resp", data: "01 08 00 15 00 04" },
    Preset { name: "43 (0x2B) Encapsulated-0D-resp1", data: "01 2B 0D 00 01 02 03" },
    Preset { name: "43 (0x2B) Encapsulated-0D-resp2", data: "01 2B 0D 00 01 01 02" },
    Preset { name: "43 (0x2B) Encapsulated-0E-resp", data: "01 2B 0E 01 01 ff 00 03 00 04 31 32 33 35 01 06 35 36 37 38 39 40 02 05 35 36 38 39 50" },
];

pub fn parse_hex(text: &str) -> Option<Vec<u8>> {
    let clean: String = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .replace("0x", "")
        .replace("0X", "");
    if clean.is_empty() || clean.len() % 2 != 0 {
        return None;
    }
    let hx = clean.as_bytes();
    let mut out = Vec::with_capacity(hx.len() / 2);
    for i in (0..hx.len()).step_by(2) {
        let hi = hex_val(hx[i]);
        let lo = hex_val(hx[i + 1]);
        if hi > 15 || lo > 15 {
            return None;
        }
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_modbus_known_vector() {
        // Classic reference: 01 03 00 00 00 0A -> CRC 0xCDC5 (low byte first: C5 CD)
        assert_eq!(crc16_modbus(&[0x01, 0x03, 0x00, 0x00, 0x00, 0x0A]), 0xCDC5);
    }

    #[test]
    fn lrc_is_twos_complement_of_sum() {
        // sum = 0x01+0x03+0x00+0x00+0x00+0x0A = 0x0E -> LRC = 0xF2
        assert_eq!(lrc(&[0x01, 0x03, 0x00, 0x00, 0x00, 0x0A]), 0xF2);
    }

    #[test]
    fn rtu_roundtrip_parses_address_and_quantity() {
        let pdu = [0x01, 0x03, 0x00, 0x6B, 0x00, 0x03];
        let frame = append_crc(&pdu);
        let p = parse_rtu(&frame, true).expect("parsed");
        assert_eq!(p.id, 0x01);
        assert_eq!(p.function, 0x03);
        assert_eq!(p.address, Some(0x006B));
        assert_eq!(p.quantity, Some(3));
        assert_eq!(p.checksum_ok, Some(true));
        assert_eq!(p.kind, FrameKind::Req);
    }

    #[test]
    fn rtu_corrupt_crc_is_flagged_failed() {
        let mut frame = append_crc(&[0x01, 0x03, 0x00, 0x6B, 0x00, 0x03]);
        frame[2] ^= 0xFF; // corrupt payload, CRC no longer matches
        let p = parse_rtu(&frame, true).expect("parsed");
        assert_eq!(p.checksum_ok, Some(false));
        assert_eq!(p.kind, FrameKind::Failed);
    }

    /// The send path (wrap_mbap) and the receive path (parse_mbap) must agree; they used
    /// to disagree by one byte in the MBAP length field, making "发送预设" emit frames
    /// that could never be parsed.
    #[test]
    fn mbap_send_and_receive_agree() {
        let pdu = [0x01, 0x03, 0x00, 0x6B, 0x00, 0x03];
        let frame = wrap_mbap(&pdu, 0x1234);
        assert_eq!(frame.len(), 6 + pdu.len());
        assert_eq!(&frame[..2], &[0x12, 0x34]); // tid
        assert_eq!(&frame[2..4], &[0x00, 0x00]); // pid
        assert_eq!(&frame[4..6], &[0x00, 0x06]); // len = uid + fc + 4 data bytes
        let (p, used) = parse_mbap(&frame, true).expect("parsed");
        assert_eq!(used, frame.len());
        assert_eq!(p.id, 0x01);
        assert_eq!(p.function, 0x03);
        assert_eq!(p.address, Some(0x006B));
        assert_eq!(p.quantity, Some(3));
    }

    #[test]
    fn mbap_rejects_non_modbus_protocol_id() {
        let mut frame = wrap_mbap(&[0x01, 0x03, 0x00, 0x00, 0x00, 0x01], 1);
        frame[3] = 0x01; // pid != 0
        assert!(parse_mbap(&frame, true).is_none());
    }

    #[test]
    fn mbap_incomplete_frame_is_not_consumed() {
        let frame = wrap_mbap(&[0x01, 0x03, 0x00, 0x6B, 0x00, 0x03], 7);
        assert!(parse_mbap(&frame[..frame.len() - 1], true).is_none());
    }

    /// An ASCII frame is ':' + hex(PDU) + hex(LRC) + CRLF. This pins the layout that the
    /// send button must produce; the old code appended the LRC twice (once decimal,
    /// once hex), which parse_ascii_text correctly rejected.
    #[test]
    fn ascii_frame_roundtrip() {
        let pdu = [0x01, 0x03, 0x00, 0x6B, 0x00, 0x03];
        let mut hex = String::new();
        for b in pdu {
            hex.push_str(&format!("{b:02X}"));
        }
        let text = format!("{hex}{:02X}", lrc(&pdu));
        let p = parse_ascii_text(text.as_bytes(), true).expect("parsed");
        assert_eq!(p.id, 0x01);
        assert_eq!(p.function, 0x03);
        assert_eq!(p.checksum_ok, Some(true));
    }

    /// build_frame must produce, for each protocol, a frame that the matching parser
    /// accepts — the ASCII branch in particular used to emit a doubled LRC.
    #[test]
    fn build_frame_roundtrips_for_every_protocol() {
        use crate::session::ProtoType;
        let pdu = [0x01, 0x03, 0x00, 0x6B, 0x00, 0x03];

        let rtu = build_frame(&pdu, ProtoType::Rtu, 0);
        assert_eq!(rtu.len(), pdu.len() + 2);
        assert_eq!(parse_rtu(&rtu, true).unwrap().checksum_ok, Some(true));

        let ascii = build_frame(&pdu, ProtoType::Ascii, 0);
        assert_eq!(ascii[0], b':');
        assert_eq!(&ascii[ascii.len() - 2..], b"\r\n");
        // ':' + 2 hex chars per byte + 2 LRC chars + CRLF
        assert_eq!(ascii.len(), 1 + pdu.len() * 2 + 2 + 2);
        let inner = &ascii[1..ascii.len() - 2];
        assert_eq!(parse_ascii_text(inner, true).unwrap().checksum_ok, Some(true));

        let tcp = build_frame(&pdu, ProtoType::Tcp, 0x0042);
        let (p, used) = parse_mbap(&tcp, true).unwrap();
        assert_eq!(used, tcp.len());
        assert_eq!(p.id, 0x01);

        assert_eq!(build_frame(&pdu, ProtoType::None, 0), pdu.to_vec());
    }

    #[test]
    fn preset_counts_match_code() {
        // Guard against documentation drifting from the tables again. The code comment
        // and README used to claim "43 响应" while the table actually holds 38 — this
        // assertion pins the real numbers so the docs must be updated with them.
        assert_eq!(REQUEST_PRESETS.len(), 23);
        assert_eq!(RESPONSE_PRESETS.len(), 38);
    }

    #[test]
    fn every_preset_is_valid_hex() {
        for p in REQUEST_PRESETS.iter().chain(RESPONSE_PRESETS.iter()) {
            assert!(parse_hex(p.data).is_some(), "preset not valid hex: {}", p.name);
        }
    }
}
