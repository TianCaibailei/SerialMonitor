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

/// Wrap a PDU (uid + function...) in a Modbus TCP MBAP header.
pub fn wrap_mbap(pdu: &[u8], tid: u16) -> Vec<u8> {
    let len = (pdu.len() + 1) as u16;
    let mut out = Vec::with_capacity(7 + pdu.len());
    out.extend_from_slice(&tid.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(pdu);
    out
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

/// Rows copied from modbus/modbus-response.bdp (43 presets).
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
