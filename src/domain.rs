use std::net::IpAddr;

pub fn detect_domain(data: &[u8]) -> Option<String> {
    detect_http_host(data).or_else(|| detect_tls_sni(data))
}

fn detect_http_host(data: &[u8]) -> Option<String> {
    let headers_end = find_http_headers_end(data)?;
    let headers = &data[..headers_end];

    for line in headers.split(|&byte| byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);

        let Some((name, value)) = split_header(line) else {
            continue;
        };

        if !name.eq_ignore_ascii_case(b"host") {
            continue;
        }

        return parse_http_host(value);
    }

    None
}

fn split_header(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let separator = line.iter().position(|&byte| byte == b':')?;

    Some((&line[..separator], &line[separator + 1..]))
}

fn find_http_headers_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_http_host(value: &[u8]) -> Option<String> {
    let value = trim_ascii_whitespace(value);

    if value.is_empty() {
        return None;
    }

    let host = if value.starts_with(b"[") {
        let end = value.iter().position(|&byte| byte == b']')?;

        if end == 1 {
            return None;
        }

        &value[1..end]
    } else if let Some(colon) = value.iter().rposition(|&byte| byte == b':') {
        let candidate = &value[..colon];
        let port = &value[colon + 1..];

        if parse_port(port).is_some() {
            candidate
        } else {
            value
        }
    } else {
        value
    };

    let host = std::str::from_utf8(host).ok()?;

    if is_domain(host) {
        Some(host.to_string())
    } else {
        None
    }
}

fn parse_port(value: &[u8]) -> Option<u16> {
    if value.is_empty() {
        return None;
    }

    let mut port = 0u16;

    for &byte in value {
        if !byte.is_ascii_digit() {
            return None;
        }

        port = port.checked_mul(10)?.checked_add(u16::from(byte - b'0'))?;
    }

    Some(port)
}

fn trim_ascii_whitespace(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(value.len());

    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|index| index + 1)
        .unwrap_or(start);

    &value[start..end]
}

fn detect_tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    /*
     * A ClientHello handshake can be split across multiple TLS records.
     * Reassemble handshake bytes from consecutive handshake records before
     * parsing the ClientHello structure.
     */
    let mut record_offset = 0usize;
    let mut handshake_bytes = Vec::new();

    while record_offset + 5 <= data.len() {
        let content_type = data[record_offset];
        let version_major = data[record_offset + 1];

        if content_type != 0x16 || version_major != 0x03 {
            break;
        }

        let record_len =
            u16::from_be_bytes([data[record_offset + 3], data[record_offset + 4]]) as usize;

        let record_end = record_offset.checked_add(5)?.checked_add(record_len)?;

        if record_end > data.len() {
            return None;
        }

        handshake_bytes.extend_from_slice(&data[record_offset + 5..record_end]);

        if handshake_bytes.len() >= 4 {
            let handshake_type = handshake_bytes[0];

            let handshake_len = u32::from_be_bytes([
                0,
                handshake_bytes[1],
                handshake_bytes[2],
                handshake_bytes[3],
            ]) as usize;

            if handshake_type != 0x01 {
                return None;
            }

            let hello_end = 4usize.checked_add(handshake_len)?;

            if handshake_bytes.len() < hello_end {
                record_offset = record_end;
                continue;
            }

            return parse_client_hello_sni(&handshake_bytes[4..hello_end]);
        }

        record_offset = record_end;
    }

    None
}

fn parse_client_hello_sni(hello: &[u8]) -> Option<String> {
    /*
     * ClientHello:
     *
     *   legacy_version: 2
     *   random:         32
     *   session_id:     1 + N
     *   cipher_suites:  2 + N
     *   compression:    1 + N
     *   extensions:     2 + N
     */

    if hello.len() < 34 {
        return None;
    }

    let mut offset = 34usize;

    let session_id_len = usize::from(*hello.get(offset)?);

    offset = offset.checked_add(1)?.checked_add(session_id_len)?;

    if offset > hello.len() {
        return None;
    }

    let cipher_len = usize::from(u16::from_be_bytes([
        *hello.get(offset)?,
        *hello.get(offset + 1)?,
    ]));

    offset = offset.checked_add(2)?.checked_add(cipher_len)?;

    if offset > hello.len() {
        return None;
    }

    let compression_len = usize::from(*hello.get(offset)?);

    offset = offset.checked_add(1)?.checked_add(compression_len)?;

    if offset > hello.len() {
        return None;
    }

    let extensions_len = usize::from(u16::from_be_bytes([
        *hello.get(offset)?,
        *hello.get(offset + 1)?,
    ]));

    offset = offset.checked_add(2)?;

    let extensions_end = offset.checked_add(extensions_len)?;

    if extensions_end > hello.len() {
        return None;
    }

    while offset + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([hello[offset], hello[offset + 1]]);

        let extension_len = usize::from(u16::from_be_bytes([hello[offset + 2], hello[offset + 3]]));

        offset += 4;

        let extension_end = offset.checked_add(extension_len)?;

        if extension_end > extensions_end {
            return None;
        }

        /*
         * server_name extension
         */
        if extension_type == 0x0000 {
            let extension = &hello[offset..extension_end];

            if extension.len() < 2 {
                return None;
            }

            let names_len = usize::from(u16::from_be_bytes([extension[0], extension[1]]));

            let names_end = 2usize.checked_add(names_len)?;

            if names_end > extension.len() {
                return None;
            }

            let mut pos = 2usize;

            while pos + 3 <= names_end {
                let name_type = extension[pos];

                let name_len =
                    usize::from(u16::from_be_bytes([extension[pos + 1], extension[pos + 2]]));

                pos += 3;

                let name_end = pos.checked_add(name_len)?;

                if name_end > names_end {
                    return None;
                }

                if name_type == 0 {
                    let host = std::str::from_utf8(&extension[pos..name_end]).ok()?;

                    if is_domain(host) {
                        return Some(host.to_string());
                    }
                }

                pos = name_end;
            }
        }

        offset = extension_end;
    }

    None
}

fn is_domain(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.parse::<IpAddr>().is_ok() {
        return false;
    }

    if host.starts_with('.') || host.ends_with('.') {
        return false;
    }

    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client_hello(host: &str) -> Vec<u8> {
        let host = host.as_bytes();

        let mut server_name = Vec::new();

        server_name.push(0x00);

        server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());

        server_name.extend_from_slice(host);

        let mut server_name_list = Vec::new();

        server_name_list.extend_from_slice(&(server_name.len() as u16).to_be_bytes());

        server_name_list.extend_from_slice(&server_name);

        let mut extension = Vec::new();

        extension.extend_from_slice(&0x0000u16.to_be_bytes());

        extension.extend_from_slice(&(server_name_list.len() as u16).to_be_bytes());

        extension.extend_from_slice(&server_name_list);

        let mut hello = Vec::new();

        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0x11; 32]);

        hello.push(0);

        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&0x1301u16.to_be_bytes());

        hello.push(1);
        hello.push(0);

        hello.extend_from_slice(&(extension.len() as u16).to_be_bytes());

        hello.extend_from_slice(&extension);

        let mut handshake = Vec::new();

        handshake.push(0x01);

        let len = hello.len() as u32;

        handshake.extend_from_slice(&[
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]);

        handshake.extend_from_slice(&hello);

        let mut record = Vec::new();

        record.extend_from_slice(&[0x16, 0x03, 0x03]);

        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());

        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn detects_http_host() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        assert_eq!(detect_domain(data).as_deref(), Some("example.com"));
    }

    #[test]
    fn detects_http_host_with_port() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";

        assert_eq!(detect_domain(data).as_deref(), Some("example.com"));
    }

    #[test]
    fn detects_http_host_case_insensitively() {
        let data = b"GET / HTTP/1.1\r\nhOsT: example.com\r\n\r\n";

        assert_eq!(detect_domain(data).as_deref(), Some("example.com"));
    }

    #[test]
    fn ignores_ip_host() {
        let data = b"GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n";

        assert_eq!(detect_domain(data), None);
    }

    #[test]
    fn ignores_invalid_http_host() {
        let data = b"GET / HTTP/1.1\r\nHost: -example.com\r\n\r\n";

        assert_eq!(detect_domain(data), None);
    }

    #[test]
    fn detects_http_host_with_non_utf8_data_after_headers() {
        let mut data = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Test: ".to_vec();

        data.extend_from_slice(&[0xff, 0xfe]);
        data.extend_from_slice(b"\r\n\r\n");

        assert_eq!(detect_domain(&data).as_deref(), Some("example.com"));
    }

    #[test]
    fn detects_tls_sni() {
        let data = make_client_hello("codeberg.org");

        assert_eq!(detect_domain(&data).as_deref(), Some("codeberg.org"));
    }

    #[test]
    fn detects_tls_sni_split_across_records() {
        let full = make_client_hello("codeberg.org");

        let record_payload_len = u16::from_be_bytes([full[3], full[4]]) as usize;

        let record_payload = &full[5..5 + record_payload_len];

        let split = record_payload.len() / 2;

        let mut first = Vec::new();

        first.extend_from_slice(&[0x16, 0x03, 0x03]);

        first.extend_from_slice(&(split as u16).to_be_bytes());

        first.extend_from_slice(&record_payload[..split]);

        let mut second = Vec::new();

        second.extend_from_slice(&[0x16, 0x03, 0x03]);

        second.extend_from_slice(&((record_payload.len() - split) as u16).to_be_bytes());

        second.extend_from_slice(&record_payload[split..]);

        first.extend_from_slice(&second);

        assert_eq!(detect_domain(&first).as_deref(), Some("codeberg.org"));
    }
}
