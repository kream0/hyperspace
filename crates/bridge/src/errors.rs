//! Error lines people read (host log, client status, `--relay-check`): one
//! plain line per case, the same on every OS, with no library names, source
//! files or function names. macOS and Windows translate their messages, so
//! their errors are recognised by number only.

use std::net::{IpAddr, SocketAddr};

/// A certificate the system's trust store does not lead to.
pub const UNTRUSTED: &str =
    "this computer does not trust the relay's certificate (on a company network that inspects HTTPS, ask IT)";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Problem {
    Name,
    Expired,
    Untrusted,
}

/// A Windows HRESULT as std prints it (a signed 32-bit number).
const fn hr(code: u32) -> i64 {
    code as i32 as i64
}

/// OS error numbers. macOS puts them in the error's Debug form only;
/// Windows also writes them in the message, as "(os error N)".
const CODES: &[(i64, Problem)] = &[
    // macOS: Security framework trust results (SecBase.h) and Secure Transport.
    (-67602, Problem::Name),      // errSecHostNameMismatch
    (-9843, Problem::Name),       // errSSLHostNameMismatch
    (-67818, Problem::Expired),   // errSecCertificateExpired
    (-9814, Problem::Expired),    // errSSLCertExpired
    (-67843, Problem::Untrusted), // errSecNotTrusted
    (-25318, Problem::Untrusted), // errSecCreateChainFailed
    (-9807, Problem::Untrusted),  // errSSLXCertChainInvalid
    (-9812, Problem::Untrusted),  // errSSLUnknownRootCert
    (-9813, Problem::Untrusted),  // errSSLNoRootCert
    // Windows: certificate chain policy and SChannel.
    (hr(0x800B_010F), Problem::Name),      // CERT_E_CN_NO_MATCH
    (hr(0x8009_0322), Problem::Name),      // SEC_E_WRONG_PRINCIPAL
    (hr(0x800B_0101), Problem::Expired),   // CERT_E_EXPIRED
    (hr(0x8009_0328), Problem::Expired),   // SEC_E_CERT_EXPIRED
    (hr(0x800B_0109), Problem::Untrusted), // CERT_E_UNTRUSTEDROOT
    (hr(0x800B_010A), Problem::Untrusted), // CERT_E_CHAINING
    (hr(0x800B_0112), Problem::Untrusted), // CERT_E_UNTRUSTEDCA
    (hr(0x8009_0325), Problem::Untrusted), // SEC_E_UNTRUSTED_ROOT
];

/// OpenSSL's certificate verify results (Linux), lowercase. OpenSSL 1.1
/// writes "self signed", 3.x "self-signed".
const TEXTS: &[(&str, Problem)] = &[
    ("hostname mismatch", Problem::Name),
    ("ip address mismatch", Problem::Name),
    ("certificate has expired", Problem::Expired),
    ("self-signed certificate", Problem::Untrusted),
    ("self signed certificate", Problem::Untrusted),
    ("unable to get local issuer certificate", Problem::Untrusted),
    ("unable to get issuer certificate", Problem::Untrusted),
    ("unable to verify the first certificate", Problem::Untrusted),
    ("certificate not trusted", Problem::Untrusted),
];

/// A failed TLS handshake with the relay at `host`, from the error's Display
/// and Debug forms.
pub fn tls_error(host: &str, display: &str, debug: &str) -> String {
    match problem(display, debug) {
        Some(Problem::Name) => format!("the relay's certificate is not valid for {host}"),
        Some(Problem::Expired) => "the relay's certificate has expired".to_string(),
        Some(Problem::Untrusted) => UNTRUSTED.to_string(),
        None => format!("secure connection to {host} failed{}", detail(display, debug)),
    }
}

fn problem(display: &str, debug: &str) -> Option<Problem> {
    let both = format!("{display}\n{debug}");
    let by_code = codes(&both).find_map(|c| CODES.iter().find(|(k, _)| *k == c).map(|(_, p)| *p));
    if by_code.is_some() {
        return by_code;
    }
    let lower = both.to_ascii_lowercase();
    TEXTS.iter().find(|(t, _)| lower.contains(*t)).map(|(_, p)| *p)
}

/// `" (detail)"` for a TLS failure without a line of its own, or nothing:
/// the OS error number on macOS and Windows, OpenSSL's reason on Linux.
pub fn detail(display: &str, debug: &str) -> String {
    let both = format!("{display}\n{debug}");
    // OpenSSL's own numbers are positive; only the OS ones are negative.
    if let Some(code) = codes(&both).find(|c| *c < 0) {
        return if code < -1_000_000 {
            format!(" (error 0x{:08X})", code as i32 as u32)
        } else {
            format!(" (error {code})")
        };
    }
    // native-tls ends an OpenSSL failure with " (verify result)".
    let display = display.trim_end();
    if let Some(inner) = display.strip_suffix(')').and_then(|d| d.rsplit_once(" (")).map(|(_, inner)| inner) {
        if is_plain(inner) && !inner.contains("os error") {
            return format!(" ({inner})");
        }
    }
    let text = clean(display);
    if is_plain(&text) {
        format!(" ({text})")
    } else {
        String::new()
    }
}

/// Short, and only letters, digits, spaces and plain punctuation: no paths,
/// function names or library names.
fn is_plain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 80
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b" -(),'".contains(&b))
        && !s.to_ascii_lowercase().contains("ssl")
}

/// Signed numbers written after "code: " (Debug forms) or "os error " (std's
/// io::Error).
fn codes(text: &str) -> impl Iterator<Item = i64> + '_ {
    ["code: ", "os error "].into_iter().flat_map(move |marker| {
        text.match_indices(marker).filter_map(move |(i, m)| {
            let rest = &text[i + m.len()..];
            let end = rest
                .char_indices()
                .find(|&(j, c)| !(c.is_ascii_digit() || (j == 0 && c == '-')))
                .map_or(rest.len(), |(j, _)| j);
            rest[..end].parse::<i64>().ok()
        })
    })
}

/// OpenSSL error entries ("error:0A000126:SSL routines::unexpected eof while
/// reading:../ssl/record/rec_layer_s3.c:303:") cut down to their reason
/// ("unexpected eof while reading"). Everything else is kept as it is.
pub fn clean(text: &str) -> String {
    const MARK: &str = "error:";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(MARK) {
        out.push_str(&rest[..i]);
        let entry = &rest[i + MARK.len()..];
        // code:library:function:reason:file:line:data
        let fields: Vec<&str> = entry.splitn(7, ':').collect();
        let openssl = fields.len() == 7
            && fields[0].len() == 8
            && fields[0].bytes().all(|b| b.is_ascii_hexdigit())
            && !fields[5].is_empty()
            && fields[5].bytes().all(|b| b.is_ascii_digit());
        if !openssl {
            out.push_str(MARK);
            rest = entry;
            continue;
        }
        out.push_str(fields[3]);
        // The data field runs to the next entry (", error:...") or to
        // native-tls's " (verify result)".
        let tail = fields[6];
        let end = [", ", " ("].iter().filter_map(|s| tail.find(*s)).min().unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// A TCP connect failure. The address is named only when `host` is a name.
pub fn connect_error(host: &str, port: u16, addr: &SocketAddr, why: &str) -> String {
    if host.parse::<IpAddr>().is_ok() {
        format!("cannot connect to {host} port {port}: {why}")
    } else {
        format!("cannot connect to {host} port {port} ({}): {why}", addr.ip())
    }
}
