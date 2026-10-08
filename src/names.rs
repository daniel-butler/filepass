//! Filename decoding and validation, and the URL-safe and
//! `Content-Disposition` forms derived from a validated name.

use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};

/// Why a raw filename segment was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    /// The decoded name is empty.
    Empty,
    /// The percent-decoded bytes are not valid UTF-8.
    InvalidUtf8,
    /// The name is `.` or `..`.
    Dot,
    /// The name contains `/` or `\`.
    Separator,
    /// The name contains a C0, DEL, C1, or bidi control character.
    Control,
    /// The name exceeds 255 bytes.
    TooLong,
}

const MAX_NAME_BYTES: usize = 255;

/// True for a C0 control (U+0000-U+001F), DEL (U+007F), a C1 control
/// (U+0080-U+009F), or a bidi control (U+200E, U+200F, U+202A-U+202E,
/// U+2066-U+2069).
fn is_forbidden_control(c: char) -> bool {
    let cp = c as u32;
    matches!(cp, 0x00..=0x1F | 0x7F | 0x80..=0x9F)
        || matches!(cp, 0x200E | 0x200F)
        || matches!(cp, 0x202A..=0x202E)
        || matches!(cp, 0x2066..=0x2069)
}

/// Percent-decodes `raw_segment`, then validates it as a filename per the
/// spec: valid UTF-8, not `.` or `..`, no `/` or `\`, no control or bidi
/// characters, and at most 255 bytes.
pub fn decode_filename(raw_segment: &str) -> Result<String, NameError> {
    let decoded = percent_encoding::percent_decode_str(raw_segment)
        .decode_utf8()
        .map_err(|_| NameError::InvalidUtf8)?;
    let name = decoded.into_owned();

    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name == "." || name == ".." {
        return Err(NameError::Dot);
    }
    if name.contains('/') || name.contains('\\') {
        return Err(NameError::Separator);
    }
    if name.chars().any(is_forbidden_control) {
        return Err(NameError::Control);
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(NameError::TooLong);
    }
    Ok(name)
}

/// Derives the URL-safe form of `name`: every character outside
/// `[A-Za-z0-9._+-]` becomes a single `_`, one per character (not per byte).
pub fn url_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// RFC 5987 `attr-char` is `ALPHA / DIGIT / "!" / "#" / "$" / "&" / "+" /
/// "-" / "." / "^" / "_" / "`" / "|" / "~"`. `NON_ALPHANUMERIC` percent-
/// encodes every byte except ASCII letters and digits; removing the extra
/// `attr-char` punctuation from it leaves exactly the bytes RFC 5987
/// requires to be escaped.
const ATTR_CHAR_EXTRAS: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'!')
    .remove(b'#')
    .remove(b'$')
    .remove(b'&')
    .remove(b'+')
    .remove(b'-')
    .remove(b'.')
    .remove(b'^')
    .remove(b'_')
    .remove(b'`')
    .remove(b'|')
    .remove(b'~');

/// Builds the `Content-Disposition` header value for a download: the
/// URL-safe `urlname` as the plain `filename`, and the original `name`
/// percent-encoded per RFC 5987 as `filename*`.
pub fn content_disposition(name: &str, urlname: &str) -> String {
    let encoded = utf8_percent_encode(name, ATTR_CHAR_EXTRAS);
    format!("attachment; filename=\"{urlname}\"; filename*=UTF-8''{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        assert_eq!(decode_filename("build.zip"), Ok("build.zip".to_string()));
        assert_eq!(
            decode_filename("my%20file.zip"),
            Ok("my file.zip".to_string())
        );
        assert_eq!(
            decode_filename("r%C3%A9sum%C3%A9.pdf"),
            Ok("résumé.pdf".to_string())
        );
    }

    #[test]
    fn accepts_255_byte_name() {
        let name = "a".repeat(255);
        assert_eq!(decode_filename(&name), Ok(name));
    }

    #[test]
    fn rejects() {
        let cases: &[(&str, NameError)] = &[
            ("", NameError::Empty),
            (".", NameError::Dot),
            ("..", NameError::Dot),
            ("a%2Fb", NameError::Separator),
            ("a%5Cb", NameError::Separator),
            ("%FF", NameError::InvalidUtf8),
            ("a%00b", NameError::Control),
            ("a%7Fb", NameError::Control),
            ("a%C2%85b", NameError::Control),
            ("a%E2%80%AEb", NameError::Control),
            ("a%E2%81%A6b", NameError::Control),
        ];
        for (raw, expected) in cases {
            assert_eq!(decode_filename(raw), Err(*expected), "raw segment {raw:?}");
        }

        let too_long = "a".repeat(256);
        assert_eq!(decode_filename(&too_long), Err(NameError::TooLong));
    }

    #[test]
    fn url_name_examples() {
        assert_eq!(url_name("my file.zip"), "my_file.zip");
        assert_eq!(url_name("résumé.pdf"), "r_sum_.pdf");
        assert_eq!(url_name("a+b-c_d.e"), "a+b-c_d.e");
    }

    #[test]
    fn content_disposition_encodes_original() {
        let name = "my file.zip";
        let urlname = url_name(name);
        assert_eq!(
            content_disposition(name, &urlname),
            "attachment; filename=\"my_file.zip\"; filename*=UTF-8''my%20file.zip"
        );
    }
}
