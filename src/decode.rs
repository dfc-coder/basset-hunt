use std::ops::Range;

use base64::engine::general_purpose::{STANDARD_PAD_INDIFFERENT, URL_SAFE_PAD_INDIFFERENT};
use base64::{DecodeSliceError, Engine as _};

pub(crate) const MAX_DECODED_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_BASE64_SEGMENTS: usize = 4096;
const MIN_BASE64_CHARS: usize = 16;
const SEPARATOR: u8 = b'\n';

pub(crate) struct Segment {
    pub(crate) decoded_range: Range<usize>,
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) column_utf16: usize,
}

pub(crate) struct Document {
    pub(crate) bytes: Vec<u8>,
    pub(crate) segments: Vec<Segment>,
    pub(crate) truncated: bool,
}

#[derive(Clone, Copy)]
struct Position {
    line: usize,
    column: usize,
    column_utf16: usize,
    utf8_remaining: u8,
}

impl Position {
    fn advance(&mut self, byte: u8) {
        if byte == b'\n' {
            self.line += 1;
            self.column = 1;
            self.column_utf16 = 1;
            self.utf8_remaining = 0;
        } else {
            self.column += 1;
            let width = if (0x80..=0xbf).contains(&byte) && self.utf8_remaining > 0 {
                self.utf8_remaining -= 1;
                0
            } else {
                self.utf8_remaining = match byte {
                    0xc2..=0xdf => 1,
                    0xe0..=0xef => 2,
                    0xf0..=0xf4 => 3,
                    _ => 0,
                };
                if (0xf0..=0xf4).contains(&byte) { 2 } else { 1 }
            };
            self.column_utf16 += width;
        }
    }

    fn after_ascii(self, bytes: usize) -> Self {
        Self {
            column: self.column + bytes,
            column_utf16: self.column_utf16 + bytes,
            utf8_remaining: 0,
            ..self
        }
    }
}

pub(crate) fn base64(input: &[u8]) -> Document {
    decode_with_limits(input, MAX_DECODED_BYTES, MAX_BASE64_SEGMENTS)
}

struct DecodeBuilder<'a> {
    input: &'a [u8],
    byte_limit: usize,
    segment_limit: usize,
    candidates: usize,
    decoded_bytes: usize,
    scratch: Vec<u8>,
    document: Document,
}

impl DecodeBuilder<'_> {
    fn try_candidate(&mut self, start: usize, end: usize, position: Position) -> bool {
        if end - start < MIN_BASE64_CHARS {
            return true;
        }
        let remaining = self.byte_limit.saturating_sub(self.decoded_bytes);
        let output_limit = remaining.saturating_add(2);
        let estimate = base64::decoded_len_estimate(end - start);
        let output_len = estimate.min(output_limit);
        if self.scratch.len() < output_len {
            self.scratch.resize(output_len, 0);
        }

        let candidate = &self.input[start..end];
        let engine = if candidate.iter().any(|&byte| matches!(byte, b'-' | b'_')) {
            &URL_SAFE_PAD_INDIFFERENT
        } else {
            &STANDARD_PAD_INDIFFERENT
        };
        let decoded_len = match engine.decode_slice(candidate, &mut self.scratch[..output_len]) {
            Ok(decoded_len) => decoded_len,
            Err(DecodeSliceError::DecodeError(_)) => return true,
            Err(DecodeSliceError::OutputSliceTooSmall) => {
                self.document.truncated = true;
                return false;
            }
        };
        if decoded_len > remaining {
            self.document.truncated = true;
            return false;
        }

        if !looks_like_text(&self.scratch[..decoded_len]) {
            return true;
        }
        if self.candidates == self.segment_limit {
            self.document.truncated = true;
            return false;
        }
        self.candidates += 1;

        if !self.document.segments.is_empty() {
            self.document.bytes.push(SEPARATOR);
        }
        let decoded_start = self.document.bytes.len();
        self.document
            .bytes
            .extend_from_slice(&self.scratch[..decoded_len]);
        self.document.segments.push(Segment {
            decoded_range: decoded_start..self.document.bytes.len(),
            line: position.line,
            column: position.column,
            column_utf16: position.column_utf16,
        });
        self.decoded_bytes += decoded_len;
        true
    }
}

/// Hashes, fingerprints and identifiers are often valid Base64 but decode to
/// binary noise; only mostly-printable output can hold a detectable secret.
fn looks_like_text(bytes: &[u8]) -> bool {
    let printable = bytes
        .iter()
        .filter(|&&byte| matches!(byte, b'\n' | b'\r' | b'\t' | 0x20..=0x7e))
        .count();
    printable * 10 >= bytes.len() * 9
}

fn decode_with_limits(input: &[u8], byte_limit: usize, segment_limit: usize) -> Document {
    let mut builder = DecodeBuilder {
        input,
        byte_limit,
        segment_limit,
        candidates: 0,
        decoded_bytes: 0,
        scratch: Vec::new(),
        document: Document {
            bytes: Vec::new(),
            segments: Vec::new(),
            truncated: false,
        },
    };
    let mut position = Position {
        line: 1,
        column: 1,
        column_utf16: 1,
        utf8_remaining: 0,
    };
    let mut index = 0usize;

    while index < input.len() {
        if !is_base64_byte(input[index]) {
            position.advance(input[index]);
            index += 1;
            continue;
        }

        let run_start = index;
        let run_position = position;
        while index < input.len() && is_base64_byte(input[index]) {
            position.advance(input[index]);
            index += 1;
        }
        let run_end = index;
        let padding_end = match trailing_padding(input, run_end) {
            Padding::None => run_end,
            Padding::Valid(end) => end,
            Padding::Invalid => continue,
        };

        if !builder.try_candidate(run_start, padding_end, run_position) {
            break;
        }

        if input[run_start..run_end].contains(&b'/') {
            let mut component_start = run_start;
            for (offset, &byte) in input[run_start..run_end].iter().enumerate() {
                if byte != b'/' {
                    continue;
                }
                let slash = run_start + offset;
                if slash > component_start
                    && !builder.try_candidate(
                        component_start,
                        slash,
                        run_position.after_ascii(component_start - run_start),
                    )
                {
                    break;
                }
                component_start = slash + 1;
            }
            if builder.document.truncated {
                break;
            }
            if component_start < run_end
                && !builder.try_candidate(
                    component_start,
                    padding_end,
                    run_position.after_ascii(component_start - run_start),
                )
            {
                break;
            }
        }
    }

    builder.document
}

#[derive(Clone, Copy)]
enum Padding {
    None,
    Valid(usize),
    Invalid,
}

fn trailing_padding(input: &[u8], run_end: usize) -> Padding {
    let mut end = run_end;
    while end < input.len() && input[end] == b'=' {
        end += 1;
    }
    let count = end - run_end;
    if count == 0 || (end < input.len() && is_base64_byte(input[end])) {
        return Padding::None;
    }
    if count <= 2 {
        Padding::Valid(end)
    } else {
        Padding::Invalid
    }
}

fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'-' | b'_')
}

#[cfg(test)]
mod tests {
    use super::{MAX_BASE64_SEGMENTS, MAX_DECODED_BYTES, decode_with_limits};
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};

    fn decoded(bytes: &[u8]) -> Vec<Vec<u8>> {
        let document = super::base64(bytes);
        document
            .segments
            .iter()
            .map(|segment| document.bytes[segment.decoded_range.clone()].to_vec())
            .collect()
    }

    #[test]
    fn decodes_standard_and_url_safe_with_either_padding_form() {
        let standard = STANDARD.encode(b"synthetic token payload");
        let url_payload = b"\xfb\xff synthetic token payload";
        let url_safe = URL_SAFE.encode(url_payload);
        assert_eq!(
            decoded(standard.as_bytes()),
            vec![b"synthetic token payload".to_vec()]
        );
        assert_eq!(
            decoded(standard.trim_end_matches('=').as_bytes()),
            vec![b"synthetic token payload".to_vec()]
        );
        assert_eq!(decoded(url_safe.as_bytes()), vec![url_payload.to_vec()]);
        assert_eq!(
            decoded(url_safe.trim_end_matches('=').as_bytes()),
            vec![url_payload.to_vec()]
        );
    }

    #[test]
    fn finds_assignment_values_and_url_path_segments() {
        let standard = STANDARD.encode(b"synthetic token payload");
        let assignment = format!("TOKEN={standard}");
        let found = super::base64(assignment.as_bytes());
        assert_eq!(found.segments.len(), 1);
        assert_eq!(found.segments[0].column, 7);

        let url_payload = URL_SAFE.encode(b"synthetic token payload");
        let path = format!("host/path/{url_payload}");
        let found = super::base64(path.as_bytes());
        assert!(found.segments.iter().any(|segment| {
            found.bytes[segment.decoded_range.clone()] == *b"synthetic token payload"
                && segment.column == 11
        }));
    }

    #[test]
    fn maps_line_and_utf16_column_of_encoded_segment() {
        let encoded = STANDARD.encode(b"synthetic token payload");
        let input = format!("\u{1f600} TOKEN={encoded}");
        let found = super::base64(input.as_bytes());
        let segment = &found.segments[0];
        assert_eq!(segment.line, 1);
        assert_eq!(segment.column, 12);
        assert_eq!(segment.column_utf16, 10);
    }

    #[test]
    fn rejects_short_or_malformed_candidates() {
        assert!(decoded(b"abcdefghijklmno").is_empty());
        assert!(decoded(b"abcdefghijklmnop====").is_empty());
        assert!(decoded(b"abcdefghijklmnop=== ").is_empty());
    }

    #[test]
    fn byte_and_segment_limits_mark_partial_results() {
        let token = STANDARD.encode(b"synthetic token payload");
        let input = format!("{token} {token}");
        let by_bytes = decode_with_limits(input.as_bytes(), 23, 10);
        assert_eq!(by_bytes.segments.len(), 1);
        assert!(by_bytes.truncated);

        let by_segments = decode_with_limits(input.as_bytes(), MAX_DECODED_BYTES, 1);
        assert_eq!(by_segments.segments.len(), 1);
        assert!(by_segments.truncated);
        assert_eq!(MAX_BASE64_SEGMENTS, 4096);
    }

    #[test]
    fn derived_document_keeps_separate_segment_ranges() {
        let first = STANDARD.encode(b"first synthetic payload");
        let second = STANDARD.encode(b"second synthetic payload");
        let document = super::base64(format!("{first} {second}").as_bytes());
        assert_eq!(document.segments.len(), 2);
        assert_ne!(
            document.segments[0].decoded_range.end,
            document.segments[1].decoded_range.start
        );
        assert_eq!(
            document.bytes[document.segments[0].decoded_range.end],
            b'\n'
        );
        assert!(!document.truncated);
    }
}
