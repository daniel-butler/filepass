//! Single-range `Range` header parsing.

/// The outcome of parsing a `Range` header against a file of a known size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeDecision {
    /// Serve the whole file with `200`.
    Full,
    /// Serve `start..=end` (inclusive) with `206`.
    Partial { start: u64, end: u64 },
    /// `416`: the range cannot be satisfied.
    Unsatisfiable,
}

/// Parses a single-range `Range` header against a file of `size` bytes, per
/// the spec: the forms are `bytes=a-b`, `bytes=a-`, and `bytes=-n`. A
/// missing header, a malformed header, a multi-range header, or any `Range`
/// on an empty file is `Full`. A start at or beyond the size of a non-empty
/// file, or a suffix length of zero, is `Unsatisfiable`. An end beyond the
/// last byte is clamped.
pub fn decide(header: Option<&str>, size: u64) -> RangeDecision {
    let Some(header) = header else {
        return RangeDecision::Full;
    };
    if size == 0 {
        return RangeDecision::Full;
    }
    let Some(spec) = header.strip_prefix("bytes=") else {
        return RangeDecision::Full;
    };
    if spec.contains(',') {
        return RangeDecision::Full;
    }
    let Some((start_s, end_s)) = spec.split_once('-') else {
        return RangeDecision::Full;
    };

    if start_s.is_empty() {
        // Suffix form: bytes=-n
        if end_s.is_empty() {
            return RangeDecision::Full;
        }
        let Ok(n) = end_s.parse::<u64>() else {
            return RangeDecision::Full;
        };
        if n == 0 {
            return RangeDecision::Unsatisfiable;
        }
        let start = size.saturating_sub(n);
        return RangeDecision::Partial {
            start,
            end: size - 1,
        };
    }

    let Ok(start) = start_s.parse::<u64>() else {
        return RangeDecision::Full;
    };

    if end_s.is_empty() {
        // bytes=a-
        if start >= size {
            return RangeDecision::Unsatisfiable;
        }
        return RangeDecision::Partial {
            start,
            end: size - 1,
        };
    }

    let Ok(end) = end_s.parse::<u64>() else {
        return RangeDecision::Full;
    };
    if start > end {
        // Inverted range is malformed.
        return RangeDecision::Full;
    }
    if start >= size {
        return RangeDecision::Unsatisfiable;
    }
    RangeDecision::Partial {
        start,
        end: end.min(size - 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_when_absent_or_malformed_or_multi() {
        assert_eq!(decide(None, 10), RangeDecision::Full);
        assert_eq!(decide(Some("bytes=x"), 10), RangeDecision::Full);
        assert_eq!(decide(Some("items=0-1"), 10), RangeDecision::Full);
        assert_eq!(decide(Some("bytes=0-1,3-4"), 10), RangeDecision::Full);
    }

    #[test]
    fn empty_file_always_full() {
        assert_eq!(decide(Some("bytes=0-"), 0), RangeDecision::Full);
        assert_eq!(decide(Some("bytes=0-0"), 0), RangeDecision::Full);
    }

    #[test]
    fn forms() {
        assert_eq!(
            decide(Some("bytes=2-5"), 10),
            RangeDecision::Partial { start: 2, end: 5 }
        );
        assert_eq!(
            decide(Some("bytes=7-"), 10),
            RangeDecision::Partial { start: 7, end: 9 }
        );
        assert_eq!(
            decide(Some("bytes=-3"), 10),
            RangeDecision::Partial { start: 7, end: 9 }
        );
        assert_eq!(
            decide(Some("bytes=-50"), 10),
            RangeDecision::Partial { start: 0, end: 9 }
        );
        assert_eq!(
            decide(Some("bytes=8-99"), 10),
            RangeDecision::Partial { start: 8, end: 9 }
        );
    }

    #[test]
    fn unsatisfiable() {
        assert_eq!(decide(Some("bytes=10-"), 10), RangeDecision::Unsatisfiable);
        assert_eq!(
            decide(Some("bytes=12-14"), 10),
            RangeDecision::Unsatisfiable
        );
    }

    #[test]
    fn inverted_is_malformed() {
        assert_eq!(decide(Some("bytes=5-2"), 10), RangeDecision::Full);
    }

    #[test]
    fn zero_suffix_is_unsatisfiable() {
        assert_eq!(decide(Some("bytes=-0"), 10), RangeDecision::Unsatisfiable);
    }
}
