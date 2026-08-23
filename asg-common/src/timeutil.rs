//! Timestamp formatting without external date crates.

/// Converts nanoseconds since the UNIX epoch to an RFC 3339 UTC string.
///
/// Sub-second precision is truncated. Implements the civil-from-days
/// algorithm (Hinnant) inline so no chrono dependency is required.
pub fn ts_ns_to_rfc3339(ts_ns: u64) -> String {
    let secs = (ts_ns / 1_000_000_000) as i64;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month,
        day,
        sod / 3_600,
        (sod % 3_600) / 60,
        sod % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 -> (y, m, d).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    ((if m <= 2 { y + 1 } else { y }), m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch() {
        assert_eq!(ts_ns_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(ts_ns_to_rfc3339(999_999_999), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_vector_2026() {
        let ns: u64 = 1_787_356_800 * 1_000_000_000;
        assert_eq!(ts_ns_to_rfc3339(ns), "2026-08-22T00:00:00Z");
    }

    #[test]
    fn known_vector_leap_day() {
        let ns: u64 = 1_709_208_000 * 1_000_000_000;
        assert_eq!(ts_ns_to_rfc3339(ns), "2024-02-29T12:00:00Z");
    }

    #[test]
    fn known_vector_millennium() {
        let ns: u64 = 946_684_800 * 1_000_000_000;
        assert_eq!(ts_ns_to_rfc3339(ns), "2000-01-01T00:00:00Z");
    }

    #[test]
    fn intraday_components() {
        let ns: u64 = (20_687 * 86_400 + 23 * 3_600 + 4 * 60 + 59) * 1_000_000_000;
        assert_eq!(ts_ns_to_rfc3339(ns), "2026-08-22T23:04:59Z");
    }
}
