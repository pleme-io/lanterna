//! What a ClickHouse exception says, read from the two places it appears.
//!
//! The server reports a failure as a non-2xx status, an
//! `X-ClickHouse-Exception-Code` header, and a plain-text body that starts
//! `Code: <n>. DB::Exception: …`. The numeric code is the stable fact; the
//! status is not (an unknown table is a `404`, a timeout a `500`). So the
//! code is read first, and only an exception with no code falls back to
//! `handan`'s reading of the status.

use crate::transport::HttpResponse;

const MESSAGE_MAX_BYTES: usize = 400;

/// The exception codes lanterna gives a meaning to. Anything else is
/// [`Known::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Known {
    /// 16, 47: a column the table or the statement does not have.
    UnknownColumn,
    /// 60: a table that does not exist.
    UnknownTable,
    /// 81: a database that does not exist.
    UnknownDatabase,
    /// 159: `max_execution_time` was exceeded.
    TimeoutExceeded,
    /// 164: the server refused a write or a setting change in `readonly` mode.
    Readonly,
    /// 192, 193, 194, 516: the credential was not accepted.
    AuthenticationFailed,
    /// 497: the user lacks the privilege.
    AccessDenied,
    /// Any other code, or none.
    Other,
}

impl Known {
    const fn of(code: u16) -> Self {
        match code {
            16 | 47 => Self::UnknownColumn,
            60 => Self::UnknownTable,
            81 => Self::UnknownDatabase,
            159 => Self::TimeoutExceeded,
            164 => Self::Readonly,
            192..=194 | 516 => Self::AuthenticationFailed,
            497 => Self::AccessDenied,
            _ => Self::Other,
        }
    }
}

/// An exception read off a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exception {
    /// The numeric code, when the server sent one.
    pub code: Option<u16>,
    /// What the code means to lanterna.
    pub known: Known,
    /// The first line of the body, bounded.
    pub message: String,
}

impl Exception {
    /// Read the exception from a response: the header first, then the
    /// `Code: <n>.` prefix of the body.
    #[must_use]
    pub fn of(resp: &HttpResponse) -> Self {
        let text = String::from_utf8_lossy(&resp.body);
        let first = text.lines().next().unwrap_or_default().trim();
        let from_header = resp
            .exception_code
            .as_deref()
            .and_then(|c| c.trim().parse::<u16>().ok());
        let from_body = first
            .strip_prefix("Code: ")
            .and_then(|rest| rest.split(['.', ' ']).next())
            .and_then(|digits| digits.parse::<u16>().ok());
        let code = from_header.or(from_body);
        let mut message = first.to_owned();
        if message.len() > MESSAGE_MAX_BYTES {
            let mut end = MESSAGE_MAX_BYTES;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        Self {
            code,
            known: code.map_or(Known::Other, Known::of),
            message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, header: Option<&str>, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            retry_after: None,
            exception_code: header.map(str::to_owned),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn the_header_wins_and_the_body_prefix_is_the_fallback() {
        let both = Exception::of(&resp(404, Some("60"), "Code: 81. DB::Exception: x"));
        assert_eq!(both.code, Some(60));
        assert_eq!(both.known, Known::UnknownTable);
        let body = Exception::of(&resp(
            500,
            None,
            "Code: 159. DB::Exception: too slow\nstack",
        ));
        assert_eq!(body.code, Some(159));
        assert_eq!(body.known, Known::TimeoutExceeded);
        assert_eq!(body.message, "Code: 159. DB::Exception: too slow");
        let none = Exception::of(&resp(502, None, "<html>bad gateway</html>"));
        assert_eq!(none.code, None);
        assert_eq!(none.known, Known::Other);
    }

    #[test]
    fn every_known_code_maps_to_its_meaning() {
        for (code, known) in [
            (16, Known::UnknownColumn),
            (47, Known::UnknownColumn),
            (60, Known::UnknownTable),
            (81, Known::UnknownDatabase),
            (159, Known::TimeoutExceeded),
            (164, Known::Readonly),
            (192, Known::AuthenticationFailed),
            (193, Known::AuthenticationFailed),
            (516, Known::AuthenticationFailed),
            (497, Known::AccessDenied),
            (62, Known::Other),
        ] {
            assert_eq!(Known::of(code), known, "{code}");
        }
    }

    #[test]
    fn a_long_or_non_ascii_message_is_bounded_on_a_char_boundary() {
        let long = "é".repeat(500);
        let e = Exception::of(&resp(400, None, &long));
        assert!(e.message.len() <= MESSAGE_MAX_BYTES);
        assert!(e.message.chars().all(|c| c == 'é'));
    }
}
