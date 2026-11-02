//! Credentials: where they come from, how they are held, how they render.
//!
//! Three rules, each a type rather than a convention:
//!
//! * A credential is read from a file, never from argv or the environment,
//!   so a secret never sits in a process listing, and it is read **when it
//!   is needed**: the user file and the password file on every call. A
//!   rotated password is picked up on the next call.
//! * Every secret lives in a [`Zeroizing<String>`] from the moment it is
//!   read. Nothing here implements `Display` for a secret, and the `Debug`
//!   impls redact.
//! * A credential's *shape* is the enum [`Credential`]. The one legal form
//!   is named once, in [`LEGAL_CREDENTIAL_FORMS`], so a `blind` answer can
//!   quote it instead of describing it.
//!
//! ClickHouse accepts the pair as the `X-ClickHouse-User` and
//! `X-ClickHouse-Key` request headers; [`AuthHeaders`] holds both in
//! zeroizing memory.

use std::fmt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// The credential form lanterna accepts, spelled as the flags that supply
/// it. Quoted verbatim in refusals and blind answers.
pub const LEGAL_CREDENTIAL_FORMS: [&str; 1] = [
    "--user-file <PATH> --password-file <PATH> (a ClickHouse user and password, sent as the X-ClickHouse-User and X-ClickHouse-Key headers)",
];

/// How lanterna authenticates, chosen once at startup and read at call time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// The user name and the password, each in its own file.
    Password {
        /// File holding the ClickHouse user name.
        user_file: PathBuf,
        /// File holding the password.
        password_file: PathBuf,
    },
    /// No credential was configured. The server still starts; every tool
    /// answers `blind` naming [`LEGAL_CREDENTIAL_FORMS`].
    None,
}

/// Why a credential could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The file could not be read. The path is named so the remedy is obvious.
    #[error("credential file {path} could not be read: {source}")]
    Unreadable {
        /// The file that was asked for.
        path: PathBuf,
        /// The OS's reason.
        #[source]
        source: std::io::Error,
    },
    /// The file was readable but held nothing after trimming line endings.
    #[error("credential file {path} is empty")]
    Empty {
        /// The file that was asked for.
        path: PathBuf,
    },
    /// No credential was configured at all.
    #[error("no credential configured; pass one of: {}", LEGAL_CREDENTIAL_FORMS.join(" | "))]
    Absent,
}

/// Read one secret file into zeroizing memory, trimming trailing line
/// endings (a file written by `echo` carries one).
///
/// Only `\n` / `\r` are trimmed, and only at the end: a password with
/// deliberate leading or trailing spaces survives intact.
pub fn read_secret(path: &Path) -> Result<Zeroizing<String>, CredentialError> {
    let raw = std::fs::read_to_string(path).map_err(|source| CredentialError::Unreadable {
        path: path.to_path_buf(),
        source,
    })?;
    let mut raw = Zeroizing::new(raw);
    let keep = raw.trim_end_matches(['\n', '\r']).len();
    raw.truncate(keep);
    if raw.is_empty() {
        return Err(CredentialError::Empty {
            path: path.to_path_buf(),
        });
    }
    Ok(raw)
}

/// The user and the key as the two request headers carry them, held in
/// zeroizing memory. `Debug` redacts both.
#[derive(Clone)]
pub struct AuthHeaders {
    user: Zeroizing<String>,
    key: Zeroizing<String>,
}

impl AuthHeaders {
    /// Wrap the two secrets. They move in, so the caller keeps no plain copy.
    #[must_use]
    pub const fn new(user: Zeroizing<String>, key: Zeroizing<String>) -> Self {
        Self { user, key }
    }

    /// Read both files now.
    pub fn read(user_file: &Path, password_file: &Path) -> Result<Self, CredentialError> {
        Ok(Self::new(
            read_secret(user_file)?,
            read_secret(password_file)?,
        ))
    }

    /// The `X-ClickHouse-User` value.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The `X-ClickHouse-Key` value.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }
}

impl fmt::Debug for AuthHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthHeaders(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn file_with(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(bytes).expect("write");
        f
    }

    #[test]
    fn a_trailing_newline_is_trimmed_but_inner_whitespace_is_kept() {
        let f = file_with(b" p4ss word \n");
        assert_eq!(
            read_secret(f.path()).expect("reads").as_str(),
            " p4ss word "
        );
        let crlf = file_with(b"tok\r\n");
        assert_eq!(read_secret(crlf.path()).expect("reads").as_str(), "tok");
        let bare = file_with(b"tok");
        assert_eq!(read_secret(bare.path()).expect("reads").as_str(), "tok");
    }

    #[test]
    fn an_empty_or_missing_file_is_a_typed_error_naming_the_path() {
        let empty = file_with(b"\n");
        let err = read_secret(empty.path()).expect_err("empty");
        assert!(matches!(err, CredentialError::Empty { .. }));
        assert!(
            err.to_string()
                .contains(&empty.path().display().to_string())
        );

        let missing = Path::new("/definitely/not/here/lanterna-secret");
        let err = read_secret(missing).expect_err("missing");
        assert!(matches!(err, CredentialError::Unreadable { .. }));
        assert!(
            err.to_string()
                .contains("/definitely/not/here/lanterna-secret")
        );
    }

    #[test]
    fn the_headers_hold_both_secrets_and_debug_redacts() {
        let user = file_with(b"observer\n");
        let key = file_with(b"hunter2\n");
        let headers = AuthHeaders::read(user.path(), key.path()).expect("reads");
        assert_eq!(headers.user(), "observer");
        assert_eq!(headers.key(), "hunter2");
        let shown = format!("{headers:?}");
        assert!(
            !shown.contains("observer") && !shown.contains("hunter2"),
            "{shown}"
        );
    }

    #[test]
    fn the_absent_credential_names_the_legal_form() {
        let msg = CredentialError::Absent.to_string();
        for form in LEGAL_CREDENTIAL_FORMS {
            assert!(msg.contains(form), "{msg}");
        }
    }
}
