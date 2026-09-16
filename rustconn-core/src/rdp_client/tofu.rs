//! Trust-on-first-use (TOFU) certificate store for the embedded IronRDP client.
//!
//! IronRDP does not validate the server certificate against a CA store — most
//! RDP servers use a self-signed certificate, so CA validation would reject
//! every one of them. Instead this module implements the same trust model SSH
//! uses for host keys: the first time a host is seen its certificate
//! fingerprint is recorded, and every later connection is checked against the
//! stored value. A changed fingerprint means either a legitimate certificate
//! rotation or a man-in-the-middle, and the caller must ask the user which.
//!
//! The store is a plain-text file in RustConn's own config directory, one line
//! per `(host, port)`, deliberately separate from FreeRDP's `known_hosts2` —
//! the external FreeRDP client keeps its own TOFU store, and the two must not
//! read or write each other's entries.
//!
//! # File format
//!
//! ```text
//! host port sha256hexfingerprint
//! ```
//!
//! Fields are whitespace-separated; the fingerprint is the lowercase hex
//! SHA-256 of the DER-encoded server certificate. Lines that do not parse are
//! skipped, so a corrupt entry degrades to "first use" rather than a hard
//! failure.

use std::path::PathBuf;

use thiserror::Error;

/// Name of the TOFU store file inside RustConn's config directory.
const STORE_FILE_NAME: &str = "ironrdp_known_hosts";

/// Errors raised while reading or updating the IronRDP TOFU store.
#[derive(Debug, Error)]
pub enum TofuError {
    /// The config directory could not be determined (no `$HOME`/`$XDG_CONFIG_HOME`).
    #[error("cannot determine the configuration directory for the certificate store")]
    NoConfigDir,

    /// Reading or writing the store file failed.
    #[error("certificate store I/O error at {path}: {source}")]
    Io {
        /// Store path that was being accessed.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
}

/// Outcome of checking a server certificate against the TOFU store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TofuVerdict {
    /// The host was not in the store; the fingerprint has now been recorded.
    FirstUse,

    /// The stored fingerprint matches the presented certificate.
    Match,

    /// The stored fingerprint differs from the presented certificate.
    ///
    /// The store is left unchanged — accepting the new certificate is an
    /// explicit user decision made through [`store_fingerprint`].
    Changed {
        /// Fingerprint recorded on a previous connection.
        stored: String,
    },
}

/// Computes the lowercase hex SHA-256 fingerprint of a DER certificate.
///
/// This is the value stored and compared by the TOFU functions. The input is
/// the raw DER bytes as returned by `ironrdp_tls::upgrade`.
#[must_use]
pub fn fingerprint_certificate(der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    hex::encode(digest.as_ref())
}

/// Returns the path to the IronRDP TOFU store file.
///
/// # Errors
///
/// Returns [`TofuError::NoConfigDir`] when no configuration directory can be
/// determined for the current user.
pub fn store_path() -> Result<PathBuf, TofuError> {
    let dir = dirs::config_dir().ok_or(TofuError::NoConfigDir)?;
    Ok(dir.join("rustconn").join(STORE_FILE_NAME))
}

/// Checks a certificate fingerprint against the store, recording it on first use.
///
/// On [`TofuVerdict::FirstUse`] the fingerprint is written to the store before
/// returning, so a subsequent connection to the same host sees
/// [`TofuVerdict::Match`]. On a mismatch the store is left untouched: accepting
/// the new certificate is a separate, explicit step via [`store_fingerprint`].
///
/// # Errors
///
/// Returns [`TofuError::NoConfigDir`] if the store location cannot be resolved,
/// or [`TofuError::Io`] if the store cannot be read or (on first use) written.
pub fn verify_or_store(host: &str, port: u16, fingerprint: &str) -> Result<TofuVerdict, TofuError> {
    let path = store_path()?;
    match read_fingerprint(&path, host, port)? {
        Some(stored) if stored == fingerprint => Ok(TofuVerdict::Match),
        Some(stored) => Ok(TofuVerdict::Changed { stored }),
        None => {
            write_fingerprint(&path, host, port, fingerprint)?;
            Ok(TofuVerdict::FirstUse)
        }
    }
}

/// Stores (or replaces) the fingerprint for a host.
///
/// Called when the user has explicitly accepted a new certificate after a
/// [`TofuVerdict::Changed`] result, so the next connection trusts it.
///
/// # Errors
///
/// Returns [`TofuError::NoConfigDir`] if the store location cannot be resolved,
/// or [`TofuError::Io`] if the store cannot be read or written.
pub fn store_fingerprint(host: &str, port: u16, fingerprint: &str) -> Result<(), TofuError> {
    let path = store_path()?;
    write_fingerprint(&path, host, port, fingerprint)
}

/// Removes the stored fingerprint for a host, if present.
///
/// Returns `true` when an entry was removed. Equivalent to deleting a line from
/// SSH `known_hosts`: the next connection is treated as first use.
///
/// # Errors
///
/// Returns [`TofuError::NoConfigDir`] if the store location cannot be resolved,
/// or [`TofuError::Io`] if the store cannot be read or written.
pub fn forget(host: &str, port: u16) -> Result<bool, TofuError> {
    let path = store_path()?;
    forget_at(&path, host, port)
}

/// Reads the stored fingerprint for `(host, port)` from `path`.
///
/// Returns `None` when the file does not exist or has no matching line. Lines
/// that do not parse are skipped rather than treated as an error.
fn read_fingerprint(
    path: &std::path::Path,
    host: &str,
    port: u16,
) -> Result<Option<String>, TofuError> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(TofuError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    Ok(content.lines().find_map(|line| {
        let (line_host, line_port, fingerprint) = parse_line(line)?;
        (line_host == host && line_port == port).then(|| fingerprint.to_owned())
    }))
}

/// Writes (creating or replacing) the fingerprint for `(host, port)` at `path`.
fn write_fingerprint(
    path: &std::path::Path,
    host: &str,
    port: u16,
    fingerprint: &str,
) -> Result<(), TofuError> {
    let mut lines = read_all_except(path, host, port)?;
    lines.push(format!("{host} {port} {fingerprint}"));
    write_all(path, &lines)
}

/// Removes the `(host, port)` entry at `path`; returns whether one was present.
fn forget_at(path: &std::path::Path, host: &str, port: u16) -> Result<bool, TofuError> {
    let existed = read_fingerprint(path, host, port)?.is_some();
    if !existed {
        return Ok(false);
    }
    let lines = read_all_except(path, host, port)?;
    write_all(path, &lines)?;
    Ok(true)
}

/// Reads every store line except the one matching `(host, port)`.
///
/// Malformed lines are preserved verbatim so an unrelated entry is never lost
/// while rewriting the file.
fn read_all_except(
    path: &std::path::Path,
    host: &str,
    port: u16,
) -> Result<Vec<String>, TofuError> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(TofuError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    Ok(content
        .lines()
        .filter(|line| match parse_line(line) {
            Some((line_host, line_port, _)) => !(line_host == host && line_port == port),
            None => !line.trim().is_empty(),
        })
        .map(str::to_owned)
        .collect())
}

/// Writes all `lines` to `path`, creating the parent directory if needed.
fn write_all(path: &std::path::Path, lines: &[String]) -> Result<(), TofuError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| TofuError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let mut body = lines.join("\n");
    body.push('\n');
    std::fs::write(path, body).map_err(|source| TofuError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Parses one store line into `(host, port, fingerprint)`.
///
/// Returns `None` for blank lines, comments, or lines whose port field is not a
/// valid `u16`, so a malformed entry degrades to "first use".
fn parse_line(line: &str) -> Option<(&str, u16, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut fields = line.split_whitespace();
    let host = fields.next()?;
    let port = fields.next()?.parse::<u16>().ok()?;
    let fingerprint = fields.next()?;
    Some((host, port, fingerprint))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ironrdp_known_hosts");
        (dir, path)
    }

    #[test]
    fn fingerprint_is_stable_lowercase_hex_sha256() {
        // SHA-256 of the empty input, a known vector.
        let fp = fingerprint_certificate(b"");
        assert_eq!(
            fp,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(fp, fp.to_lowercase());
    }

    #[test]
    fn first_use_records_then_matches() {
        let (_dir, path) = tmp_store();
        assert!(read_fingerprint(&path, "host.example.com", 3389).unwrap().is_none());

        write_fingerprint(&path, "host.example.com", 3389, "aabb").unwrap();
        assert_eq!(
            read_fingerprint(&path, "host.example.com", 3389).unwrap(),
            Some("aabb".to_owned())
        );
    }

    #[test]
    fn replacing_a_fingerprint_does_not_duplicate_the_host() {
        let (_dir, path) = tmp_store();
        write_fingerprint(&path, "h", 3389, "old").unwrap();
        write_fingerprint(&path, "h", 3389, "new").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().filter(|l| l.starts_with("h ")).count(), 1);
        assert_eq!(
            read_fingerprint(&path, "h", 3389).unwrap(),
            Some("new".to_owned())
        );
    }

    #[test]
    fn different_port_is_a_different_entry() {
        let (_dir, path) = tmp_store();
        write_fingerprint(&path, "h", 3389, "a").unwrap();
        write_fingerprint(&path, "h", 3390, "b").unwrap();

        assert_eq!(read_fingerprint(&path, "h", 3389).unwrap(), Some("a".to_owned()));
        assert_eq!(read_fingerprint(&path, "h", 3390).unwrap(), Some("b".to_owned()));
    }

    #[test]
    fn forget_removes_only_the_matching_entry() {
        let (_dir, path) = tmp_store();
        write_fingerprint(&path, "keep.example.com", 3389, "k").unwrap();
        write_fingerprint(&path, "drop.example.com", 3389, "d").unwrap();

        assert!(forget_at(&path, "drop.example.com", 3389).unwrap());
        assert!(!forget_at(&path, "drop.example.com", 3389).unwrap());

        assert!(read_fingerprint(&path, "drop.example.com", 3389).unwrap().is_none());
        assert_eq!(
            read_fingerprint(&path, "keep.example.com", 3389).unwrap(),
            Some("k".to_owned())
        );
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let (_dir, path) = tmp_store();
        std::fs::write(
            &path,
            "# a comment\nnot-enough-fields\nhost badport fp\nvalid.example.com 3389 goodfp\n",
        )
        .unwrap();

        assert_eq!(
            read_fingerprint(&path, "valid.example.com", 3389).unwrap(),
            Some("goodfp".to_owned())
        );
    }

    #[test]
    fn rewriting_preserves_unparseable_lines() {
        // A comment line must survive a write to an unrelated host.
        let (_dir, path) = tmp_store();
        std::fs::write(&path, "# keep me\nother 3389 x\n").unwrap();

        write_fingerprint(&path, "new", 3389, "y").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("# keep me"));
        assert!(content.contains("other 3389 x"));
        assert!(content.contains("new 3389 y"));
    }
}
