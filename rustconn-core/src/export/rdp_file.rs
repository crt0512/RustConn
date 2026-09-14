//! Microsoft `.rdp` file exporter.
//!
//! Exports RDP connections to the standard `.rdp` file format used by
//! Windows Remote Desktop (mstsc.exe), FreeRDP, and other RDP clients.
//!
//! # Format Reference
//!
//! The `.rdp` format uses `key:type:value` lines where type is:
//! - `s` — string
//! - `i` — integer
//! - `b` — binary (base64, not used here)
//!
//! See: <https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files>
//!
//! # Security
//!
//! Passwords are **never** exported. The `.rdp` format supports password hashing
//! (`password 51:b:...`) but it uses reversible encryption with a machine-specific
//! key (DPAPI), making it both insecure and non-portable. The user must enter
//! credentials manually when opening the exported file.

use std::fmt::Write as FmtWrite;
use std::path::Path;

use super::{
    ExportError, ExportFormat, ExportOperationResult, ExportOptions, ExportResult, ExportTarget,
    write_export_file,
};
use crate::models::{Connection, ConnectionGroup, ProtocolConfig, ProtocolType, RdpAudioMode};

/// The `.rdp` performance keys, named so the polarity is visible at the call site.
///
/// A bare tuple of six integers was how this started, and it shipped with two of
/// the three modes wrong: `disable wallpaper` was set for Quality and cleared for
/// Speed's neighbour. Named fields make that class of mistake readable.
struct PerformanceKeys {
    disable_wallpaper: u8,
    allow_font_smoothing: u8,
    allow_desktop_composition: u8,
    disable_full_window_drag: u8,
    disable_menu_anims: u8,
    disable_themes: u8,
    disable_cursor_setting: u8,
}

/// Microsoft `.rdp` file exporter.
///
/// Exports RDP connections to the standard `.rdp` file format.
/// Only RDP connections can be exported; other protocols are skipped.
pub struct RdpFileExporter;

impl RdpFileExporter {
    /// Creates a new `.rdp` file exporter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Exports a single RDP connection to `.rdp` file content.
    ///
    /// # Arguments
    ///
    /// * `connection` - The connection to export (must be RDP protocol)
    ///
    /// # Errors
    ///
    /// Returns `ExportError::UnsupportedProtocol` if the connection is not RDP.
    pub fn export_to_rdp_content(connection: &Connection) -> Result<String, ExportError> {
        if connection.protocol != ProtocolType::Rdp {
            return Err(ExportError::UnsupportedProtocol(format!(
                "{:?}",
                connection.protocol
            )));
        }

        let mut output = String::with_capacity(2048);

        // Header comment
        let _ = writeln!(output, "# RustConn RDP Export");
        let _ = writeln!(output, "# Connection: {}", connection.name);
        let _ = writeln!(output);

        // Required: full address (host:port)
        if connection.port == 3389 {
            let _ = writeln!(output, "full address:s:{}", connection.host);
        } else {
            let _ = writeln!(
                output,
                "full address:s:{}:{}",
                connection.host, connection.port
            );
        }

        // Username (without domain prefix — domain is separate)
        if let Some(ref username) = connection.username {
            let _ = writeln!(output, "username:s:{username}");
        }

        // Domain
        if let Some(ref domain) = connection.domain {
            let _ = writeln!(output, "domain:s:{domain}");
        }

        // RDP-specific settings
        if let ProtocolConfig::Rdp(ref rdp) = connection.protocol_config {
            Self::write_display_settings(&mut output, rdp);
            Self::write_performance_settings(&mut output, rdp);
            Self::write_redirection_settings(&mut output, rdp);
            Self::write_gateway_settings(&mut output, rdp);
            Self::write_security_settings(&mut output, rdp);
            Self::write_remoteapp_settings(&mut output, rdp);
        }

        // Common settings
        let _ = writeln!(output, "autoreconnection enabled:i:1");
        let _ = writeln!(output, "prompt for credentials:i:1");

        Ok(output)
    }

    /// Writes display-related settings.
    fn write_display_settings(output: &mut String, rdp: &crate::models::RdpConfig) {
        use crate::models::RdpDisplayMode;

        // Screen mode: 1 = windowed, 2 = fullscreen
        let screen_mode = match rdp.external_display_mode {
            RdpDisplayMode::Fullscreen | RdpDisplayMode::AllMonitors => 2,
            _ => 1,
        };
        let _ = writeln!(output, "screen mode id:i:{screen_mode}");

        // Resolution (only for custom mode)
        if let Some(ref resolution) = rdp.resolution {
            let _ = writeln!(output, "desktopwidth:i:{}", resolution.width);
            let _ = writeln!(output, "desktopheight:i:{}", resolution.height);
        }

        // Color depth
        let color_depth = rdp.effective_color_depth();
        let _ = writeln!(output, "session bpp:i:{color_depth}");

        // Multi-monitor
        if matches!(rdp.external_display_mode, RdpDisplayMode::AllMonitors) {
            let _ = writeln!(output, "use multimon:i:1");
        }
    }

    /// Writes performance-related settings.
    ///
    /// The three modes mirror `rdp_client::client::connection::build_performance_flags`,
    /// which is the definition RustConn's own sessions use. Note the polarity
    /// difference: `.rdp` spells four of these as `disable …` and two as
    /// `allow …`, so a mode that enables an effect writes `0` to one key and `1`
    /// to the other. Getting that backwards is invisible in a diff, which is why
    /// `performance_modes_match_the_session_flags` pins all three rows.
    fn write_performance_settings(output: &mut String, rdp: &crate::models::RdpConfig) {
        use crate::models::RdpPerformanceMode;

        let flags = match rdp.performance_mode {
            // Font smoothing and desktop composition on, nothing disabled.
            RdpPerformanceMode::Quality => PerformanceKeys {
                disable_wallpaper: 0,
                allow_font_smoothing: 1,
                allow_desktop_composition: 1,
                disable_full_window_drag: 0,
                disable_menu_anims: 0,
                disable_themes: 0,
                disable_cursor_setting: 0,
            },
            // The session default: drag and menu animations off, font smoothing
            // on, composition off.
            RdpPerformanceMode::Balanced => PerformanceKeys {
                disable_wallpaper: 0,
                allow_font_smoothing: 1,
                allow_desktop_composition: 0,
                disable_full_window_drag: 1,
                disable_menu_anims: 1,
                disable_themes: 0,
                disable_cursor_setting: 0,
            },
            // Every visual effect off.
            RdpPerformanceMode::Speed => PerformanceKeys {
                disable_wallpaper: 1,
                allow_font_smoothing: 0,
                allow_desktop_composition: 0,
                disable_full_window_drag: 1,
                disable_menu_anims: 1,
                disable_themes: 1,
                disable_cursor_setting: 1,
            },
        };

        let _ = writeln!(output, "disable wallpaper:i:{}", flags.disable_wallpaper);
        let _ = writeln!(
            output,
            "allow font smoothing:i:{}",
            flags.allow_font_smoothing
        );
        let _ = writeln!(
            output,
            "allow desktop composition:i:{}",
            flags.allow_desktop_composition
        );
        let _ = writeln!(
            output,
            "disable full window drag:i:{}",
            flags.disable_full_window_drag
        );
        let _ = writeln!(output, "disable menu anims:i:{}", flags.disable_menu_anims);
        let _ = writeln!(output, "disable themes:i:{}", flags.disable_themes);
        let _ = writeln!(
            output,
            "disable cursor setting:i:{}",
            flags.disable_cursor_setting
        );

        // Compression and bitmap caching (always enabled for better performance)
        let _ = writeln!(output, "compression:i:1");
        let _ = writeln!(output, "bitmapcachepersistenable:i:1");
    }

    /// Writes redirection settings (clipboard, audio, drives, etc.).
    fn write_redirection_settings(output: &mut String, rdp: &crate::models::RdpConfig) {
        // Clipboard
        let _ = writeln!(
            output,
            "redirectclipboard:i:{}",
            i32::from(rdp.clipboard_enabled)
        );

        // Audio mode: 0 = local, 1 = remote, 2 = none
        let audio_mode = match rdp.effective_audio_mode() {
            RdpAudioMode::Local => 0,
            RdpAudioMode::Remote => 1,
            RdpAudioMode::None => 2,
        };
        let _ = writeln!(output, "audiomode:i:{audio_mode}");

        // Printer redirection
        let _ = writeln!(
            output,
            "redirectprinters:i:{}",
            i32::from(rdp.printer_enabled)
        );

        // Drive redirection
        if !rdp.shared_folders.is_empty() {
            // drivestoredirect format: "C:\;D:\" or "*" for all or "DynamicDrives" for plug-ins
            let drives: Vec<String> = rdp
                .shared_folders
                .iter()
                .map(|f| f.local_path.display().to_string())
                .collect();
            let _ = writeln!(output, "drivestoredirect:s:{}", drives.join(";"));
        }

        // Smart card redirection (not currently configurable, default off)
        let _ = writeln!(output, "redirectsmartcards:i:0");

        // COM ports and POS devices (default off)
        let _ = writeln!(output, "redirectcomports:i:0");
        let _ = writeln!(output, "redirectposdevices:i:0");
    }

    /// Writes RD Gateway settings.
    fn write_gateway_settings(output: &mut String, rdp: &crate::models::RdpConfig) {
        if let Some(ref gateway) = rdp.gateway {
            // Gateway hostname with port if non-default
            if gateway.port == 443 {
                let _ = writeln!(output, "gatewayhostname:s:{}", gateway.hostname);
            } else {
                let _ = writeln!(
                    output,
                    "gatewayhostname:s:{}:{}",
                    gateway.hostname, gateway.port
                );
            }

            // Usage method: 1 = always use gateway
            let _ = writeln!(output, "gatewayusagemethod:i:1");

            // Credentials source: 0 = prompt, 4 = use session credentials
            let _ = writeln!(output, "gatewaycredentialssource:i:0");

            // Gateway username if different from session
            if let Some(ref gw_user) = gateway.username {
                let _ = writeln!(output, "gatewayusername:s:{gw_user}");
            }
        } else {
            // No gateway
            let _ = writeln!(output, "gatewayusagemethod:i:0");
        }
    }

    /// Writes security settings.
    fn write_security_settings(output: &mut String, rdp: &crate::models::RdpConfig) {
        use crate::models::RdpSecurityLayer;

        // Authentication level: 0 = connect anyway, 2 = warn, 3 = do not connect
        // Default to 2 (warn) for balance between security and usability
        let _ = writeln!(output, "authentication level:i:2");

        // Enable CredSSP support (NLA)
        let enable_credssp = !rdp.disable_nla;
        let _ = writeln!(
            output,
            "enablecredsspsupport:i:{}",
            i32::from(enable_credssp)
        );

        // Security protocol: negotiation, nla, tls, rdp
        let negotiate = match rdp.security_layer {
            RdpSecurityLayer::Negotiate => 1,
            _ => 0,
        };
        let _ = writeln!(output, "negotiate security layer:i:{negotiate}");
    }

    /// Writes RemoteApp (RAIL) settings.
    fn write_remoteapp_settings(output: &mut String, rdp: &crate::models::RdpConfig) {
        if let Some(ref program) = rdp.remote_app_program {
            let _ = writeln!(output, "remoteapplicationmode:i:1");
            let _ = writeln!(output, "remoteapplicationprogram:s:{program}");

            if let Some(ref args) = rdp.remote_app_args {
                let _ = writeln!(output, "remoteapplicationcmdline:s:{args}");
            }

            if let Some(ref name) = rdp.remote_app_name {
                let _ = writeln!(output, "remoteapplicationname:s:{name}");
            }
        } else {
            let _ = writeln!(output, "remoteapplicationmode:i:0");
        }
    }
}

impl Default for RdpFileExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ExportTarget for RdpFileExporter {
    fn format_id(&self) -> ExportFormat {
        ExportFormat::RdpFile
    }

    fn display_name(&self) -> &'static str {
        "RDP File (.rdp)"
    }

    fn export(
        &self,
        connections: &[Connection],
        _groups: &[ConnectionGroup],
        options: &ExportOptions,
    ) -> ExportOperationResult<ExportResult> {
        let mut result = ExportResult::new();

        // Filter to RDP connections only
        let rdp_connections: Vec<_> = connections
            .iter()
            .filter(|c| c.protocol == ProtocolType::Rdp)
            .collect();

        if rdp_connections.is_empty() {
            result.add_warning("No RDP connections to export");
            return Ok(result);
        }

        // Always a directory with one file per connection, even for a single
        // connection — see `ExportFormat::exports_to_directory` for why the
        // count cannot decide this. `export_rdp_file` is the single-file API.
        std::fs::create_dir_all(&options.output_path)?;

        let mut used_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        for conn in rdp_connections {
            let file_path = options.output_path.join(format!(
                "{}.rdp",
                unique_filename(&conn.name, &mut used_names)
            ));

            match Self::export_to_rdp_content(conn) {
                Ok(content) => {
                    write_export_file(&file_path, &content)?;
                    result.add_output_file(file_path);
                    result.increment_exported();
                }
                Err(e) => {
                    result.add_warning(format!("Failed to export '{}': {}", conn.name, e));
                }
            }
        }

        // Count what did not make it out. Assigned rather than added to, because
        // the per-file loop above already counted its own failures; deriving the
        // total from `exported_count` covers both those and the non-RDP
        // connections in one number, so the two cannot double-count.
        let skipped = connections.len().saturating_sub(result.exported_count);
        if skipped > 0 {
            let non_rdp = connections
                .iter()
                .filter(|c| c.protocol != ProtocolType::Rdp)
                .count();
            result.skipped_count = skipped;
            if non_rdp > 0 {
                result.add_warning(format!(
                    "{non_rdp} non-RDP connection(s) skipped (only RDP can be exported to .rdp format)"
                ));
            }
        }

        Ok(result)
    }

    fn export_connection(&self, connection: &Connection) -> ExportOperationResult<String> {
        Self::export_to_rdp_content(connection)
    }

    fn supports_protocol(&self, protocol: &ProtocolType) -> bool {
        *protocol == ProtocolType::Rdp
    }
}

/// Sanitizes a connection name for use as a filename.
///
/// Anything outside `[A-Za-z0-9-_.]` becomes `_`. A name that leaves nothing
/// usable — empty, or all separators — falls back to `connection`, because the
/// alternatives are a hidden `.rdp` file (an empty name) or a `...rdp` that reads
/// like a traversal attempt (a name of dots).
fn sanitize_filename(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();

    if sanitized.chars().all(|c| c == '.' || c == '_' || c == '-') {
        return "connection".to_string();
    }
    sanitized
}

/// Returns a sanitized filename stem that has not been used in this export yet.
///
/// Sanitizing is lossy — `web/prod` and `web prod` both become `web_prod` — so
/// without this a second connection would silently overwrite the first and the
/// export would report more files than it wrote. Collisions get a `-2`, `-3` …
/// suffix.
fn unique_filename(name: &str, used: &mut std::collections::HashSet<String>) -> String {
    let base = sanitize_filename(name);
    if used.insert(base.clone()) {
        return base;
    }
    for suffix in 2..=u32::MAX {
        let candidate = format!("{base}-{suffix}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    base
}

/// Exports a single RDP connection directly to a file.
///
/// Convenience function for quick single-file export.
///
/// # Arguments
///
/// * `connection` - The RDP connection to export
/// * `path` - Output file path
///
/// # Errors
///
/// Returns an error if the connection is not RDP or if writing fails.
pub fn export_rdp_file(connection: &Connection, path: &Path) -> Result<(), ExportError> {
    let content = RdpFileExporter::export_to_rdp_content(connection)?;
    write_export_file(path, &content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{RdpGateway, Resolution};

    fn make_rdp_connection(name: &str, host: &str, port: u16) -> Connection {
        Connection::new_rdp(name.to_string(), host.to_string(), port)
    }

    #[test]
    fn test_basic_rdp_export() {
        let conn = make_rdp_connection("Test Server", "server.example.com", 3389);
        let content = RdpFileExporter::export_to_rdp_content(&conn).unwrap();

        assert!(content.contains("full address:s:server.example.com"));
        assert!(!content.contains(":3389")); // Default port should be omitted
        assert!(content.contains("# RustConn RDP Export"));
    }

    #[test]
    fn test_rdp_export_with_custom_port() {
        let conn = make_rdp_connection("Custom Port", "server.example.com", 3390);
        let content = RdpFileExporter::export_to_rdp_content(&conn).unwrap();

        assert!(content.contains("full address:s:server.example.com:3390"));
    }

    #[test]
    fn test_rdp_export_with_username_and_domain() {
        let mut conn = make_rdp_connection("Corp Server", "server.corp.com", 3389);
        conn.username = Some("jdoe".to_string());
        conn.domain = Some("CORP".to_string());

        let content = RdpFileExporter::export_to_rdp_content(&conn).unwrap();

        assert!(content.contains("username:s:jdoe"));
        assert!(content.contains("domain:s:CORP"));
    }

    #[test]
    fn test_rdp_export_with_resolution() {
        let mut conn = make_rdp_connection("HD Server", "server.example.com", 3389);
        if let ProtocolConfig::Rdp(ref mut rdp) = conn.protocol_config {
            rdp.resolution = Some(Resolution {
                width: 1920,
                height: 1080,
            });
        }

        let content = RdpFileExporter::export_to_rdp_content(&conn).unwrap();

        assert!(content.contains("desktopwidth:i:1920"));
        assert!(content.contains("desktopheight:i:1080"));
    }

    #[test]
    fn test_rdp_export_with_gateway() {
        let mut conn = make_rdp_connection("Internal Server", "internal.corp.com", 3389);
        if let ProtocolConfig::Rdp(ref mut rdp) = conn.protocol_config {
            rdp.gateway = Some(RdpGateway {
                hostname: "gateway.corp.com".to_string(),
                port: 443,
                username: None,
            });
        }

        let content = RdpFileExporter::export_to_rdp_content(&conn).unwrap();

        assert!(content.contains("gatewayhostname:s:gateway.corp.com"));
        assert!(content.contains("gatewayusagemethod:i:1"));
    }

    #[test]
    fn test_rdp_export_with_gateway_custom_port() {
        let mut conn = make_rdp_connection("Internal Server", "internal.corp.com", 3389);
        if let ProtocolConfig::Rdp(ref mut rdp) = conn.protocol_config {
            rdp.gateway = Some(RdpGateway {
                hostname: "gateway.corp.com".to_string(),
                port: 8443,
                username: Some("gwadmin".to_string()),
            });
        }

        let content = RdpFileExporter::export_to_rdp_content(&conn).unwrap();

        assert!(content.contains("gatewayhostname:s:gateway.corp.com:8443"));
        assert!(content.contains("gatewayusername:s:gwadmin"));
    }

    #[test]
    fn test_rdp_export_with_remoteapp() {
        let mut conn = make_rdp_connection("RemoteApp", "rdserver.corp.com", 3389);
        if let ProtocolConfig::Rdp(ref mut rdp) = conn.protocol_config {
            rdp.remote_app_program = Some("||notepad".to_string());
            rdp.remote_app_args = Some("/p readme.txt".to_string());
            rdp.remote_app_name = Some("Notepad".to_string());
        }

        let content = RdpFileExporter::export_to_rdp_content(&conn).unwrap();

        assert!(content.contains("remoteapplicationmode:i:1"));
        assert!(content.contains("remoteapplicationprogram:s:||notepad"));
        assert!(content.contains("remoteapplicationcmdline:s:/p readme.txt"));
        assert!(content.contains("remoteapplicationname:s:Notepad"));
    }

    #[test]
    fn test_rdp_export_no_password() {
        let mut conn = make_rdp_connection("Secure Server", "server.example.com", 3389);
        conn.username = Some("admin".to_string());

        let content = RdpFileExporter::export_to_rdp_content(&conn).unwrap();

        // Password must never be in the output
        assert!(!content.to_lowercase().contains("password"));
    }

    #[test]
    fn test_non_rdp_connection_rejected() {
        let conn = Connection::new_ssh("SSH Server".to_string(), "ssh.example.com".to_string(), 22);
        let result = RdpFileExporter::export_to_rdp_content(&conn);

        assert!(result.is_err());
        assert!(matches!(result, Err(ExportError::UnsupportedProtocol(_))));
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("Simple Name"), "Simple_Name");
        assert_eq!(sanitize_filename("Server/Corp"), "Server_Corp");
        assert_eq!(sanitize_filename("192.168.1.1"), "192.168.1.1");
        assert_eq!(sanitize_filename("test<>:file"), "test___file");
    }

    #[test]
    fn test_export_to_file() {
        let conn = make_rdp_connection("Export Test", "server.example.com", 3389);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.rdp");

        export_rdp_file(&conn, &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("full address:s:server.example.com"));
    }

    #[test]
    fn test_exporter_supports_protocol() {
        let exporter = RdpFileExporter::new();
        assert!(exporter.supports_protocol(&ProtocolType::Rdp));
        assert!(!exporter.supports_protocol(&ProtocolType::Ssh));
        assert!(!exporter.supports_protocol(&ProtocolType::Vnc));
    }

    fn export_with_performance(mode: crate::models::RdpPerformanceMode) -> String {
        let mut conn = make_rdp_connection("Perf", "server.example.com", 3389);
        if let ProtocolConfig::Rdp(ref mut rdp) = conn.protocol_config {
            rdp.performance_mode = mode;
        }
        RdpFileExporter::export_to_rdp_content(&conn).unwrap()
    }

    /// Pins every row of the performance table against the flags a RustConn
    /// session itself uses (`build_performance_flags`). Two of the three rows
    /// disagreed with it on arrival, and `disable …`/`allow …` polarity makes that
    /// unreadable in a diff.
    #[test]
    fn performance_modes_match_the_session_flags() {
        use crate::models::RdpPerformanceMode;

        let quality = export_with_performance(RdpPerformanceMode::Quality);
        for expected in [
            "disable wallpaper:i:0",
            "allow font smoothing:i:1",
            "allow desktop composition:i:1",
            "disable full window drag:i:0",
            "disable menu anims:i:0",
            "disable themes:i:0",
            "disable cursor setting:i:0",
        ] {
            assert!(
                quality.contains(expected),
                "Quality must emit {expected}\n{quality}"
            );
        }

        let balanced = export_with_performance(RdpPerformanceMode::Balanced);
        for expected in [
            "disable wallpaper:i:0",
            "allow font smoothing:i:1",
            "allow desktop composition:i:0",
            "disable full window drag:i:1",
            "disable menu anims:i:1",
            "disable themes:i:0",
        ] {
            assert!(
                balanced.contains(expected),
                "Balanced must emit {expected}\n{balanced}"
            );
        }

        let speed = export_with_performance(RdpPerformanceMode::Speed);
        for expected in [
            "disable wallpaper:i:1",
            "allow font smoothing:i:0",
            "allow desktop composition:i:0",
            "disable full window drag:i:1",
            "disable menu anims:i:1",
            "disable themes:i:1",
            "disable cursor setting:i:1",
        ] {
            assert!(
                speed.contains(expected),
                "Speed must emit {expected}\n{speed}"
            );
        }
    }

    #[test]
    fn a_name_with_nothing_usable_does_not_become_a_hidden_file() {
        assert_eq!(sanitize_filename(""), "connection");
        assert_eq!(sanitize_filename(".."), "connection");
        assert_eq!(sanitize_filename("///"), "connection");
    }

    /// A mixed selection reports the non-RDP entries once, and the two counters
    /// add up to what was handed in.
    #[test]
    fn a_mixed_selection_counts_skipped_once() {
        let dir = tempfile::tempdir().unwrap();
        let connections = vec![
            make_rdp_connection("win-a", "a.example.com", 3389),
            make_rdp_connection("win-b", "b.example.com", 3389),
            Connection::new_ssh("shell".to_string(), "c.example.com".to_string(), 22),
        ];
        let options = ExportOptions::new(ExportFormat::RdpFile, dir.path().join("out"));

        let result = RdpFileExporter::new()
            .export(&connections, &[], &options)
            .unwrap();

        assert_eq!(result.exported_count, 2);
        assert_eq!(result.skipped_count, 1);
        assert_eq!(result.exported_count + result.skipped_count, 3);
        assert_eq!(
            result
                .warnings
                .iter()
                .filter(|w| w.contains("non-RDP"))
                .count(),
            1
        );
        assert!(dir.path().join("out").join("win-a.rdp").exists());
        assert!(dir.path().join("out").join("win-b.rdp").exists());
    }

    /// Sanitizing is lossy, so two different names can collide. Both must survive.
    #[test]
    fn colliding_names_do_not_overwrite_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let connections = vec![
            make_rdp_connection("web/prod", "a.example.com", 3389),
            make_rdp_connection("web prod", "b.example.com", 3389),
        ];
        let options = ExportOptions::new(ExportFormat::RdpFile, dir.path().join("out"));

        let result = RdpFileExporter::new()
            .export(&connections, &[], &options)
            .unwrap();

        assert_eq!(result.exported_count, 2);
        assert_eq!(result.output_files.len(), 2);
        let out = dir.path().join("out");
        assert!(out.join("web_prod.rdp").exists());
        assert!(out.join("web_prod-2.rdp").exists());
        let first = std::fs::read_to_string(out.join("web_prod.rdp")).unwrap();
        let second = std::fs::read_to_string(out.join("web_prod-2.rdp")).unwrap();
        assert!(first.contains("a.example.com"));
        assert!(second.contains("b.example.com"));
    }

    /// A selection with no RDP connection is a warning, not an error, and creates
    /// nothing.
    #[test]
    fn a_selection_without_rdp_exports_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let connections = vec![Connection::new_ssh(
            "shell".to_string(),
            "c.example.com".to_string(),
            22,
        )];
        let options = ExportOptions::new(ExportFormat::RdpFile, dir.path().join("out"));

        let result = RdpFileExporter::new()
            .export(&connections, &[], &options)
            .unwrap();

        assert_eq!(result.exported_count, 0);
        assert!(!dir.path().join("out").exists());
    }
}
