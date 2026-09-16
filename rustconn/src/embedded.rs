//! Embedded session support for RDP/VNC connections
//!
//! This module provides support for embedding RDP and VNC sessions
//! within the main application window using native protocol clients.
//! On Wayland, sessions fall back to external windows.

use std::cell::RefCell;
use std::process::Child;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Button, DrawingArea, Label, Orientation, glib};
use libadwaita as adw;
use thiserror::Error;
use uuid::Uuid;

// Re-export DisplayServer from the unified display module for backward compatibility
pub use crate::display::DisplayServer;
use crate::i18n::{i18n, i18n_f};

/// Error type for embedding operations
#[derive(Debug, Clone, Error)]
pub enum EmbeddingError {
    /// Embedding not supported on Wayland
    #[error("Embedding not supported on Wayland for {protocol}")]
    WaylandNotSupported {
        /// The protocol that doesn't support embedding
        protocol: String,
    },
    /// Failed to get window ID for embedding
    #[error("Failed to get window ID for embedding")]
    WindowIdNotAvailable,
    /// Client process failed to start
    #[error("Failed to start client process: {0}")]
    ProcessStartFailed(String),
    /// Client exited unexpectedly
    #[error("Client exited with code {code}")]
    ClientExited {
        /// The exit code
        code: i32,
    },
}

/// Session controls for embedded sessions
#[derive(Clone)]
pub struct SessionControls {
    container: GtkBox,
    disconnect_button: Button,
    status_label: Label,
}

impl SessionControls {
    /// Creates new session controls
    #[must_use]
    pub fn new() -> Self {
        let container = GtkBox::new(Orientation::Horizontal, 8);
        container.set_margin_start(12);
        container.set_margin_end(12);
        container.set_margin_top(6);
        container.set_margin_bottom(6);

        let status_label = Label::new(Some(&i18n("Connecting…")));
        status_label.set_hexpand(true);
        status_label.set_halign(gtk4::Align::Start);
        status_label.add_css_class("dim-label");
        container.append(&status_label);

        // No fullscreen button here. There was one, and pressing it flipped a
        // private `bool` and called no window API at all — a control that could
        // not do what its tooltip promised. It was never seen: the only
        // `EmbeddedSessionTab` built is the `force_external` one in
        // `window::rdp_vnc`, which exists to own the spawned viewer process and
        // is never added to the notebook. Fullscreen for a real session is
        // `win.toggle-fullscreen`.
        let disconnect_button = Button::from_icon_name("process-stop-symbolic");
        disconnect_button.set_tooltip_text(Some(&i18n("Disconnect")));
        disconnect_button.add_css_class("flat");
        disconnect_button.add_css_class("destructive-action");
        disconnect_button
            .update_property(&[gtk4::accessible::Property::Label(&i18n("Disconnect"))]);
        container.append(&disconnect_button);

        Self {
            container,
            disconnect_button,
            status_label,
        }
    }

    /// Returns the container widget
    #[must_use]
    pub const fn widget(&self) -> &GtkBox {
        &self.container
    }

    /// Sets the status text
    pub fn set_status(&self, status: &str) {
        self.status_label.set_text(status);
    }

    /// Connects a callback for the disconnect button
    pub fn connect_disconnect<F: Fn() + 'static>(&self, callback: F) {
        self.disconnect_button.connect_clicked(move |_| callback());
    }
}

impl Default for SessionControls {
    fn default() -> Self {
        Self::new()
    }
}

/// The three mutually-exclusive outcomes of a tabless external RDP launch.
///
/// Grouped into one struct because they always travel together and a bare list
/// of three closures on [`RdpLauncher::start`] reads as noise at the call site.
/// Exactly one fires per launch: an early failure, a changed certificate the
/// user must decide on, or a session that survived the early window and is handed
/// to the shared registry.
pub struct RdpLaunchCallbacks {
    /// Fired with a user-facing message when the client fails shortly after launch.
    pub on_early_failure: Box<dyn FnOnce(String) + 'static>,
    /// Fired with `(host, port, message)` when FreeRDP reports a changed
    /// certificate; the caller shows a confirmation dialog. (#324)
    pub on_cert_changed: Box<dyn FnOnce(String, u16, String) + 'static>,
    /// Fired once the session survives the early window; the caller hands the
    /// spawned child to the external-session registry here.
    pub on_connected: Box<dyn FnOnce() + 'static>,
}
/// Embedded session tab for RDP/VNC connections
#[expect(dead_code, reason = "Fields kept for GTK widget lifecycle")]
pub struct EmbeddedSessionTab {
    id: Uuid,
    connection_id: Uuid,
    protocol: String,
    container: GtkBox,
    embed_area: DrawingArea,
    controls: SessionControls,
    process: Rc<RefCell<Option<Child>>>,
    is_embedded: bool,
}

impl EmbeddedSessionTab {
    /// Creates a new embedded session tab
    ///
    /// If `force_external` is `true`, the tab always shows the external-window
    /// StatusPage regardless of display server capabilities.
    #[must_use]
    pub fn new(
        connection_id: Uuid,
        connection_name: &str,
        protocol: &str,
        force_external: bool,
    ) -> (Self, bool) {
        let id = Uuid::new_v4();
        let display_server = DisplayServer::detect();
        let is_embedded = !force_external && display_server.supports_embedding();

        let container = GtkBox::new(Orientation::Vertical, 0);
        container.set_hexpand(true);
        container.set_vexpand(true);

        let controls = SessionControls::new();
        container.append(controls.widget());

        let embed_area = DrawingArea::new();
        embed_area.set_hexpand(true);
        embed_area.set_vexpand(true);

        if is_embedded {
            embed_area.set_content_width(800);
            embed_area.set_content_height(600);
            controls.set_status(&format!(
                "{} session - {} (embedded)",
                protocol.to_uppercase(),
                connection_name
            ));
        } else {
            controls.set_status(&format!(
                "{} session - {} (external window)",
                protocol.to_uppercase(),
                connection_name
            ));

            // StatusPage for external sessions — shows hotkeys and connection info.
            // adw::StatusPage description already supports Pango markup natively.
            let description = format!(
                "{}\n\n<b>Ctrl+Alt+Enter</b>  —  {}\n<b>Right Ctrl</b>  —  {}\n<b>Ctrl+Alt+C</b>  —  {}\n\n<small>{}</small>",
                glib::markup_escape_text(connection_name),
                i18n("Toggle fullscreen"),
                i18n("Release keyboard/mouse grab"),
                i18n("Toggle remote control (assistance)"),
                i18n("This tab will close automatically when the session ends"),
            );
            let status_page = adw::StatusPage::builder()
                .icon_name("preferences-desktop-remote-desktop-symbolic")
                .title(i18n("Session running in separate window"))
                .description(description)
                .hexpand(true)
                .vexpand(true)
                .build();
            container.append(&status_page);

            tracing::debug!(
                connection = %connection_name,
                "External RDP tab: StatusPage appended to container (children: controls + status_page)"
            );
        }

        if is_embedded {
            container.append(&embed_area);
        }

        let tab = Self {
            id,
            connection_id,
            protocol: protocol.to_string(),
            container,
            embed_area,
            controls,
            process: Rc::new(RefCell::new(None)),
            is_embedded,
        };

        tab.setup_controls();

        (tab, is_embedded)
    }

    fn setup_controls(&self) {
        let process = self.process.clone();
        self.controls.connect_disconnect(move || {
            if let Some(mut child) = process.borrow_mut().take() {
                let _ = child.kill();
            }
        });
    }

    /// Returns the session UUID
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// Returns the connection UUID
    #[must_use]
    pub const fn connection_id(&self) -> Uuid {
        self.connection_id
    }

    /// Returns the protocol type
    #[must_use]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Returns the main container widget
    #[must_use]
    pub const fn widget(&self) -> &GtkBox {
        &self.container
    }

    /// Returns whether the session is embedded
    #[must_use]
    pub const fn is_embedded(&self) -> bool {
        self.is_embedded
    }

    /// Sets the status text
    pub fn set_status(&self, status: &str) {
        self.controls.set_status(status);
    }

    /// Sets the child process
    pub fn set_process(&self, child: Child) {
        *self.process.borrow_mut() = Some(child);
    }

    /// Returns a clone of the process handle for external cleanup
    #[must_use]
    pub fn process_handle(&self) -> Rc<RefCell<Option<Child>>> {
        self.process.clone()
    }
}

/// RDP session launcher for embedded and external sessions
pub struct RdpLauncher;

impl RdpLauncher {
    fn find_freerdp_binary() -> Option<String> {
        // macOS: a FreeRDP shipped as an `.app` bundle is not on PATH; the
        // in-bundle executable path is used as a fallback below.
        const MACOS_BUNDLES: &[(&str, &str)] = &[
            ("FreeRDP.app", "freerdp"),
            ("SDL-freerdp.app", "sdl-freerdp"),
            ("wlfreerdp.app", "wlfreerdp"),
        ];
        let candidates = [
            "sdl-freerdp3", // FreeRDP 3.x SDL3 — versioned (distro packages)
            "sdl-freerdp",  // FreeRDP 3.x SDL3 — unversioned (Flatpak / upstream)
            "xfreerdp3",    // FreeRDP 3.x X11
            "xfreerdp",     // FreeRDP 2.x X11
            "freerdp",      // Generic
        ];
        if let Some(bin) = candidates
            .into_iter()
            .find(|candidate| rustconn_core::which::is_available(candidate))
        {
            return Some(bin.to_owned());
        }

        rustconn_core::which::find_macos_app(MACOS_BUNDLES)
            .and_then(|p| p.into_os_string().into_string().ok())
    }

    /// Starts an RDP session in an external FreeRDP window.
    ///
    /// Every connection parameter comes from `config`, and the argument list is
    /// built by [`rustconn_core::protocol::build_freerdp_args`] — the same
    /// builder the embedded client's FreeRDP fallback uses. This function used
    /// to assemble its own list from fifteen loose parameters, and being the
    /// older of the two it had drifted: it emitted no `/gateway:` at all, so a
    /// connection behind an RD Gateway dialled the target host directly, and it
    /// passed the user's custom arguments through unfiltered, so a stray `/p:`
    /// aborted the launch instead of being dropped.
    ///
    /// One of [`RdpLaunchCallbacks`] fires on the main loop per launch: an early
    /// failure with a user-facing message, a changed certificate the user must
    /// accept or reject, or a surviving session handed to the registry. The
    /// spawned child stays in `tab`'s handle until one of the first two resolves
    /// or `on_connected` fires — so the changed-certificate decision (#324) is
    /// made while this watcher, not the registry's exit-only poll, owns it.
    ///
    /// # Errors
    /// Returns an error if the FreeRDP binary is missing or the process fails to
    /// spawn. Early post-spawn failures are reported asynchronously through
    /// `callbacks` instead, so the GTK main loop is never blocked.
    pub fn start(
        tab: &EmbeddedSessionTab,
        config: &rustconn_core::protocol::FreeRdpConfig,
        callbacks: RdpLaunchCallbacks,
    ) -> Result<(), EmbeddingError> {
        use secrecy::ExposeSecret;
        use std::process::{Command, Stdio};

        let RdpLaunchCallbacks {
            on_early_failure,
            on_cert_changed,
            on_connected,
        } = callbacks;

        let binary = Self::find_freerdp_binary().ok_or_else(|| {
            EmbeddingError::ProcessStartFailed(
                "FreeRDP client not found. Install xfreerdp, sdl-freerdp3, sdl-freerdp, or xfreerdp3."
                    .to_string(),
            )
        })?;

        let host = config.host.as_str();

        // Forgetting the stored certificate is a local side effect rather than
        // an argument, so it stays here instead of in the shared builder. It goes
        // through the shared helper: this used to be a second copy of the same
        // logic, and it kept the substring match (`line.contains("host port")`)
        // that the helper was written to replace, so `db.example.com` also
        // dropped `my-db.example.com` — and it never looked in `freerdp3/`.
        if config.ignore_certificate {
            crate::embedded_rdp::cert::remove_known_certificate(host, config.port);
        }

        // Connection arguments are written to a guarded file so credentials
        // never appear in the FreeRDP process argument vector.
        let mut plain_args = rustconn_core::protocol::build_freerdp_args(config);

        // SDL-FreeRDP draws its certificate prompt in its own SDL window and
        // never prints the "Certificate … has changed!!!" banner to stdout, so
        // the watcher below would have nothing to read. Force the console
        // callback so it behaves like xfreerdp3 (prints the report to stdout,
        // reads the answer from stdin). Shares the detection helper with the
        // embedded-widget launcher rather than repeating it. (#324)
        if crate::embedded_rdp::launcher::is_sdl_freerdp_binary(&binary) {
            plain_args.push("+force-console-callbacks".to_string());
        }

        let password = config
            .password
            .as_ref()
            .filter(|value| !value.expose_secret().is_empty());
        let mut secret_args = Vec::new();
        if let Some(password) = password {
            secret_args.push(("p", password));
        }
        let prepared_args = crate::embedded_rdp::SafeFreeRdpLauncher::prepare_args_file(
            &binary,
            &plain_args,
            &secret_args,
        )
        .map_err(|error| EmbeddingError::ProcessStartFailed(error.to_string()))?;

        let mut cmd = Command::new(&binary);
        cmd.arg(prepared_args.argument());

        // Never block on a prompt nobody can answer. On a changed certificate
        // FreeRDP asks "Do you trust the above certificate? (Y/T/N)" and reads
        // stdin; inherited from a terminal it blocks forever, which is exactly
        // how #324 presented ("no errors, no warnings, no connection"). With
        // stdin at `/dev/null` it reads EOF, declines, and exits with a
        // certificate error the watcher can classify — after the banner has
        // been captured from stdout below and turned into a GUI dialog. (#324)
        cmd.stdin(Stdio::null());

        // Capture stderr for error detection.
        cmd.stderr(Stdio::piped());

        // Capture stdout too: FreeRDP prints the whole certificate report — the
        // changed-certificate banner and both thumbprints — to stdout with plain
        // `printf`, while only the `ERRCONNECT_*` codes go to stderr. Reading
        // stderr alone is why this path never noticed a changed certificate. (#324)
        cmd.stdout(Stdio::piped());

        match cmd.spawn() {
            Ok(mut child) => {
                prepared_args.retain_for_post_spawn_parse();

                // Drain stdout on a background thread into a shared buffer so the
                // watcher can spot the changed-certificate banner while the client
                // is still running (it prints the banner, then waits on stdin).
                let stdout_lines: crate::embedded_rdp::StdoutLines =
                    std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
                if let Some(stdout) = child.stdout.take() {
                    let lines = std::sync::Arc::clone(&stdout_lines);
                    std::thread::spawn(move || {
                        use std::io::{BufRead, BufReader};
                        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                            let trimmed = line.trim();
                            if !trimmed.is_empty()
                                && let Ok(mut buf) = lines.lock()
                            {
                                buf.push(trimmed.to_owned());
                            }
                        }
                    });
                }

                tab.set_process(child);
                tab.set_status(&i18n_f("Connecting to {}…", &[host]));
                Self::watch_early_failure(
                    tab,
                    host,
                    config.port,
                    stdout_lines,
                    on_early_failure,
                    on_cert_changed,
                    on_connected,
                );
                Ok(())
            }
            Err(e) => Err(EmbeddingError::ProcessStartFailed(e.to_string())),
        }
    }

    /// Watches a freshly spawned FreeRDP process for immediate failures
    /// (certificate errors, auth failures) without blocking the GTK main loop.
    ///
    /// FreeRDP exits within ~1s on such errors; the 1500ms window (6 ticks ×
    /// 250ms) matches the blocking detection delay this replaces. It is shorter
    /// than the 2s session monitor in `rdp_vnc.rs`, so an early failure is
    /// always reported here first: the child is taken out of the shared handle,
    /// which makes the session monitor stop without double-closing the tab.
    ///
    /// Also watches `stdout_lines` for the changed-certificate banner. FreeRDP
    /// prints that banner and then waits on stdin, so it never surfaces as an
    /// exit; the watcher must notice the banner, stop the client, and hand the
    /// trust decision to a GUI dialog through `on_cert_changed`. This is the
    /// tabless-path counterpart of the embedded widget's watchdog. (#324)
    fn watch_early_failure(
        tab: &EmbeddedSessionTab,
        host: &str,
        port: u16,
        stdout_lines: crate::embedded_rdp::StdoutLines,
        on_early_failure: Box<dyn FnOnce(String) + 'static>,
        on_cert_changed: Box<dyn FnOnce(String, u16, String) + 'static>,
        on_connected: Box<dyn FnOnce() + 'static>,
    ) {
        // A changed certificate makes FreeRDP refuse the TLS handshake and print
        // its banner well inside this window, then wait on stdin; the stdout
        // check below catches it before the process is handed to the registry.
        const EARLY_FAILURE_TICKS: u32 = 6;

        let process = tab.process_handle();
        let controls = tab.controls.clone();
        let host = host.to_string();
        let mut on_failure = Some(on_early_failure);
        let mut on_cert = Some(on_cert_changed);
        let mut on_connected = Some(on_connected);
        let mut ticks = 0u32;

        glib::timeout_add_local(std::time::Duration::from_millis(250), move || {
            ticks += 1;
            let mut guard = process.borrow_mut();
            let Some(child) = guard.as_mut() else {
                // Process was taken (user disconnected) — nothing to watch.
                return glib::ControlFlow::Break;
            };

            // A changed certificate stalls the client on a stdin prompt rather
            // than exiting, so check the captured stdout before try_wait.
            let certificate_changed = {
                let lines = stdout_lines.lock().unwrap_or_else(|e| e.into_inner());
                crate::embedded_rdp::connection::reports_changed_certificate(&lines.join(" "))
            };
            if certificate_changed {
                tracing::info!(
                    protocol = "rdp",
                    %host,
                    port,
                    "[FreeRDP] Server certificate changed — stopping the client and asking the user"
                );
                let message =
                    crate::embedded_rdp::connection::certificate_changed_message(&stdout_lines);
                // Take the child so the session monitor sees an empty handle and
                // stops without reporting an error over the dialog.
                if let Some(mut child) = guard.take() {
                    let _ = child.kill();
                    std::thread::spawn(move || {
                        let _ = child.wait();
                    });
                }
                drop(guard);
                if let Some(callback) = on_cert.take() {
                    callback(host.clone(), port, message);
                }
                return glib::ControlFlow::Break;
            }

            match child.try_wait() {
                Ok(Some(status)) if !status.success() => {
                    // Early exit with error — take the child so the session
                    // monitor sees an empty handle and stops silently.
                    let error_msg = guard
                        .take()
                        .and_then(|mut child| child.stderr.take())
                        .and_then(|stderr| {
                            use std::io::Read;
                            let mut buf = String::new();
                            let mut reader = std::io::BufReader::new(stderr);
                            reader.read_to_string(&mut buf).ok()?;
                            Some(buf)
                        })
                        .unwrap_or_default();
                    drop(guard);

                    let user_error = Self::parse_freerdp_error(&error_msg);
                    if let Some(callback) = on_failure.take() {
                        callback(user_error);
                    }
                    glib::ControlFlow::Break
                }
                Ok(Some(_)) => {
                    // Exited cleanly right away — the session monitor closes the tab.
                    glib::ControlFlow::Break
                }
                Ok(None) if ticks >= EARLY_FAILURE_TICKS => {
                    // Survived the early window with no changed-certificate
                    // banner. A changed certificate makes FreeRDP refuse the TLS
                    // handshake within this window (it prints the banner and
                    // waits, which the check above catches), so a live process
                    // here is a real session. Hand ownership to the shared
                    // registry now — deferred until this point precisely so the
                    // watcher, not the registry, owns the child while the
                    // certificate decision is still open.
                    drop(guard);
                    controls.set_status(&i18n_f("Connected to {}", &[&host]));
                    if let Some(callback) = on_connected.take() {
                        callback();
                    }
                    glib::ControlFlow::Break
                }
                Ok(None) => glib::ControlFlow::Continue,
                Err(_) => glib::ControlFlow::Break,
            }
        });
    }

    /// Parses FreeRDP stderr output to extract a user-friendly error message
    fn parse_freerdp_error(stderr: &str) -> String {
        if stderr.contains("certificate not trusted")
            || stderr.contains("ERRCONNECT_TLS_CONNECT_FAILED")
        {
            if stderr.contains("NEW HOST IDENTIFICATION") || stderr.contains("has changed") {
                return "RDP certificate has changed. Enable 'Ignore Certificate' or accept the new certificate.".to_string();
            }
            return "TLS certificate verification failed. Enable 'Ignore Certificate' in connection settings.".to_string();
        }
        if stderr.contains("ERRCONNECT_CONNECT_CANCELLED")
            || stderr.contains("nla_client_setup_identity")
        {
            return "NLA authentication failed. Check username/password or disable NLA."
                .to_string();
        }
        if stderr.contains("ERRCONNECT_CONNECT_TRANSPORT_FAILED") {
            return "Connection refused. Check host and port.".to_string();
        }
        if stderr.contains("ERRCONNECT_DNS_NAME_NOT_FOUND") {
            return "Host not found. Check the hostname.".to_string();
        }
        // Fallback: return last ERROR line or generic message
        stderr
            .lines()
            .rev()
            .find(|line| line.contains("[ERROR]"))
            .map(|line| {
                // Extract the message part after the last ]:
                line.rsplit("]: ").next().unwrap_or(line).trim().to_string()
            })
            .unwrap_or_else(|| "FreeRDP exited with error (exit code non-zero)".to_string())
    }
}
