//! mRemoteNG connection file importer.
//!
//! mRemoteNG stores its connection tree in `confCons.xml`: a root
//! `<Connections>` element containing nested `<Node>` elements. A node with
//! `Type="Container"` is a folder that nests further nodes; a node with
//! `Type="Connection"` is a connection whose settings live in the element's
//! attributes (`Hostname`, `Protocol`, `Port`, `Username`, `Domain`, ...).
//!
//! Only unencrypted documents are imported. A document saved with full-file
//! encryption (`FullFileEncryption="true"`) is not decrypted — the import
//! reports it and stops — and per-connection encrypted passwords are never
//! decoded, so no password is imported.
//!
//! Reference: <https://mremoteng.org/>

use std::path::{Path, PathBuf};

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use uuid::Uuid;

use super::normalize::parse_host_port;
use super::traits::{ImportResult, ImportSource, SkippedEntry, read_import_file};
use crate::error::ImportError;
use crate::models::{
    Connection, ConnectionGroup, ProtocolConfig, RdpConfig, SshConfig, TelnetConfig, VncConfig,
};

const SOURCE_NAME: &str = "mRemoteNG";

/// Importer for mRemoteNG `confCons.xml` connection files.
pub struct MRemoteNgImporter {
    /// Custom paths to import from. When empty, [`Self::default_paths`] returns
    /// nothing — mRemoteNG is a Windows application with no canonical Linux
    /// location, so the user selects the exported `confCons.xml` explicitly.
    custom_paths: Vec<PathBuf>,
}

impl MRemoteNgImporter {
    /// Creates a new mRemoteNG importer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            custom_paths: Vec::new(),
        }
    }

    /// Creates an mRemoteNG importer bound to specific files.
    #[must_use]
    pub const fn with_paths(paths: Vec<PathBuf>) -> Self {
        Self {
            custom_paths: paths,
        }
    }

    /// Parses `confCons.xml` content into connections and groups.
    ///
    /// Container nodes become nested [`ConnectionGroup`]s; connection nodes
    /// become [`Connection`]s assigned to the group they are nested in. A
    /// full-file-encrypted document yields a single parse error and no
    /// connections.
    #[must_use]
    pub fn parse_xml(&self, content: &str, source_path: &str) -> ImportResult {
        let mut result = ImportResult::new();

        let mut reader = Reader::from_str(content);
        reader.config_mut().trim_text(true);

        // Group IDs of the enclosing container nodes; the top is the current
        // parent for any node opened next.
        let mut group_stack: Vec<Uuid> = Vec::new();
        // One entry per non-empty `<Node>` still open, in nesting order.
        // `Some(id)` marks a container (whose id is also on `group_stack`),
        // `None` marks a connection node that happened to have children. An
        // `End(Node)` pops this and, when it was a container, pops the group.
        let mut open_nodes: Vec<Option<Uuid>> = Vec::new();

        loop {
            match reader.read_event() {
                Ok(Event::Start(e)) => {
                    let name = local_name(&e);
                    if name == "Connections" {
                        if let Err(reason) = check_not_encrypted(&e) {
                            result.add_error(ImportError::ParseError {
                                source_name: SOURCE_NAME.to_string(),
                                reason,
                            });
                            return result;
                        }
                    } else if name == "Node" {
                        match node_type(&e) {
                            NodeType::Container => {
                                let group = Self::build_group(&e, group_stack.last().copied());
                                let id = group.id;
                                result.add_group(group);
                                group_stack.push(id);
                                open_nodes.push(Some(id));
                            }
                            NodeType::Connection => {
                                Self::handle_connection_node(
                                    &e,
                                    group_stack.last().copied(),
                                    source_path,
                                    &mut result,
                                );
                                open_nodes.push(None);
                            }
                        }
                    }
                }
                Ok(Event::Empty(e)) => {
                    // Self-closing `<Node ... />` — the common case for a
                    // connection with no children. It opens and closes at once,
                    // so it never touches the open-node or group stacks.
                    if local_name(&e) == "Node" {
                        match node_type(&e) {
                            NodeType::Container => {
                                // An empty folder: record the group so it is
                                // preserved, but nothing nests inside it.
                                let group = Self::build_group(&e, group_stack.last().copied());
                                result.add_group(group);
                            }
                            NodeType::Connection => {
                                Self::handle_connection_node(
                                    &e,
                                    group_stack.last().copied(),
                                    source_path,
                                    &mut result,
                                );
                            }
                        }
                    }
                }
                Ok(Event::End(e)) => {
                    if local_name_end(&e) == "Node"
                        && let Some(opened) = open_nodes.pop()
                        && opened.is_some()
                    {
                        // A container closed: leave its subtree.
                        group_stack.pop();
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    result.add_error(ImportError::ParseError {
                        source_name: SOURCE_NAME.to_string(),
                        reason: format!("XML parse error: {e}"),
                    });
                    return result;
                }
                _ => {}
            }
        }

        result
    }

    /// Builds a [`ConnectionGroup`] from a container node's `Name` attribute.
    fn build_group(element: &BytesStart<'_>, parent: Option<Uuid>) -> ConnectionGroup {
        let name = attr(element, "Name").unwrap_or_else(|| "mRemoteNG Folder".to_string());
        match parent {
            Some(pid) => ConnectionGroup::with_parent(name, pid),
            None => ConnectionGroup::new(name),
        }
    }

    /// Builds a connection from a connection node and records it, or records a
    /// skip when the node cannot be represented.
    fn handle_connection_node(
        element: &BytesStart<'_>,
        group_id: Option<Uuid>,
        source_path: &str,
        result: &mut ImportResult,
    ) {
        let name = attr(element, "Name").unwrap_or_default();

        let raw_host = attr(element, "Hostname").unwrap_or_default();
        if raw_host.trim().is_empty() {
            result.add_skipped(SkippedEntry::with_location(
                if name.is_empty() { "(unnamed)" } else { &name },
                "No Hostname",
                source_path,
            ));
            return;
        }
        let (host, parsed_port) = parse_host_port(raw_host.trim());

        let protocol = attr(element, "Protocol").unwrap_or_else(|| "SSH2".to_string());
        let attr_port: Option<u16> = attr(element, "Port").and_then(|p| p.trim().parse().ok());
        let port_hint = attr_port.or(parsed_port);

        let (protocol_config, default_port) = match protocol.to_ascii_uppercase().as_str() {
            "SSH1" | "SSH2" | "SSH" => (ProtocolConfig::Ssh(SshConfig::default()), 22u16),
            "RDP" => (Self::build_rdp_config(element), 3389u16),
            "VNC" => (ProtocolConfig::Vnc(VncConfig::default()), 5900u16),
            "TELNET" => (ProtocolConfig::Telnet(TelnetConfig::default()), 23u16),
            // Rlogin and Raw are line protocols RustConn serves through Telnet.
            "RLOGIN" => (ProtocolConfig::Telnet(TelnetConfig::default()), 513u16),
            "RAW" => (ProtocolConfig::Telnet(TelnetConfig::default()), 23u16),
            other => {
                // HTTP/HTTPS, ICA (Citrix), IntApp and similar have no direct
                // RustConn equivalent.
                result.add_skipped(SkippedEntry::with_location(
                    if name.is_empty() { &host } else { &name },
                    format!("Unsupported protocol: {other}"),
                    source_path,
                ));
                return;
            }
        };

        let port = port_hint.unwrap_or(default_port);
        let display_name = if name.is_empty() { host.clone() } else { name };
        let mut connection = Connection::new(display_name, host, port, protocol_config);

        if let Some(user) = attr(element, "Username").filter(|s| !s.trim().is_empty()) {
            connection.username = Some(user.trim().to_string());
        }
        if let Some(domain) = attr(element, "Domain").filter(|s| !s.trim().is_empty()) {
            connection.domain = Some(domain.trim().to_string());
        }

        connection.group_id = group_id;
        result.add_connection(connection);
    }

    /// Builds an RDP protocol config from an mRemoteNG connection node.
    ///
    /// Only settings with a clean RustConn equivalent are carried; the rest stay
    /// at RustConn's defaults. mRemoteNG's `RedirectSound="BringToThisComputer"`
    /// is the one value that means "play remote audio locally"; every other
    /// value (`DoNotPlay`, `LeaveAtRemoteComputer`) leaves audio off.
    fn build_rdp_config(element: &BytesStart<'_>) -> ProtocolConfig {
        let clipboard_enabled = match attr(element, "RedirectClipboard") {
            // mRemoteNG defaults clipboard redirection on; only an explicit
            // "false" turns it off, matching RustConn's own default of on.
            Some(v) => !v.eq_ignore_ascii_case("false"),
            None => true,
        };

        ProtocolConfig::Rdp(RdpConfig {
            audio_redirect: attr(element, "RedirectSound")
                .is_some_and(|v| v.eq_ignore_ascii_case("BringToThisComputer")),
            clipboard_enabled,
            ..RdpConfig::default()
        })
    }
}

/// mRemoteNG node kinds.
enum NodeType {
    Container,
    Connection,
}

/// Reads the `Type` attribute; anything that is not `Container` is a connection.
fn node_type(element: &BytesStart<'_>) -> NodeType {
    match attr(element, "Type") {
        Some(t) if t.eq_ignore_ascii_case("Container") => NodeType::Container,
        _ => NodeType::Connection,
    }
}

/// Returns the local element name of a start/empty tag as a `String`.
fn local_name(element: &BytesStart<'_>) -> String {
    element.local_name().as_ref().to_string()
}

/// Returns the local element name of an end tag as a `String`.
fn local_name_end(element: &quick_xml::events::BytesEnd<'_>) -> String {
    element.local_name().as_ref().to_string()
}

/// Reads a named attribute's value, if present, with XML entities unescaped.
fn attr(element: &BytesStart<'_>, key: &str) -> Option<String> {
    element.attributes().flatten().find_map(|a| {
        if a.key.local_name().as_ref() == key {
            Some(unescape_xml_entities(a.value.as_ref()))
        } else {
            None
        }
    })
}

/// Unescapes the five predefined XML entities in an attribute value.
///
/// mRemoteNG attribute values may contain `&amp;`, `&lt;`, `&gt;`, `&quot;`
/// and `&apos;` (a name like `A &amp; B`). quick-xml hands the raw bytes back
/// for `Attribute::value`; the entities are resolved here so the imported name
/// reads correctly. Numeric character references are left as-is — they do not
/// occur in practice in these files and resolving them fully is not worth a
/// dependency.
fn unescape_xml_entities(raw: &str) -> String {
    raw.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        // Ampersand last, so an already-decoded `<` is not re-processed and a
        // literal `&amp;lt;` decodes to `&lt;` rather than `<`.
        .replace("&amp;", "&")
}

/// Rejects a full-file-encrypted document before any node is read.
fn check_not_encrypted(element: &BytesStart<'_>) -> Result<(), String> {
    if attr(element, "FullFileEncryption").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        return Err(
            "The document is fully encrypted. Export it without full-file encryption, \
             or decrypt it in mRemoteNG first, then import."
                .to_string(),
        );
    }
    Ok(())
}

impl Default for MRemoteNgImporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ImportSource for MRemoteNgImporter {
    fn source_id(&self) -> &'static str {
        "mremoteng"
    }

    fn display_name(&self) -> &'static str {
        "mRemoteNG"
    }

    fn is_available(&self) -> bool {
        self.default_paths().iter().any(|p| p.exists())
    }

    fn default_paths(&self) -> Vec<PathBuf> {
        self.custom_paths.clone()
    }

    fn import(&self) -> Result<ImportResult, ImportError> {
        let paths = self.default_paths();
        if paths.is_empty() {
            return Err(ImportError::FileNotFound(PathBuf::from(
                "mRemoteNG confCons.xml (select a file)",
            )));
        }
        let mut combined = ImportResult::new();
        for path in paths {
            match self.import_from_path(&path) {
                Ok(result) => combined.merge(result),
                Err(e) => combined.add_error(e),
            }
        }
        Ok(combined)
    }

    fn import_from_path(&self, path: &Path) -> Result<ImportResult, ImportError> {
        let content = read_import_file(path, SOURCE_NAME)?;
        Ok(self.parse_xml(&content, &path.display().to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssh_connection_from_attributes() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Connections Name="Connections" ConfVersion="2.6">
  <Node Name="Web Server" Type="Connection" Hostname="192.168.1.10" Protocol="SSH2" Port="22" Username="admin" />
</Connections>"#;

        let result = MRemoteNgImporter::new().parse_xml(xml, "confCons.xml");
        assert!(result.errors.is_empty(), "{:?}", result.errors);
        assert_eq!(result.connections.len(), 1);
        let conn = &result.connections[0];
        assert_eq!(conn.name, "Web Server");
        assert_eq!(conn.host, "192.168.1.10");
        assert_eq!(conn.port, 22);
        assert_eq!(conn.username, Some("admin".to_string()));
        assert!(matches!(conn.protocol_config, ProtocolConfig::Ssh(_)));
    }

    #[test]
    fn container_becomes_group_and_nests_connection() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Connections>
  <Node Name="Production" Type="Container">
    <Node Name="DB" Type="Connection" Hostname="db.example.com" Protocol="SSH2" />
  </Node>
</Connections>"#;

        let result = MRemoteNgImporter::new().parse_xml(xml, "confCons.xml");
        assert_eq!(result.groups.len(), 1);
        assert_eq!(result.connections.len(), 1);
        let group = &result.groups[0];
        assert_eq!(group.name, "Production");
        assert_eq!(result.connections[0].group_id, Some(group.id));
    }

    #[test]
    fn nested_containers_track_the_right_parent() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Connections>
  <Node Name="Outer" Type="Container">
    <Node Name="Inner" Type="Container">
      <Node Name="Deep" Type="Connection" Hostname="deep.example.com" Protocol="SSH2" />
    </Node>
    <Node Name="Sibling" Type="Connection" Hostname="sib.example.com" Protocol="SSH2" />
  </Node>
</Connections>"#;

        let result = MRemoteNgImporter::new().parse_xml(xml, "confCons.xml");
        assert_eq!(result.groups.len(), 2);
        assert_eq!(result.connections.len(), 2);

        let outer = result.groups.iter().find(|g| g.name == "Outer").unwrap();
        let inner = result.groups.iter().find(|g| g.name == "Inner").unwrap();
        assert_eq!(inner.parent_id, Some(outer.id));

        let deep = result
            .connections
            .iter()
            .find(|c| c.name == "Deep")
            .unwrap();
        let sibling = result
            .connections
            .iter()
            .find(|c| c.name == "Sibling")
            .unwrap();
        // Deep sits under Inner; Sibling under Outer — the parent stack popped
        // correctly when </Node> for Inner closed.
        assert_eq!(deep.group_id, Some(inner.id));
        assert_eq!(sibling.group_id, Some(outer.id));
    }

    #[test]
    fn maps_protocols_and_default_ports() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Connections>
  <Node Name="R" Type="Connection" Hostname="r.example.com" Protocol="RDP" />
  <Node Name="V" Type="Connection" Hostname="v.example.com" Protocol="VNC" />
  <Node Name="T" Type="Connection" Hostname="t.example.com" Protocol="Telnet" />
</Connections>"#;

        let result = MRemoteNgImporter::new().parse_xml(xml, "confCons.xml");
        assert_eq!(result.connections.len(), 3);
        let rdp = result.connections.iter().find(|c| c.name == "R").unwrap();
        let vnc = result.connections.iter().find(|c| c.name == "V").unwrap();
        let telnet = result.connections.iter().find(|c| c.name == "T").unwrap();
        assert_eq!(rdp.port, 3389);
        assert!(matches!(rdp.protocol_config, ProtocolConfig::Rdp(_)));
        assert_eq!(vnc.port, 5900);
        assert!(matches!(vnc.protocol_config, ProtocolConfig::Vnc(_)));
        assert_eq!(telnet.port, 23);
        assert!(matches!(telnet.protocol_config, ProtocolConfig::Telnet(_)));
    }

    #[test]
    fn explicit_port_wins_over_default() {
        let xml = r#"<Connections>
  <Node Name="Alt" Type="Connection" Hostname="alt.example.com" Protocol="SSH2" Port="2222" />
</Connections>"#;
        let result = MRemoteNgImporter::new().parse_xml(xml, "confCons.xml");
        assert_eq!(result.connections[0].port, 2222);
    }

    #[test]
    fn hostless_connection_is_skipped() {
        let xml = r#"<Connections>
  <Node Name="Broken" Type="Connection" Protocol="SSH2" />
</Connections>"#;
        let result = MRemoteNgImporter::new().parse_xml(xml, "confCons.xml");
        assert!(result.connections.is_empty());
        assert_eq!(result.skipped.len(), 1);
    }

    #[test]
    fn unsupported_protocol_is_skipped() {
        let xml = r#"<Connections>
  <Node Name="Citrix" Type="Connection" Hostname="ica.example.com" Protocol="ICA" />
</Connections>"#;
        let result = MRemoteNgImporter::new().parse_xml(xml, "confCons.xml");
        assert!(result.connections.is_empty());
        assert_eq!(result.skipped.len(), 1);
    }

    #[test]
    fn full_file_encryption_is_reported_not_parsed() {
        let xml = r#"<Connections FullFileEncryption="true" Protected="base64data">
  <Node Name="Hidden" Type="Connection" Hostname="secret.example.com" Protocol="SSH2" />
</Connections>"#;
        let result = MRemoteNgImporter::new().parse_xml(xml, "confCons.xml");
        assert!(result.connections.is_empty());
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn rdp_domain_is_imported() {
        let xml = r#"<Connections>
  <Node Name="DC" Type="Connection" Hostname="dc.example.com" Protocol="RDP" Username="admin" Domain="CORP" />
</Connections>"#;
        let result = MRemoteNgImporter::new().parse_xml(xml, "confCons.xml");
        assert_eq!(result.connections.len(), 1);
        assert_eq!(result.connections[0].domain, Some("CORP".to_string()));
    }

    #[test]
    fn no_password_is_imported_even_when_present() {
        // mRemoteNG stores an encrypted Password attribute; it must never
        // become a credential.
        let xml = r#"<Connections>
  <Node Name="S" Type="Connection" Hostname="s.example.com" Protocol="SSH2" Password="encrypted==" />
</Connections>"#;
        let result = MRemoteNgImporter::new().parse_xml(xml, "confCons.xml");
        assert_eq!(result.connections.len(), 1);
        assert!(!result.has_credentials());
    }
}
