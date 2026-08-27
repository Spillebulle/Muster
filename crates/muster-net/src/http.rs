//! One HTTP request over a connection, and what came back.
//!
//! Phase four has asked its questions in datagrams and in three binary
//! protocols, and never in the one protocol every device on the link speaks.
//! That is the gap this fills. Two things want it:
//!
//! * **The UPnP description.** [`crate::ssdp`] reads a `LOCATION` header out of
//!   every SSDP reply and has never followed it. The document at the other end
//!   carries the manufacturer, the model name, the model number and often a
//!   serial number, and on a router it also carries the control URL that
//!   [`crate::igd`] needs.
//! * **The `WWW-Authenticate` realm.** A device that answers a bare `GET /`
//!   with a 401 names its realm in the refusal, and on cameras, routers and
//!   NAS boxes that realm is very often the exact model. Reading a challenge
//!   sends nothing back and answers nothing, so it stays inside the conduct
//!   rules as cleanly as the SSH greeting does.
//!
//! ## Why there is a client here at all
//!
//! `Cargo.toml` carries `log`, `socket2` and the two platform crates, and none
//! of them speaks HTTP. The alternative was a crate, and the smallest honest
//! one pulls a TLS stack, a URL parser and an async runtime behind it — for a
//! request that is one line, three headers and a read to end of stream. What is
//! here is that request and the reader for its answer, and nothing else: no
//! redirects followed, no cookies kept, no connection reused, no compression
//! offered.
//!
//! ## What it will not do
//!
//! **It speaks `http` and refuses `https`, and it says so rather than
//! pretending.** There is no TLS in this crate, so a description behind one is
//! a blank rather than a guess, which is `CLAUDE.md`'s rule about blanks.
//!
//! **It will not follow a URL off the device that gave it.** A `LOCATION`
//! header is text a device wrote, and a device that put `http://example.com/`
//! in one would have this machine open a connection to the internet on its
//! say-so. That is the conduct rule — nothing leaves the machine — broken by a
//! stranger rather than by a bug, so [`Session`] is built around one address
//! and refuses every URL that does not name it. It is the reason the address is
//! a field of the session rather than a parameter of the request.
//!
//! ## Nothing here opens a socket in a test
//!
//! The platform surface is [`Wire`], with one method, the same shape
//! [`crate::service::Speak`] and [`crate::identify::Ask`] already use. Building
//! a request and reading a response are separate functions over bytes, and they
//! are tested against recorded exchanges.

use crate::rate::Bucket;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

/// The most of one response that is worth reading.
///
/// A UPnP description is two to eight kilobytes and a SOAP reply is a few
/// hundred bytes. This is generous by an order of magnitude, and it is a cap
/// rather than a target: without one, a device answering with a megabyte a
/// second decides how much of this machine's memory a scan spends.
pub const MOST: usize = 128 * 1024;

/// How long one request and its answer may take.
///
/// The same reasoning as [`crate::service::Options::timeout`]: a connection, an
/// exchange, and a device that has to build the answer. A router enumerating a
/// port mapping out of its own table is slower than a NAS greeting a socket.
pub const TIMEOUT: Duration = Duration::from_millis(1_500);

/// What Muster calls itself to a device it asks.
///
/// The product and its version, and **deliberately not the operating system**,
/// which the `User-Agent` of a browser and the `SERVER` of a UPnP stack both
/// carry. A scan is entitled to say what is asking; it is not entitled to hand
/// every device on the link a description of the machine it is running on.
fn agent() -> String {
    format!("Muster/{}", env!("CARGO_PKG_VERSION"))
}

/// One HTTP exchange over one connection.
///
/// The whole platform surface of this module. An error is "it did not answer":
/// a refused connection, a timeout and a reset all arrive here the same way,
/// and none of them is evidence about the device beyond silence.
pub trait Wire: Sync {
    /// Connects to `to`, writes `request`, and reads the answer until the far
    /// end closes, `most` bytes have arrived, or `timeout` runs out.
    ///
    /// **Reading to the close is the contract**, and it is why this is not
    /// [`crate::service::Speak`]: that trait stops at the first thirty-two
    /// bytes on purpose, because an SSH server never closes and every answer it
    /// reads arrives in one segment. An XML description is neither.
    fn exchange(
        &self,
        to: SocketAddr,
        request: &[u8],
        timeout: Duration,
        most: usize,
    ) -> io::Result<Vec<u8>>;
}

/// The real connection: `std` and nothing else, on every platform.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sockets;

impl Wire for Sockets {
    fn exchange(
        &self,
        to: SocketAddr,
        request: &[u8],
        timeout: Duration,
        most: usize,
    ) -> io::Result<Vec<u8>> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Instant;

        let stream = TcpStream::connect_timeout(&to, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        // One write per connection, so there is no second one for Nagle to
        // wait for.
        let _ = stream.set_nodelay(true);

        let mut stream = stream;
        stream.write_all(request)?;
        stream.flush()?;

        let deadline = Instant::now() + timeout;
        let mut out = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    if out.is_empty() {
                        return Err(e);
                    }
                    break;
                }
            }
            if out.len() >= most || Instant::now() >= deadline {
                break;
            }
        }

        out.truncate(most);
        if out.is_empty() {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "the connection opened and nothing was said on it",
            ));
        }
        Ok(out)
    }
}

/// An `http` URL, split into the parts a request needs.
///
/// No query is separated out and no fragment is dropped: whatever follows the
/// host is the request target verbatim, which is what a server wants and what
/// keeps a control URL with a query string in it intact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    /// The host as written, without the brackets an IPv6 literal wears.
    pub host: String,
    pub port: u16,
    /// The request target, always starting with a slash.
    pub path: String,
}

impl Url {
    /// Reads an absolute `http` URL.
    ///
    /// [`None`] for anything else, `https` included: see the module note. A
    /// scheme this cannot speak is a blank, and a blank is an answer.
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        let mut rest = None;
        for prefix in ["http://", "HTTP://", "Http://"] {
            if let Some(after) = raw.strip_prefix(prefix) {
                rest = Some(after);
                break;
            }
        }
        let rest = rest?;
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
        // No credentials are carried and none are sent, so a URL that asks for
        // them is not one this will open.
        if authority.contains('@') || authority.is_empty() {
            return None;
        }

        let (host, port) = if let Some(shut) = authority.strip_prefix('[') {
            // An IPv6 literal: `[::1]:80`.
            let (inside, after) = shut.split_once(']')?;
            (inside.to_string(), after.strip_prefix(':'))
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            (host.to_string(), Some(port))
        } else {
            (authority.to_string(), None)
        };
        if host.is_empty() {
            return None;
        }
        let port = match port {
            Some(text) => text.parse::<u16>().ok().filter(|p| *p != 0)?,
            None => 80,
        };

        Some(Self {
            host,
            port,
            path: path.to_string(),
        })
    }

    /// Does this URL name that address, and no other place?
    ///
    /// The guard the whole module is built around. The host has to parse as an
    /// address and be the one the answer came from; a name does not pass, and
    /// neither does a different address. **A name is refused even though
    /// resolving it would usually reach the same device**, because resolving it
    /// is a question this machine would be asking on a stranger's instruction,
    /// and the point of the rule is that a device cannot send a scan anywhere.
    pub fn names(&self, address: IpAddr) -> bool {
        self.host.parse::<IpAddr>() == Ok(address)
    }

    /// What goes in `Host`. The brackets come back for an IPv6 literal, and the
    /// default port is left off, which is what every server expects.
    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 80 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// Where to connect, once the host is known to be an address.
    fn socket(&self) -> Option<SocketAddr> {
        Some(SocketAddr::new(self.host.parse().ok()?, self.port))
    }

    /// Resolves a possibly relative URL against this one.
    ///
    /// UPnP writes control URLs three ways in the wild — absolute
    /// (`http://192.168.1.1:5000/ctl/IPConn`), rooted (`/ctl/IPConn`) and
    /// relative (`ctl/IPConn`) — and a description is entitled to change the
    /// base out from under all three with a `URLBase` element. All three are
    /// read here so that the callers do not each get it slightly wrong.
    pub fn join(&self, other: &str) -> Option<Self> {
        let other = other.trim();
        if other.is_empty() {
            return None;
        }
        if other.contains("://") {
            return Self::parse(other);
        }
        if let Some(rooted) = other.strip_prefix('/') {
            return Some(Self {
                host: self.host.clone(),
                port: self.port,
                path: format!("/{rooted}"),
            });
        }
        // Relative: everything up to and including the last slash of this path.
        let base = match self.path.rfind('/') {
            Some(at) => &self.path[..=at],
            None => "/",
        };
        Some(Self {
            host: self.host.clone(),
            port: self.port,
            path: format!("{base}{other}"),
        })
    }
}

/// A `GET` with no body, asking for nothing but the document.
///
/// `Connection: close` is not politeness: it is what makes the end of the
/// response the end of the stream, so a server that sends neither a length nor
/// a chunked encoding is still read whole.
pub fn get(url: &Url) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: {}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\
         \r\n",
        url.path,
        url.authority(),
        agent()
    )
    .into_bytes()
}

/// A `POST` with a body, which is how SOAP is asked.
///
/// `extra` carries the one header UPnP adds, `SOAPACTION`, rather than it being
/// baked in: this module knows HTTP and [`crate::igd`] knows UPnP, and the line
/// between them is worth keeping.
pub fn post(url: &Url, content_type: &str, extra: &[(&str, String)], body: &[u8]) -> Vec<u8> {
    let mut head = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n",
        url.path,
        url.authority(),
        agent(),
        content_type,
        body.len()
    );
    for (name, value) in extra {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");

    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// A response, read far enough to be useful and no further.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    /// Names, lower cased, and values as written.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// The first header with that name, whatever the server capitalised it.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(had, _)| *had == name)
            .map(|(_, value)| value.as_str())
    }

    /// The body as text.
    ///
    /// Lossy, and on purpose: a description with one bad byte in a model name
    /// is still a description, and throwing the document away for it would lose
    /// every other field in it.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Reads a response: the status line, the headers, and the body.
///
/// [`None`] when the front of it is not HTTP at all, which is what something
/// else listening on port 80 looks like.
pub fn parse(raw: &[u8]) -> Option<Response> {
    let (head_end, body_at) = find(raw, b"\r\n\r\n")
        .map(|at| (at, at + 4))
        .or_else(|| find(raw, b"\n\n").map(|at| (at, at + 2)))?;
    let head = String::from_utf8_lossy(&raw[..head_end]);

    let mut lines = head.split('\n');
    let status_line = lines.next()?.trim_end_matches('\r');
    let mut parts = status_line.split_whitespace();
    if !parts.next()?.starts_with("HTTP/") {
        return None;
    }
    let status: u16 = parts.next()?.parse().ok()?;

    let mut headers = Vec::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }

    let rest = &raw[body_at..];
    let chunked = headers.iter().any(|(name, value)| {
        name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked")
    });
    let body = if chunked {
        dechunk(rest)
    } else if let Some(length) = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
    {
        // A server that promised more than it sent has been cut off, and what
        // did arrive is still the front of the document.
        rest[..length.min(rest.len())].to_vec()
    } else {
        rest.to_vec()
    };

    Some(Response {
        status,
        headers,
        body,
    })
}

/// Reassembles a chunked body.
///
/// Routers do send these — MiniUPnPd answers with a length and several stock
/// firmwares do not — and a reader that ignored the encoding would hand
/// [`crate::igd`] an XML document with hexadecimal counts scattered through it.
/// That parses to nothing, and looks on screen exactly like a router that
/// answered nothing, which is the lie this project keeps refusing to tell.
///
/// Stops at the first chunk it cannot read and keeps what came before, for the
/// same reason a short `Content-Length` is kept: half a document is still the
/// half that was sent.
fn dechunk(mut rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rest.len());
    while let Some(eol) = find(rest, b"\r\n") {
        let line = String::from_utf8_lossy(&rest[..eol]);
        // A chunk size may carry extensions after a semicolon.
        let size = line.split(';').next().unwrap_or("").trim().to_string();
        let Ok(size) = usize::from_str_radix(&size, 16) else {
            break;
        };
        if size == 0 {
            break;
        }
        let start = eol + 2;
        let end = start + size;
        if end > rest.len() {
            out.extend_from_slice(&rest[start.min(rest.len())..]);
            break;
        }
        out.extend_from_slice(&rest[start..end]);
        // Past the chunk's own trailing newline.
        rest = &rest[(end + 2).min(rest.len())..];
    }
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// What a device demanded when it refused a bare `GET`.
///
/// The realm is the interesting half. `WWW-Authenticate: Basic realm="TL-WR841N"`
/// is a router naming its own model in a refusal, and cameras and NAS boxes do
/// the same. **Only the realm is taken.** Nothing here answers a challenge,
/// offers a credential or tries one, which is the conduct rule and is also why
/// this is worth having at all: it is a fact a device volunteers to anybody who
/// knocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// `Basic`, `Digest`, whatever it asked for. Kept because it is part of
    /// what the device said, not because anything answers it.
    pub scheme: String,
    pub realm: Option<String>,
}

/// The challenge out of a 401.
///
/// **Only out of a 401.** A `WWW-Authenticate` on any other status is a device
/// volunteering a header it had no reason to send, and reading a realm off a
/// 200 would put a login prompt's name on a device that never asked for one.
pub fn challenge(response: &Response) -> Option<Challenge> {
    if response.status != 401 {
        return None;
    }
    let header = response.header("www-authenticate")?;
    let scheme = header.split_whitespace().next()?.to_string();
    if scheme.is_empty() {
        return None;
    }
    Some(Challenge {
        realm: realm(header),
        scheme,
    })
}

/// The `realm` parameter of a challenge, quoted or bare.
///
/// The parameters are comma separated and a realm may contain a comma, so the
/// quoted form is read to its closing quote rather than to the next comma. A
/// bare realm is not legal and firmware sends it anyway.
fn realm(header: &str) -> Option<String> {
    let lower = header.to_ascii_lowercase();
    let mut at = 0;
    while let Some(found) = lower[at..].find("realm") {
        let start = at + found;
        at = start + "realm".len();
        // What comes before has to be a separator, or this is `realm` inside
        // another parameter's value.
        if !matches!(
            lower[..start].chars().next_back(),
            None | Some(' ' | ',' | ';' | '\t')
        ) {
            continue;
        }
        let after = header[at..].trim_start();
        let Some(value) = after.strip_prefix('=') else {
            continue;
        };
        let value = value.trim_start();
        let text = match value.strip_prefix('"') {
            Some(quoted) => quoted.split('"').next().unwrap_or("").to_string(),
            None => value
                .split([',', ';'])
                .next()
                .unwrap_or("")
                .trim()
                .to_string(),
        };
        let text: String = text.chars().take(SHORT).collect();
        return (!text.is_empty()).then_some(text);
    }
    None
}

/// How much of a realm or a `Server` header is worth keeping.
///
/// Both are labels: one goes on a login box and one names a product. A device
/// sending a paragraph in either is not naming a model, and the table is not
/// the place to find that out.
const SHORT: usize = 64;

/// What a bare `GET /` got back, and nothing more than that.
///
/// Both fields are things a server volunteers to anybody who connects, which is
/// the same standing the SSH greeting in [`crate::service`] has. `Server` is
/// deliberately kept as written rather than reduced to a product: it is the
/// device's own words.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Greeting {
    pub status: u16,
    pub server: Option<String>,
    /// The realm of a 401, where there was one.
    pub realm: Option<String>,
}

impl Greeting {
    pub fn is_empty(&self) -> bool {
        self.server.is_none() && self.realm.is_none()
    }
}

/// A conversation with one device, bounded to that device.
///
/// Every request goes through the rate limiter, every request is checked
/// against the one address this session may reach, and every request is
/// abandoned when the scan is cancelled. Holding those three in a struct rather
/// than passing them to each call is what stops the next question being the one
/// that forgets one of them.
pub struct Session<'a, W: Wire + ?Sized> {
    pub wire: &'a W,
    /// The only address this session will open a connection to.
    pub address: IpAddr,
    pub rate: &'a Bucket,
    pub timeout: Duration,
    pub cancel: &'a AtomicBool,
}

impl<W: Wire + ?Sized> Session<'_, W> {
    /// Sends one already-built request to a URL on this session's device.
    pub fn send(&self, url: &Url, request: &[u8]) -> io::Result<Response> {
        if !url.names(self.address) {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "that device named somewhere other than itself, so nothing was fetched",
            ));
        }
        let Some(to) = url.socket() else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "that is not an address",
            ));
        };
        if !self.rate.wait_unless(self.cancel) {
            return Err(io::Error::new(
                ErrorKind::Interrupted,
                "the scan was stopped",
            ));
        }
        let raw = self.wire.exchange(to, request, self.timeout, MOST)?;
        parse(&raw).ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidData,
                "something answered on that port and it was not HTTP",
            )
        })
    }

    /// Fetches a document.
    pub fn get(&self, url: &Url) -> io::Result<Response> {
        self.send(url, &get(url))
    }

    /// Posts a body, with whatever extra headers the protocol above needs.
    pub fn post(
        &self,
        url: &Url,
        content_type: &str,
        extra: &[(&str, String)],
        body: &[u8],
    ) -> io::Result<Response> {
        self.send(url, &post(url, content_type, extra, body))
    }

    /// Knocks on a port and reads what the server volunteers.
    ///
    /// One `GET /`, and nothing is done with the answer's body. A device that
    /// is not there, does not answer or does not speak HTTP gives an empty
    /// [`Greeting`], which is the blank this is entitled to report.
    pub fn greeting(&self, port: u16) -> Greeting {
        let url = Url {
            host: self.address.to_string(),
            port,
            path: "/".to_string(),
        };
        let Ok(response) = self.get(&url) else {
            return Greeting::default();
        };
        Greeting {
            status: response.status,
            server: response
                .header("server")
                .map(|value| value.chars().take(SHORT).collect::<String>())
                .filter(|value| !value.is_empty()),
            realm: challenge(&response).and_then(|challenge| challenge.realm),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Recorded exchanges, keyed by where the connection went. Nothing in this
    /// crate's tests opens a socket, and [`crate::igd`]'s tests borrow this one
    /// rather than growing a second fake that could drift from it.
    #[derive(Default)]
    pub struct Fake {
        pub replies: BTreeMap<SocketAddr, Vec<u8>>,
        pub sent: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
    }

    impl Fake {
        /// Records a 200 with a body, framed with a length the way a router
        /// frames one.
        pub fn answers(&mut self, at: &str, content_type: &str, body: &str) {
            let raw = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                content_type,
                body.len(),
                body
            );
            self.replies
                .insert(at.parse().expect("an address"), raw.into_bytes());
        }
    }

    impl Wire for Fake {
        fn exchange(
            &self,
            to: SocketAddr,
            request: &[u8],
            _timeout: Duration,
            _most: usize,
        ) -> io::Result<Vec<u8>> {
            self.sent.lock().unwrap().push((to, request.to_vec()));
            match self.replies.get(&to) {
                Some(reply) => Ok(reply.clone()),
                None => Err(io::Error::new(ErrorKind::TimedOut, "nothing answered")),
            }
        }
    }

    fn url(raw: &str) -> Url {
        Url::parse(raw).expect("a URL")
    }

    #[test]
    fn a_location_is_split_into_the_parts_a_request_needs() {
        let u = url("http://192.168.1.1:5000/rootDesc.xml");
        assert_eq!(u.host, "192.168.1.1");
        assert_eq!(u.port, 5000);
        assert_eq!(u.path, "/rootDesc.xml");
        assert_eq!(u.authority(), "192.168.1.1:5000");
    }

    #[test]
    fn a_url_with_no_port_and_no_path_is_still_a_url() {
        let u = url("http://192.168.1.1");
        assert_eq!(u.port, 80, "the scheme's own port");
        assert_eq!(u.path, "/");
        assert_eq!(u.authority(), "192.168.1.1", "and it is left off Host");
    }

    #[test]
    fn an_ipv6_literal_keeps_its_brackets_where_they_belong() {
        let u = url("http://[fe80::1]:2869/desc.xml");
        assert_eq!(u.host, "fe80::1", "not in the address");
        assert_eq!(u.port, 2869);
        assert_eq!(u.authority(), "[fe80::1]:2869", "and in the header");
    }

    /// There is no TLS in this crate, so a scheme it cannot speak is a blank.
    #[test]
    fn https_is_refused_rather_than_attempted() {
        assert_eq!(Url::parse("https://192.168.1.1/desc.xml"), None);
        assert_eq!(Url::parse("ftp://192.168.1.1/desc.xml"), None);
        assert_eq!(Url::parse("192.168.1.1/desc.xml"), None);
        assert_eq!(Url::parse(""), None);
    }

    #[test]
    fn a_url_carrying_credentials_is_not_opened() {
        assert_eq!(Url::parse("http://admin:admin@192.168.1.1/"), None);
    }

    #[test]
    fn a_control_url_is_resolved_all_three_ways_it_is_written() {
        let base = url("http://192.168.1.1:5000/dev/desc.xml");
        assert_eq!(base.join("/ctl/IPConn").unwrap().path, "/ctl/IPConn");
        assert_eq!(base.join("ctl/IPConn").unwrap().path, "/dev/ctl/IPConn");
        let absolute = base.join("http://192.168.1.1:80/upnp/ctl").unwrap();
        assert_eq!(absolute.port, 80);
        assert_eq!(absolute.path, "/upnp/ctl");
        assert_eq!(base.join(""), None);
    }

    /// The guard the module exists for: a device's own text cannot send this
    /// machine anywhere but back to that device.
    #[test]
    fn a_url_naming_somewhere_else_is_not_this_device() {
        let here: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(url("http://192.168.1.1:5000/d.xml").names(here));
        assert!(!url("http://192.168.1.2:5000/d.xml").names(here));
        assert!(
            !url("http://example.com/d.xml").names(here),
            "a name is refused even where it would resolve to the device"
        );
        assert!(!url("http://router.local/d.xml").names(here));
    }

    #[test]
    fn a_session_refuses_to_fetch_off_the_device_it_is_talking_to() {
        let fake = Fake::default();
        let rate = Bucket::new(1_000_000);
        let cancel = AtomicBool::new(false);
        let session = Session {
            wire: &fake,
            address: "192.168.1.1".parse().unwrap(),
            rate: &rate,
            timeout: TIMEOUT,
            cancel: &cancel,
        };
        let refused = session.get(&url("http://93.184.216.34/desc.xml"));
        assert!(refused.is_err());
        assert!(
            fake.sent.lock().unwrap().is_empty(),
            "and no connection was opened at all"
        );
    }

    #[test]
    fn a_cancelled_session_sends_nothing() {
        let fake = Fake::default();
        let rate = Bucket::new(1_000_000);
        let cancel = AtomicBool::new(true);
        let session = Session {
            wire: &fake,
            address: "192.168.1.1".parse().unwrap(),
            rate: &rate,
            timeout: TIMEOUT,
            cancel: &cancel,
        };
        assert!(session.get(&url("http://192.168.1.1/desc.xml")).is_err());
        assert!(fake.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn a_request_says_what_is_asking_and_nothing_about_this_machine() {
        let text = String::from_utf8(get(&url("http://192.168.1.1:5000/d.xml"))).unwrap();
        assert!(text.starts_with("GET /d.xml HTTP/1.1\r\n"));
        assert!(text.contains("Host: 192.168.1.1:5000\r\n"));
        assert!(text.contains(&format!("User-Agent: Muster/{}", env!("CARGO_PKG_VERSION"))));
        // The close is what makes the end of the stream the end of the answer.
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_post_carries_its_length_and_its_extra_header() {
        let body = b"<s:Envelope/>";
        let raw = post(
            &url("http://192.168.1.1:5000/ctl/IPConn"),
            "text/xml; charset=\"utf-8\"",
            &[("SOAPACTION", "\"urn:x#GetExternalIPAddress\"".to_string())],
            body,
        );
        let text = String::from_utf8(raw).unwrap();
        assert!(text.starts_with("POST /ctl/IPConn HTTP/1.1\r\n"));
        assert!(text.contains("Content-Length: 13\r\n"));
        assert!(text.contains("SOAPACTION: \"urn:x#GetExternalIPAddress\"\r\n"));
        assert!(text.ends_with("\r\n\r\n<s:Envelope/>"));
    }

    #[test]
    fn a_response_is_read_by_its_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 5\r\n\r\nhellotrailing rubbish";
        let r = parse(raw).expect("a response");
        assert_eq!(r.status, 200);
        assert_eq!(r.header("content-type"), Some("text/xml"));
        assert_eq!(
            r.header("CONTENT-TYPE"),
            Some("text/xml"),
            "case is nothing"
        );
        assert_eq!(r.text(), "hello");
    }

    /// A server that sent no length and no encoding has said everything it is
    /// going to say by closing.
    #[test]
    fn a_response_with_no_length_is_read_to_the_end_of_the_stream() {
        let raw = b"HTTP/1.0 200 OK\r\nServer: Boa/0.94\r\n\r\n<root/>";
        let r = parse(raw).expect("a response");
        assert_eq!(r.text(), "<root/>");
    }

    /// The one that would have looked like a router answering nothing.
    #[test]
    fn a_chunked_body_is_put_back_together() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n<root>\n\r\n8\r\n</root>\n\r\n0\r\n\r\n";
        let r = parse(raw).expect("a response");
        assert_eq!(r.text(), "<root>\n</root>\n");
    }

    #[test]
    fn a_truncated_body_keeps_what_arrived() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n<root/>";
        assert_eq!(parse(raw).expect("a response").text(), "<root/>");
    }

    #[test]
    fn something_that_is_not_http_is_not_a_response() {
        assert_eq!(parse(b""), None);
        assert_eq!(parse(b"\x00\x01\x02\x03\r\n\r\n"), None);
        assert_eq!(parse(b"SSH-2.0-OpenSSH_9.6\r\n\r\n"), None);
    }

    /// The whole reason a 401 is worth reading: the realm is the model.
    #[test]
    fn the_realm_of_a_refusal_is_often_the_model() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"TL-WR841N\"\r\nServer: Router Webserver\r\n\r\n";
        let r = parse(raw).expect("a response");
        let c = challenge(&r).expect("a challenge");
        assert_eq!(c.scheme, "Basic");
        assert_eq!(c.realm.as_deref(), Some("TL-WR841N"));
    }

    #[test]
    fn a_digest_challenge_gives_up_its_realm_and_nothing_else() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest qop=\"auth\", realm=\"AXIS_ACCC8E1B2C3D\", nonce=\"abc\"\r\n\r\n";
        let c = challenge(&parse(raw).expect("a response")).expect("a challenge");
        assert_eq!(c.scheme, "Digest");
        assert_eq!(c.realm.as_deref(), Some("AXIS_ACCC8E1B2C3D"));
    }

    /// A realm on anything but a refusal is a device volunteering a header it
    /// had no reason to send, and it is not a login prompt's name.
    #[test]
    fn only_a_refusal_carries_a_challenge() {
        let raw = b"HTTP/1.1 200 OK\r\nWWW-Authenticate: Basic realm=\"nothing\"\r\n\r\n";
        assert_eq!(challenge(&parse(raw).expect("a response")), None);
    }

    #[test]
    fn a_refusal_with_no_realm_is_still_a_refusal() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\n\r\n";
        let c = challenge(&parse(raw).expect("a response")).expect("a challenge");
        assert_eq!(c.scheme, "Basic");
        assert_eq!(c.realm, None, "and a blank realm is an answer");
    }

    #[test]
    fn a_greeting_is_one_get_and_the_headers_it_came_back_with() {
        let mut fake = Fake::default();
        fake.replies.insert(
            "192.168.1.20:80".parse().unwrap(),
            b"HTTP/1.1 401 Unauthorized\r\nServer: lighttpd/1.4.45\r\nWWW-Authenticate: Basic realm=\"DS920+\"\r\n\r\n".to_vec(),
        );
        let rate = Bucket::new(1_000_000);
        let cancel = AtomicBool::new(false);
        let session = Session {
            wire: &fake,
            address: "192.168.1.20".parse().unwrap(),
            rate: &rate,
            timeout: TIMEOUT,
            cancel: &cancel,
        };
        let greeting = session.greeting(80);
        assert_eq!(greeting.status, 401);
        assert_eq!(greeting.server.as_deref(), Some("lighttpd/1.4.45"));
        assert_eq!(greeting.realm.as_deref(), Some("DS920+"));

        let sent = fake.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "one request");
        let text = String::from_utf8(sent[0].1.clone()).unwrap();
        assert!(text.starts_with("GET / HTTP/1.1\r\n"));
        assert!(
            !text.to_ascii_lowercase().contains("authorization"),
            "and nothing was offered in answer to the challenge"
        );
    }

    #[test]
    fn a_device_that_does_not_answer_gives_a_blank_greeting() {
        let fake = Fake::default();
        let rate = Bucket::new(1_000_000);
        let cancel = AtomicBool::new(false);
        let session = Session {
            wire: &fake,
            address: "192.168.1.21".parse().unwrap(),
            rate: &rate,
            timeout: TIMEOUT,
            cancel: &cancel,
        };
        assert!(session.greeting(80).is_empty());
    }
}
