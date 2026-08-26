//! The other half of phase four: asking a device what it **serves**.
//!
//! [`crate::identify`] asks a device what it is, over UDP, and every question
//! there is a datagram out and one back. The questions here are the ones that
//! can only be asked over a connection — the file servers, and the shell — so
//! they need a transport of their own, and that transport is [`Speak`].
//!
//! ## What a role costs, and what it is worth
//!
//! `CLAUDE.md`: **a role is only ever a service that answered.** Never an open
//! port, never a vendor that usually runs one. So none of these is a knock on a
//! port: each opens a connection, speaks the protocol's own opening move, and
//! reads the protocol's own answer. A device with 445 open that answers nothing
//! in SMB gets no badge, which is the whole difference between this and a port
//! scan.
//!
//! Three, and the reason each is here rather than another:
//!
//! * **SMB**, port 445. What one machine on a home or office network is almost
//!   always doing for the others, and the thing somebody scanning a network is
//!   most often looking for. The opening is an SMB2 `NEGOTIATE`, which is what
//!   every client sends as its first packet; anything answering with the SMB
//!   header is a file server, including every Samba box, every NAS and every
//!   Windows machine with sharing switched on.
//! * **NFS**, port 2049. The same question asked of the other half of the
//!   world. The opening is an ONC RPC `NULL` call to the NFS programme, which
//!   is the no-op the protocol defines for exactly this: it asks the server to
//!   do nothing and answer, and reads nothing off any file system.
//! * **SSH**, port 22, and this one **sends nothing at all**. An SSH server
//!   volunteers its identification string the moment a connection opens, and
//!   reading it is the purest form of the banner grabbing `CLAUDE.md`'s conduct
//!   rules allow. Nothing is offered, nothing is authenticated, and the
//!   connection is dropped after the greeting.
//!
//! What is deliberately **not** here is HTTP. Nearly every device on a modern
//! network answers on 80 or 443 — a printer, a camera, a light bulb bridge —
//! so a "web" badge would be on every row and would separate nothing from
//! anything. A badge that is always true is a column of noise.
//!
//! ## Nothing here opens a socket in a test
//!
//! The whole platform surface is [`Speak`], with one method, and the tests
//! drive it with recorded exchanges. The message builders and the readers are
//! separate functions over bytes for the same reason: the part that can be
//! wrong is the part that reads a reply, and it is tested against captured
//! bytes rather than against a server.

use crate::rate::Bucket;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Where a file server listens, and where a shell does.
pub const SMB_PORT: u16 = 445;
pub const NFS_PORT: u16 = 2049;
pub const SSH_PORT: u16 = 22;

/// One connection: an opening, and what came back.
///
/// The whole platform surface of this phase, and the reason it is a trait is
/// `CLAUDE.md`'s: an engine whose tests need a network has no tests.
pub trait Speak: Sync {
    /// Connects to `to`, sends `opening`, and reads up to `most` bytes of
    /// whatever the far end says.
    ///
    /// **An empty opening sends nothing**, which is how a service that greets
    /// first is read: SSH announces itself to anything that connects, so the
    /// honest probe is to connect and listen.
    ///
    /// An error is "it did not answer" and is never "it is not there": a
    /// refused connection, a timeout and a reset all arrive here as an error,
    /// and none of them is evidence of anything but silence.
    fn speak(
        &self,
        to: SocketAddr,
        opening: &[u8],
        timeout: Duration,
        most: usize,
    ) -> io::Result<Vec<u8>>;
}

/// What a device serves, as far as this phase could tell.
///
/// Every field is "it answered in the protocol". [`Default`] is "nothing
/// answered", which is also what a device gets when the question was never
/// asked — the difference between the two is kept in [`Options`], where the
/// caller decided, rather than being smuggled into a `bool` here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Serves {
    /// It answered an SMB2 `NEGOTIATE` on port 445.
    pub smb: bool,
    /// It answered an ONC RPC `NULL` call to the NFS programme on port 2049.
    pub nfs: bool,
    /// The identification string an SSH server volunteered, trimmed.
    ///
    /// `SSH-2.0-OpenSSH_9.2p1 Debian-2`. Kept rather than reduced to a flag for
    /// the same reason [`crate::identify::Resolver::version`] is: it is the
    /// software the device runs, in the device's own words, and it is the most
    /// precise thing most servers ever volunteer.
    pub ssh: Option<String>,
}

impl Serves {
    pub fn is_empty(&self) -> bool {
        !self.smb && !self.nfs && self.ssh.is_none()
    }
}

/// What to ask, and how long to wait for it.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// How long one connection and its answer may take.
    ///
    /// Longer than [`crate::identify::Options::timeout`], because this is a
    /// three-way handshake and then an exchange rather than one datagram, and
    /// a sleeping NAS answers its first connection slowly.
    pub timeout: Duration,
    pub workers: usize,
    pub smb: bool,
    pub nfs: bool,
    pub ssh: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(900),
            // Every probe is a blocking connection that mostly waits, so this
            // follows the port scan's reasoning rather than the CPU's.
            workers: 32,
            // Off, and the same decision `prefs::Prefs::scan_dhcp` records: a
            // connection is a thing the far end writes down, where a datagram
            // to a name server is not, so asking is a deliberate act.
            smb: false,
            nfs: false,
            ssh: false,
        }
    }
}

impl Options {
    /// Is there anything to ask at all?
    pub fn any(&self) -> bool {
        self.smb || self.nfs || self.ssh
    }
}

/// The most any of these replies is worth reading.
///
/// An SMB2 `NEGOTIATE` response with a security blob is a few hundred bytes, an
/// RPC reply is forty, and an SSH greeting is one line. Nothing here needs more
/// than the front of the answer, and a cap is what keeps a device that answers
/// with a megabyte from being able to spend this machine's memory.
const MOST: usize = 2048;

/// Asks one device what it serves.
///
/// Never fails. A device that answers nothing gets an empty [`Serves`], which
/// is a real answer.
pub fn one<S: Speak>(address: IpAddr, speak: &S, rate: &Bucket, opts: Options) -> Serves {
    let mut serves = Serves::default();

    if opts.smb {
        rate.wait();
        if let Ok(reply) = speak.speak(
            SocketAddr::new(address, SMB_PORT),
            &smb_negotiate(),
            opts.timeout,
            MOST,
        ) {
            serves.smb = smb_answered(&reply);
        }
    }

    if opts.nfs {
        rate.wait();
        // The transaction id is a constant rather than a counter: a reply is
        // read off the connection it was asked on, so the id is only here to
        // catch a server answering somebody else's call, and a fixed one does
        // that as well as a random one without pretending to be a nonce.
        let xid = NFS_XID;
        if let Ok(reply) = speak.speak(
            SocketAddr::new(address, NFS_PORT),
            &rpc_null(xid, NFS_PROGRAM, NFS_VERSION),
            opts.timeout,
            MOST,
        ) {
            serves.nfs = nfs_answered(&reply, xid);
        }
    }

    if opts.ssh {
        rate.wait();
        // Nothing is sent. See [`Speak::speak`].
        if let Ok(reply) = speak.speak(SocketAddr::new(address, SSH_PORT), &[], opts.timeout, MOST)
        {
            serves.ssh = ssh_greeting(&reply);
        }
    }

    serves
}

/// Asks many devices, in parallel, cancellably.
///
/// Returns one [`Serves`] per input address, in the same order, so the caller
/// can zip it against the sweep the way it does with [`crate::identify::many`].
pub fn many<S: Speak>(
    addresses: &[IpAddr],
    speak: &S,
    rate: &Bucket,
    opts: Options,
    cancel: &AtomicBool,
    progress: &(dyn Fn(usize, usize) + Sync),
) -> Vec<Serves> {
    let next = AtomicU64::new(0);
    let done = AtomicU64::new(0);
    let mut out: Vec<Serves> = vec![Serves::default(); addresses.len()];
    if !opts.any() {
        return out;
    }
    let workers = opts.workers.clamp(1, 256).min(addresses.len().max(1));

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let (next, done) = (&next, &done);
            handles.push(scope.spawn(move || {
                let mut mine: Vec<(usize, Serves)> = Vec::new();
                loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed) as usize;
                    let Some(&address) = addresses.get(i) else {
                        break;
                    };
                    mine.push((i, one(address, speak, rate, opts)));
                    progress(
                        done.fetch_add(1, Ordering::Relaxed) as usize + 1,
                        addresses.len(),
                    );
                }
                mine
            }));
        }
        for handle in handles {
            for (i, serves) in handle.join().unwrap_or_default() {
                out[i] = serves;
            }
        }
    });

    out
}

/// The NetBIOS session service header every SMB message over 445 carries.
///
/// Four bytes: a zero for "session message", then the length in the low three.
/// It is a hangover from port 139 and port 445 kept it, so a message without it
/// is not read by anything.
fn nbss(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&[0, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
    out.extend_from_slice(payload);
    out
}

/// The dialects offered, oldest first, as the specification requires.
///
/// 3.1.1 is deliberately absent: it requires negotiate contexts and a client
/// GUID that is not zero, and a request without them is answered with a refusal
/// rather than ignored. A refusal is an SMB2 message and would prove the point
/// as well as an acceptance does, but offering a dialect that cannot be
/// completed is asking a server to start something this will not finish. The
/// four here reach every SMB2 and SMB3 server, and a server that speaks only
/// 3.1.1 still answers them with `STATUS_NOT_SUPPORTED` in SMB2.
const DIALECTS: [u16; 4] = [0x0202, 0x0210, 0x0300, 0x0302];

/// An SMB2 `NEGOTIATE` request: the first packet any SMB client sends.
///
/// A fixed 64-byte header with the command and nothing else set, then the
/// 36-byte request body and the dialects. The client GUID is left as zeros,
/// which is what a probe should send: it identifies nothing about this machine,
/// and a `NEGOTIATE` is where a client would otherwise hand a server a stable
/// identifier for itself.
pub fn smb_negotiate() -> Vec<u8> {
    let mut msg = Vec::with_capacity(64 + 36 + DIALECTS.len() * 2);

    // The header.
    msg.extend_from_slice(&SMB2_MAGIC); // ProtocolId
    msg.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    msg.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    msg.extend_from_slice(&0u32.to_le_bytes()); // Status
    msg.extend_from_slice(&0u16.to_le_bytes()); // Command: NEGOTIATE
    msg.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
    msg.extend_from_slice(&0u32.to_le_bytes()); // Flags: a request
    msg.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    msg.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    msg.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    msg.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    msg.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    msg.extend_from_slice(&[0u8; 16]); // Signature

    // The request.
    msg.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    msg.extend_from_slice(&(DIALECTS.len() as u16).to_le_bytes());
    msg.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: signing enabled
    msg.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    msg.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    msg.extend_from_slice(&[0u8; 16]); // ClientGuid
    msg.extend_from_slice(&0u64.to_le_bytes()); // ClientStartTime
    for dialect in DIALECTS {
        msg.extend_from_slice(&dialect.to_le_bytes());
    }

    nbss(&msg)
}

/// `\xFESMB`, the SMB2 and SMB3 protocol identifier.
const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];
/// `\xFFSMB`, SMB1's. Still answered by old NAS firmware and by anything with
/// SMB1 left switched on, and it is as much a file server as the other.
const SMB1_MAGIC: [u8; 4] = [0xFF, b'S', b'M', b'B'];

/// Did that answer come from an SMB server?
///
/// The test is the protocol identifier and nothing else. **Not the status**: a
/// server that refuses every dialect offered, or refuses the request outright,
/// has still spoken SMB, and "there is a file server here" is the whole of what
/// the badge claims. Requiring a successful negotiation would lose every server
/// hardened to one dialect.
///
/// The identifier is looked for at the front of the message and at the front of
/// the NetBIOS payload, because a server may or may not frame its reply — and
/// both shapes have been seen from the same vendor on two ports.
pub fn smb_answered(reply: &[u8]) -> bool {
    let magic = |at: usize| {
        reply
            .get(at..at + 4)
            .is_some_and(|head| head == SMB2_MAGIC || head == SMB1_MAGIC)
    };
    magic(0) || magic(4)
}

/// The NFS programme number, its version, and the call's id. All three fixed by
/// the protocol, except the last, which is fixed by us. See [`one`].
const NFS_PROGRAM: u32 = 100_003;
const NFS_VERSION: u32 = 3;
const NFS_XID: u32 = 0x4d75_7374;

/// An ONC RPC `NULL` call, record-marked for TCP.
///
/// Procedure zero of every RPC programme is defined to do nothing and return
/// nothing, and it exists so that a client can ask "are you there" without
/// asking for anything else. That is exactly the question here, and it is why
/// this probe reads no file, lists no export and needs no credentials:
/// `AUTH_NONE` is what a `NULL` call carries.
pub fn rpc_null(xid: u32, program: u32, version: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(40);
    for word in [xid, CALL, RPC_VERSION, program, version, 0] {
        body.extend_from_slice(&word.to_be_bytes());
    }
    // Credentials and verifier, both `AUTH_NONE`: a flavour and a zero length.
    body.extend_from_slice(&[0u8; 16]);

    let mut out = Vec::with_capacity(body.len() + 4);
    // The record marker: the last-fragment bit, and the fragment's length.
    // TCP is a stream and RPC is a message protocol, so without this a reader
    // cannot tell where the call ends.
    out.extend_from_slice(&(LAST_FRAGMENT | body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

const CALL: u32 = 0;
const REPLY: u32 = 1;
const RPC_VERSION: u32 = 2;
const LAST_FRAGMENT: u32 = 0x8000_0000;
/// The reply said the call was accepted, as against rejected by the
/// authentication it does not use.
const MSG_ACCEPTED: u32 = 0;
/// The programme ran. A `NULL` call always can.
const SUCCESS: u32 = 0;
/// The programme is here and does not speak the version asked for.
const PROG_MISMATCH: u32 = 2;

/// Did that answer come from an NFS server?
///
/// Three things have to hold, and the third is the interesting one:
///
/// * It is an RPC reply, to this call's transaction id. Anything else on 2049
///   is something else entirely.
/// * The reply was accepted rather than rejected by authentication.
/// * The accept status is `SUCCESS` **or** `PROG_MISMATCH`. A mismatch is a
///   server saying "I have NFS, not that version", which is a file server as
///   surely as a success is — an NFSv4-only server answers a version 3 call
///   this way. What is *not* accepted is `PROG_UNAVAIL`, which is rpcbind or
///   another RPC service answering on this port with no NFS behind it, and
///   badging that would be the port-scan mistake this module exists to avoid.
pub fn nfs_answered(reply: &[u8], xid: u32) -> bool {
    let word = |i: usize| -> Option<u32> {
        reply
            .get(i * 4..i * 4 + 4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    };
    // Word 0 is the record marker; the message starts at word 1.
    if word(1) != Some(xid) || word(2) != Some(REPLY) || word(3) != Some(MSG_ACCEPTED) {
        return false;
    }
    // Then the verifier, which is a flavour and a length and then that many
    // bytes, rounded up to a multiple of four. It is `AUTH_NONE` and empty in
    // every reply seen, and it is read properly anyway: a server is entitled to
    // send one, and skipping a fixed eight bytes would read the accept status
    // out of the middle of it.
    let Some(verifier) = word(5) else {
        return false;
    };
    let padded = verifier.next_multiple_of(4) as usize;
    let at = 6 * 4 + padded;
    let status = reply
        .get(at..at + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    matches!(status, Some(SUCCESS) | Some(PROG_MISMATCH))
}

/// The identification string out of an SSH server's greeting.
///
/// RFC 4253 §4.2: the server may send any number of lines before the
/// identification string, and the identification string is the first line
/// beginning `SSH-`. Everything before it is a legal notice or a banner, and
/// dropping it is what keeps a device's login warning out of the interface.
pub fn ssh_greeting(reply: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(reply);
    let line = text.lines().find(|line| line.starts_with("SSH-"))?;
    let line = line.trim();
    // A greeting is one short line. A device sending a long one is either
    // broken or hostile, and either way the table is not the place to find out.
    let trimmed: String = line.chars().take(GREETING_MOST).collect();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// How much of a greeting is worth keeping. RFC 4253 caps the line at 255.
const GREETING_MOST: usize = 96;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Recorded exchanges, keyed by where the connection went. No socket is
    /// opened by anything in this file's tests.
    #[derive(Default)]
    struct Fake {
        replies: BTreeMap<SocketAddr, Vec<u8>>,
        spoken: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
    }

    impl Speak for Fake {
        fn speak(
            &self,
            to: SocketAddr,
            opening: &[u8],
            _timeout: Duration,
            _most: usize,
        ) -> io::Result<Vec<u8>> {
            self.spoken.lock().unwrap().push((to, opening.to_vec()));
            match self.replies.get(&to) {
                Some(reply) => Ok(reply.clone()),
                None => Err(io::Error::new(io::ErrorKind::TimedOut, "nothing answered")),
            }
        }
    }

    fn at(address: &str, port: u16) -> SocketAddr {
        SocketAddr::new(address.parse().unwrap(), port)
    }

    fn everything() -> Options {
        Options {
            smb: true,
            nfs: true,
            ssh: true,
            ..Default::default()
        }
    }

    /// An SMB2 reply, framed the way Samba frames one.
    fn smb2_reply() -> Vec<u8> {
        let mut body = SMB2_MAGIC.to_vec();
        body.extend_from_slice(&[0u8; 60]);
        nbss(&body)
    }

    /// An accepted RPC reply with an empty `AUTH_NONE` verifier.
    fn rpc_reply(xid: u32, status: u32) -> Vec<u8> {
        let mut body = Vec::new();
        for word in [xid, REPLY, MSG_ACCEPTED, 0, 0, status] {
            body.extend_from_slice(&word.to_be_bytes());
        }
        let mut out = (LAST_FRAGMENT | body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn the_negotiate_is_the_shape_a_server_expects() {
        let msg = smb_negotiate();
        // The NetBIOS length must be the rest of the message, or a server reads
        // half a header and waits for ever.
        let length = u32::from_be_bytes([0, msg[1], msg[2], msg[3]]) as usize;
        assert_eq!(length, msg.len() - 4);
        assert_eq!(&msg[4..8], &SMB2_MAGIC);
        // The header is 64 bytes and the request says it is 36.
        assert_eq!(&msg[4 + 64..4 + 66], &36u16.to_le_bytes());
        assert_eq!(&msg[4 + 66..4 + 68], &(DIALECTS.len() as u16).to_le_bytes());
        // Nothing about this machine goes out in it.
        assert!(msg[4 + 64 + 12..4 + 64 + 28].iter().all(|b| *b == 0));
    }

    #[test]
    fn an_smb_header_is_the_whole_test() {
        assert!(smb_answered(&smb2_reply()));
        // Unframed, which some devices answer with.
        assert!(smb_answered(&SMB2_MAGIC));
        // And SMB1, which is old and is still a file server.
        assert!(smb_answered(&nbss(&SMB1_MAGIC)));
        // A web server on the wrong port is not one.
        assert!(!smb_answered(b"HTTP/1.1 400 Bad Request\r\n"));
        assert!(!smb_answered(&[]));
    }

    #[test]
    fn the_null_call_is_a_null_call() {
        let call = rpc_null(NFS_XID, NFS_PROGRAM, NFS_VERSION);
        assert_eq!(call.len(), 44);
        let word = |i: usize| u32::from_be_bytes(call[i * 4..i * 4 + 4].try_into().unwrap());
        assert_eq!(word(0), LAST_FRAGMENT | 40);
        assert_eq!(word(1), NFS_XID);
        assert_eq!(word(2), CALL);
        assert_eq!(word(3), RPC_VERSION);
        assert_eq!(word(4), NFS_PROGRAM);
        assert_eq!(word(5), NFS_VERSION);
        // Procedure zero, which is the one that does nothing.
        assert_eq!(word(6), 0);
    }

    /// The rule this module is written for: a programme that is there answers,
    /// a version that is not is still NFS, and rpcbind on the wrong port is
    /// not.
    #[test]
    fn only_an_nfs_programme_counts_as_nfs() {
        assert!(nfs_answered(&rpc_reply(NFS_XID, SUCCESS), NFS_XID));
        assert!(nfs_answered(&rpc_reply(NFS_XID, PROG_MISMATCH), NFS_XID));
        // `PROG_UNAVAIL`: something speaks RPC here and it is not NFS.
        assert!(!nfs_answered(&rpc_reply(NFS_XID, 1), NFS_XID));
        // Somebody else's call.
        assert!(!nfs_answered(&rpc_reply(1, SUCCESS), NFS_XID));
        assert!(!nfs_answered(b"nothing like a reply", NFS_XID));
    }

    /// A verifier with something in it moves the accept status along, and a
    /// reader that skipped a fixed eight bytes would read the middle of it.
    #[test]
    fn a_verifier_with_a_body_is_stepped_over() {
        let mut body = Vec::new();
        for word in [NFS_XID, REPLY, MSG_ACCEPTED, 0, 4] {
            body.extend_from_slice(&word.to_be_bytes());
        }
        body.extend_from_slice(b"junk");
        body.extend_from_slice(&SUCCESS.to_be_bytes());
        let mut reply = (LAST_FRAGMENT | body.len() as u32).to_be_bytes().to_vec();
        reply.extend_from_slice(&body);
        assert!(nfs_answered(&reply, NFS_XID));
    }

    #[test]
    fn the_greeting_is_read_and_a_login_notice_is_not() {
        assert_eq!(
            ssh_greeting(b"SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n").as_deref(),
            Some("SSH-2.0-OpenSSH_9.2p1 Debian-2")
        );
        // RFC 4253 lets a server say anything it likes first.
        assert_eq!(
            ssh_greeting(b"Authorised users only\r\nSSH-2.0-dropbear\r\n").as_deref(),
            Some("SSH-2.0-dropbear")
        );
        assert_eq!(ssh_greeting(b"220 ftp ready\r\n"), None);
        assert_eq!(ssh_greeting(&[]), None);
    }

    #[test]
    fn a_device_that_serves_everything_says_so() {
        let mut fake = Fake::default();
        fake.replies
            .insert(at("192.168.1.10", SMB_PORT), smb2_reply());
        fake.replies
            .insert(at("192.168.1.10", NFS_PORT), rpc_reply(NFS_XID, SUCCESS));
        fake.replies.insert(
            at("192.168.1.10", SSH_PORT),
            b"SSH-2.0-OpenSSH_9.6\r\n".to_vec(),
        );

        let serves = one(
            "192.168.1.10".parse().unwrap(),
            &fake,
            &Bucket::new(1_000_000),
            everything(),
        );
        assert!(serves.smb);
        assert!(serves.nfs);
        assert_eq!(serves.ssh.as_deref(), Some("SSH-2.0-OpenSSH_9.6"));
        assert!(!serves.is_empty());
    }

    /// The rule: silence is not a service, and neither is an open port that
    /// says nothing in the protocol.
    #[test]
    fn a_port_that_answers_nothing_in_the_protocol_earns_no_badge() {
        let mut fake = Fake::default();
        fake.replies
            .insert(at("192.168.1.11", SMB_PORT), b"\0\0\0\0".to_vec());
        let serves = one(
            "192.168.1.11".parse().unwrap(),
            &fake,
            &Bucket::new(1_000_000),
            everything(),
        );
        assert!(serves.is_empty());
    }

    /// An SSH probe sends nothing. This is the conduct rule, and it is a test
    /// rather than a comment because it is one line away from being false.
    #[test]
    fn the_ssh_probe_sends_nothing_at_all() {
        let mut fake = Fake::default();
        fake.replies
            .insert(at("192.168.1.12", SSH_PORT), b"SSH-2.0-x\r\n".to_vec());
        let opts = Options {
            ssh: true,
            ..Default::default()
        };
        one(
            "192.168.1.12".parse().unwrap(),
            &fake,
            &Bucket::new(1_000_000),
            opts,
        );
        let spoken = fake.spoken.lock().unwrap();
        assert_eq!(spoken.len(), 1, "one connection, to port 22");
        assert!(spoken[0].1.is_empty(), "and nothing was sent on it");
    }

    /// A question that was not asked is not asked. The whole of the difference
    /// between "off" and "nobody answered" is here.
    #[test]
    fn nothing_is_asked_when_nothing_was_switched_on() {
        let fake = Fake::default();
        let serves = one(
            "192.168.1.13".parse().unwrap(),
            &fake,
            &Bucket::new(1_000_000),
            Options::default(),
        );
        assert!(serves.is_empty());
        assert!(fake.spoken.lock().unwrap().is_empty());
        assert!(!Options::default().any());
    }

    #[test]
    fn many_keeps_results_in_the_order_it_was_given() {
        let mut fake = Fake::default();
        fake.replies.insert(at("10.0.0.2", SMB_PORT), smb2_reply());
        let addresses: Vec<IpAddr> = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let out = many(
            &addresses,
            &fake,
            &Bucket::new(1_000_000),
            Options {
                smb: true,
                ..Default::default()
            },
            &AtomicBool::new(false),
            &|_, _| {},
        );
        assert_eq!(out.len(), 3);
        assert!(!out[0].smb);
        assert!(out[1].smb, "the one that answered is the one that answered");
        assert!(!out[2].smb);
    }

    #[test]
    fn a_cancelled_pass_asks_nothing() {
        let mut fake = Fake::default();
        fake.replies.insert(at("10.0.0.2", SMB_PORT), smb2_reply());
        let addresses: Vec<IpAddr> = vec!["10.0.0.2".parse().unwrap()];
        let out = many(
            &addresses,
            &fake,
            &Bucket::new(1_000_000),
            Options {
                smb: true,
                ..Default::default()
            },
            &AtomicBool::new(true),
            &|_, _| {},
        );
        assert!(out[0].is_empty());
        assert!(fake.spoken.lock().unwrap().is_empty());
    }
}
