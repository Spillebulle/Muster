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
//!
//!   **The reply is read rather than counted.** A `NEGOTIATE` response is a
//!   server describing itself before anybody has said who they are: the
//!   dialect it settled on, a GUID that is the same one on every address the
//!   machine answers, what its clock says, and when it started. None of that
//!   costs another packet - it arrived in the answer to the question that was
//!   already being asked, and for a long time it was counted as a `bool` and
//!   dropped. See [`Smb`].
//!
//! * **SMB1**, on the same port and behind the same switch, as a second
//!   opening. A server that answers an SMB1 `NEGOTIATE` with a dialect has
//!   proved it speaks SMB1, which is a thing an administrator would want to
//!   know about a machine on their network and which nothing else here can
//!   establish. It is reported as what it is, "it answered an SMB1 negotiate",
//!   and never as a grade, a score or a warning. Muster says what answered;
//!   what to do about it is not its opinion to have.
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
use std::time::{Duration, SystemTime};

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
    /// It answered in SMB on port 445, and what it said about itself.
    ///
    /// [`Some`] is "a file server answered", which is what the badge claims and
    /// is true of a server that refused every dialect offered. What is inside
    /// is whatever the answer carried, and an empty [`Smb`] is a legitimate
    /// value: a refusal is an answer in the protocol and carries no fields.
    pub smb: Option<Smb>,
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
        self.smb.is_none() && !self.nfs && self.ssh.is_none()
    }
}

/// What an SMB server said about itself in its `NEGOTIATE` response.
///
/// **All of it arrived in the answer to a question that was already being
/// asked**, and all of it used to be thrown away for one `bool`. MS-SMB2
/// §2.2.4 is the layout; what is kept is the four fields that say something
/// about the machine rather than about the connection about to be set up.
///
/// Every field is optional and [`None`] means the server did not say, which is
/// a different thing from a zero and is kept as a different thing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Smb {
    /// `DialectRevision`: the dialect the server settled on.
    ///
    /// **The ceiling is what was offered, not what the server can do.**
    /// [`DIALECTS`] stops at 3.0.2 for the reason written there, so 0x0311 can
    /// never come back from this probe and a server that answers 0x0302 may
    /// well speak 3.1.1. What the low end says is solid and is the useful half:
    /// 0x0202 is the dialect Vista and Server 2008 shipped with, and a box on a
    /// modern network that will go no higher than that is a box worth looking
    /// at.
    ///
    /// [`None`] where the server answered in SMB without completing a
    /// negotiation, which a refusal is.
    pub dialect: Option<u16>,
    /// `ServerGuid`: the same sixteen bytes from every address one machine
    /// answers on, and a different sixteen from every other machine.
    ///
    /// Worth keeping because it is the only identifier on this network that a
    /// dual-homed server cannot wear two of: two addresses with one GUID are
    /// one machine, whatever the rest of the scan made of them.
    pub guid: Option<[u8; 16]>,
    /// `SystemTime`: what the server's clock said when it answered.
    ///
    /// A fault worth surfacing rather than a curiosity. Kerberos refuses a
    /// ticket over five minutes of skew, backup schedules and log timestamps
    /// go quietly wrong long before that, and a clock that has drifted is
    /// invisible until somebody compares two of them - which is what a scanner
    /// is in a position to do and nothing else on the network is.
    pub clock: Option<SystemTime>,
    /// `ServerStartTime`: when the server started, where it says.
    ///
    /// **[`None`] is itself the finding.** Windows fills this in with its own
    /// boot time and Samba sends a zero, so the absence of a start time
    /// separates a Windows machine from the NAS beside it - and it does so on a
    /// field neither of them chose for the purpose, which is why it is worth
    /// more than a banner. Muster reports what the field said; it does not name
    /// an operating system on the strength of it.
    pub started: Option<SystemTime>,
    /// The SMB1 dialect the server chose, where it was asked and chose one.
    ///
    /// One of [`SMB1_DIALECTS`], because it can only be one of the dialects
    /// that were offered. [`None`] is "it did not answer an SMB1 negotiate, or
    /// it answered by refusing every dialect", and a refusal here is a server
    /// saying it does not speak SMB1 - which is the opposite claim from the one
    /// a refusal makes in SMB2, and the reason this field is read from the
    /// chosen dialect rather than from the reply having arrived.
    pub smb1: Option<&'static str>,
}

impl Smb {
    /// How the dialect number is written down, where it is one this knows.
    pub const fn dialect_label(&self) -> Option<&'static str> {
        match self.dialect {
            Some(0x0202) => Some("SMB 2.0.2"),
            Some(0x0210) => Some("SMB 2.1"),
            Some(0x0300) => Some("SMB 3.0"),
            Some(0x0302) => Some("SMB 3.0.2"),
            Some(0x0311) => Some("SMB 3.1.1"),
            _ => None,
        }
    }

    /// How far the server's clock is from this machine's, in seconds, positive
    /// where the server is ahead.
    ///
    /// **`now` is the caller's**, which is the whole reason this is not done in
    /// the parser: a function that reads the clock cannot be tested against a
    /// recorded reply, and `CLAUDE.md` has the rate limiter driven from a clock
    /// the test controls for the same reason.
    pub fn skew(&self, now: SystemTime) -> Option<i64> {
        let clock = self.clock?;
        Some(match clock.duration_since(now) {
            Ok(ahead) => ahead.as_secs() as i64,
            Err(behind) => -(behind.duration().as_secs() as i64),
        })
    }

    /// How long the server says it has been up, where it said when it started.
    ///
    /// Measured against the server's own clock rather than against this
    /// machine's, so a box whose clock is wrong still reports a sensible
    /// uptime; a start time later than the server's own idea of now is a
    /// nonsense and answers [`None`].
    pub fn uptime(&self) -> Option<Duration> {
        self.clock?.duration_since(self.started?).ok()
    }

    /// One line of what the server said, for a panel or a report.
    ///
    /// Facts, in the order of how much they say, and nothing that is not one:
    /// there is no grade here and no warning. A skew under a minute is left out
    /// because every clock on a network is a few seconds from every other and a
    /// row that always has something in it says nothing.
    pub fn stated(&self, now: SystemTime) -> String {
        let mut parts: Vec<String> = Vec::new();
        match self.dialect_label() {
            Some(label) => parts.push(label.to_string()),
            // A dialect this does not know is still a number worth printing,
            // and a refusal is worth saying out loud rather than leaving as a
            // blank that reads as "nothing answered".
            None => parts.push(match self.dialect {
                Some(number) => format!("an SMB2 dialect of {number:#06x}"),
                None => "answered without settling on a dialect".to_string(),
            }),
        }
        if let Some(dialect) = self.smb1 {
            parts.push(format!("answered an SMB1 negotiate as {dialect}"));
        }
        if let Some(skew) = self.skew(now)
            && skew.abs() >= 60
        {
            let minutes = skew.abs() / 60;
            let side = if skew > 0 { "ahead of" } else { "behind" };
            parts.push(format!("its clock is {minutes} min {side} this machine"));
        }
        match self.uptime() {
            Some(up) => parts.push(format!("up {} days", up.as_secs() / 86_400)),
            // The Samba tell, said as what it is rather than as a conclusion.
            None if self.dialect.is_some() => {
                parts.push("it did not say when it started, as Samba does not".to_string());
            }
            None => {}
        }
        parts.join(", ")
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
        ) && smb_answered(&reply)
        {
            serves.smb = Some(smb_details(&reply));
        }

        // The SMB1 question, on a connection of its own because a `NEGOTIATE`
        // is a connection's first packet and there is no second one to send.
        //
        // **It rides on the same switch rather than getting one of its own.**
        // The question the switch asks is "may Muster connect to this device
        // and ask what it serves", and somebody who has answered yes has
        // answered it for both halves of the same question about the same
        // service on the same port. A second switch would be a second thing to
        // find, for a second connection to a port already being connected to.
        rate.wait();
        if let Ok(reply) = speak.speak(
            SocketAddr::new(address, SMB_PORT),
            &smb1_negotiate(),
            opts.timeout,
            MOST,
        ) && smb_answered(&reply)
        {
            // A device that answers only here is a file server too, and an old
            // enough NAS answers nothing else.
            let details = serves.smb.get_or_insert_with(Smb::default);
            details.smb1 = smb1_dialect(&reply);
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
///
/// **Every report carries the device it is about**, for the reason
/// [`crate::identify::many`] gives: a badge that is known now is worth showing
/// now, and a count cannot carry one.
pub fn many<S: Speak>(
    addresses: &[IpAddr],
    speak: &S,
    rate: &Bucket,
    opts: Options,
    cancel: &AtomicBool,
    progress: &(dyn Fn(usize, usize, IpAddr, &Serves) + Sync),
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
                    let serves = one(address, speak, rate, opts);
                    progress(
                        done.fetch_add(1, Ordering::Relaxed) as usize + 1,
                        addresses.len(),
                        address,
                        &serves,
                    );
                    mine.push((i, serves));
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

/// Reads what an SMB2 `NEGOTIATE` response said about the server.
///
/// MS-SMB2 §2.2.4. Called only for a reply [`smb_answered`] has already
/// accepted, so this never decides whether there is a file server there; it
/// decides only what the file server said, and every field it cannot read
/// comes back [`None`].
///
/// Three things are checked before a byte is believed, and each of them is a
/// reply this has to survive rather than a hypothetical:
///
/// * **The framing.** A server may or may not put the NetBIOS session header
///   on its reply, exactly as [`smb_answered`] documents, so the header is
///   found rather than assumed to be at four.
/// * **The status.** A non-zero `Status` is a refusal, and a refusal carries
///   no response body - the fields after it are whatever the server had in the
///   buffer. It is still a file server, so this answers with an empty [`Smb`]
///   rather than with nothing.
/// * **The `StructureSize`.** 65, always, and it is the server's own statement
///   that what follows is the structure this is about to read. Anything else
///   is a different message wearing an SMB2 header.
pub fn smb_details(reply: &[u8]) -> Smb {
    let mut found = Smb::default();
    let Some(header) = [0usize, 4]
        .into_iter()
        .find(|at| reply.get(*at..at + 4) == Some(&SMB2_MAGIC))
    else {
        return found;
    };
    let word = |at: usize| -> Option<u16> {
        reply
            .get(at..at + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let long = |at: usize| -> Option<u64> {
        reply
            .get(at..at + 8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_le_bytes)
    };
    // `Status`, at 8 in the fixed 64-byte header.
    if reply
        .get(header + 8..header + 12)
        .is_none_or(|b| b != [0, 0, 0, 0])
    {
        return found;
    }
    let body = header + 64;
    if word(body) != Some(NEGOTIATE_RESPONSE) {
        return found;
    }
    found.dialect = word(body + 4);
    found.guid = reply
        .get(body + 8..body + 24)
        .and_then(|b| <[u8; 16]>::try_from(b).ok());
    found.clock = long(body + 40).and_then(filetime);
    found.started = long(body + 48).and_then(filetime);
    found
}

/// The `StructureSize` an SMB2 `NEGOTIATE` response carries, which is one more
/// than its length: MS-SMB2 counts the first byte of the variable part.
const NEGOTIATE_RESPONSE: u16 = 65;

/// A Windows `FILETIME` as an ordinary point in time.
///
/// Hundred-nanosecond intervals since the first of January 1601, which is a
/// choice somebody made in the 1980s and which every SMB server on a network
/// still writes its clock in.
///
/// Two values answer [`None`], and both mean "the server did not say": a zero,
/// which is what Samba sends for a start time it does not keep, and anything
/// before 1970, which is a clock this has no way to represent and no reason to
/// believe.
fn filetime(raw: u64) -> Option<SystemTime> {
    let seconds = raw.checked_div(10_000_000)?.checked_sub(FILETIME_EPOCH)?;
    let nanos = (raw % 10_000_000) as u32 * 100;
    (raw != 0).then(|| std::time::UNIX_EPOCH + Duration::new(seconds, nanos))
}

/// Seconds between the `FILETIME` epoch and the Unix one.
const FILETIME_EPOCH: u64 = 11_644_473_600;

/// The SMB1 dialects offered, oldest first, which is the order the protocol
/// requires and the order a server's `DialectIndex` counts in.
///
/// **Only SMB1 dialects are here, and that is the whole honesty of this
/// probe.** A client may put `SMB 2.002` and `SMB 2.???` at the end of this
/// list, and every modern server answers those with an SMB2 message - so a
/// probe that offered them would be answered by a machine with SMB1 removed
/// entirely, and reading that answer as "it speaks SMB1" would be exactly the
/// lie this module exists to avoid. Offering nothing but SMB1 means the only
/// thing that can choose a dialect here is a server that speaks one.
pub const SMB1_DIALECTS: [&str; 6] = [
    "PC NETWORK PROGRAM 1.0",
    "LANMAN1.0",
    "Windows for Workgroups 3.1a",
    "LM1.2X002",
    "LANMAN2.1",
    "NT LM 0.12",
];

/// An SMB1 `NEGOTIATE` request: the opening move of the older protocol.
///
/// The same shape of question as [`smb_negotiate`] and the same conduct: a
/// fixed 32-byte header, a word count of zero, and a list of dialect strings.
/// No credential, no name, and nothing about this machine - the process id, the
/// tree id and the user id are all left at zero or at the wildcard, because a
/// probe has no session to identify.
///
/// `NT_STATUS` is set in the flags so that the reply reports its status as one
/// thirty-two-bit code rather than as the DOS class-and-code pair, which is the
/// difference between reading one field and reading two.
pub fn smb1_negotiate() -> Vec<u8> {
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(&SMB1_MAGIC);
    msg.push(SMB_COM_NEGOTIATE);
    msg.extend_from_slice(&0u32.to_le_bytes()); // Status
    msg.push(0x18); // Flags: case insensitive, canonicalised paths
    msg.extend_from_slice(&0x4001u16.to_le_bytes()); // Flags2: long names, NT status
    msg.extend_from_slice(&0u16.to_le_bytes()); // PIDHigh
    msg.extend_from_slice(&[0u8; 8]); // SecurityFeatures
    msg.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    msg.extend_from_slice(&0xffffu16.to_le_bytes()); // TID: no tree connected
    msg.extend_from_slice(&0u16.to_le_bytes()); // PIDLow
    msg.extend_from_slice(&0u16.to_le_bytes()); // UID
    msg.extend_from_slice(&0u16.to_le_bytes()); // MID

    msg.push(0); // WordCount: a negotiate carries no words
    let mut dialects = Vec::new();
    for dialect in SMB1_DIALECTS {
        // Each is a buffer-format byte, the name, and a terminator.
        dialects.push(0x02);
        dialects.extend_from_slice(dialect.as_bytes());
        dialects.push(0);
    }
    msg.extend_from_slice(&(dialects.len() as u16).to_le_bytes()); // ByteCount
    msg.extend_from_slice(&dialects);

    nbss(&msg)
}

/// `SMB_COM_NEGOTIATE`, the only SMB1 command this module can build.
const SMB_COM_NEGOTIATE: u8 = 0x72;
/// The `DialectIndex` a server sends when it will speak none of what it was
/// offered.
const NO_DIALECT: u16 = 0xffff;

/// Which SMB1 dialect the server chose, if it chose one.
///
/// **A reply is not the test here, and that is a departure worth stating.**
/// Everywhere else in this module a reply in the protocol is the whole of the
/// claim, because the claim is "there is a file server here" and a server that
/// refuses a request has still proved that. The claim here is narrower - "it
/// speaks SMB1" - and a server that answers an SMB1 negotiate with
/// `DialectIndex` 0xFFFF has said the opposite of it: those are the words for
/// "none of those, thank you", which is what a Samba built with SMB1 disabled
/// answers. So the evidence is the dialect it picked, and nothing else.
///
/// An error status is read the same way, for the same reason.
pub fn smb1_dialect(reply: &[u8]) -> Option<&'static str> {
    let header = [0usize, 4]
        .into_iter()
        .find(|at| reply.get(*at..at + 4) == Some(&SMB1_MAGIC))?;
    if *reply.get(header + 4)? != SMB_COM_NEGOTIATE {
        return None;
    }
    if reply.get(header + 5..header + 9)? != [0, 0, 0, 0] {
        return None;
    }
    // `WordCount`, then the first word, which is the chosen dialect's index
    // into the list that was sent. A response with no words at all is a server
    // that answered without answering.
    if *reply.get(header + 32)? == 0 {
        return None;
    }
    let index = reply
        .get(header + 33..header + 35)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))?;
    (index != NO_DIALECT)
        .then(|| SMB1_DIALECTS.get(index as usize).copied())
        .flatten()
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
        /// What answers the *SMB1* opening, which goes to the same address and
        /// the same port as the SMB2 one and is a different question. Keyed by
        /// address alone, a fake would answer both with one datagram, which is
        /// the one thing a recorded transport must not do.
        smb1: BTreeMap<SocketAddr, Vec<u8>>,
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
            let table = if opening.get(4..8) == Some(&SMB1_MAGIC) {
                &self.smb1
            } else {
                &self.replies
            };
            match table.get(&to) {
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

    /// An SMB2 reply, framed the way Samba frames one, with nothing readable
    /// after the header.
    fn smb2_reply() -> Vec<u8> {
        let mut body = SMB2_MAGIC.to_vec();
        body.extend_from_slice(&[0u8; 60]);
        nbss(&body)
    }

    /// The `FILETIME` for noon on the first of June 2024, and for twelve days
    /// before it. Hundred-nanosecond intervals since 1601, which is what every
    /// SMB server on a network writes a time in.
    const CLOCK: u64 = 133_617_168_000_000_000;
    const STARTED: u64 = 133_606_800_000_000_000;
    /// The same instant as [`CLOCK`], in the units the rest of the world uses.
    const CLOCK_UNIX: u64 = 1_717_243_200;

    const GUID: [u8; 16] = [
        0x2b, 0x7a, 0x11, 0x9c, 0x5d, 0x4e, 0x40, 0x1a, 0x8f, 0x33, 0x0e, 0x91, 0xc4, 0x6d, 0x77,
        0x02,
    ];

    /// A full SMB2 `NEGOTIATE` response.
    ///
    /// **Constructed from MS-SMB2 §2.2.4 rather than captured**: the network
    /// this was written against has one file server and it was not going to
    /// prove the Vista-era dialect or a broken clock on its own. Every offset
    /// here is the specification's, and
    /// `the_response_this_reads_is_the_shape_the_specification_describes`
    /// checks the structure against it rather than against these bytes.
    fn smb2_negotiate_response(dialect: u16, clock: u64, started: u64, status: u32) -> Vec<u8> {
        let mut msg = Vec::with_capacity(128);
        msg.extend_from_slice(&SMB2_MAGIC);
        msg.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
        msg.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
        msg.extend_from_slice(&status.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes()); // Command: NEGOTIATE
        msg.extend_from_slice(&1u16.to_le_bytes()); // CreditResponse
        msg.extend_from_slice(&1u32.to_le_bytes()); // Flags: a response
        msg.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
        msg.extend_from_slice(&0u64.to_le_bytes()); // MessageId
        msg.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        msg.extend_from_slice(&0u32.to_le_bytes()); // TreeId
        msg.extend_from_slice(&0u64.to_le_bytes()); // SessionId
        msg.extend_from_slice(&[0u8; 16]); // Signature

        msg.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
        msg.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode
        msg.extend_from_slice(&dialect.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
        msg.extend_from_slice(&GUID);
        msg.extend_from_slice(&0x0000_0007u32.to_le_bytes()); // Capabilities
        msg.extend_from_slice(&0x0080_0000u32.to_le_bytes()); // MaxTransactSize
        msg.extend_from_slice(&0x0080_0000u32.to_le_bytes()); // MaxReadSize
        msg.extend_from_slice(&0x0080_0000u32.to_le_bytes()); // MaxWriteSize
        msg.extend_from_slice(&clock.to_le_bytes());
        msg.extend_from_slice(&started.to_le_bytes());
        msg.extend_from_slice(&128u16.to_le_bytes()); // SecurityBufferOffset
        msg.extend_from_slice(&0u16.to_le_bytes()); // SecurityBufferLength
        msg.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset

        nbss(&msg)
    }

    /// An SMB1 `NEGOTIATE` response choosing the dialect at `index`, or
    /// refusing them all with 0xFFFF.
    ///
    /// **Constructed from MS-CIFS §2.2.4.52.2 rather than captured.** The word
    /// count is the seventeen a server sends when it has chosen `NT LM 0.12`;
    /// only the first word is read here, and a refusal carries one word.
    fn smb1_negotiate_response(index: u16) -> Vec<u8> {
        let mut msg = Vec::with_capacity(64);
        msg.extend_from_slice(&SMB1_MAGIC);
        msg.push(SMB_COM_NEGOTIATE);
        msg.extend_from_slice(&0u32.to_le_bytes()); // Status
        msg.push(0x98); // Flags: a reply
        msg.extend_from_slice(&0x4001u16.to_le_bytes()); // Flags2
        msg.extend_from_slice(&0u16.to_le_bytes()); // PIDHigh
        msg.extend_from_slice(&[0u8; 8]); // SecurityFeatures
        msg.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        msg.extend_from_slice(&0xffffu16.to_le_bytes()); // TID
        msg.extend_from_slice(&0u16.to_le_bytes()); // PIDLow
        msg.extend_from_slice(&0u16.to_le_bytes()); // UID
        msg.extend_from_slice(&0u16.to_le_bytes()); // MID

        let words: u8 = if index == NO_DIALECT { 1 } else { 17 };
        msg.push(words);
        msg.extend_from_slice(&index.to_le_bytes());
        msg.extend_from_slice(&vec![0u8; (words as usize - 1) * 2]);
        msg.extend_from_slice(&0u16.to_le_bytes()); // ByteCount

        nbss(&msg)
    }

    /// The instant [`CLOCK`] names, as this machine would hold it.
    fn noon() -> SystemTime {
        std::time::UNIX_EPOCH + Duration::from_secs(CLOCK_UNIX)
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

    /// Everything the `NEGOTIATE` response was already carrying, which used to
    /// be counted as a `bool` and dropped.
    #[test]
    fn a_negotiate_response_is_read_field_by_field() {
        let reply = smb2_negotiate_response(0x0302, CLOCK, STARTED, 0);
        let smb = smb_details(&reply);
        assert_eq!(smb.dialect, Some(0x0302));
        assert_eq!(smb.dialect_label(), Some("SMB 3.0.2"));
        assert_eq!(smb.guid, Some(GUID));
        assert_eq!(smb.clock, Some(noon()));
        assert_eq!(smb.uptime(), Some(Duration::from_secs(12 * 86_400)));
        assert_eq!(smb.smb1, None, "nothing asked it about SMB1");
    }

    /// The unframed shape, which some devices answer with and which
    /// [`smb_answered`] already had to allow for.
    #[test]
    fn a_reply_with_no_netbios_header_reads_the_same_way() {
        let framed = smb2_negotiate_response(0x0210, CLOCK, STARTED, 0);
        let bare = smb_details(&framed[4..]);
        assert_eq!(bare.dialect, Some(0x0210));
        assert_eq!(bare.dialect_label(), Some("SMB 2.1"));
        assert_eq!(bare, smb_details(&framed));
    }

    /// **The rule this module is written for, applied to the new fields.** A
    /// server that refuses the request has still proved it is a file server,
    /// and it has said nothing else - so the refusal must not be read as a
    /// dialect of zero and a clock at the start of 1601.
    #[test]
    fn a_refusal_is_a_file_server_that_said_nothing_further() {
        // `STATUS_NOT_SUPPORTED`, which is what a server hardened to 3.1.1
        // answers a request that did not offer it.
        let reply = smb2_negotiate_response(0, 0, 0, 0xc000_00bb);
        assert!(smb_answered(&reply), "it spoke SMB");
        assert_eq!(smb_details(&reply), Smb::default(), "and said nothing else");

        let mut fake = Fake::default();
        fake.replies.insert(at("192.168.1.20", SMB_PORT), reply);
        let serves = one(
            "192.168.1.20".parse().unwrap(),
            &fake,
            &Bucket::new(1_000_000),
            everything(),
        );
        assert!(
            serves.smb.is_some(),
            "the badge is unchanged by any of this"
        );
    }

    /// The one field that separates a Windows machine from the NAS beside it,
    /// and it separates them by being absent.
    #[test]
    fn a_server_that_keeps_no_start_time_is_reported_as_keeping_none() {
        let samba = smb_details(&smb2_negotiate_response(0x0302, CLOCK, 0, 0));
        assert_eq!(samba.clock, Some(noon()), "it still knows what time it is");
        assert_eq!(samba.started, None);
        assert_eq!(samba.uptime(), None);
        assert!(
            samba.stated(noon()).contains("did not say when it started"),
            "{}",
            samba.stated(noon())
        );

        let windows = smb_details(&smb2_negotiate_response(0x0302, CLOCK, STARTED, 0));
        assert!(windows.started.is_some());
        assert!(
            !windows
                .stated(noon())
                .contains("did not say when it started")
        );
    }

    /// The skew is measured against a clock the test hands it, which is the
    /// only way a reading of somebody else's clock can be tested at all.
    #[test]
    fn a_drifted_clock_is_measured_against_a_clock_the_test_controls() {
        let smb = smb_details(&smb2_negotiate_response(0x0302, CLOCK, STARTED, 0));
        assert_eq!(smb.skew(noon()), Some(0));
        // This machine is five minutes behind the server.
        let behind = noon() - Duration::from_secs(300);
        assert_eq!(smb.skew(behind), Some(300));
        assert!(smb.stated(behind).contains("5 min ahead of this machine"));
        // And five minutes in front of it.
        let ahead = noon() + Duration::from_secs(300);
        assert_eq!(smb.skew(ahead), Some(-300));
        assert!(smb.stated(ahead).contains("5 min behind this machine"));

        // Every clock on a network is a few seconds from every other, so a
        // line that always has something in it would say nothing.
        let near = noon() + Duration::from_secs(9);
        assert!(!smb.stated(near).contains("clock"), "{}", smb.stated(near));
    }

    /// A zero is a server saying nothing, not a server that started in 1601.
    #[test]
    fn a_time_of_zero_is_not_a_time() {
        assert_eq!(filetime(0), None);
        assert_eq!(filetime(CLOCK), Some(noon()));
        // Anything before 1970 is a clock with nothing behind it.
        assert_eq!(filetime(1), None);
    }

    /// The structure this reads is the specification's, checked against the
    /// request builder that has to agree with it about where a header ends.
    #[test]
    fn the_response_this_reads_is_the_shape_the_specification_describes() {
        let reply = smb2_negotiate_response(0x0300, CLOCK, STARTED, 0);
        // The NetBIOS length is the rest of the message, the same property the
        // request is held to.
        let length = u32::from_be_bytes([0, reply[1], reply[2], reply[3]]) as usize;
        assert_eq!(length, reply.len() - 4);
        // 64 bytes of header, then a structure that says it is 65.
        assert_eq!(&reply[4 + 64..4 + 66], &NEGOTIATE_RESPONSE.to_le_bytes());
        // A body that stops before the times is read for what it has and
        // invents nothing.
        let short = smb_details(&reply[..4 + 64 + 40]);
        assert_eq!(short.dialect, Some(0x0300));
        assert_eq!(short.clock, None);
        assert_eq!(short.started, None);
    }

    /// **The whole honesty of the SMB1 probe.** A client may offer `SMB 2.002`
    /// at the end of an SMB1 dialect list, and then a machine with SMB1
    /// removed answers - in SMB2. Reading that as "it speaks SMB1" is the lie
    /// this list is written to make impossible.
    #[test]
    fn the_smb1_negotiate_offers_nothing_but_smb1() {
        let msg = smb1_negotiate();
        let text = String::from_utf8_lossy(&msg);
        assert!(!text.contains("SMB 2"), "no SMB2 dialect may be offered");
        assert!(text.contains("NT LM 0.12"));
        assert!(text.contains("PC NETWORK PROGRAM 1.0"));

        let length = u32::from_be_bytes([0, msg[1], msg[2], msg[3]]) as usize;
        assert_eq!(length, msg.len() - 4);
        assert_eq!(&msg[4..8], &SMB1_MAGIC);
        assert_eq!(msg[4 + 4], SMB_COM_NEGOTIATE);
        // A negotiate carries no words, and the byte count is the rest of it.
        assert_eq!(msg[4 + 32], 0);
        let bytes = u16::from_le_bytes([msg[4 + 33], msg[4 + 34]]) as usize;
        assert_eq!(bytes, msg.len() - 4 - 35);
        // And nothing about this machine goes out in it.
        assert!(msg[4 + 14..4 + 22].iter().all(|b| *b == 0));
    }

    /// A chosen dialect is the evidence, and a refusal is the opposite of it.
    #[test]
    fn only_a_chosen_dialect_proves_smb1() {
        assert_eq!(
            smb1_dialect(&smb1_negotiate_response(5)),
            Some("NT LM 0.12")
        );
        assert_eq!(
            smb1_dialect(&smb1_negotiate_response(0)),
            Some("PC NETWORK PROGRAM 1.0")
        );
        // 0xFFFF is the server saying "none of those", which is what a Samba
        // built without SMB1 answers. It is a reply, and it is a reply saying
        // the opposite of what a badge would claim.
        assert_eq!(smb1_dialect(&smb1_negotiate_response(NO_DIALECT)), None);
        // An index outside the list that was offered names no dialect.
        assert_eq!(smb1_dialect(&smb1_negotiate_response(9)), None);
        // And an SMB2 answer to the SMB1 question is not an SMB1 answer.
        assert_eq!(
            smb1_dialect(&smb2_negotiate_response(0x0302, CLOCK, STARTED, 0)),
            None
        );
        assert_eq!(smb1_dialect(b""), None);
    }

    /// A server with SMB1 left on says so, and it is said as a fact rather
    /// than as a grade: this module reports what answered and has no opinion
    /// about it.
    #[test]
    fn a_server_that_speaks_smb1_says_so_on_its_own_row() {
        let mut fake = Fake::default();
        fake.replies.insert(
            at("192.168.1.21", SMB_PORT),
            smb2_negotiate_response(0x0302, CLOCK, 0, 0),
        );
        fake.smb1
            .insert(at("192.168.1.21", SMB_PORT), smb1_negotiate_response(5));

        let serves = one(
            "192.168.1.21".parse().unwrap(),
            &fake,
            &Bucket::new(1_000_000),
            everything(),
        );
        let smb = serves.smb.expect("a file server");
        assert_eq!(smb.dialect_label(), Some("SMB 3.0.2"));
        assert_eq!(smb.smb1, Some("NT LM 0.12"));
        assert!(smb.stated(noon()).contains("answered an SMB1 negotiate"));

        // Two connections to 445, and the second one asked a different
        // question. One reply cannot be allowed to answer both.
        let spoken = fake.spoken.lock().unwrap();
        let to_smb: Vec<&Vec<u8>> = spoken
            .iter()
            .filter(|(to, _)| to.port() == SMB_PORT)
            .map(|(_, opening)| opening)
            .collect();
        assert_eq!(to_smb.len(), 2);
        assert_eq!(to_smb[0].get(4..8), Some(&SMB2_MAGIC[..]));
        assert_eq!(to_smb[1].get(4..8), Some(&SMB1_MAGIC[..]));
    }

    /// An old enough NAS answers the SMB1 question and nothing else, and it is
    /// a file server.
    #[test]
    fn a_server_that_answers_only_smb1_is_still_a_file_server() {
        let mut fake = Fake::default();
        fake.smb1
            .insert(at("192.168.1.22", SMB_PORT), smb1_negotiate_response(5));
        let serves = one(
            "192.168.1.22".parse().unwrap(),
            &fake,
            &Bucket::new(1_000_000),
            everything(),
        );
        let smb = serves.smb.expect("a file server");
        assert_eq!(smb.dialect, None, "it never answered in SMB2");
        assert_eq!(smb.smb1, Some("NT LM 0.12"));
    }

    /// The switch covers both openings, and with it off neither goes out.
    #[test]
    fn the_smb1_question_is_behind_the_switch_the_rest_is_behind() {
        let fake = Fake::default();
        one(
            "192.168.1.23".parse().unwrap(),
            &fake,
            &Bucket::new(1_000_000),
            Options::default(),
        );
        assert!(fake.spoken.lock().unwrap().is_empty());
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
        assert!(serves.smb.is_some());
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
            &|_, _, _, _| {},
        );
        assert_eq!(out.len(), 3);
        assert!(out[0].smb.is_none());
        assert!(
            out[1].smb.is_some(),
            "the one that answered is the one that answered"
        );
        assert!(out[2].smb.is_none());
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
            &|_, _, _, _| {},
        );
        assert!(out[0].is_empty());
        assert!(fake.spoken.lock().unwrap().is_empty());
    }
}
