//! The binary.
//!
//! One executable with a window and a text mode in it, which is the shape
//! `CLAUDE.md` settled on: `muster` opens the interface and `muster <command>`
//! runs the same engine and prints. There is no second binary to package, sign
//! and update.
//!
//! The window does not exist yet, so for the moment every path leads to the
//! text mode and the no-argument case runs the survey. That is stated here
//! rather than left as a surprise: when `muster-app` arrives, the no-argument
//! case changes and nothing else does.
//!
//! Everything printed here is a table of figures with aligned columns, which is
//! `CLAUDE.md`'s rule for the device list and is enforced by a test rather than
//! by care — the marker for a randomised address was appended to the hardware
//! address once, and one phone knocked every field after it out of line.

// A release build declares the **windows** subsystem, so that opening Muster
// from the Start menu, from Explorer or from the installer's "Start Muster"
// does not put a console window behind it. 0.0.3 shipped without this and did
// exactly that.
//
// The catch, and the reason this is two changes rather than one: a
// GUI-subsystem process does not inherit the console it was launched from
// either, so `muster survey` in a terminal would print nothing at all. That
// would trade a cosmetic defect for the loss of the text mode, which is half
// the product. `attach_parent_console` is the other half of the fix.
//
// A debug build keeps the console subsystem, because a panic message with
// nowhere to go is worse than a console window nobody minds.
//
// Linux needs none of this: it opens no terminal for a binary started from a
// launcher, and keeps the one it was started from.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod portcmd;

use muster_net::rate::Bucket;
use muster_net::survey::{Reading, Survey};
use muster_net::{Prefix, discover, identify};
use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn main() {
    // Before the first write to either stream: that is when the standard
    // library resolves the handle.
    attach_parent_console();

    // Warnings from our own crates, and nothing from the graphics stack below
    // `warn`. wgpu's HAL warns once per surface configuration about present
    // modes its driver enumerates and it does not recognise — true, harmless,
    // and a dozen lines on every launch, which trains the reader to ignore the
    // stream that Muster's own warnings arrive in. `RUST_LOG` still overrides
    // all of it, so `RUST_LOG=wgpu_hal=debug` gets the noise back when the
    // graphics stack is what is being chased.
    env_logger::Builder::from_env(
        env_logger::Env::default().filter_or("RUST_LOG", "warn,wgpu_hal=error,wgpu_core=error"),
    )
    .init();

    // This executable is also its own installer, twice over, and both are read
    // before anything else because neither is a Muster command.
    //
    // `--install-update` is the helper an update spawns: a running executable
    // cannot replace itself, so the process that puts the package in place
    // cannot be this one. `muster-setup.exe` is this same binary with an MSI
    // appended to it, and it arrives with **no arguments at all**, because it
    // is double-clicked. So the payload on the end of the file is what tells
    // setup from Muster; asking the command line alone would leave the
    // installer unreachable. Sixteen bytes off our own file, once, before any
    // window exists. See `muster_app::update::installer` and `update::payload`.
    let carries_payload =
        std::env::current_exe().is_ok_and(|exe| muster_app::update::payload::carried_by(&exe));
    if let Some(job) = muster_app::update::installer::job(std::env::args(), carries_payload) {
        if let Err(e) = muster_app::update::installwin::show(job) {
            eprintln!("muster: the installer could not open a window: {e}");
            std::process::exit(1);
        }
        return;
    }

    // A Windows update leaves the binary it displaced beside the new one,
    // because a running executable cannot be deleted. This is the first moment
    // it can go.
    muster_app::update::sweep_previous_binary();

    let args: Vec<String> = std::env::args().skip(1).collect();

    // No arguments opens the window: the window is the product, and the text
    // mode is what the same binary does when asked a question directly.
    let Some(command) = args.first().map(String::as_str) else {
        if let Err(e) = muster_app::run() {
            eprintln!("muster: could not open a window: {e}");
            eprintln!("        the text commands still work; try `muster survey`");
            std::process::exit(1);
        }
        return;
    };

    match command {
        "survey" => {
            let mut out = std::io::stdout().lock();
            print_survey(&mut out, &muster_net::survey());
        }
        "scan" => scan(args.get(1).map(String::as_str)),
        "ports" => portcmd::run(
            args.get(1).map(String::as_str),
            args.get(2).map(String::as_str),
        ),
        "--help" | "-h" | "help" => usage(),
        other => {
            eprintln!("muster: no command '{other}'\n");
            usage();
            std::process::exit(2);
        }
    }
}

fn usage() {
    println!(
        "muster {}\n\n\
         Usage:\n  \
           muster survey                 what this machine knows, no packets sent\n  \
           muster scan [prefix]          sweep the local network for devices\n  \
           muster ports <host> [ports]   which ports are open on one host\n  \
           muster --help                 this\n\n\
         None of these needs administrator rights. With no prefix, the scan\n\
         sweeps the network this machine is on and nothing beyond it.\n\n\
         Devices are identified by hardware vendor, and by name where they\n\
         answer reverse DNS, mDNS or NetBIOS. The port scan uses connect(),\n\
         which is slower than the SYN scan it will use once raw packet access\n\
         is in, and says so in its result. Ports may be given as 80,443 or\n\
         1-1024; the default is a short list of the ones worth knowing about.",
        env!("CARGO_PKG_VERSION")
    );
}

/// Sweeps a prefix and prints what answered.
///
/// With no argument it takes the survey and sweeps what that found, which is
/// `CLAUDE.md`'s rule that the default target is the local prefix and never a
/// range somebody typed. A prefix given on the command line is the deliberate
/// act, and it is checked against the local networks so that reaching beyond
/// the link is something the user is told they are doing.
fn scan(target: Option<&str>) {
    let survey = muster_net::survey();

    let prefixes: Vec<Prefix> = match target {
        None => survey.default_targets(),
        Some(text) => match text.parse::<Prefix>() {
            Ok(p) => vec![p],
            Err(e) => {
                eprintln!("muster: '{text}' is not a network: {e}");
                eprintln!("        try something like 192.168.1.0/24");
                std::process::exit(2);
            }
        },
    };

    if prefixes.is_empty() {
        eprintln!(
            "muster: no local network to sweep.\n        \
             Run `muster survey` to see what this machine knows, or name a\n        \
             network: muster scan 192.168.1.0/24"
        );
        std::process::exit(1);
    }

    let local: Vec<Prefix> = survey
        .interfaces
        .iter()
        .filter(|i| i.is_scannable())
        .flat_map(|i| i.v4_prefixes())
        .collect();

    let transport = muster_net::platform::Host;
    let rate = Bucket::polite();
    let cancel = Arc::new(AtomicBool::new(false));

    // Whether anything is watching. Decided once rather than per update, and it
    // is the *error* stream that is asked because that is where progress goes:
    // piping the results to a file should still show progress on the screen.
    let live = std::io::stderr().is_terminal();

    // Ctrl-C cancels rather than killing, so a sweep stopped halfway still
    // prints what it found and says that it stopped.
    {
        let _ = ctrl_c(Arc::clone(&cancel));
    }

    for prefix in prefixes {
        // Whether the prefix is on this machine's own wire decides both the
        // notice and the method: ARP only settles an address on-link. The
        // survey is what knows that, which is why the engine takes it as an
        // option rather than guessing.
        let on_link = local.iter().any(|l| l.contains(prefix.network()));
        if !on_link {
            println!(
                "Note: {prefix} is not a network this machine is on. Scanning it is\n      \
                 your decision and your responsibility.\n"
            );
        }
        let opts = if on_link {
            discover::Options::on_link()
        } else {
            discover::Options::default()
        };

        println!(
            "Sweeping {prefix} ({} addresses) at {}/s",
            prefix.host_count(),
            rate.rate()
        );

        let started = Instant::now();
        let last = Mutex::new(Instant::now() - Duration::from_secs(1));
        let result = discover::sweep(prefix, &transport, &rate, opts, &cancel, &|p, _| {
            // A progress line is drawn by returning to the start of it, which
            // only means anything on a terminal. Redirected, every update
            // becomes another line of rubbish in the file — and because it goes
            // to stderr, it lands in the middle of the table when both streams
            // are captured together.
            if !live {
                return;
            }
            // Throttled to ten a second: a line per probe is 254 lines of
            // scrollback for a result that fits on one.
            let mut last = last.lock().expect("progress clock poisoned");
            if last.elapsed() >= Duration::from_millis(100) || p.probed == p.total {
                *last = Instant::now();
                eprint!(
                    "\r  {} of {} probed, {} found   ",
                    p.probed, p.total, p.found
                );
                let _ = std::io::stderr().flush();
            }
        });
        if live {
            // Blank the line rather than leaving the last count above the
            // table. Spaces rather than an erase escape, because a console
            // without ANSI processing would print the escape instead.
            eprint!("\r{:<48}\r", "");
        }

        // Phase four, and only for what answered: two hundred and fifty
        // addresses were just probed and a handful of them are devices worth
        // asking anything of.
        let addresses: Vec<_> = result.found.iter().map(|f| f.address).collect();
        let names = identify::many(
            &addresses,
            &muster_net::platform::udp::Udp,
            &rate,
            identify::Options {
                // The resolver the machine actually uses. `None` where it could
                // not be read, which skips the reverse lookup rather than
                // guessing at an address.
                resolver: survey.resolvers.iter().copied().find(IpAddr::is_ipv4),
                ..Default::default()
            },
            &cancel,
            &|done, total| {
                if live {
                    eprint!("\r  identifying {done} of {total}   ");
                    let _ = std::io::stderr().flush();
                }
            },
        );
        if live {
            eprint!("\r{:<48}\r", "");
        }

        print_sweep(&result, &names, started.elapsed());
    }
}

/// Column widths for the device table.
///
/// `CLAUDE.md` makes the device list a dense table of figures whose columns
/// align, so every field gets a width of its own and nothing shares one. The
/// randomised marker having been *appended to the MAC* is exactly how that goes
/// wrong: the widest hardware address is 17 characters, the marker is 12 more,
/// and one such row pushes the timing and the reason out of line with every
/// other row in the table.
const W_ADDRESS: usize = 15; // 255.255.255.255
/// Wide enough for a full IPv6 address, which the neighbour table contains and
/// the sweep does not.
const W_ADDRESS6: usize = 39;
const W_MAC: usize = 17; // aa:bb:cc:dd:ee:ff
/// Wide enough for most organisation names without pushing the reason column
/// off an eighty-column terminal. Longer names are cut with an ellipsis rather
/// than wrapping, because a wrapped row stops being a row.
const W_VENDOR: usize = 24;
/// The name a device gives for itself.
const W_NAME: usize = 22;
const W_RTT: usize = 6; // 1234 ms, or <1 ms

/// What an address says about its maker, in one place because it is shown in
/// three.
///
/// This had been written out at each site and had already drifted into two
/// spellings of the randomised case. It is now one function, and it answers
/// with the vendor where there is one — `Origin` keeps the three cases apart so
/// that a randomised address cannot be reported as an unknown vendor.
fn vendor_cell(mac: Option<muster_net::MacAddr>) -> String {
    let Some(mac) = mac else { return String::new() };
    truncate(muster_net::vendor::lookup(mac).label(), W_VENDOR)
}

/// One line of the device table.
///
/// A function rather than an inline `println!` so that the alignment rule has
/// somewhere to be tested. A test that reimplements the formatting proves only
/// that it agrees with itself.
fn device_row(host: &discover::Found, named: Option<&identify::Identity>) -> String {
    let mac = host.mac.map(|m| m.to_string()).unwrap_or_default();
    // Its own column, not a suffix on the hardware address.
    let vendor = vendor_cell(host.mac);
    let rtt = match host.rtt {
        Some(t) if t.as_millis() > 0 => format!("{} ms", t.as_millis()),
        // A reply faster than the platform's resolution. `0 ms` would claim a
        // precision that is not there.
        Some(_) => "<1 ms".into(),
        None => String::new(),
    };
    // The name column holds the name and nothing else. A note about it goes in
    // the trailing column, which is the only one with no width to overflow:
    // appending "(disputed)" here instead cost most of the name to truncation,
    // which is the same defect the randomised marker had.
    let best = named.and_then(identify::Identity::best);
    let name = truncate(best.map(|n| n.value.as_str()).unwrap_or(""), W_NAME);

    let mut why: Vec<String> = host.evidence.iter().map(|e| e.reason()).collect();
    if let Some(best) = best {
        why.push(format!("named by {}", best.source.label()));
    }
    if named.is_some_and(identify::Identity::disputed) {
        // Two sources naming a device differently is information, not noise:
        // usually a router with two identities, or an address whose previous
        // occupant the resolver still remembers.
        let others = named
            .map(identify::Identity::other_names)
            .unwrap_or_default();
        why.push(format!("also called {}", others.join(", ")));
    }
    if let Some(group) = named.and_then(|i| i.workgroup.as_deref()) {
        why.push(format!("workgroup {group}"));
    }
    for service in named.map(|i| i.services.as_slice()).unwrap_or(&[]) {
        why.push(service.clone());
    }

    format!(
        "  {:<W_ADDRESS$}  {:<W_NAME$}  {:<W_MAC$}  {:<W_VENDOR$}  {:>W_RTT$}  {}",
        host.address,
        name,
        mac,
        vendor,
        rtt,
        why.join(", ")
    )
}

/// Cuts a cell to fit, on a character boundary.
///
/// Byte slicing would panic on the first name in a script that is not Latin,
/// and both the registry and a device's own mDNS name contain those.
fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let cut: String = text.chars().take(width - 1).collect();
    format!("{}…", cut.trim_end())
}

fn print_sweep(s: &discover::Sweep, names: &[identify::Identity], took: Duration) {
    if s.found.is_empty() {
        println!("  nothing answered");
    } else {
        println!(
            "  {:<W_ADDRESS$}  {:<W_NAME$}  {:<W_MAC$}  {:<W_VENDOR$}  {:>W_RTT$}  How it answered",
            "Address", "Name", "Hardware", "Made by", "Time"
        );
    }
    for (i, host) in s.found.iter().enumerate() {
        println!("{}", device_row(host, names.get(i)));
    }

    println!(
        "\n  {} device{} in {:.1}s, {} of {} addresses probed",
        s.found.len(),
        if s.found.len() == 1 { "" } else { "s" },
        took.as_secs_f32(),
        s.probed,
        s.total
    );

    // The rule: a partial sweep never presents its count as the answer.
    if s.cancelled {
        println!("  Stopped early, so this is not the whole network.");
    }
    for missed in &s.not_done {
        println!("  Incomplete: {missed}.");
    }
    println!();
}

/// Installs a Ctrl-C handler without taking a dependency for it.
///
/// Answers whether one is now installed. A bool rather than a `Result` because
/// there is exactly one thing to know and no error worth carrying: the scan
/// runs either way, and without a handler Ctrl-C kills the process, which loses
/// the findings but is not worse than not scanning.
#[cfg(windows)]
#[must_use]
pub fn ctrl_c(flag: Arc<AtomicBool>) -> bool {
    // Imported here rather than at the top of the file: this is the only thing
    // in the binary that orders an atomic, and it is Windows-only, so a
    // top-level import is an unused one on Linux — which `-D warnings` makes a
    // build failure rather than a note.
    use std::sync::OnceLock;
    use std::sync::atomic::Ordering;

    // The console handler is a bare `extern "system" fn`, so what it acts on
    // has to be reachable without a capture. A shared flag is that, and it
    // needs no unsafe of its own — a boxed closure in the same place would.
    // The `OnceLock` also enforces the one handler per process this wants.
    static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    if FLAG.set(flag).is_err() {
        return false;
    }

    unsafe extern "system" fn on_signal(_kind: u32) -> i32 {
        match FLAG.get() {
            Some(flag) => {
                flag.store(true, Ordering::SeqCst);
                1 // Handled: the scan stops itself and prints what it has.
            }
            None => 0,
        }
    }

    let ok =
        unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_signal), 1) };
    ok != 0
}

/// No handler on this platform yet, so Ctrl-C ends the process and the findings
/// with it. Saying so here rather than silently doing nothing is what keeps the
/// gap visible when the Unix side is written.
#[cfg(not(windows))]
#[must_use]
pub fn ctrl_c(_flag: Arc<AtomicBool>) -> bool {
    false
}

/// Prints the survey.
///
/// Takes a writer rather than using `println!` so the shape of the output can
/// be asserted in a test. What it must never do is print an empty section for a
/// reading that failed: a machine whose routing table could not be read has an
/// unknown gateway, not no gateway, and the two look identical once a blank
/// line is all that is left of the difference.
fn print_survey<W: Write>(w: &mut W, s: &Survey) {
    let _ = writeln!(w, "Interfaces");
    let scannable: Vec<_> = s.interfaces.iter().filter(|i| i.is_scannable()).collect();
    if !s.has(Reading::Interfaces) {
        let _ = writeln!(w, "  could not be read");
    } else if scannable.is_empty() {
        let _ = writeln!(w, "  none up with an address");
    } else {
        let primary = s.primary().map(|i| i.index);
        for iface in scannable {
            let mark = if Some(iface.index) == primary {
                '*'
            } else {
                ' '
            };
            let mac = match iface.mac {
                Some(m) => format!("{m}  {}", vendor_cell(iface.mac)),
                None => "no hardware address".into(),
            };
            let _ = writeln!(w, "{mark} {} — {}", iface.friendly, mac.trim_end());
            for addr in &iface.addresses {
                let _ = writeln!(w, "      {} in {}", addr.address, addr.prefix);
            }
        }
    }

    let _ = writeln!(w, "\nGateway");
    if !s.has(Reading::Routes) {
        let _ = writeln!(w, "  could not be read");
    } else if s.gateways.is_empty() {
        let _ = writeln!(w, "  none — this machine has no default route");
    } else {
        for g in &s.gateways {
            let via = s
                .interface(g.interface_index)
                .map(|i| i.friendly.as_str())
                .unwrap_or("unknown interface");
            let _ = writeln!(w, "  {} via {} (metric {})", g.address, via, g.metric);
        }
    }

    let _ = writeln!(w, "\nDNS");
    if !s.has(Reading::Resolvers) && s.resolvers.is_empty() {
        let _ = writeln!(w, "  could not be read");
    } else if s.resolvers.is_empty() {
        let _ = writeln!(w, "  none configured");
    } else {
        for r in &s.resolvers {
            let _ = writeln!(w, "  {r}");
        }
    }

    let _ = writeln!(w, "\nDHCP");
    if s.dhcp_servers.is_empty() {
        // Not a failure and not an absence of servers: it is an absence of a
        // recorded lease, which a static address also produces.
        let _ = writeln!(w, "  no lease recorded on any interface");
    } else {
        for d in &s.dhcp_servers {
            let _ = writeln!(w, "  {d}");
        }
    }

    let _ = writeln!(w, "\nAlready seen");
    if !s.has(Reading::Neighbours) {
        let _ = writeln!(w, "  the neighbour table could not be read");
    } else {
        let mut devices: Vec<_> = s.known_devices().collect();
        devices.sort_by_key(|n| n.address);
        if devices.is_empty() {
            let _ = writeln!(w, "  nothing in the neighbour table yet");
        } else {
            for n in devices {
                // Trimmed because the marker is the last column and is usually
                // empty: padding to it would put trailing spaces on almost
                // every line, which is invisible on screen and noise the moment
                // the output is redirected into a file or a diff.
                let row = format!(
                    "  {:<W_ADDRESS6$}  {:<W_MAC$}  {}",
                    n.address,
                    n.mac,
                    vendor_cell(Some(n.mac))
                );
                let _ = writeln!(w, "{}", row.trim_end());
            }
        }
    }

    let _ = writeln!(w, "\nTargets");
    let targets = s.default_targets();
    if targets.is_empty() {
        let _ = writeln!(
            w,
            "  none — no local network small enough to sweep by default"
        );
    } else {
        for t in targets {
            let _ = writeln!(w, "  {t}  ({} addresses)", t.host_count());
        }
    }

    if !s.gaps.is_empty() {
        let _ = writeln!(w, "\nCould not read");
        for gap in &s.gaps {
            let _ = writeln!(w, "  {}: {}", gap.reading, gap.because);
        }
    }
}

/// Take the console Muster was launched from, where there is one.
///
/// The `windows` subsystem above is what stops a console appearing for a
/// double-click, and it also stops a release build inheriting the one it was
/// started from, so `muster scan` in a terminal would otherwise print nothing.
/// That is a real loss rather than a cosmetic one: the text mode is how Muster
/// is used over SSH and in a script.
///
/// `AttachConsole(ATTACH_PARENT_PROCESS)` asks for the parent's console and
/// fails harmlessly where there is not one — started from Explorer, from the
/// Start menu, or by the installer — which is exactly the case the subsystem
/// change exists to fix.
///
/// The known wart is that a GUI-subsystem process does not hold the shell's
/// prompt, so its output arrives after the prompt has come back. That is what
/// every Windows application doing this looks like, and it is a great deal
/// better than a text mode that cannot speak.
#[cfg(all(windows, not(debug_assertions)))]
fn attach_parent_console() {
    // SAFETY: no pointer arguments, and a documented failure return for "there
    // is no console to attach to", which is the ordinary case and is ignored.
    unsafe {
        windows_sys::Win32::System::Console::AttachConsole(
            windows_sys::Win32::System::Console::ATTACH_PARENT_PROCESS,
        );
    }
}

/// Every other build already has whatever console it is going to get.
#[cfg(not(all(windows, not(debug_assertions))))]
fn attach_parent_console() {}

#[cfg(test)]
mod tests {
    use super::*;
    use muster_net::sysinfo::Recorded;

    /// The rule from `CLAUDE.md`, at the one place a user actually reads it: a
    /// probe that could not look must not print like a network with nothing on
    /// it.
    #[test]
    fn a_survey_that_could_not_look_says_so_rather_than_printing_nothing() {
        let s = Survey::take(Recorded {
            broken: true,
            ..Default::default()
        });
        let mut out = Vec::new();
        print_survey(&mut out, &s);
        let text = String::from_utf8(out).unwrap();

        assert_eq!(
            text.matches("could not be read").count(),
            4,
            "every failed reading says so:\n{text}"
        );
        assert!(
            text.contains("Could not read"),
            "and the reasons are listed:\n{text}"
        );
        assert!(
            !text.contains("none up with an address"),
            "a failure must not read as an empty network:\n{text}"
        );
    }

    /// `CLAUDE.md`: the device list is a dense table of figures and the columns
    /// align. A randomised MAC is a whole column wider than a registered one,
    /// and appending its marker to the hardware address is how one phone knocks
    /// every field after it out of line for its row alone.
    #[test]
    fn every_row_of_the_device_table_aligns() {
        use muster_net::discover::{Evidence, Found, Sweep};

        let mac: muster_net::MacAddr = "3c:22:fb:aa:bb:cc".parse().unwrap();
        let randomised: muster_net::MacAddr = "36:d6:0f:80:3e:8a".parse().unwrap();
        assert!(
            randomised.is_randomised(),
            "the fixture must exercise the wide case"
        );

        let sweep = Sweep {
            found: vec![
                // A registered MAC with a sub-millisecond reply.
                Found {
                    address: "192.168.0.1".parse().unwrap(),
                    mac: Some(mac),
                    evidence: vec![Evidence::Arp(mac), Evidence::Ping],
                    rtt: Some(Duration::from_micros(300)),
                },
                // The wide case: a randomised MAC and a three-digit time.
                Found {
                    address: "192.168.0.11".parse().unwrap(),
                    mac: Some(randomised),
                    evidence: vec![Evidence::Arp(randomised)],
                    rtt: Some(Duration::from_millis(937)),
                },
                // No hardware address and no timing at all: found by a refusal.
                Found {
                    address: "10.0.0.254".parse().unwrap(),
                    mac: None,
                    evidence: vec![Evidence::TcpRefused(443)],
                    rtt: None,
                },
            ],
            probed: 3,
            total: 3,
            ..Default::default()
        };

        // No identities: the alignment has to hold for the empty name column
        // as well, which is the common case on a network with no mDNS on it.
        let rows: Vec<String> = sweep.found.iter().map(|f| device_row(f, None)).collect();

        // The reason is the last column, so where it starts is where every
        // preceding field has finished. One position for every row, or it is
        // not a table.
        let starts: Vec<usize> = rows
            .iter()
            .map(|line| {
                line.find("answered")
                    .or_else(|| line.find("port "))
                    .unwrap_or_else(|| panic!("no reason column in {line:?}"))
            })
            .collect();
        assert!(
            starts.iter().all(|&s| s == starts[0]),
            "the reason column moves between rows: {starts:?}\n{}",
            rows.join("\n")
        );

        // And the marker is present without having widened anything.
        assert!(rows[1].contains("randomised"));
        assert!(
            rows[0].contains("<1 ms"),
            "sub-millisecond is not rounded to 0"
        );
    }

    /// The other direction: a machine with genuinely nothing configured reads
    /// as empty, not as broken.
    #[test]
    fn an_empty_machine_reads_as_empty_and_not_as_broken() {
        let s = Survey::take(Recorded::default());
        let mut out = Vec::new();
        print_survey(&mut out, &s);
        let text = String::from_utf8(out).unwrap();

        assert!(!text.contains("could not be read"), "{text}");
        assert!(text.contains("none up with an address"), "{text}");
        assert!(text.contains("no default route"), "{text}");
    }
}
