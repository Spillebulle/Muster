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
use std::sync::atomic::{AtomicBool, Ordering};
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
        "scan" => {
            // `--dhcp` may come before or after the prefix, because both read
            // naturally and a tool that accepts only one order is a tool that
            // has to be argued with.
            let rest: Vec<&str> = args[1..].iter().map(String::as_str).collect();
            let dhcp = rest.contains(&"--dhcp");
            // The three questions that need a connection rather than a
            // datagram, named one at a time rather than behind one switch: they
            // are three different things to ask a network, and the window asks
            // them one at a time too.
            let serves = muster_net::service::Options {
                smb: rest.contains(&"--smb"),
                nfs: rest.contains(&"--nfs"),
                ssh: rest.contains(&"--ssh"),
                ..Default::default()
            };
            scan(
                rest.into_iter().find(|a| !a.starts_with("--")),
                dhcp,
                serves,
            );
        }
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
           muster scan --dhcp            and ask who hands out addresses\n  \
           muster scan --smb --nfs --ssh  and ask what each device serves\n  \
           muster ports <host> [ports]   which ports are open on one host\n  \
           muster --help                 this\n\n\
         None of these needs administrator rights. With no prefix, the scan\n\
         sweeps the network this machine is on and nothing beyond it.\n\n\
         A scan asks each device what it is over mDNS, SSDP and NetBIOS, and\n\
         asks the link as a whole, which is what most devices answer. It also\n\
         asks each one whether it is a name server. `--dhcp` adds a DISCOVER\n\
         broadcast, which finds every server willing to hand out an address:\n\
         two is a fault worth knowing about. Nothing ever accepts an offer.\n\n\
         `--smb`, `--nfs` and `--ssh` open a connection to each device that\n\
         answered and speak that protocol's own opening move: the negotiate an\n\
         SMB client sends first, the null call NFS defines, and for SSH nothing\n\
         at all, because a server greets whoever connects. Nothing is opened,\n\
         listed or authenticated.\n\n\
         Devices are identified by hardware vendor, and by name where they\n\
         answer reverse DNS, mDNS or NetBIOS. The port scan uses connect(),\n\
         which is slower than the SYN scan it will use once raw packet access\n\
         is in, and says so in its result. Ports may be given as 80,443 or\n\
         1-1024; the default is a short list of the ones worth knowing about.",
        env!("CARGO_PKG_VERSION")
    );
}

/// How long the listen runs for. The same window the window uses, and for the
/// same reason: it overlaps the rest of the scan, so it costs only the tail.
const LISTEN_WINDOW: Duration = Duration::from_secs(15);

/// Sweeps a prefix and prints what answered.
///
/// With no argument it takes the survey and sweeps what that found, which is
/// `CLAUDE.md`'s rule that the default target is the local prefix and never a
/// range somebody typed. A prefix given on the command line is the deliberate
/// act, and it is checked against the local networks so that reaching beyond
/// the link is something the user is told they are doing.
fn scan(target: Option<&str>, dhcp: bool, serves: muster_net::service::Options) {
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
    // prints what it found and says that it stopped. Where the handler could
    // not be installed the scan still runs, and the user is told what Ctrl-C
    // will cost rather than finding out by pressing it.
    if !ctrl_c(Arc::clone(&cancel)) && live {
        eprintln!("  Note: Ctrl-C will end this scan without printing what it found.");
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

        // Started before the sweep and collected after identification, so its
        // three-second window costs the scan nothing. See `muster_app::scan`,
        // which does the same thing for the same reason.
        let offers = (dhcp && on_link).then(|| dhcp_probe(&survey)).flatten();

        // What the link is asked, beside the sweep rather than after it: every
        // question in it is one datagram and then a wait, so a phase of its own
        // would add its whole window to the scan for nothing. Same shape and
        // same reasoning as `muster_app::scan`, which this mirrors.
        let link_opts = muster_net::link::Options {
            netbios: on_link,
            reverse: true,
            broadcast: on_link.then(|| prefix.broadcast()).flatten(),
            // **Only a resolver on this machine's own link.** See
            // `Survey::local_resolver`: asking a stranger's resolver for a name
            // for every address on this network hands them the network.
            resolver: survey.local_resolver(),
            ..Default::default()
        };
        let every: Vec<IpAddr> = prefix
            .hosts()
            .map(|hosts| hosts.collect())
            .unwrap_or_default();

        // This machine's own addresses, which is what a multicast group is
        // joined on: a machine with a VPN up has more than one.
        let own: Vec<std::net::Ipv4Addr> = survey
            .interfaces
            .iter()
            .filter(|i| i.is_scannable())
            .flat_map(|i| i.addresses.iter())
            .filter_map(|a| match a.address {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .collect();
        // Stopped when every phase that asks a question is done, which is a
        // different flag from the user's cancel: one means the scan finished
        // and the other means the results are partial.
        let hush = AtomicBool::new(false);

        let last = Mutex::new(Instant::now() - Duration::from_secs(1));
        let (result, heard, overheard) = std::thread::scope(|scope| {
            // Sits on the discovery ports for as long as the rest of the scan
            // takes, and sends nothing but what keeps a stateful firewall from
            // dropping what it is listening for. See `muster_net::listen`.
            let ears = scope.spawn(|| {
                muster_net::listen::overhear(
                    &muster_net::platform::listen::Link,
                    &own,
                    LISTEN_WINDOW,
                    &hush,
                )
            });
            let (result, heard) = std::thread::scope(|scope| {
                let asked = scope.spawn(|| {
                    muster_net::link::ask(
                        &muster_net::platform::udp::Udp,
                        link_opts,
                        &every,
                        &rate,
                        &cancel,
                    )
                });
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

                (result, asked.join().unwrap_or_default())
            });

            // Everything that asks a question is done; what is left is the
            // listen's own window.
            while !cancel.load(Ordering::SeqCst) {
                let left = LISTEN_WINDOW.saturating_sub(started.elapsed());
                if left.is_zero() {
                    break;
                }
                if live {
                    eprint!(
                        "
  listening, {} more seconds   ",
                        left.as_secs() + 1
                    );
                    let _ = std::io::stderr().flush();
                }
                std::thread::sleep(Duration::from_millis(200).min(left));
            }
            hush.store(true, Ordering::SeqCst);
            (result, heard, ears.join().unwrap_or_default())
        });
        if live {
            eprint!(
                "
{:<48}
",
                ""
            );
        }
        let mut result = result;
        if live {
            // Blank the line rather than leaving the last count above the
            // table. Spaces rather than an erase escape, because a console
            // without ANSI processing would print the escape instead.
            eprint!("\r{:<48}\r", "");
        }

        // The union: a device that answered a question put to the whole link
        // is a device, whether or not anything sent to its own address came
        // back. See `muster_net::link` — this is the half of discovery the
        // sweep cannot do.
        for (address, _) in heard.speakers() {
            if let Some(protocol) = heard.credit(address) {
                result.admit(discover::Found::announced(address, protocol));
            }
        }
        // And what the operating system already knew, which costs no packet.
        for neighbour in survey.known_in(prefix) {
            result.admit_neighbour(neighbour.address, neighbour.mac);
        }
        result.not_done.extend(heard.not_done.iter().cloned());

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
                // The resolver this machine uses, and only where it is on
                // this machine's own link.
                resolver: survey.local_resolver(),
                ..Default::default()
            },
            &cancel,
            &|done, total, _device, _identity| {
                if live {
                    eprint!("\r  identifying {done} of {total}   ");
                    let _ = std::io::stderr().flush();
                }
            },
        );
        if live {
            eprint!("\r{:<48}\r", "");
        }

        let mut names = names;

        // What the link said about each of them, beside what they said when
        // asked privately. This is where a device that answered only the group
        // gets its name, its services and its model.
        for (address, identity) in addresses.iter().zip(names.iter_mut()) {
            if let Some(voice) = heard.by.get(address) {
                identity.merge(&voice.identity);
            }
        }

        // And what was overheard while all of that ran. Folded by the engine's
        // own function so that the device list and the names beside it stay in
        // step here exactly as they do in the window.
        muster_net::link::fold(&overheard, &mut result, &mut names);
        result.not_done.extend(overheard.not_done.iter().cloned());

        // What they serve, over a connection. After identification and only for
        // what answered, and skipped entirely unless a flag asked: see
        // `muster_net::service`.
        if serves.any() {
            let serving = muster_net::service::many(
                &addresses,
                &muster_net::platform::tcp::Stream,
                &rate,
                serves,
                &cancel,
                &|done, total, _device, _serves| {
                    if live {
                        eprint!("\r  asking {done} of {total} what they serve   ");
                        let _ = std::io::stderr().flush();
                    }
                },
            );
            if live {
                eprint!("\r{:<48}\r", "");
            }
            for (identity, found) in names.iter_mut().zip(serving.iter()) {
                identity.serves(found);
            }
        }

        let offers = offers.and_then(|handle| handle.join().ok());
        if let Some(probe) = &offers {
            for server in probe.servers() {
                let server = IpAddr::V4(server);
                if let Some(i) = addresses.iter().position(|a| *a == server) {
                    names[i].offers_addresses();
                }
            }
        }

        print_sweep(&result, &names, &survey, started.elapsed());

        // After the table, because it is a statement about the link rather
        // than about a device, and because two servers is the one thing here
        // worth ending on.
        if let Some(probe) = &offers {
            println!("\n  {}", probe.verdict());
            for offer in probe.distinct_offers() {
                println!(
                    "  {:<W_ADDRESS$}  offered {}{}",
                    offer.server.to_string(),
                    offer.offered,
                    offer
                        .router
                        .map(|r| format!(", gateway {r}"))
                        .unwrap_or_default()
                );
                if let Some(portal) = offer.captive_portal() {
                    println!("  {:<W_ADDRESS$}  captive portal at {portal}", "");
                }
            }
        }
    }
}

/// Broadcasts a DISCOVER on a thread, to be collected when the scan is done.
///
/// [`None`] where this machine has no interface with a hardware address to ask
/// from, because an offer comes back addressed to whoever sent it and an
/// address nothing on the link owns collects nothing.
fn dhcp_probe(
    survey: &muster_net::Survey,
) -> Option<std::thread::JoinHandle<muster_net::dhcp::Probe>> {
    let mac = survey
        .interfaces
        .iter()
        .find(|i| i.is_scannable())
        .and_then(|i| i.mac)?;
    Some(std::thread::spawn(move || {
        // A fresh transaction id per probe, from the clock rather than a
        // counter: a predictable id on a real network collects somebody else's
        // negotiation.
        let xid = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0x4d75_7374, |d| d.subsec_nanos() ^ d.as_secs() as u32);
        muster_net::dhcp::probe(
            &muster_net::platform::udp::Dhcp,
            mac,
            xid,
            Duration::from_secs(3),
        )
    }))
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
/// Wide enough for the longest of [`muster_net::Kind`]'s labels.
const W_KIND: usize = 10; // "Smart home"

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
fn device_row(
    host: &discover::Found,
    named: Option<&identify::Identity>,
    vantage: muster_net::kind::Vantage,
) -> String {
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
    // The model, where the device named one. It is short, it is the device's
    // own words, and it is the single most useful thing in this column.
    if let Some(model) = named.and_then(|i| i.model.as_deref()) {
        why.push(model.to_string());
    }
    if let Some(group) = named.and_then(|i| i.workgroup.as_deref()) {
        why.push(format!("workgroup {group}"));
    }
    for service in named.map(|i| i.services.as_slice()).unwrap_or(&[]) {
        why.push(service.clone());
    }
    // What the device announced over UPnP. The `SERVER` header is a sentence
    // and the type URNs are long, so this column shows the header and counts
    // the rest: the device window is where the whole list belongs.
    if let Some(product) = named.and_then(|i| i.product.as_deref()) {
        why.push(format!("announces {product}"));
    }
    match named.map(|i| i.upnp.len()).unwrap_or(0) {
        0 => {}
        1 => why.push("1 UPnP type".into()),
        many => why.push(format!("{many} UPnP types")),
    }
    if named.is_some_and(|i| i.llmnr) {
        why.push("answered LLMNR".into());
    }
    // What it serves the network. The window draws these as badges; here they
    // are words, in the same order, out of the same function.
    for role in named.map(identify::Identity::roles).unwrap_or_default() {
        why.push(role.reason().to_string());
    }
    if let Some(version) = named.and_then(|i| i.resolver.as_ref()?.version.as_deref()) {
        why.push(version.to_string());
    }
    // And what the file server said while it was answering, which is the same
    // sentence the window puts in its SMB row.
    if let Some(smb) = named.and_then(|i| i.serves.smb.as_ref()) {
        let said = smb.stated(std::time::SystemTime::now());
        if !said.is_empty() {
            why.push(said);
        }
    }

    // The kind, and its reason with the rest of the evidence. The window shows
    // the same guess from the same function; a text mode that could not say
    // what a device is would be a different product from the one with the
    // icons in it.
    let empty = identify::Identity::default();
    let guess = muster_net::kind::identify(host, named.unwrap_or(&empty), vantage);
    let kind = match guess {
        Some(guess) => {
            why.insert(0, guess.clue.reason().to_string());
            guess.kind.label()
        }
        None => "",
    };

    format!(
        "  {:<W_ADDRESS$}  {:<W_KIND$}  {:<W_NAME$}  {:<W_MAC$}  {:<W_VENDOR$}  {:>W_RTT$}  {}",
        host.address,
        kind,
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

fn print_sweep(
    s: &discover::Sweep,
    names: &[identify::Identity],
    survey: &muster_net::Survey,
    took: Duration,
) {
    if s.found.is_empty() {
        println!("  nothing answered");
    } else {
        println!(
            "  {:<W_ADDRESS$}  {:<W_KIND$}  {:<W_NAME$}  {:<W_MAC$}  {:<W_VENDOR$}  {:>W_RTT$}               How it answered",
            "Address", "What", "Name", "Hardware", "Made by", "Time"
        );
    }
    for (i, host) in s.found.iter().enumerate() {
        println!(
            "{}",
            device_row(host, names.get(i), survey.vantage(host.address))
        );
    }

    println!(
        "\n  {} device{} in {:.1}s, {} of {} addresses probed",
        s.found.len(),
        if s.found.len() == 1 { "" } else { "s" },
        took.as_secs_f32(),
        s.probed,
        s.total
    );

    // **The count has to say what it is counting.** Some of these devices were
    // never probed at all: they answered a question put to the whole link, or
    // they were already in this machine's neighbour table. That is a real
    // device found by a real means, and it is not the same claim as an address
    // that answered when it was asked, so the line says which.
    let heard = s.heard();
    if heard > 0 {
        println!(
            "  {heard} of them answered a question put to the whole network, or were already known to this machine, rather than answering a probe."
        );
    }

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

/// The same thing on Unix, through `signal`.
///
/// This is the platform most likely to be used from a terminal, and until this
/// existed Ctrl-C killed `muster scan` outright and took the findings with it,
/// while Windows stopped politely and printed a partial table. The same command
/// on two platforms must not answer a keystroke differently.
///
/// No dependency for it: `signal` is one symbol out of the C library that every
/// Rust binary on Unix already links, so it is declared here rather than
/// pulling `libc` into a crate that otherwise needs none of it.
///
/// What a handler may do is the constraint that shapes the rest. It runs
/// between two instructions of whatever the process was doing, so it may not
/// allocate, may not lock and may not print — one atomic store is the whole of
/// it, and the scan notices at its next probe. `OnceLock::get` on an already
/// set cell and dereferencing the `Arc` inside it are both plain loads, which
/// is why the flag can be reached at all without a capture.
#[cfg(unix)]
#[must_use]
pub fn ctrl_c(flag: Arc<AtomicBool>) -> bool {
    use std::sync::OnceLock;
    use std::sync::atomic::Ordering;

    // The same shape as the Windows handler above, and for the same reason: a
    // signal handler is a bare `extern "C" fn` with nowhere to put a capture.
    static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    if FLAG.set(flag).is_err() {
        return false;
    }

    extern "C" fn on_signal(_signum: i32) {
        if let Some(flag) = FLAG.get() {
            flag.store(true, Ordering::SeqCst);
        }
    }

    // The handler is declared as a function *pointer* rather than as a word,
    // so that passing `on_signal` needs no cast: casting a function item
    // straight to an integer is a lint, and `-D warnings` makes a lint a
    // broken build on the platform this code only compiles for.
    unsafe extern "C" {
        fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    }
    // 2 on every Unix Muster targets, and it has been 2 since the seventh
    // edition. Written out rather than taken from a crate.
    const SIGINT: i32 = 2;
    // `SIG_ERR` is `(void(*)(int))-1` rather than a null, which is why the
    // failure test is against `usize::MAX` and not against zero: zero is
    // `SIG_DFL`, a perfectly ordinary previous handler.
    const SIG_ERR: usize = usize::MAX;

    // SAFETY: the signal number is valid and `on_signal` has the signature the
    // C library requires of a handler.
    unsafe { signal(SIGINT, on_signal) != SIG_ERR }
}

/// Neither Windows nor Unix, so Ctrl-C ends the process and the findings with
/// it. Saying so here rather than silently doing nothing is what keeps the gap
/// visible.
#[cfg(not(any(windows, unix)))]
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
        let rows: Vec<String> = sweep
            .found
            .iter()
            .map(|f| device_row(f, None, muster_net::kind::Vantage::default()))
            .collect();

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
