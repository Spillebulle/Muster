//! `muster ports` — which ports are open on one host.
//!
//! One host rather than a network, deliberately. A port scan is a much larger
//! and much louder thing than a sweep: fifty ports across a /24 is twelve
//! thousand probes where the sweep sent two hundred and fifty. Until there is
//! an interface in which the scope of a scan is visible while it runs, it is
//! asked for one host at a time.

use crate::ctrl_c;
use muster_net::rate::Bucket;
use muster_net::{Prefix, portscan};
use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

pub fn run(host: Option<&str>, spec: Option<&str>) {
    let Some(host) = host else {
        eprintln!(
            "muster: which host?\n        \
             muster ports 192.168.0.1 [80,443 | 1-1024]"
        );
        std::process::exit(2);
    };
    let target: IpAddr = match host.parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("muster: '{host}' is not an address");
            std::process::exit(2);
        }
    };
    let ports: portscan::Ports = match spec {
        None => portscan::Ports::common(),
        Some(text) => match text.parse() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("muster: {e}");
                std::process::exit(2);
            }
        },
    };

    let survey = muster_net::survey();
    let local: Vec<Prefix> = survey
        .interfaces
        .iter()
        .filter(|i| i.is_scannable())
        .flat_map(|i| i.v4_prefixes())
        .collect();
    if !local.iter().any(|l| l.contains(target)) {
        println!(
            "Note: {target} is not on a network this machine is on. Scanning it\n      \
             is your decision and your responsibility.\n"
        );
    }

    let rate = Bucket::polite();
    let cancel = Arc::new(AtomicBool::new(false));
    let _ = ctrl_c(Arc::clone(&cancel));
    let live = std::io::stderr().is_terminal();

    println!("Scanning {} ports on {target}", ports.len());
    let started = Instant::now();
    let result = portscan::scan(
        &[target],
        &ports,
        &portscan::ConnectScanner,
        &rate,
        portscan::Options::default(),
        &cancel,
        &|done, total| {
            if live {
                eprint!("\r  {done} of {total} probed   ");
                let _ = std::io::stderr().flush();
            }
        },
    );
    if live {
        eprint!("\r{:<40}\r", "");
    }

    let host = &result.hosts[0];
    let open: Vec<u16> = host.open().collect();
    if open.is_empty() {
        println!("  no open ports found");
    } else {
        for port in &open {
            println!("  {:<7} {:<8} {}", port, "open", service_name(*port));
        }
    }
    println!(
        "\n  {} open, {} closed, {} no reply, in {:.1}s by {}",
        open.len(),
        host.closed(),
        host.filtered,
        started.elapsed().as_secs_f32(),
        result.method.label()
    );
    // The caveats carry the two things that would otherwise be silently
    // assumed: which engine answered, and that a port which said nothing is not
    // a port that is shut.
    for caveat in result.caveats() {
        println!("  Note: {caveat}.");
    }
}

/// The usual occupant of a port.
///
/// A hint rather than a finding: nothing has been asked of the service, so this
/// says what the number conventionally means and not what is actually there. A
/// claim about the service itself would need its own evidence, which is what
/// the identification phase does for names.
fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios",
        143 => "imap",
        443 => "https",
        445 => "smb",
        515 => "printer",
        548 => "afp",
        631 => "ipp",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1883 => "mqtt",
        2049 => "nfs",
        3306 => "mysql",
        3389 => "rdp",
        5000 => "upnp",
        5432 => "postgres",
        5900 | 5901 => "vnc",
        6379 => "redis",
        8006 => "proxmox",
        8080 | 8081 => "http-alt",
        8123 => "home-assistant",
        8443 => "https-alt",
        9090 => "cockpit",
        9100 => "jetdirect",
        27017 => "mongodb",
        32400 => "plex",
        51820 => "wireguard",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hint is only useful if it is right for the ports the default list
    /// actually scans, and wrong hints are worse than none.
    #[test]
    fn the_common_ports_that_have_a_name_get_the_right_one() {
        assert_eq!(service_name(22), "ssh");
        assert_eq!(service_name(443), "https");
        assert_eq!(service_name(9100), "jetdirect");
        assert_eq!(service_name(32400), "plex");
        assert_eq!(service_name(5901), "vnc");
    }

    /// An unknown port gets nothing rather than a guess.
    #[test]
    fn an_unnamed_port_says_nothing() {
        assert_eq!(service_name(1234), "");
        assert_eq!(service_name(0), "");
    }
}
