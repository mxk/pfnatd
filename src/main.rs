//! Easy NAT mode for OpenBSD packet filter (pf).

use anyhow::{Context as _, Result, bail};
use clap::{ArgMatches, Command, arg, command, crate_name, crate_version, value_parser};
use log::{error, info, trace};
use std::borrow::Cow;
use std::io::Cursor;
use std::net::{SocketAddr, ToSocketAddrs as _};
use std::process::ExitCode;
use std::str::FromStr as _;
use std::sync::OnceLock;
use std::time::Duration;
use std::{env, net};

mod daemon;
mod install;
mod pf;
mod pflog;
mod stun;
mod sys;

fn main() -> ExitCode {
    static LOGGER: OnceLock<env_logger::Logger> = OnceLock::new();

    let cmd = command!()
        .args([
            arg!(--"log-level" <LEVEL> "Log level (off, error, warn, info, debug, trace)")
                .value_parser(value_parser!(log::LevelFilter))
                .default_value("warn")
                .global(true),
            arg!(--"pflog" <UNIT> "pflog(4) interface unit number")
                .value_parser(value_parser!(u8))
                .default_value("1"),
        ])
        .subcommand(
            Command::new("stun").about("Perform a STUN request").args([
                arg!(-p --"src-port" <PORT> "Source port (use 0 for random)")
                    .value_parser(value_parser!(u16))
                    .default_value("32853"),
                arg!(<host> "Destination host[:port]"),
            ]),
        );
    #[cfg(target_os = "openbsd")]
    let cmd = cmd.subcommand(
        Command::new("install")
            .about("Install and enable rc.d(8) script")
            .args(install::args()),
    );
    let args = cmd.get_matches();

    let log = LOGGER.get_or_init(|| {
        let mut b = env_logger::Builder::new();
        if let Some(&level) = args.get_one::<log::LevelFilter>("log-level") {
            b.filter_level(level);
        }
        #[cfg(target_os = "openbsd")]
        sys::Syslog::init(&mut b);
        b.format_indent(None).build()
    });
    log::set_logger(log).expect("Another logger was already set");
    log::set_max_level(log.filter());

    let ec = match match args.subcommand() {
        #[cfg(target_os = "openbsd")]
        Some(("install", args)) => install::install(args),
        Some(("stun", args)) => stun(args),
        #[cfg(target_os = "openbsd")]
        None => daemon::daemon(*args.get_one::<u8>("pflog").unwrap()),
        #[cfg(not(target_os = "openbsd"))]
        None => Err(anyhow::anyhow!(concat!(
            crate_name!(),
            " daemon is only supported on OpenBSD"
        ))),
        _ => unreachable!(),
    } {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:?}");
            ExitCode::FAILURE
        }
    };
    log::logger().flush();
    ec
}

/// Performs a STUN request and prints the mapped address to stdout.
fn stun(args: &ArgMatches) -> Result<()> {
    // Create request
    let mut w = stun::Writer::request(Cursor::new([0_u8; 548]))?;
    w.software(concat!(crate_name!(), " v", crate_version!()))?;
    let (id, mut buf) = (w.id(), w.flush()?);
    let req = &buf.get_ref()[..usize::try_from(buf.position())?];

    // Resolve remote host
    let mut host = Cow::from(args.get_one::<String>("host").unwrap());
    if (host.rsplit_once(':')).is_none_or(|(_, p)| u16::from_str(p).is_err()) {
        host.to_mut().push_str(":3478");
    }
    let Some(host) = host.to_socket_addrs()?.find(SocketAddr::is_ipv4) else {
        bail!("{host} did not resolve to an IPv4 address");
    };
    info!("Remote host: {host}");

    // Open UDP socket and send request
    let src = ("0.0.0.0", *args.get_one::<u16>("src-port").unwrap());
    let sock = net::UdpSocket::bind(src).context("Failed to open local socket")?;
    info!("Local socket: {}", sock.local_addr()?);
    trace!("Request: {req:x?}");
    (sock.send_to(req, host)).context("Failed to send request")?;

    // Receive response
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (n, _) = (sock.recv_from(buf.get_mut())).context("Failed to receive response")?;
    let rsp = &buf.get_ref()[..n];
    trace!("Response: {rsp:x?}");

    // Print mapped address
    let m = stun::Msg::try_from(rsp)?;
    if m.id() != id {
        bail!("Transaction ID mismatch");
    }
    let Some(addr) = m.mapped_address() else {
        bail!("Server did not report a mapped address ({:?})", m.class());
    };
    println!("{addr}");
    Ok(())
}
