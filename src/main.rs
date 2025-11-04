#![expect(missing_docs)]

use anyhow::{Context as _, Result, bail};
use clap::{ArgMatches, Command, arg, command, crate_name, crate_version, value_parser};
use log::{info, trace};
use std::borrow::Cow;
use std::io::Cursor;
use std::net;
use std::net::{SocketAddr, ToSocketAddrs as _};
use std::str::FromStr as _;
use std::time::Duration;

mod daemon;
mod pf;
mod pflog;
mod stun;
mod sys;

fn main() -> Result<()> {
    let args = command!()
        .arg(
            arg!(--"log-level" <LEVEL>)
                .help("Log level (off, error, warn, info, debug, trace)")
                .value_parser(value_parser!(log::LevelFilter))
                .default_value("warn")
                .global(true),
        )
        .subcommand(
            Command::new("stun")
                .about("Perform a STUN request")
                .arg(
                    arg!(-p --"src-port" <PORT>)
                        .help("Source port (use 0 for random)")
                        .value_parser(value_parser!(u16))
                        .default_value("32853"),
                )
                .arg(arg!(<host>).help("Destination host[:port]")),
        )
        .get_matches();

    let mut logger = env_logger::builder();
    if let Some(&v) = args.get_one::<log::LevelFilter>("log-level") {
        logger.filter_level(v);
    }
    logger.parse_default_env();
    logger.init();

    match args.subcommand() {
        Some(("stun", matches)) => return stun(matches),
        None => {}
        _ => unreachable!(),
    }

    #[cfg(not(target_os = "openbsd"))]
    bail!("Only supported on OpenBSD");

    #[cfg(target_os = "openbsd")]
    daemon::daemon()
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
