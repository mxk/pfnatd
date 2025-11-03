#![expect(missing_docs)]

use crate::stun::{Attr, Binding};
use anyhow::{Context as _, Result, bail};
use clap::{ArgMatches, Command, arg, command, value_parser};
use log::{info, trace};
use std::borrow::Cow;
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
                .about("Performs a stun request")
                .arg(
                    arg!(-p --"src-port" <PORT>)
                        .help("Source port")
                        .value_parser(value_parser!(u16))
                        .default_value("0"),
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

/// Performs a STUN request.
fn stun(args: &ArgMatches) -> Result<()> {
    let mut host = Cow::from(args.get_one::<String>("host").unwrap());
    if (host.rsplit_once(':')).is_none_or(|(_, p)| u16::from_str(p).is_err()) {
        host.to_mut().push_str(":3478");
    }
    let Some(host) = host.to_socket_addrs()?.find(SocketAddr::is_ipv4) else {
        bail!("{host} did not resolve to a valid IPv4 address");
    };
    info!("Remote host: {host}");

    let src_port = *args.get_one::<u16>("src-port").unwrap();
    let sock =
        net::UdpSocket::bind(("0.0.0.0", src_port)).context("Failed to open local socket")?;
    info!("Local socket: {}", sock.local_addr().unwrap());

    let mut buf = [0; 548];
    let n = Binding::request().write(buf.as_mut_slice())?;
    trace!("STUN request: {:x?}", &buf[..n]);
    sock.send_to(&buf[..n], host)
        .context("Failed to send STUN request")?;

    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (n, _) = (sock.recv_from(buf.as_mut_slice())).context("Failed to receive STUN response")?;
    trace!("STUN response: {:x?}", &buf[..n]);
    let attrs = match Binding::try_from(&buf[..n]).context("Failed to decode STUN response")? {
        Binding::Success(_, attrs) => attrs,
        Binding::Error(_, _) => bail!("STUN error response"),
        _ => bail!("Unexpected STUN response"),
    };

    for a in attrs {
        if let Attr::MappedAddress(s) | Attr::XorMappedAddress(s) = a {
            println!("STUN response: {s}");
            return Ok(());
        }
    }
    bail!("STUN server did not report mapped address");
}
