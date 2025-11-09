//! Command for installing and enabling rc.d(8) script.

#![cfg(target_os = "openbsd")]

use anyhow::{Context as _, bail};
use clap::{ArgMatches, arg, crate_name};
use log::{info, warn};
use std::env::current_exe;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;
use std::{env, fs, io};

const RCD_SCRIPT: &str = r#"#!/bin/ksh

daemon="<bin>"

. /etc/rc.d/rc.subr

rc_bg=YES
rc_reload=NO

rc_cmd $1
"#;

#[inline]
#[must_use]
pub fn args() -> [clap::Arg; 2] {
    [
        arg!(--"no-copy" "Do not copy binary to /usr/local/sbin"),
        arg!(--"no-enable" "Do not enable daemon"),
    ]
}

/// Installs and enables rc.d(8) script.
pub fn install(args: &ArgMatches) -> anyhow::Result<()> {
    const SBIN: &str = concat!("/usr/local/sbin/", crate_name!());
    const RCD: &str = concat!("/etc/rc.d/", crate_name!());

    // https://github.com/rust-lang/rust/issues/60560
    let bin_path = current_exe().context(concat!(
        "Failed to determine path to ",
        crate_name!(),
        " (re-run using absolute path)"
    ))?;
    let mut bin = (bin_path.to_str()).context("Path to binary is not valid UTF-8")?;

    if !args.get_flag("no-copy") {
        info!("Copying {bin} to {SBIN}");
        if let Err(e) = fs::remove_file(SBIN)
            && e.kind() != io::ErrorKind::NotFound
        {
            warn!("Failed to remove {SBIN}: {e}");
        }
        fs::copy(bin, SBIN).context("Failed to copy binary")?;
        bin = SBIN;
    }

    info!("Writing {RCD}");
    fs::write(RCD, RCD_SCRIPT.replacen("<bin>", bin, 1))
        .with_context(|| format!("Failed to write {RCD}"))?;
    fs::set_permissions(RCD, fs::Permissions::from_mode(0o555))
        .with_context(|| format!("Failed to set permissions on {RCD}"))?;

    if !args.get_flag("no-enable") {
        info!(concat!("Enabling ", crate_name!()));
        let status = (Command::new("rcctl").args(["enable", crate_name!()]))
            .status()
            .context("Failed to execute rcctl")?;
        if !status.success() {
            bail!(format!("Failed to enable {} ({status})", crate_name!()));
        }
    }

    println!("{RCD} installed");
    Ok(())
}
