//! pfnatd daemon.

#![cfg(target_os = "openbsd")]

use crate::pf::Pf;
use crate::pflog::{Interrupt, PcapError, Pflog};
use crate::sys::{SIG_BLOCK, pthread_sigmask, sigfillset, sigset_t};
use anyhow::{Context as _, Result, bail};
use clap::{crate_name, crate_version};
use log::{debug, info};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator;
use signal_hook::iterator::Signals;
use signal_hook::low_level::emulate_default_handler;
use std::io::{BufRead as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::raw::c_int;
use std::thread::JoinHandle;
use std::{fs, io, ptr, thread};

/// Runs the main pfnatd daemon.
pub fn daemon(logif: u8) -> Result<()> {
    info!(concat!(crate_name!(), " v", crate_version!(), " starting"));
    let _pid = PidFile::lock()?;

    let mut pf = Pf::open(logif)?;
    let mut pflog = Pflog::open(logif)?;

    let (sig_handle, sig_thread) = signal_setup(TERM_SIGNALS, pflog.interrupt())?;

    // TODO: pledge?

    let e = loop {
        match pflog.next() {
            Ok(None) => pf.expire_rules()?,
            Ok(Some(p)) => {
                if let Some(s) = p.stun_nat() {
                    pf.add_nat(&s)?;
                }
            }
            Err(e) => break e,
        }
    };

    sig_handle.close();
    sig_thread.join().unwrap();

    match e.downcast::<PcapError>() {
        Ok(e) if e.is_interrupt() => Ok(()),
        Ok(e) => Err(e.into()),
        Err(e) => Err(e),
    }
}

/// Process ID file used to prevent multiple daemons from running concurrently.
#[clippy::has_significant_drop]
#[expect(dead_code)]
#[must_use = "if unused, the process will lose execution lock"]
struct PidFile(OwnedFd);

impl PidFile {
    /// Acquires an exclusive advisory lock and writes the current process ID to
    /// the PID file.
    fn lock() -> Result<Self> {
        const PID_FILE: &str = concat!("/var/run/", crate_name!(), ".pid");
        let mut f = (fs::OpenOptions::new().read(true).write(true).create(true))
            .truncate(false)
            .open(PID_FILE)
            .with_context(|| format!("Failed to open {PID_FILE}"))?;
        match f.try_lock() {
            Ok(()) => {
                let pid = std::process::id();
                debug!("Writing {PID_FILE} (pid {pid})");
                f.set_len(0)?;
                writeln!(f, "{pid}")?;
                Ok(Self(f.into()))
            }
            Err(fs::TryLockError::WouldBlock) => {
                let pid = (io::BufReader::new(f).lines().next().and_then(Result::ok))
                    .unwrap_or_else(|| "?".to_owned());
                bail!(
                    "Another instance of {} is running (pid {pid})",
                    crate_name!()
                )
            }
            Err(fs::TryLockError::Error(e)) => {
                Err(e).with_context(|| format!("Failed to lock {PID_FILE}"))
            }
        }
    }
}

// Configures signal handling for graceful termination. A dedicated thread is
// used to avoid interrupting syscalls from the main thread. Only the first
// received signal is handled gracefully. Any additional signals will use the
// default handlers.
fn signal_setup(sigs: &[c_int], intr: Interrupt) -> Result<(iterator::Handle, JoinHandle<()>)> {
    let mut sig = Signals::new(sigs)?;
    let sig_handle = sig.handle();

    let sig_thread = thread::spawn(move || {
        if sig.forever().next().is_some() {
            drop(intr);
            for s in sig.forever() {
                drop(emulate_default_handler(s));
            }
        }
    });

    // SAFETY: masking all signals for the main thread. No safety concerns.
    let rc = unsafe {
        let mut set = sigset_t::default();
        sigfillset(&raw mut set);
        pthread_sigmask(SIG_BLOCK, &raw const set, ptr::null_mut())
    };
    assert_eq!(rc, 0, "pthread_sigmask failed");
    Ok((sig_handle, sig_thread))
}
