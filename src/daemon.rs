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
use signal_hook::low_level::{emulate_default_handler, signal_name};
use std::io::{BufRead as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::raw::c_int;
use std::{fs, io, ptr, thread};

/// Runs the main pfnatd daemon.
pub fn daemon(logif: u8) -> Result<()> {
    info!(concat!(crate_name!(), " v", crate_version!(), " starting"));
    let _pid = PidFile::lock()?;

    let mut pf = Pf::open(logif)?;
    let mut pflog = Pflog::open(logif)?;

    let _sig = SignalHandler::register(TERM_SIGNALS, pflog.interrupt())?;

    // pf pledge does not allow DIOCCHANGERULE.
    // if unsafe { pledge(c"stdio pf".as_ptr(), ptr::null()) } < 0 {
    //     return errno_err("pledge failed");
    // }

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

/// Registered signal handler.
#[clippy::has_significant_drop]
#[must_use = "if unused, the signal handler thread will terminate immediately"]
struct SignalHandler(iterator::Handle, Option<thread::JoinHandle<()>>);

impl SignalHandler {
    // Configures signal handling for graceful termination. A dedicated thread
    // is used to avoid interrupting syscalls from the main thread. Only the
    // first received signal is handled gracefully. Any additional signals will
    // use the default handlers.
    fn register(sigs: &[c_int], intr: Interrupt) -> Result<Self> {
        let mut sig = Signals::new(sigs)?;
        let hdl = sig.handle();
        let thr = thread::spawn(move || {
            match sig.forever().next() {
                Some(s) => match signal_name(s) {
                    Some(name) => info!("Exiting due to {name}"),
                    None => info!("Exiting due to signal {s}"),
                },
                None => return,
            }
            drop(intr);
            for s in sig.forever() {
                drop(emulate_default_handler(s));
            }
        });

        // SAFETY: masking all signals for the main thread. No safety concerns.
        let rc = unsafe {
            let mut set = sigset_t::default();
            sigfillset(&raw mut set);
            pthread_sigmask(SIG_BLOCK, &raw const set, ptr::null_mut())
        };
        if rc != 0 {
            bail!("Failed to set main thread signal mask ({rc})")
        }
        Ok(Self(hdl, Some(thr)))
    }
}

impl Drop for SignalHandler {
    fn drop(&mut self) {
        self.0.close();
        (self.1.take().unwrap().join()).expect("Signal thread panicked");
    }
}
