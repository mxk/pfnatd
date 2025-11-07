//! pfnatd daemon.

#![cfg(target_os = "openbsd")]

use crate::pf::Pf;
use crate::pflog::{Interrupt, PcapError, Pflog};
use crate::sys::{SIG_BLOCK, pthread_sigmask, sigfillset, sigset_t};
use clap::{crate_name, crate_version};
use log::info;
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator;
use signal_hook::iterator::Signals;
use signal_hook::low_level::emulate_default_handler;
use std::os::raw::c_int;
use std::thread::JoinHandle;
use std::{ptr, thread};

/// Runs the main pfnatd daemon.
pub fn daemon(logif: u8) -> anyhow::Result<()> {
    info!(concat!(crate_name!(), " v", crate_version!(), " starting"));

    let mut pf = Pf::open(logif)?;
    let mut pflog = Pflog::open(logif)?;

    let (sig_handle, sig_thread) = signal_setup(TERM_SIGNALS, pflog.interrupt())?;

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

// Configures signal handling for graceful termination. A dedicated thread is
// used to avoid interrupting syscalls from the main thread. Only the first
// received signal is handled gracefully. Any additional signals will use the
// default handlers.
fn signal_setup(
    sigs: &[c_int],
    intr: Interrupt,
) -> anyhow::Result<(iterator::Handle, JoinHandle<()>)> {
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
