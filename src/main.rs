#![expect(missing_docs)]

use crate::pf::Pf;
use crate::pflog::{Interrupt, PcapError, Pflog};
use crate::sys::{SIG_BLOCK, pthread_sigmask, sigfillset, sigset_t};
use anyhow::Result;
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator;
use signal_hook::iterator::Signals;
use signal_hook::low_level::emulate_default_handler;
use std::os::raw::c_int;
use std::thread::JoinHandle;
use std::{ptr, thread};

mod pf;
mod pflog;
mod sys;

fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info) // TODO: Reset to Warn
        .parse_default_env()
        .init();

    let mut pf = Pf::open()?;
    pf.init()?;
    let mut pflog = Pflog::open("pflog0")?;

    let (sig_handle, sig_thread) = signal_setup(TERM_SIGNALS, pflog.interrupt())?;

    let e = loop {
        let p = match pflog.next() {
            Err(e) => break e,
            Ok(p) => p,
        };
        pf.expire_rules()?; // TODO: Run more frequently?
        if let Some(stun) = p.stun_nat() {
            pf.add_stun(stun)?;
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

    // SAFETY: Masking all signals for the main thread. No safety concerns.
    let rc = unsafe {
        let mut set = sigset_t::default();
        sigfillset(&raw mut set);
        pthread_sigmask(SIG_BLOCK, &raw const set, ptr::null_mut())
    };
    assert_eq!(rc, 0, "pthread_sigmask failed");
    Ok((sig_handle, sig_thread))
}
