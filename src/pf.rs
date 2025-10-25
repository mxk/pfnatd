use crate::sys::*;
use anyhow::{Context as _, Result, bail};
use log::warn;
use std::convert::Into as _;
use std::ffi::CStr;
use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::{fs, io};

/// Read-write handle to `/dev/pf`.
#[derive(Debug)]
pub struct Pf {
    dev: File,
}

impl Pf {
    const ANCHOR: &'static CStr = c"pfnatd";

    /// Opens `/dev/pf` for read-write access and checks packet filter status.
    pub fn open() -> Result<Self> {
        let dev = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/pf")
            .context("Failed to open /dev/pf")?;
        let this = Self { dev };

        // Check if pf is enabled
        let mut status = pf_status::default();
        // SAFETY: this.dev and status are valid.
        if unsafe { ioctl(this.dev.as_raw_fd(), DIOCGETSTATUS, &raw mut status) } < 0 {
            return errno("Failed to get pf status");
        }
        if status.running == 0 {
            warn!("pf is disabled");
        }

        // Check anchor
        let mut prs = PfRules::list(&this.dev, c"")?;
        while let Some((anchor, r)) = prs.next()? {
            if anchor != Self::ANCHOR {
                continue;
            }
            if !matches!(r.direction.into(), PF_INOUT | PF_OUT) {
                bail! {"{:?} anchor has wrong direction", Self::ANCHOR}
            }
            drop(prs);
            return Ok(this);
        }
        bail! {"{:?} anchor not found", Self::ANCHOR}
    }
}

/// Iterator over all rules in the active ruleset.
#[derive(Debug)]
struct PfRules<'a> {
    dev: &'a File,
    pr: pfioc_rule,
}

impl<'a> PfRules<'a> {
    /// Creates a new rule iterator.
    fn list<T: AsRef<CStr>>(dev: &'a File, anchor: T) -> Result<Self> {
        let mut this = Self {
            dev,
            pr: pfioc_rule::default(),
        };
        cstrcpy(&raw mut this.pr.anchor, anchor);
        // SAFETY: valid ioctl.
        if unsafe { ioctl(dev.as_raw_fd(), DIOCGETRULES, &raw mut this.pr) } < 0 {
            return errno("Failed to get pf rules");
        }
        Ok(this)
    }

    /// Returns the next rule or [`None`] after the last rule.
    fn next(&mut self) -> Result<Option<(&CStr, &pf_rule)>> {
        // SAFETY: valid ioctl.
        if unsafe { ioctl(self.dev.as_raw_fd(), DIOCGETRULE, &raw mut self.pr) } < 0 {
            return match io::Error::last_os_error().kind() {
                io::ErrorKind::NotFound => Ok(None),
                _ => errno("Failed to get next pf rule"),
            };
        }
        Ok(Some((cstr(&self.pr.anchor_call), &self.pr.rule)))
    }
}

impl Drop for PfRules<'_> {
    fn drop(&mut self) {
        if self.pr.ticket != 0 {
            assert_ne!(
                // SAFETY: self.dev and self.pr.ticket are valid.
                unsafe { ioctl(self.dev.as_raw_fd(), DIOCXEND, &raw const self.pr.ticket) },
                -1,
                "DIOCXEND ioctl failed"
            );
        }
    }
}
