use crate::sys::*;
use anyhow::{Result, bail};
use libc::*;
use log::warn;
use std::convert::Into;
use std::ffi::CStr;
use std::io;
use std::marker::PhantomData;

/// Read-write handle to `/dev/pf`.
#[derive(Debug)]
pub struct Pf {
    dev: c_int,
}

impl Pf {
    const ANCHOR: &'static CStr = c"pfnatd";

    /// Opens `/dev/pf` for read-write access and checks packet filter status.
    pub fn open() -> Result<Self> {
        let this = {
            // SAFETY: safe C call.
            let dev = unsafe { open(c"/dev/pf".as_ptr(), O_RDWR) };
            if dev < 0 {
                return errno("Failed to open /dev/pf");
            }
            Self { dev }
        };

        // Check if pf is enabled
        let mut status = pf_status::default();
        // SAFETY: this.dev and status are valid.
        if unsafe { ioctl(this.dev, DIOCGETSTATUS.into(), &raw mut status) } < 0 {
            return errno("Failed to get pf status");
        }
        if status.running == 0 {
            warn!("pf is disabled");
        }

        // Check anchor
        let mut prs = PfRules::list(this.dev, c"")?;
        while let Some((anchor, r)) = prs.next()? {
            if anchor != Self::ANCHOR {
                continue;
            }
            if !matches!(r.direction.into(), PF_INOUT | PF_OUT) {
                bail! {"{:?} anchor has wrong direction", Self::ANCHOR}
            }
            return Ok(this);
        }
        bail! {"{:?} anchor not found", Self::ANCHOR}
    }
}

impl Drop for Pf {
    fn drop(&mut self) {
        // SAFETY: self.fd is valid.
        unsafe { close(self.dev) };
    }
}

/// Iterator over all rules in the active ruleset.
struct PfRules<'a> {
    dev: c_int,
    pr: pfioc_rule,
    _lifetime: PhantomData<&'a ()>,
}

impl PfRules<'_> {
    /// Creates a new rule iterator.
    fn list<T: AsRef<CStr>>(dev: c_int, anchor: T) -> Result<Self> {
        let mut this = Self {
            dev,
            pr: pfioc_rule::default(),
            _lifetime: PhantomData,
        };
        cstrcpy(&raw mut this.pr.anchor, anchor);
        // SAFETY: valid ioctl.
        if unsafe { ioctl(dev, DIOCGETRULES.into(), &raw mut this.pr) } < 0 {
            return errno("Failed to get pf rules");
        }
        Ok(this)
    }

    /// Returns the next rule or [`None`] after the last rule.
    fn next(&mut self) -> Result<Option<(&CStr, &pf_rule)>> {
        // SAFETY: valid ioctl.
        if unsafe { ioctl(self.dev, DIOCGETRULE.into(), &raw mut self.pr) } < 0 {
            return match io::Error::last_os_error().raw_os_error() {
                Some(ENOENT) => Ok(None),
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
                unsafe { ioctl(self.dev, DIOCXEND.into(), &raw const self.pr.ticket) },
                -1,
                "DIOCXEND ioctl failed"
            );
        }
    }
}
