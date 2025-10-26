use crate::pflog::StunNat;
use crate::sys::*;
use anyhow::{Context as _, Result, bail};
use std::convert::Into as _;
use std::ffi::CStr;
use std::fs::File;
use std::{fs, io};

/// Read-write handle to `/dev/pf`.
#[derive(Debug)]
pub struct Pf {
    dev: File,
    _state: Vec<PfStunRule>,
}

impl Pf {
    const ANCHOR: &'static CStr = c"pfnatd";

    /// Opens `/dev/pf` for read-write access and checks packet filter status.
    pub fn open() -> Result<Self> {
        let dev = (fs::OpenOptions::new().read(true).write(true))
            .open("/dev/pf")
            .context("Failed to open /dev/pf")?;
        let this = Self {
            dev,
            _state: Vec::new(),
        };
        if this.status()?.running == 0 {
            bail!("pf is disabled");
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

    /// Returns pf status.
    #[inline]
    fn status(&self) -> io::Result<pf_status> {
        self.dev.ioctlr(DIOCGETSTATUS)
    }
}

#[derive(Debug)]
struct PfStunRule {
    _stun: StunNat,
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
        (dev.ioctl(DIOCGETRULES, &raw mut this.pr).map(|()| this)).context("Failed to get pf rules")
    }

    /// Returns the next rule and its anchor name, if any, or [`None`] if no
    /// more rules are available.
    fn next(&mut self) -> Result<Option<(&CStr, &pf_rule)>> {
        match self.dev.ioctl(DIOCGETRULE, &raw mut self.pr) {
            Ok(()) => Ok(Some((cstr(&self.pr.anchor_call), &self.pr.rule))),
            Err(e) if e.raw_os_error() == Some(ENOENT) => Ok(None),
            Err(e) => Err(e).context("Failed to get next pf rule"),
        }
    }
}

impl Drop for PfRules<'_> {
    fn drop(&mut self) {
        if self.pr.ticket != 0 {
            (self.dev.ioctl(DIOCXEND, &raw const self.pr.ticket))
                .expect("Failed to release pf rules list ticket");
        }
    }
}
