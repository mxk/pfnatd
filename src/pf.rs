use crate::pflog::StunNat;
use crate::sys::*;
use anyhow::{Context as _, Result, bail};
use log::{debug, info, warn};
use std::ffi::CStr;
use std::fmt::Debug;
use std::fs;
use std::fs::File;
use std::mem::ManuallyDrop;
use std::os::raw::c_char;
use std::time::{Duration, Instant};

/// Read-write handle to `/dev/pf`.
pub struct Pf {
    dev: File,
    ruleset: Vec<PfNatRule>,
    states: Vec<pfsync_state>,
    status: pf_status,
}

impl Pf {
    const ANCHOR: &'static CStr = c"pfnatd";

    /// Opens `/dev/pf` for read-write access and checks packet filter status.
    pub fn open() -> Result<Self> {
        let dev = (fs::OpenOptions::new().read(true).write(true))
            .open("/dev/pf")
            .context("Failed to open /dev/pf")?;
        let mut this = Self {
            dev,
            ruleset: Vec::new(),
            states: Vec::new(),
            status: pf_status::default(),
        };
        if this.status()?.running == 0 {
            warn!("pf is disabled");
        }

        // Check anchor
        let mut prs = PfRules::list(&this.dev, c"")?;
        while let Some((anchor, r)) = prs.next()? {
            if anchor != Self::ANCHOR {
                continue;
            }
            if !matches!(r.direction, PF_INOUT | PF_OUT) {
                bail! {"{:?} anchor has wrong direction", Self::ANCHOR}
            }
            drop(prs);
            return Ok(this);
        }
        bail! {"{:?} anchor not found", Self::ANCHOR}
    }

    /// Initializes anchor rules.
    pub fn init(&self) -> Result<()> {
        // TODO: Restore state
        self.rebuild()
    }

    /// Adds a NAT rule for the specified STUN request.
    pub fn add_stun(&mut self, s: StunNat) -> Result<()> {
        for r in &self.ruleset {
            if s.ifname != r.stun.ifname || s.src != r.stun.src {
                continue;
            }
            if s.nat != r.stun.nat {
                warn!("Inconsistent translation for {} -> {}", r.stun, s.nat);
                // TODO: Kill state?
            }
            return Ok(());
        }
        info!("Adding rule: {s}");
        let nat = PfNatRule {
            stun: s,
            expire: Instant::now() + Duration::from_secs(30),
        };
        let mut r = pf_rule::default();
        nat.pf_rule(&mut r);
        self.add_rule(&r)?;
        self.ruleset.push(nat);
        Ok(())
    }

    /// Removes any expired NAT rules.
    pub fn expire_rules(&mut self) -> Result<()> {
        let now = Instant::now();
        if self.ruleset.iter().all(|r| now < r.expire) {
            return Ok(());
        }
        self.load_states()?;
        for r in self.ruleset.iter_mut().filter(|r| r.expire <= now) {
            for s in self.states.iter().filter(|&s| r.stun.matches(s)) {
                let d = Duration::from_secs(u32::from_be(s.expire).into());
                r.expire = r.expire.max(now + d);
            }
        }
        if (self.ruleset.extract_if(.., |nat| nat.expire <= now))
            .inspect(|nat| info!("Removing expired rule: {}", nat.stun))
            .count()
            != 0
        {
            self.rebuild()?;
        }
        Ok(())
    }

    /// Returns pf status.
    #[inline]
    fn status(&mut self) -> Result<&pf_status> {
        (self.dev.ioctl(DIOCGETSTATUS, &raw mut self.status)).context("Failed to get pf status")?;
        Ok(&self.status)
    }

    /// Appends a rule to the anchor ruleset.
    fn add_rule(&self, r: &pf_rule) -> Result<()> {
        let mut pcr = pfioc_rule {
            action: PF_CHANGE_GET_TICKET,
            anchor: carray(Self::ANCHOR),
            rule: *r,
            ..Default::default()
        };
        (self.dev.ioctl(DIOCCHANGERULE, &raw mut pcr))
            .context("Failed to get ticket for appending pf rule")?;
        pcr.action = PF_CHANGE_ADD_TAIL;
        (self.dev.ioctl(DIOCCHANGERULE, &raw mut pcr)).context("Failed to append pf rule")?;
        Ok(())
    }

    fn rebuild(&self) -> Result<()> {
        debug!("Rebuilding ruleset with {} rule(s)", self.ruleset.len());
        let mut tx = PfTx::begin(&self.dev, Self::ANCHOR)?;
        tx.add_rule(|r| {
            r.action = PF_MATCH;
            r.direction = PF_OUT;
            r.log = PF_LOG_MATCHES;
            r.proto = IPPROTO_UDP;
            r.dst.port = [3478_u16.to_be(), 0];
            r.dst.port_op = PF_OP_EQ;
        })?;
        for nat in &self.ruleset {
            tx.add_rule(|r| nat.pf_rule(r))?;
        }
        tx.commit()
    }

    /// Loads all pf states into `state_buf`.
    fn load_states(&mut self) -> Result<()> {
        self.states.clear();
        loop {
            let mut ps = pfioc_states {
                ps_len: self.states.capacity() * size_of::<pfsync_state>(),
                ps_u: pfioc_states__bindgen_ty_1 {
                    psu_states: self.states.as_mut_ptr(),
                },
            };
            (self.dev.ioctl(DIOCGETSTATES, &raw mut ps)).context("Failed to get pf states")?;
            let n = ps.ps_len / size_of::<pfsync_state>();
            if n <= self.states.capacity() {
                // SAFETY: have n initialized states.
                unsafe { self.states.set_len(n) };
                return Ok(());
            }
            self.states.reserve(n + (n >> 1));
        }
    }
}

/// Active NAT rule.
#[derive(Debug)]
struct PfNatRule {
    stun: StunNat,
    expire: Instant,
}

impl PfNatRule {
    const TAG: [c_char; PF_TAG_NAME_SIZE] = carray(c"PFNATD");

    /// Creates pf nat-to rule from STUN NAT parameters.
    #[inline]
    fn pf_rule(&self, r: &mut pf_rule) {
        r.action = PF_MATCH;
        r.direction = PF_OUT;
        r.ifname = self.stun.ifname;
        r.af = sa_family(self.stun.src.ip());
        r.proto = IPPROTO_UDP;
        r.src = pf_rule_addr::from(self.stun.src);
        r.nat = pf_pool::from(self.stun.nat);
        r.tagname = Self::TAG;
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
    fn list(dev: &'a File, anchor: &CStr) -> Result<Self> {
        let mut pr = pfioc_rule {
            anchor: carray(anchor),
            ..pfioc_rule::default()
        };
        dev.ioctl(DIOCGETRULES, &raw mut pr)
            .context("Failed to get pf rules")?;
        Ok(Self { dev, pr })
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
        (self.dev.ioctl(DIOCXEND, &raw mut self.pr.ticket))
            .expect("Failed to release pf rules list ticket");
    }
}

/// Ruleset update transaction.
struct PfTx<'a> {
    dev: &'a File,
    e: pfioc_trans_e,
    r: pfioc_rule,
}

impl<'a> PfTx<'a> {
    /// Starts a new ruleset update transaction.
    fn begin(dev: &'a File, anchor: &CStr) -> Result<Self> {
        let mut e = pfioc_trans_e {
            type_: PF_TRANS_RULESET,
            anchor: carray(anchor),
            ..Default::default()
        };
        let mut tx = Self::trans(&mut e);
        dev.ioctl(DIOCXBEGIN, &raw mut tx)
            .context("Failed to start ruleset update transaction")?;
        let r = pfioc_rule {
            ticket: e.ticket,
            anchor: e.anchor,
            ..pfioc_rule::default()
        };
        Ok(Self { dev, e, r })
    }

    /// Adds a rule to the end of the ruleset.
    fn add_rule(&mut self, r: impl FnOnce(&mut pf_rule)) -> Result<()> {
        self.r.rule = pf_rule::default();
        r(&mut self.r.rule);
        (self.dev.ioctl(DIOCADDRULE, &raw mut self.r)).context("Failed to add rule to ruleset")
    }

    /// Commits any changes.
    fn commit(self) -> Result<()> {
        let mut this = ManuallyDrop::new(self);
        let mut tx = Self::trans(&mut this.e);
        (this.dev.ioctl(DIOCXCOMMIT, &raw mut tx))
            .context("Failed to commit ruleset update transaction")
    }

    /// Returns a `pfioc_trans` for `e`.
    fn trans(e: &mut pfioc_trans_e) -> pfioc_trans {
        pfioc_trans {
            size: 1,
            esize: size_of_val(e).try_into().unwrap(),
            array: &raw mut *e,
        }
    }
}

impl Drop for PfTx<'_> {
    fn drop(&mut self) {
        let mut tx = Self::trans(&mut self.e);
        (self.dev.ioctl(DIOCXROLLBACK, &raw mut tx))
            .expect("Failed to rollback ruleset update transaction");
    }
}
