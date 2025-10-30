use crate::pflog::StunNat;
use crate::sys::*;
use anyhow::{Context as _, Result, bail};
use log::debug;
use std::ffi::CStr;
use std::fs::File;
use std::mem::ManuallyDrop;
use std::{fmt, fs};

/// Read-write handle to `/dev/pf`.
pub struct Pf {
    dev: File,
    status: pf_status,
    state: pfioc_state,
    state_buf: Vec<pfsync_state>,
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
            status: pf_status::default(),
            state: pfioc_state::default(),
            state_buf: Vec::new(),
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
        let mut tx = PfTx::begin(&self.dev, Self::ANCHOR)?;
        tx.add_rule(|r| {
            r.action = PF_MATCH;
            r.direction = PF_OUT;
            r.log = PF_LOG_MATCHES;
            r.ifname = carray(c"egress");
            r.proto = IPPROTO_UDP;
            r.dst.port_op = PF_OP_EQ;
            r.dst.port = [3478_u16.to_be(), 0];
        })?;
        tx.commit()
    }

    /// Adds a NAT rule for the specified STUN request.
    pub fn add_stun(&mut self, s: StunNat) -> Result<()> {
        debug!("Adding {s}");
        debug!("Matching state ID {:?}", self.match_state(s, true));
        // TODO: Implement
        Ok(())
    }

    /// Returns pf status.
    #[inline]
    fn status(&mut self) -> Result<&pf_status> {
        (self.dev.ioctl(DIOCGETSTATUS, &raw mut self.status)).context("Failed to get pf status")?;
        Ok(&self.status)
    }

    /// Appends a rule to the anchor ruleset.
    fn append_rule(&self, r: &pf_rule) -> Result<()> {
        let mut pcr = pfioc_rule {
            action: PF_CHANGE_GET_TICKET,
            anchor: carray(Self::ANCHOR),
            rule: *r,
            ..Default::default()
        };
        (self.dev.ioctl(DIOCCHANGERULE, &raw mut pcr))
            .context("Failed to get ticket for appending pf rule")?;
        pcr.action = PF_CHANGE_ADD_TAIL;
        (self.dev.ioctl(DIOCCHANGERULE, &raw mut pcr)).context("Failed to append pf rule")
    }

    /// Returns the ID of a state matching STUN NAT, if any.
    fn match_state(&mut self, stun: StunNat, recent: bool) -> Result<Option<PfStateId>> {
        if recent {
            let id = self.status()?.into();
            if self.state_by_id(id).is_some_and(|s| stun.matches(s)) {
                return Ok(Some(id));
            }
        }
        Ok(self
            .all_states()?
            .iter()
            .find_map(|ps| stun.matches(ps).then(|| PfStateId::from(ps))))
    }

    /// Returns a single state by id.
    fn state_by_id(&mut self, id: PfStateId) -> Option<&pfsync_state> {
        self.state.state.id = id.id.to_be();
        self.state.state.creatorid = id.creatorid.to_be();
        (self.dev.ioctl(DIOCGETSTATE, &raw mut self.state).ok()).map(|()| &self.state.state)
    }

    /// Returns all pf states.
    fn all_states(&mut self) -> Result<&[pfsync_state]> {
        self.state_buf.clear();
        loop {
            let mut ps = pfioc_states {
                ps_len: self.state_buf.capacity() * size_of::<pfsync_state>(),
                ps_u: pfioc_states__bindgen_ty_1 {
                    psu_states: self.state_buf.as_mut_ptr(),
                },
            };
            (self.dev.ioctl(DIOCGETSTATES, &raw mut ps)).context("Failed to get pf states")?;
            let n = ps.ps_len / size_of::<pfsync_state>();
            if n <= self.state_buf.capacity() {
                // SAFETY: have n initialized states.
                unsafe { self.state_buf.set_len(n) };
                return Ok(self.state_buf.as_slice());
            }
            self.state_buf.reserve(n + (n >> 1));
        }
    }
}

/// Active NAT rule.
#[derive(Debug)]
struct PfNatRule {
    _stun: StunNat,
}

/// Unique state ID.
#[derive(Clone, Copy)]
struct PfStateId {
    id: u64,
    creatorid: u32,
}

impl From<&pfsync_state> for PfStateId {
    #[inline]
    fn from(ps: &pfsync_state) -> Self {
        Self {
            id: u64::from_be(ps.id),
            creatorid: u32::from_be(ps.creatorid),
        }
    }
}

impl From<&pf_status> for PfStateId {
    #[inline]
    fn from(ps: &pf_status) -> Self {
        Self {
            id: ps.stateid - 1,
            creatorid: u32::from_be(ps.hostid),
        }
    }
}

impl fmt::Debug for PfStateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (id, creatorid) = (self.id, self.creatorid);
        write!(f, "PfStateId {{ id: {id:x?}, creatorid: {creatorid:x?} }}")
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
    fn list(dev: &'a File, anchor: impl AsRef<CStr>) -> Result<Self> {
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
    fn begin(dev: &'a File, anchor: impl AsRef<CStr>) -> Result<Self> {
        let mut e = pfioc_trans_e {
            type_: PF_TRANS_RULESET,
            anchor: carray(anchor),
            ..pfioc_trans_e::default()
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
