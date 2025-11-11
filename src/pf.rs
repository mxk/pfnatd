//! [pf(4)] rule management interface.
//!
//! [pf(4)]: https://man.openbsd.org/pf.4

#![cfg(target_os = "openbsd")]

use crate::pflog::StunNat;
use crate::sys::*;
use anyhow::{Context as _, Result, bail};
use log::{debug, error, info, warn};
use std::ffi::CStr;
use std::fmt::{Debug, Display, Formatter};
use std::fs::File;
use std::mem::ManuallyDrop;
use std::net::SocketAddr;
use std::os::raw::{c_char, c_ulong};
use std::time::{Duration, Instant};
use std::{fmt, fs, io};

/// pf(4) rule management interface.
pub struct Pf {
    dev: File,                 // Read-write handle to /dev/pf
    logif: u8,                 // pflog interface unit
    ruleset: Vec<NatRule>,     // Active NAT rules
    states: Vec<pfsync_state>, // pf state buffer
    next_expire: Instant,      // Minimum expiration in ruleset
}

impl Pf {
    const ANCHOR: &'static CStr = c"pfnatd";

    /// Opens `/dev/pf` for read-write access and configures the ruleset.
    pub fn open(logif: u8) -> Result<Self> {
        let dev = (fs::OpenOptions::new().read(true).write(true))
            .open("/dev/pf")
            .context("Failed to open /dev/pf")?;
        let mut this = Self {
            dev,
            logif,
            ruleset: Vec::new(),
            states: Vec::new(),
            next_expire: Instant::now(),
        };

        // Check status
        let mut status = pf_status::default();
        (this.dev.ioctl(DIOCGETSTATUS, &raw mut status)).context("Failed to get pf status")?;
        if status.running == 0 {
            warn!("pf is disabled");
        }

        // Check and configure anchor
        let mut rules = Rules::list(&this.dev, c"")?;
        while let Some((anchor, r)) = rules.next()? {
            if anchor != Self::ANCHOR {
                continue;
            }
            if !matches!(r.direction, PF_INOUT | PF_OUT) {
                bail! {"{:?} anchor has wrong direction", Self::ANCHOR}
            }
            drop(rules);
            this.restore()?;
            this.apply()?;
            return Ok(this);
        }
        bail! {"{:?} anchor not found", Self::ANCHOR}
    }

    /// Adds a NAT rule for the specified STUN request.
    pub fn add_nat(&mut self, s: &StunNat) -> Result<()> {
        if let Some(r) = (self.ruleset.iter()).find(|r| r.ifname == s.ifname && r.src == s.src) {
            if r.nat != s.nat {
                warn!("Killing states for duplicate translation: {r} -> {}", s.nat);
                self.kill(s)?;
            }
            return Ok(());
        }

        let r = NatRule {
            ifname: s.ifname,
            src: s.src,
            nat: s.nat,
            expire: self.next_expire,
        };
        let mut pr = pfioc_rule {
            anchor: carray(Self::ANCHOR),
            rule: pf_rule::default(),
            ..Default::default()
        };
        r.pf_rule(&mut pr.rule);
        info!("Adding rule: {r}");

        // DIOCCHANGERULE returns EINVAL if the ruleset is modified between
        // PF_CHANGE_GET_TICKET and PF_CHANGE_ADD_TAIL calls. This loop
        // implements retry logic where the error is only returned after
        // PF_CHANGE_GET_TICKET generates two sequential tickets, indicating an
        // error due to something other than external modification.
        let mut tries = 0;
        loop {
            let old_ticket = pr.ticket;
            pr.action = PF_CHANGE_GET_TICKET;
            (self.dev.ioctl(DIOCCHANGERULE, &raw mut pr))
                .context("Failed to get ticket for appending pf rule")?;
            if tries > 0 && pr.ticket == old_ticket.wrapping_add(1) {
                break Err(io::Error::from_raw_os_error(EINVAL));
            }

            tries += 1;
            pr.action = PF_CHANGE_ADD_TAIL;
            match self.dev.ioctl(DIOCCHANGERULE, &raw mut pr) {
                Ok(()) => {
                    self.ruleset.push(r);
                    return Ok(());
                }
                Err(e) if e.raw_os_error() == Some(EINVAL) && tries < 3 => {}
                Err(e) => break Err(e),
            }
        }
        .context("Failed to append pf rule")
    }

    /// Removes all rules that do not match any states.
    pub fn expire_rules(&mut self) -> Result<()> {
        let now = Instant::now();
        if self.ruleset.is_empty() || now < self.next_expire {
            return Ok(());
        }

        // Run at least once every minute to detect external state changes
        self.next_expire = now + Duration::from_secs(60);
        self.load_states()?;
        debug!(
            "Checking {} rules against {} states for expiration",
            self.ruleset.len(),
            self.states.len()
        );

        // Mark all rules as expired unless a matching state is found
        for r in &mut self.ruleset {
            r.expire = now;
        }
        for s in self.states.iter().filter(|s| NatRule::could_match(s)) {
            if let Some(r) = self.ruleset.iter_mut().find(|r| r.matches(s)) {
                let secs = Duration::from_secs(u32::from_be(s.expire).into());
                // The extra second avoids a race with state expiration
                r.expire = r.expire.max(now + secs + Duration::from_secs(1));
            }
        }

        // Remove expired states and apply the changes, if any
        let n = self.ruleset.len();
        self.ruleset.retain(|r| {
            if r.expire <= now {
                info!("Removing rule: {r}");
                false
            } else {
                self.next_expire = self.next_expire.min(r.expire);
                true
            }
        });
        if self.ruleset.len() != n {
            self.apply()?;
        }
        Ok(())
    }

    /// Restores state from pf rules.
    fn restore(&mut self) -> Result<()> {
        self.ruleset.clear();
        let mut rules = Rules::list(&self.dev, Self::ANCHOR)?;
        while let Some((_, pr)) = rules.next()? {
            if let Some(r) = NatRule::try_restore(pr, self.next_expire) {
                info!("Restoring rule: {r}");
                self.ruleset.push(r);
            }
        }
        Ok(())
    }

    /// Rebuilds and activates the complete ruleset.
    fn apply(&self) -> Result<()> {
        let mut tries = 0;
        loop {
            tries += 1;
            debug!("Rebuilding ruleset with {} rules", self.ruleset.len());
            let mut tx = Tx::begin(&self.dev, Self::ANCHOR)
                .context("Failed to create ruleset update transaction")?;
            tx.add_rule(|r| {
                r.action = PF_MATCH;
                r.direction = PF_OUT;
                r.log = PF_LOG_MATCHES;
                r.logif = self.logif;
                r.proto = IPPROTO_UDP;
            })
            .context("Failed to add log rule to the ruleset")?;
            for r in &self.ruleset {
                tx.add_rule(|pr| r.pf_rule(pr))
                    .context("Failed to add nat-to rule to ruleset")?;
            }
            match tx.commit() {
                Err(e) if e.raw_os_error() == Some(EBUSY) && tries < 3 => {
                    warn!("Ruleset was modified externally (retrying)");
                }
                r => return r.context("Failed to commit ruleset update transaction"),
            }
        }
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
                if n < self.states.capacity() / 4 {
                    self.states.shrink_to(self.states.capacity() / 2);
                }
                return Ok(());
            }
            self.states.reserve(n + n / 2);
        }
    }

    /// Kills all states for the specified STUN request.
    fn kill(&self, s: &StunNat) -> Result<()> {
        let mut k = pfioc_state_kill {
            psk_proto: IPPROTO_UDP.into(),
            psk_src: pf_rule_addr::from(s.src),
            psk_dst: pf_rule_addr::from(s.dst),
            ..Default::default()
        };
        // DIOCKILLSTATES had a bug in the fast path that prevented it from
        // finding matching states:
        // <https://marc.info/?l=openbsd-bugs&m=176209866016448&w=2>
        // TODO: Determine actual fix revision
        #[expect(clippy::unreadable_literal)]
        if *OS_REV > 202510 {
            k.psk_af = sa_family(s.src.ip());
        }
        (self.dev.ioctl(DIOCKILLSTATES, &raw mut k))
            .with_context(|| format!("Failed to kill state: {} -> {}", s.src, s.dst))?;
        debug!("Killed {} states: {} -> {}", k.psk_killed, s.src, s.dst);
        Ok(())
    }
}

/// Active NAT rule.
#[derive(Debug)]
struct NatRule {
    ifname: [c_char; IFNAMSIZ],
    src: SocketAddr,
    nat: SocketAddr,
    expire: Instant,
}

impl NatRule {
    const TAG: [c_char; PF_TAG_NAME_SIZE] = carray(c"PFNATD");

    /// Tries to restore `NatRule` from `pf_rule`.
    fn try_restore(r: &pf_rule, expire: Instant) -> Option<Self> {
        if r.action == PF_MATCH
            && r.direction == PF_OUT
            && r.ifname[0] != 0
            && r.proto == IPPROTO_UDP
            && r.tagname == Self::TAG
            && let Some(src) = r.src.try_to_sock(r.af)
            && let Some(nat) = r.nat.try_to_sock(r.af)
        {
            return Some(Self {
                ifname: r.ifname,
                src,
                nat,
                expire,
            });
        }
        None
    }

    /// Creates pf nat-to rule from STUN NAT parameters.
    #[inline]
    fn pf_rule(&self, r: &mut pf_rule) {
        r.action = PF_MATCH;
        r.direction = PF_OUT;
        r.ifname = self.ifname;
        r.af = sa_family(self.src.ip());
        r.proto = IPPROTO_UDP;
        r.src = pf_rule_addr::from(self.src);
        r.nat = pf_pool::from(self.nat);
        r.tagname = Self::TAG;
    }

    /// Returns whether state `s` could potentially match one of the rules.
    #[inline]
    #[must_use]
    const fn could_match(s: &pfsync_state) -> bool {
        s.direction == PF_OUT
            && s.proto == IPPROTO_UDP
            && s.key[0].af == s.key[1].af
            && s.expire != 0
    }

    /// Returns whether state `s` matches the rule.
    #[inline]
    #[must_use]
    fn matches(&self, s: &pfsync_state) -> bool {
        const SK: usize = PF_SK_STACK;
        const NK: usize = PF_SK_WIRE;
        Self::could_match(s)
            && (s.ifname == carray(c"all") || s.ifname == self.ifname)
            && self.src == s.key[SK].addr[1].to_sock(s.key[SK].af, s.key[SK].port[1])
            && self.nat == s.key[NK].addr[1].to_sock(s.key[NK].af, s.key[NK].port[1])
    }
}

impl Display for NatRule {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let ifname = cstr(&self.ifname).to_string_lossy();
        let (src, nat) = (self.src, self.nat);
        write!(f, "out on {ifname} from {src} nat-to {nat}")
    }
}

/// Iterator over all rules in the active ruleset.
#[derive(Debug)]
struct Rules<'a> {
    dev: &'a File,
    pr: pfioc_rule,
}

impl<'a> Rules<'a> {
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

impl Drop for Rules<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.dev.ioctl(DIOCXEND, &raw mut self.pr.ticket) {
            error!("Failed to release pf rules list ticket ({e})");
        }
    }
}

/// Ruleset update transaction.
struct Tx<'a> {
    dev: &'a File,
    e: pfioc_trans_e,
    r: pfioc_rule,
}

impl<'a> Tx<'a> {
    /// Creates a new ruleset update transaction.
    fn begin(dev: &'a File, anchor: &CStr) -> io::Result<Self> {
        let mut e = pfioc_trans_e {
            type_: PF_TRANS_RULESET,
            anchor: carray(anchor),
            ..Default::default()
        };
        Self::ioctl(dev, DIOCXBEGIN, &mut e)?;
        let r = pfioc_rule {
            ticket: e.ticket,
            anchor: e.anchor,
            ..pfioc_rule::default()
        };
        Ok(Self { dev, e, r })
    }

    /// Adds a rule to the end of the ruleset.
    fn add_rule(&mut self, r: impl FnOnce(&mut pf_rule)) -> io::Result<()> {
        self.r.rule = pf_rule::default();
        r(&mut self.r.rule);
        self.dev.ioctl(DIOCADDRULE, &raw mut self.r)
    }

    /// Commits any changes.
    fn commit(self) -> io::Result<()> {
        let mut this = ManuallyDrop::new(self);
        Self::ioctl(this.dev, DIOCXCOMMIT, &mut this.e)
    }

    /// Executes an ioctl that takes a `pfioc_trans` argument.
    fn ioctl(dev: &File, req: c_ulong, e: &mut pfioc_trans_e) -> io::Result<()> {
        let mut tx = pfioc_trans {
            size: 1,
            esize: size_of_val(e).try_into().unwrap(),
            array: &raw mut *e,
        };
        dev.ioctl(req, &raw mut tx)
    }
}

impl Drop for Tx<'_> {
    fn drop(&mut self) {
        if let Err(e) = Self::ioctl(self.dev, DIOCXROLLBACK, &mut self.e) {
            error!("Failed to roll back ruleset update transaction ({e})");
        }
    }
}
