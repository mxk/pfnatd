use crate::sys::*;
use anyhow::{Context, bail};
use libc::*;
use log::warn;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt::Display;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{Arc, Mutex, PoisonError};
use std::{fmt, mem, ptr};

const _: () = assert!(
    size_of::<pfloghdr>() == PFLOG_HDRLEN as usize,
    "size of pfloghdr != PFLOG_HDRLEN"
);

/// Pcap pflog interface.
#[derive(Debug)]
pub struct Pflog {
    iface: String,               // Interface name
    p: *mut pcap_t,              // Valid pcap handle
    mu: Arc<Mutex<*mut pcap_t>>, // Same as p, but used for PflogInterrupt
}

unsafe impl Send for Pflog {}

impl Pflog {
    /// Number of bytes to capture for each packet.
    const SNAPLEN: c_int =
        (size_of::<pfloghdr>() + size_of::<ip6_hdr>() + size_of::<udphdr>()) as _;

    /// Milliseconds before pcap_next_ex times out without matching packets.
    const TIMEOUT_MS: c_int = 250;

    /// Packet buffer size allocated by the kernel and libpcap. Default is 32K.
    const BUFSIZE: c_int = 65536;

    /// Opens the specified pflog interface and activates packet capture.
    pub fn open<T: AsRef<str>>(iface: T) -> anyhow::Result<Self> {
        let iface = iface.as_ref();
        let this = {
            let mut errbuf = [0; PCAP_ERRBUF_SIZE as _];
            // SAFETY: iface and errbuf are valid.
            let p = unsafe { pcap_create(CString::new(iface)?.as_ptr(), errbuf.as_mut_ptr()) };
            if p.is_null() {
                let status = PCAP_ERROR;
                let err = Some(
                    // SAFETY: errbuf contains a valid error message.
                    unsafe { CStr::from_ptr(errbuf.as_ptr()) }
                        .to_string_lossy()
                        .into_owned(),
                );
                return Err(PcapError { status, err }).context("Failed to create pcap interface");
            };
            Self {
                iface: iface.to_owned(),
                p,
                #[allow(clippy::arc_with_non_send_sync)]
                mu: Arc::new(Mutex::new(p)),
            }
        };

        // SAFETY: this.p is valid and these functions only check that the
        // capture hasn't been activated, so are guaranteed to succeed.
        unsafe {
            assert_eq!(pcap_set_snaplen(this.p, Self::SNAPLEN), 0);
            assert_eq!(pcap_set_promisc(this.p, 1), 0);
            assert_eq!(pcap_set_timeout(this.p, Self::TIMEOUT_MS), 0);
            assert_eq!(pcap_set_immediate_mode(this.p, 1), 0);
            assert_eq!(pcap_set_buffer_size(this.p, Self::BUFSIZE), 0);
        };

        // SAFETY: this.p is valid.
        let status = unsafe { pcap_activate(this.p) };
        if status < 0 {
            return Err(PcapError::new(this.p, status))
                .with_context(|| format!("Failed to start packet capture on {iface}"));
        }

        // SAFETY: this.p is valid.
        if unsafe { pcap_datalink(this.p) } != DLT_PFLOG as _ {
            bail!("Not a pflog interface: {iface}");
        }
        Ok(this)
    }

    pub fn next(&mut self) -> anyhow::Result<PflogPacket> {
        unsafe { pcap_geterr(self.p).write(0) }
        loop {
            let mut hdr: *mut pcap_pkthdr = ptr::null_mut();
            let mut pkt: *const u_char = ptr::null();
            match unsafe { pcap_next_ex(self.p, &raw mut hdr, &raw mut pkt) } {
                0 => continue, // Timeout
                1 => {}
                status => return Err(PcapError::new(self.p, status).into()),
            }
            if hdr.is_null()
                || !hdr.is_aligned()
                || pkt.is_null()
                || pkt.align_offset(align_of::<pfloghdr>()) != 0
            {
                warn!("Invalid pcap packet ({hdr:?} {pkt:?})");
                continue;
            }

            // SAFETY: hdr is valid.
            let hdr = unsafe { &*hdr };
            let mut len = hdr.caplen.try_into().unwrap();
            let Some(pf) = self.next_hdr::<PflogHdr>(&mut pkt, &mut len) else {
                warn!("Pcap packet missing pflog header ({hdr:?})");
                continue;
            };

            let Some(ip) = (match pf.0.naf.into() {
                AF_INET => self.next_hdr(&mut pkt, &mut len).map(IpHdr::V4),
                AF_INET6 => self.next_hdr(&mut pkt, &mut len).map(IpHdr::V6),
                _ => {
                    warn!("Unknown pflog header naf: {}", pf.0.naf);
                    continue;
                }
            }) else {
                warn!("Pflog packet missing IP header ({hdr:?})");
                continue;
            };

            let mut p = PflogPacket { pf, ip, udp: None };
            let Some(off) = p.ip.udp_offset() else {
                return Ok(p);
            };
            match len.checked_sub(off) {
                None => return Ok(p),
                Some(n) => len = n,
            }
            pkt = pkt.wrapping_add(off);
            p.udp = self.next_hdr(&mut pkt, &mut len);
            return Ok(p);
        }
    }

    /// Returns a guard that causes [`Self::next`] to return an error when
    /// dropped.
    pub fn interrupt(&self) -> PflogInterrupt {
        PflogInterrupt(self.mu.clone())
    }

    /// Returns the next `T` in `pkt`, moving `pkt` and decrementing `len` by
    /// `size_of::<T>()`.
    fn next_hdr<T>(&self, pkt: &mut *const u_char, len: &mut usize) -> Option<&T> {
        let align = (*pkt).align_offset(align_of::<T>());
        (*len).checked_sub(align + size_of::<T>()).map(|n| {
            let p = (*pkt).wrapping_add(align);
            *len = n;
            *pkt = p.wrapping_add(size_of::<T>());
            // SAFETY: p is valid for &T.
            unsafe { &*p.cast() }
        })
    }
}

impl Drop for Pflog {
    fn drop(&mut self) {
        let mut g = self.mu.lock().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: self.p is valid.
        unsafe { pcap_close(self.p) }
        *g = ptr::null_mut();
    }
}

impl Display for Pflog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.iface)
    }
}

/// Guard that interrupts [`Pflog::next`] when dropped.
#[derive(Clone, Debug)]
pub struct PflogInterrupt(Arc<Mutex<*mut pcap_t>>);

unsafe impl Send for PflogInterrupt {}

impl Drop for PflogInterrupt {
    fn drop(&mut self) {
        let p = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if !p.is_null() {
            // SAFETY: p is valid.
            unsafe { pcap_breakloop(*p) }
        }
    }
}

/// NAT mapping for a STUN request.
#[derive(Clone, Debug)]
pub struct StunNat {
    src: SocketAddr,
    nat: SocketAddr,
    ifname: [c_char; IFNAMSIZ],
}

impl Display for StunNat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ifname = cstr(&self.ifname).to_string_lossy();
        write!(
            f,
            "STUN out on {ifname} from {} nat-to {}",
            self.src, self.nat
        )
    }
}

/// Packet from the pflog pcap interface.
pub struct PflogPacket<'a> {
    pf: &'a PflogHdr,
    ip: IpHdr<'a>,
    udp: Option<&'a UdpHdr>,
}

impl PflogPacket<'_> {
    /// Returns the NAT mapping if the packet represents a translated STUN
    /// request.
    pub fn stun_nat(&self) -> Option<StunNat> {
        Some(StunNat {
            src: SocketAddr::new(self.ip.src(), self.udp.as_ref()?.src_port()),
            nat: self.pf.stun_nat_addr()?,
            ifname: self.pf.0.ifname,
        })
    }
}

impl Display for PflogPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pf)?;
        let (src, dst) = (self.ip.src(), self.ip.dst());
        match self.udp {
            None => write!(f, " {src} > {dst}"),
            Some(udp) => write!(f, " {src}.{} > {dst}.{}", udp.src_port(), udp.dst_port()),
        }
    }
}

/// Pflog pcap header.
#[repr(transparent)]
struct PflogHdr(pfloghdr);

impl PflogHdr {
    /// Returns the translated source address for a STUN request.
    fn stun_nat_addr(&self) -> Option<SocketAddr> {
        (self.0.af == self.0.naf
            && self.0.action == PF_PASS as _
            && self.0.dir == PF_OUT as _
            && self.0.rewritten != 0
            && u16::from_be(self.0.dport) == 3478)
            .then(|| Self::sock(self.0.naf, self.0.saddr, self.0.sport))
    }

    fn sock(af: crate::sys::sa_family_t, a: pf_addr, port: u_int16_t) -> SocketAddr {
        let port = u16::from_be(port);
        match af.into() {
            // SAFETY: a is an IPv4 address.
            AF_INET => SocketAddr::V4(SocketAddrV4::new(unsafe { a.pfa.v4 }.into(), port)),
            // SAFETY: a is an IPv6 address.
            AF_INET6 => SocketAddr::V6(SocketAddrV6::new(unsafe { a.pfa.v6 }.into(), port, 0, 0)),
            _ => unimplemented!(),
        }
    }
}

impl Display for PflogHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("rule ")?;
        match u32::from_be(self.0.rulenr) {
            u32::MAX => f.write_str("def")?,
            n => {
                write!(f, "{n}")?;
                if self.0.ruleset[0] != 0 {
                    write!(f, ".{}", cstr(&self.0.ruleset).to_string_lossy())?;
                    match u32::from_be(self.0.subrulenr) {
                        u32::MAX => f.write_str(".def")?,
                        n => write!(f, ".{n}")?,
                    };
                }
            }
        };

        let action = match self.0.action.into() {
            PF_MATCH => "match",
            PF_SCRUB => "scrub",
            PF_PASS => "pass",
            PF_DROP => "block",
            PF_NAT | PF_NONAT => "nat",
            PF_BINAT | PF_NOBINAT => "binat",
            PF_RDR | PF_NORDR => "rdr",
            _ => "???",
        };
        let dir = match self.0.dir.into() {
            PF_OUT => "out",
            _ => "in",
        };
        let ifname = cstr(&self.0.ifname).to_string_lossy();
        write!(f, " {action} {dir} on {ifname}:")?;

        if self.0.pid != NO_PID as _ {
            write!(f, " [uid {}, pid {}]", self.0.uid, self.0.pid)?;
        }
        if self.0.rewritten != 0 {
            let src = Self::sock(self.0.naf, self.0.saddr, self.0.sport);
            let dst = Self::sock(self.0.naf, self.0.daddr, self.0.dport);
            write!(f, " [rewritten: src {src}, dst {dst}]")?;
        }
        Ok(())
    }
}

/// IP header after [`pfloghdr`].
enum IpHdr<'a> {
    V4(&'a ip),
    V6(&'a ip6_hdr),
}

impl IpHdr<'_> {
    /// Returns the source address.
    pub fn src(&self) -> IpAddr {
        match self {
            IpHdr::V4(h) => h.ip_src.into(),
            IpHdr::V6(h) => h.ip6_src.into(),
        }
    }

    /// Returns the destination address.
    pub fn dst(&self) -> IpAddr {
        match self {
            IpHdr::V4(h) => h.ip_dst.into(),
            IpHdr::V6(h) => h.ip6_dst.into(),
        }
    }

    /// Returns the offset of the UDP header, if there is one. The offset is
    /// relative to the end of the fixed IP header.
    fn udp_offset(&self) -> Option<usize> {
        match self {
            IpHdr::V4(h) => {
                // SAFETY: __BindgenBitfieldUnit is a [u8; 1] array.
                let ver_ihl: u8 = unsafe { mem::transmute(h._bitfield_1) };
                let hlen = usize::from(ver_ihl & 0xf) * 4; //h._bitfield_1.get(4, 4) as usize * 4;
                (ver_ihl >> 4 == IPVERSION as _
                    && h.ip_p == IPPROTO_UDP as _
                    && u16::from_be(h.ip_off) & 0x1fff == 0
                    && size_of::<ip>() <= hlen
                    && hlen + size_of::<udphdr>() <= u16::from_be(h.ip_len).into())
                .then_some(hlen - size_of::<ip>())
            }
            IpHdr::V6(_) => unimplemented!(),
        }
    }
}

/// UDP header.
#[derive(Debug)]
#[repr(transparent)]
struct UdpHdr(udphdr);

impl UdpHdr {
    /// Returns the source port.
    #[inline(always)]
    pub fn src_port(&self) -> u16 {
        u16::from_be(self.0.uh_sport)
    }

    /// Returns the destination port.
    #[inline(always)]
    pub fn dst_port(&self) -> u16 {
        u16::from_be(self.0.uh_dport)
    }
}

/// Error returned by libpcap.
#[derive(Clone, Debug, Default)]
pub struct PcapError {
    pub status: c_int,
    pub err: Option<String>,
}

impl PcapError {
    /// Creates a new error.
    fn new(p: *mut pcap_t, status: c_int) -> Self {
        if p.is_null() {
            return Self { status, err: None };
        }
        // SAFETY: p is valid.
        let err = unsafe { CStr::from_ptr(pcap_geterr(p)) }.to_string_lossy();
        Self {
            status,
            err: (!err.is_empty()).then(|| err.into_owned()),
        }
    }
}

impl Error for PcapError {}

impl Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.status == 0 {
            return match &self.err {
                None => write!(f, "No error"),
                Some(err) => write!(f, "{err}"),
            };
        }
        // SAFETY: pcap_statustostr always returns a valid C string.
        let status = unsafe { CStr::from_ptr(pcap_statustostr(self.status)) }.to_string_lossy();
        match &self.err {
            None => write!(f, "{status}"),
            Some(err) if self.status == PCAP_ERROR || err.contains(status.as_ref()) => {
                write!(f, "{err}")
            }
            Some(err) => write!(f, "{err} ({status})"),
        }
    }
}
