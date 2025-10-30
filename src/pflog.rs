use crate::sys::*;
use anyhow::{Context as _, Result, bail};
use log::{trace, warn};
use std::convert::TryInto as _;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt::Display;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::os::raw::{c_char, c_int};
use std::ptr::NonNull;
use std::sync::{Arc, Weak};
use std::{fmt, mem, ptr, slice};

/// Pflog packet capture interface.
#[derive(Debug)]
pub struct Pflog(Pcap<PflogHdr>);

impl Pflog {
    /// Number of bytes to capture for each packet. 60 is the maximum IPv4
    /// header size.
    const SNAPLEN: usize = size_of::<PflogHdr>() + 60 + size_of::<UdpHdr>();

    /// Opens the specified pflog interface and activates packet capture. The
    /// interface is created if it does not exist.
    pub fn open(iface: impl AsRef<str>) -> Result<Self> {
        let iface = iface.as_ref();
        if !(iface.strip_prefix("pflog").unwrap_or_default())
            .starts_with(|c: char| c.is_ascii_digit())
        {
            bail!("Not a pflog interface: {iface}");
        }
        let iface = CString::new(iface)?;
        Ifconfig::open()?.up(&iface)?;
        Ok(Self(Pcap(
            Arc::new(PcapHandle::open(&iface)?.activate(DLT_PFLOG, Self::SNAPLEN)?),
            PhantomData,
        )))
    }

    /// Returns the next pflog packet.
    pub fn next<'a>(&'a mut self) -> Result<PflogPacket<'a>> {
        loop {
            let (hdr, pf, mut pkt) = self.0.next()?;
            let Some(ip) = (match pf.0.naf {
                AF_INET => Pcap::try_as(&mut pkt).map(IpHdr::V4),
                AF_INET6 => Pcap::try_as(&mut pkt).map(IpHdr::V6),
                _ => {
                    warn!("Unknown pflog header naf: {}", pf.0.naf);
                    continue;
                }
            }) else {
                warn!("pflog packet without IP header ({hdr:?})");
                continue;
            };
            let udp = (ip.udp_offset())
                .and_then(|off| pkt.split_at_checked(off))
                .and_then(|(_, mut pkt)| Pcap::try_as(&mut pkt));
            let p = PflogPacket { pf, ip, udp };
            trace!("{p}");
            // SAFETY: extension of PflogPacket lifetime.
            return Ok(unsafe { mem::transmute::<PflogPacket<'_>, PflogPacket<'a>>(p) });
        }
    }

    /// Returns a guard that, when dropped, causes [`Self::next`] to return an
    /// interrupt error.
    #[inline]
    #[must_use]
    pub fn interrupt(&self) -> Interrupt {
        Interrupt(Arc::downgrade(&self.0.0))
    }
}

/// NAT mapping for a STUN request.
#[derive(Clone, Copy, Debug)]
pub struct StunNat {
    ifname: [c_char; IFNAMSIZ],
    src: SocketAddr,
    nat: SocketAddr,
}

impl StunNat {
    #[must_use]
    pub fn matches(&self, s: &pfsync_state) -> bool {
        const ALL: [c_char; IFNAMSIZ] = {
            let mut v = [0; IFNAMSIZ];
            (v[0], v[1], v[2]) = ('a' as _, 'l' as _, 'l' as _);
            v
        };
        const SK: usize = PF_SK_STACK;
        const NK: usize = PF_SK_WIRE;
        if s.direction != PF_OUT
            || s.proto != IPPROTO_UDP
            || (s.ifname != ALL && s.ifname != self.ifname)
        {
            return false;
        }
        s.key[SK].af == s.key[NK].af
            && self.src == s.key[SK].addr[1].to_sock(s.key[SK].af, s.key[SK].port[1])
            && self.nat == s.key[NK].addr[1].to_sock(s.key[NK].af, s.key[NK].port[1])
    }
}

impl Display for StunNat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ifname = cstr(&self.ifname).to_string_lossy();
        let (src, nat) = (self.src, self.nat);
        write!(f, "STUN out on {ifname} from {src} nat-to {nat}",)
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
    #[must_use]
    pub fn stun_nat(&self) -> Option<StunNat> {
        Some(StunNat {
            ifname: self.pf.0.ifname,
            src: SocketAddr::new(self.ip.src(), self.udp.as_ref()?.src_port()),
            nat: self.pf.stun_nat_addr()?,
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
#[derive(Debug)]
#[repr(transparent)]
struct PflogHdr(pfloghdr);

impl PflogHdr {
    /// Returns the translated source address for a STUN request.
    #[must_use]
    fn stun_nat_addr(&self) -> Option<SocketAddr> {
        (self.0.af == self.0.naf
            && self.0.action == PF_PASS
            && self.0.dir == PF_OUT
            && self.0.rewritten != 0
            && u16::from_be(self.0.dport) == 3478)
            .then(|| self.0.saddr.to_sock(self.0.naf, self.0.sport))
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
                    }
                }
            }
        }

        let action = match self.0.action {
            PF_MATCH => "match",
            PF_SCRUB => "scrub",
            PF_PASS => "pass",
            PF_DROP => "block",
            PF_NAT | PF_NONAT => "nat",
            PF_BINAT | PF_NOBINAT => "binat",
            PF_RDR | PF_NORDR => "rdr",
            _ => "???",
        };
        let dir = match self.0.dir {
            PF_OUT => "out",
            _ => "in",
        };
        let ifname = cstr(&self.0.ifname).to_string_lossy();
        write!(f, " {action} {dir} on {ifname}:")?;

        if self.0.pid != NO_PID {
            write!(f, " [uid {}, pid {}]", self.0.uid, self.0.pid)?;
        }
        if self.0.rewritten != 0 {
            let src = self.0.saddr.to_sock(self.0.naf, self.0.sport);
            let dst = self.0.daddr.to_sock(self.0.naf, self.0.dport);
            write!(f, " [rewritten: src {src}, dst {dst}]")?;
        }
        Ok(())
    }
}

/// IP header after [`PflogHdr`].
enum IpHdr<'a> {
    V4(&'a ip),
    V6(&'a ip6_hdr),
}

impl IpHdr<'_> {
    /// Returns the source address.
    #[must_use]
    pub fn src(&self) -> IpAddr {
        match *self {
            IpHdr::V4(h) => h.ip_src.into(),
            IpHdr::V6(h) => h.ip6_src.into(),
        }
    }

    /// Returns the destination address.
    #[must_use]
    pub fn dst(&self) -> IpAddr {
        match *self {
            IpHdr::V4(h) => h.ip_dst.into(),
            IpHdr::V6(h) => h.ip6_dst.into(),
        }
    }

    /// Returns the offset of the UDP header, if there is one. The offset is
    /// relative to the end of the fixed IP header.
    #[must_use]
    fn udp_offset(&self) -> Option<usize> {
        match *self {
            IpHdr::V4(h) => {
                // SAFETY: this __BindgenBitfieldUnit is a [u8; 1] array.
                let ver_ihl: u8 = unsafe { mem::transmute(h._bitfield_1) };
                let hlen = usize::from(ver_ihl & 0xf) * 4;
                (u32::from(ver_ihl >> 4) == 4
                    && h.ip_p == IPPROTO_UDP
                    && u16::from_be(h.ip_off).trailing_zeros() >= 13
                    && size_of::<ip>() <= hlen
                    && hlen + size_of::<udphdr>() <= u16::from_be(h.ip_len).into())
                .then_some(hlen - size_of::<ip>())
            }
            IpHdr::V6(_) => None, // TODO: Implement
        }
    }
}

impl Display for IpHdr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ver = match *self {
            IpHdr::V4(_) => "ipv4",
            IpHdr::V6(_) => "ipv6",
        };
        write!(f, "{ver} {} > {}", self.src(), self.dst())
    }
}

/// UDP header after [`IpHdr`].
#[derive(Debug)]
#[repr(transparent)]
struct UdpHdr(udphdr);

impl UdpHdr {
    /// Returns payload length in bytes.
    #[inline(always)]
    #[must_use]
    pub fn payload_len(&self) -> usize {
        usize::from(u16::from_be(self.0.uh_ulen)).saturating_sub(size_of::<Self>())
    }

    /// Returns the source port.
    #[inline(always)]
    #[must_use]
    pub const fn src_port(&self) -> u16 {
        u16::from_be(self.0.uh_sport)
    }

    /// Returns the destination port.
    #[inline(always)]
    #[must_use]
    pub const fn dst_port(&self) -> u16 {
        u16::from_be(self.0.uh_dport)
    }
}

impl Display for UdpHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (src, dst, len) = (self.src_port(), self.dst_port(), self.payload_len());
        write!(f, "udp {src} > {dst}: {len} bytes")
    }
}

/// Network configuration interface.
#[derive(Debug)]
#[repr(transparent)]
struct Ifconfig(OwnedFd);

impl Ifconfig {
    /// Opens network configuration interface.
    fn open() -> Result<Self> {
        // SAFETY: safe C call.
        let fd = unsafe { socket(AF_INET.into(), SOCK_DGRAM, 0) };
        if fd < 0 {
            return errno_err("Failed to open AF_INET socket");
        }
        // SAFETY: fd is a valid file descriptor that only needs to be closed.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Brings up the specified interface, creating it if necessary.
    fn up(&self, iface: &CStr) -> Result<()> {
        let mut ifr = ifreq {
            ifr_name: carray(iface),
            ..ifreq::default()
        };
        if let Err(e) = self.0.ioctl(SIOCGIFFLAGS, &raw mut ifr) {
            if e.raw_os_error() != Some(ENXIO) {
                return Err(e).context(format!("Failed to get flags for {iface:?}"));
            }
            if let Err(e) = self.0.ioctl(SIOCIFCREATE, &raw mut ifr)
                && e.raw_os_error() != Some(EEXIST)
            {
                return Err(e).context(format!("Failed to create {iface:?}"));
            }
            (self.0.ioctl(SIOCGIFFLAGS, &raw mut ifr))
                .with_context(|| format!("Failed to get flags for {iface:?}"))?;
        }
        // SAFETY: ifr contains interface flags.
        let flags = unsafe { &mut ifr.ifr_ifru.ifru_flags };
        if *flags & IFF_UP == IFF_UP {
            return Ok(());
        }
        *flags |= IFF_UP;
        (self.0.ioctl(SIOCSIFFLAGS, &raw mut ifr))
            .with_context(|| format!("Failed to bring up {iface:?}"))
    }
}

/// Packet capture interface.
#[derive(Debug)]
#[repr(transparent)]
struct Pcap<T>(Arc<PcapHandle>, PhantomData<T>);

impl<T> Pcap<T> {
    /// Returns the next pcap header, payload `T`, and any remaining bytes.
    fn next(&mut self) -> Result<(&pcap_pkthdr, &T, &[u8])> {
        // SAFETY: the error buffer is always valid and mutable.
        unsafe { pcap_geterr(self.0.p()).write(0) };
        loop {
            let mut hdr: *mut pcap_pkthdr = ptr::null_mut();
            let mut pkt: *const u_char = ptr::null();
            // SAFETY: all parameters are valid.
            match unsafe { pcap_next_ex(self.0.p(), &raw mut hdr, &raw mut pkt) } {
                0 => continue, // Timeout
                1 => {}
                status => return Err(self.0.err(status).into()),
            }
            if hdr.is_null() || !hdr.is_aligned() || pkt.is_null() || !pkt.cast::<T>().is_aligned()
            {
                warn!("Invalid pcap packet (hdr={hdr:?} pkt={pkt:?})");
                continue;
            }
            // SAFETY: hdr can be converted to a reference.
            let (hdr, mut pkt) = unsafe {
                let hdr = &*hdr;
                let len = hdr.caplen.try_into().unwrap_or_default();
                (hdr, slice::from_raw_parts(pkt, len))
            };
            match Self::try_as(&mut pkt) {
                Some(v) => return Ok((hdr, v, pkt)),
                None => warn!("Short pcap packet ({hdr:?} {pkt:x?})"),
            }
        }
    }

    /// Tries to cast `pkt` into `&T`. If successful, `pkt` will refer to any
    /// remaining bytes after `T`.
    fn try_as<'a>(pkt: &mut &'a [u8]) -> Option<&'a T> {
        let p = pkt.as_ptr();
        let align = p.align_offset(align_of::<T>());
        let len = align + size_of::<T>();
        // SAFETY: aligned p can be cast to T with rem bytes remaining in pkt.
        pkt.len().checked_sub(len).map(|rem| unsafe {
            *pkt = slice::from_raw_parts(p.wrapping_add(len), rem);
            &*p.wrapping_add(align).cast()
        })
    }
}

/// Guard that interrupts packet capture when dropped.
#[derive(Debug)]
pub struct Interrupt(Weak<PcapHandle>);

impl Drop for Interrupt {
    fn drop(&mut self) {
        if let Some(p) = self.0.upgrade() {
            p.breakloop();
        }
    }
}

/// Pcap handle that is closed when dropped.
#[derive(Debug)]
#[repr(transparent)]
struct PcapHandle(NonNull<pcap_t>, PhantomData<*mut pcap_t>);

// SAFETY: PcapHandle can be sent to other threads.
unsafe impl Send for PcapHandle {}

// SAFETY: PcapHandle can be used concurrently for breakloop.
unsafe impl Sync for PcapHandle {}

impl PcapHandle {
    /// Milliseconds before `pcap_next_ex` times out without matching packets.
    /// This determines breakloop delay.
    const TIMEOUT_MS: c_int = 250;

    /// Packet buffer size allocated by the kernel and libpcap. Default is 32K.
    const BUFSIZE: c_int = 64 * 1024;

    /// Opens the specified interface.
    fn open(iface: &CStr) -> Result<Self> {
        let iface = iface.as_ref().as_ptr();
        let mut errbuf = [0; PCAP_ERRBUF_SIZE];
        // SAFETY: iface and errbuf are valid.
        NonNull::new(unsafe { pcap_create(iface, errbuf.as_mut_ptr()) }).map_or_else(
            || {
                Err(PcapError {
                    status: PCAP_ERROR,
                    err: Some(
                        // SAFETY: errbuf contains a valid error message.
                        unsafe { CStr::from_ptr(errbuf.as_ptr()) }
                            .to_string_lossy()
                            .into_owned(),
                    ),
                })
                .context("Failed to open pcap interface")
            },
            |p| Ok(Self(p, PhantomData)),
        )
    }

    /// Activates packet capture.
    fn activate(self, dlt: c_int, snaplen: usize) -> Result<Self> {
        // SAFETY: have a valid handle.
        #[expect(clippy::missing_assert_message)]
        unsafe {
            // These functions only check that the capture hasn't been activated
            assert_eq!(pcap_set_snaplen(self.p(), snaplen.try_into()?), 0);
            assert_eq!(pcap_set_promisc(self.p(), 1), 0);
            assert_eq!(pcap_set_timeout(self.p(), Self::TIMEOUT_MS), 0);
            assert_eq!(pcap_set_immediate_mode(self.p(), 1), 0);
            assert_eq!(pcap_set_buffer_size(self.p(), Self::BUFSIZE), 0);

            let status = pcap_activate(self.p());
            if status < 0 {
                return Err(self.err(status)).context("Failed to activate packet capture");
            }
            if pcap_datalink(self.p()) != dlt {
                bail!("Packet capture interface datalink type mismatch");
            }
            Ok(self)
        }
    }

    /// Returns the pcap handle.
    #[inline(always)]
    #[must_use]
    const fn p(&self) -> *mut pcap_t {
        self.0.as_ptr()
    }

    /// Causes `pcap_read` call to return `PCAP_ERROR_BREAK`.
    #[inline]
    fn breakloop(&self) {
        // SAFETY: have a valid handle.
        unsafe { pcap_breakloop(self.p()) };
    }

    /// Creates a new error.
    #[must_use]
    fn err(&self, status: c_int) -> PcapError {
        // SAFETY: have a valid handle.
        let err = unsafe { CStr::from_ptr(pcap_geterr(self.p())) }.to_string_lossy();
        PcapError {
            status,
            err: (!err.is_empty()).then(|| err.into_owned()),
        }
    }
}

impl Drop for PcapHandle {
    fn drop(&mut self) {
        // SAFETY: have a valid handle.
        unsafe { pcap_close(self.0.as_ptr()) };
    }
}

/// Error from libpcap API.
#[derive(Clone, Debug, Default)]
pub struct PcapError {
    status: c_int,
    err: Option<String>,
}

impl PcapError {
    /// Returns whether the error represents an interrupt request.
    #[inline(always)]
    #[must_use]
    pub const fn is_interrupt(&self) -> bool {
        self.status == PCAP_ERROR_BREAK
    }
}

impl Error for PcapError {}

impl Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.status == 0 {
            return match self.err.as_ref() {
                None => write!(f, "No error"),
                Some(err) => write!(f, "{err}"),
            };
        }
        // SAFETY: pcap_statustostr always returns a valid C string.
        let status = unsafe { CStr::from_ptr(pcap_statustostr(self.status)) }.to_string_lossy();
        match self.err.as_ref() {
            None => write!(f, "{status}"),
            Some(err) if self.status == PCAP_ERROR || err.contains(status.as_ref()) => {
                write!(f, "{err}")
            }
            Some(err) => write!(f, "{err} ({status})"),
        }
    }
}
