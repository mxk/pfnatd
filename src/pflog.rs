use crate::sys::*;
use anyhow::{Context as _, Result, bail};
use log::warn;
use std::convert::TryInto as _;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt::Display;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr::NonNull;
use std::sync::{Arc, Weak};
use std::{fmt, io, mem, ptr, slice};

/// Pflog packet capture interface.
#[derive(Debug)]
pub struct Pflog(Pcap<PflogHdr>);

impl Pflog {
    /// Opens the specified pflog interface and activates packet capture. The
    /// interface is created if it does not exist.
    pub fn open(iface: impl AsRef<str>) -> Result<Self> {
        let iface = iface.as_ref();
        if iface
            .strip_prefix("pflog")
            .is_none_or(|n| n.is_empty() || !n.chars().all(|c| c.is_ascii_digit()))
        {
            bail!("Not a pflog interface: {iface}");
        }
        let iface = CString::new(iface)?;
        Ifconfig::open()?.up(&iface)?;
        Ok(Self(Pcap::open(&iface)?.activate(DLT_PFLOG)?))
    }

    pub fn next<'a>(&'a mut self) -> Result<PflogPacket<'a>> {
        loop {
            let (hdr, pf, mut pkt) = self.0.next()?;
            let Some(ip) = (match pf.0.naf {
                AF_INET => Pcap::consume(&mut pkt).map(IpHdr::V4),
                AF_INET6 => Pcap::consume(&mut pkt).map(IpHdr::V6),
                _ => {
                    warn!("Unknown pflog header naf: {}", pf.0.naf);
                    continue;
                }
            }) else {
                warn!("pflog packet missing IP header ({hdr:?})");
                continue;
            };
            let udp = ip
                .udp_offset()
                .and_then(|off| pkt.split_at_checked(off))
                .and_then(|(_, mut pkt)| Pcap::consume(&mut pkt));
            // SAFETY: safe extension of PflogPacket lifetime.
            return Ok(unsafe {
                mem::transmute::<PflogPacket<'_>, PflogPacket<'a>>(PflogPacket { pf, ip, udp })
            });
        }
    }

    /// Returns a guard that causes [`Self::next`] to return an interrupt error
    /// when dropped.
    pub fn interrupt(&self) -> Interrupt {
        Interrupt(Arc::downgrade(&self.0.0))
    }
}

/// Network configuration socket.
#[derive(Debug)]
#[repr(transparent)]
struct Ifconfig(OwnedFd);

impl Ifconfig {
    /// Opens network configuration socket.
    fn open() -> Result<Self> {
        // SAFETY: safe C call.
        let sock = unsafe { socket(AF_INET.into(), SOCK_DGRAM, 0) };
        if sock < 0 {
            return errno("Failed to open AF_INET socket");
        }
        // SAFETY: sock is a valid file descriptor that only needs to be closed.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(sock) }))
    }

    /// Brings up the specified interface, creating it if necessary.
    fn up(&self, iface: &CStr) -> Result<()> {
        // SAFETY: safe ifreq operations.
        unsafe {
            let fd = self.0.as_raw_fd();
            let mut ifr: ifreq = mem::zeroed();
            cstrcpy(&raw mut ifr.ifr_name, iface);
            if ioctl(fd, SIOCGIFFLAGS, &raw mut ifr) < 0 {
                if io::Error::last_os_error().raw_os_error() != Some(ENXIO) {
                    return errno(format!("Failed to get flags for {iface:?}"));
                }
                if ioctl(fd, SIOCIFCREATE, &raw mut ifr) < 0
                    && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                {
                    return errno(format!("Failed to create {iface:?}"));
                }
                if ioctl(fd, SIOCGIFFLAGS, &raw mut ifr) < 0 {
                    return errno(format!("Failed to get flags for {iface:?}"));
                }
            }
            if (ifr.ifr_ifru.ifru_flags & IFF_UP) == 0 {
                ifr.ifr_ifru.ifru_flags |= IFF_UP;
                if ioctl(fd, SIOCSIFFLAGS, &raw mut ifr) < 0 {
                    return errno(format!("Failed to bring up {iface:?}"));
                }
            }
            Ok(())
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
#[derive(Debug)]
#[repr(transparent)]
struct PflogHdr(pfloghdr);

impl PflogHdr {
    /// Returns the translated source address for a STUN request.
    fn stun_nat_addr(&self) -> Option<SocketAddr> {
        (self.0.af == self.0.naf
            && c_uint::from(self.0.action) == PF_PASS
            && c_uint::from(self.0.dir) == PF_OUT
            && self.0.rewritten != 0
            && u16::from_be(self.0.dport) == 3478)
            .then(|| Self::sock(self.0.naf, self.0.saddr, self.0.sport))
    }

    fn sock(af: sa_family_t, a: pf_addr, port: u_int16_t) -> SocketAddr {
        let port = u16::from_be(port);
        match af {
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
                    }
                }
            }
        }

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

        if self.0.pid != NO_PID {
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

/// IP header after [`PflogHdr`].
enum IpHdr<'a> {
    V4(&'a ip),
    V6(&'a ip6_hdr),
}

impl IpHdr<'_> {
    /// Returns the source address.
    pub fn src(&self) -> IpAddr {
        match *self {
            IpHdr::V4(h) => h.ip_src.into(),
            IpHdr::V6(h) => h.ip6_src.into(),
        }
    }

    /// Returns the destination address.
    pub fn dst(&self) -> IpAddr {
        match *self {
            IpHdr::V4(h) => h.ip_dst.into(),
            IpHdr::V6(h) => h.ip6_dst.into(),
        }
    }

    /// Returns the offset of the UDP header, if there is one. The offset is
    /// relative to the end of the fixed IP header.
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
        let (src, dst) = (self.src(), self.dst());
        write!(f, "{ver} {src} > {dst}")
    }
}

/// UDP header after [`IpHdr`].
#[derive(Debug)]
#[repr(transparent)]
struct UdpHdr(udphdr);

impl UdpHdr {
    /// Returns payload length in bytes.
    pub fn payload_len(&self) -> usize {
        usize::from(u16::from_be(self.0.uh_ulen)).saturating_sub(size_of::<Self>())
    }

    /// Returns the source port.
    pub const fn src_port(&self) -> u16 {
        u16::from_be(self.0.uh_sport)
    }

    /// Returns the destination port.
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

/// Pcap handle that is closed when dropped.
#[derive(Debug)]
#[repr(transparent)]
struct Pcap<T>(ManuallyDrop<Arc<NonNull<pcap_t>>>, PhantomData<T>);

// SAFETY: PcapHandle can be sent to other threads.
unsafe impl<T> Send for Pcap<T> {}

impl<T> Pcap<T> {
    /// Number of bytes to capture for each packet. 60 is the maximum IPv4
    /// header size.
    #[expect(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    const SNAPLEN: c_int = (size_of::<T>() + 60 + size_of::<udphdr>()) as _;

    /// Milliseconds before `pcap_next_ex` times out without matching packets.
    const TIMEOUT_MS: c_int = 250;

    /// Packet buffer size allocated by the kernel and libpcap. Default is 32K.
    const BUFSIZE: c_int = 64 * 1024;

    fn open(iface: &CStr) -> Result<Self> {
        let mut errbuf = [0; PCAP_ERRBUF_SIZE];
        let iface = iface.as_ref().as_ptr();
        // SAFETY: iface and errbuf are valid.
        if let Some(p) = NonNull::new(unsafe { pcap_create(iface, errbuf.as_mut_ptr()) }) {
            #[expect(clippy::arc_with_non_send_sync)]
            return Ok(Self(ManuallyDrop::new(Arc::new(p)), PhantomData));
        }
        let status = PCAP_ERROR;
        // SAFETY: errbuf contains a valid error message.
        let err = Some(
            unsafe { CStr::from_ptr(errbuf.as_ptr()) }
                .to_string_lossy()
                .into_owned(),
        );
        Err(PcapError { status, err }).context("Failed to create pcap interface")
    }

    fn activate(self, dlt: c_int) -> Result<Self> {
        // SAFETY: self.0 is a valid handle.
        #[expect(clippy::missing_assert_message)]
        unsafe {
            // These functions only check that the capture hasn't been activated
            assert_eq!(pcap_set_snaplen(self.0.as_ptr(), Self::SNAPLEN), 0);
            assert_eq!(pcap_set_promisc(self.0.as_ptr(), 1), 0);
            assert_eq!(pcap_set_timeout(self.0.as_ptr(), Self::TIMEOUT_MS), 0);
            assert_eq!(pcap_set_immediate_mode(self.0.as_ptr(), 1), 0);
            assert_eq!(pcap_set_buffer_size(self.0.as_ptr(), Self::BUFSIZE), 0);

            let status = pcap_activate(self.0.as_ptr());
            if status < 0 {
                return Err(PcapError::new(self.0.as_ptr(), status))
                    .context("Failed to activate packet capture");
            }
            if pcap_datalink(self.0.as_ptr()) != dlt {
                bail!("Packet capture interface datalink type mismatch");
            }
            Ok(self)
        }
    }

    /// Returns the pcap header, payload `T`, and any remaining bytes.
    fn next(&mut self) -> Result<(&pcap_pkthdr, &T, &[u8])> {
        // SAFETY: the error buffer is always valid and mutable.
        unsafe { pcap_geterr(self.0.as_ptr()).write(0) };
        let mut hdr: *mut pcap_pkthdr = ptr::null_mut();
        let mut pkt: *const u_char = ptr::null();
        loop {
            // SAFETY: all parameters are valid.
            match unsafe { pcap_next_ex(self.0.as_ptr(), &raw mut hdr, &raw mut pkt) } {
                0 => continue, // Timeout
                1 => {}
                status => return Err(PcapError::new(self.0.as_ptr(), status).into()),
            }
            if hdr.is_null() || !hdr.is_aligned() || pkt.is_null() || !pkt.cast::<T>().is_aligned()
            {
                warn!("Invalid pcap packet ({hdr:?} {pkt:?})");
                continue;
            }
            // SAFETY: hdr can be converted to a reference.
            let (hdr, mut pkt) = unsafe {
                let hdr = &*hdr;
                let len = hdr.caplen.try_into().unwrap_or_default();
                (hdr, slice::from_raw_parts(pkt, len))
            };
            match Self::consume(&mut pkt) {
                Some(v) => return Ok((hdr, v, pkt)),
                None => warn!("Short pcap packet ({hdr:?} {pkt:?})"),
            }
        }
    }

    /// Returns the next `U` in `pkt` and reduces `pkt` by the consumed bytes.
    fn consume<'a>(pkt: &mut &'a [u8]) -> Option<&'a T> {
        let p = pkt.as_ptr();
        let align = p.align_offset(align_of::<T>());
        let len = align + size_of::<T>();
        // SAFETY: aligned p can be cast to T with rem bytes remaining in pkt.
        pkt.len().checked_sub(len).map(|rem| unsafe {
            *pkt = slice::from_raw_parts(p.wrapping_add(len), rem);
            &*p.wrapping_add(align).cast()
        })
    }

    /// Closes the pcap interface if p is the last reference.
    fn try_close(p: Arc<NonNull<pcap_t>>) {
        if let Some(p) = Arc::into_inner(p) {
            // SAFETY: have a valid handle.
            unsafe { pcap_close(p.as_ptr()) };
        }
    }
}

impl<T> Drop for Pcap<T> {
    fn drop(&mut self) {
        // SAFETY: self.0 is never used again.
        Self::try_close(unsafe { ManuallyDrop::take(&mut self.0) });
    }
}

/// Guard that interrupts pcap packet reader when dropped.
#[derive(Debug)]
pub struct Interrupt(Weak<NonNull<pcap_t>>);

// SAFETY: Interrupt is intended for concurrent use.
unsafe impl Send for Interrupt {}

// SAFETY: Interrupt is intended for concurrent use.
unsafe impl Sync for Interrupt {}

impl Drop for Interrupt {
    fn drop(&mut self) {
        if let Some(p) = self.0.upgrade() {
            // SAFETY: have a valid handle.
            unsafe { pcap_breakloop(p.as_ptr()) };
            Pcap::<()>::try_close(p);
        }
    }
}

/// Error from libpcap API.
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

    /// Returns whether the error represents an interrupt from
    /// [`Interrupt`].
    #[inline(always)]
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
