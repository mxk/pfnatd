use anyhow::bail;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ptr::NonNull;
use std::{io, ptr, slice};

const CLASS_MASK: u16 = 0x0110;

#[expect(dead_code)] // TODO: Remove
#[repr(u16)]
pub enum Binding {
    Request(TxId, Vec<Attr>) = 0x0001,
    Indication(TxId, Vec<Attr>) = 0x0011,
    Success(TxId, Vec<Attr>) = 0x0101,
    Error(TxId, Vec<Attr>) = 0x0111,
}

impl Binding {
    pub fn request() -> Self {
        Self::Request(TxId::rand(), Vec::new()) // TODO: Include Software
    }

    /// Serializes the message to `w`.
    pub fn write(&self, mut w: impl Write) -> io::Result<usize> {
        struct LenWriter(usize);
        impl Write for LenWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0 += buf.len();
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let Self::Request(id, ref attrs) = *self else {
            unimplemented!()
        };
        let mut len = LenWriter(0);
        for a in attrs {
            a.write(&mut len)?;
        }
        w.write_all(&self.typ().to_be_bytes())?;
        w.write_all(&u16::try_from(len.0).unwrap().to_be_bytes())?;
        w.write_all(&id.0.to_be_bytes())?;
        for a in attrs {
            a.write(&mut w)?;
        }
        Ok(20 + len.0)
    }

    fn typ(&self) -> u16 {
        // SAFETY: valid conversion for `repr(u16)` enum.
        unsafe { *<*const _>::from(self).cast() }
    }
}

impl TryFrom<&[u8]> for Binding {
    type Error = anyhow::Error;

    fn try_from(b: &[u8]) -> Result<Self, anyhow::Error> {
        let mut m = Msg(b);
        let (typ, len, id) = (m.u16(), m.u16(), TxId(m.u128()));
        if !m.is_ok() || usize::from(len) != m.0.len() || !id.has_magic_cookie() {
            bail!("Invalid STUN message header");
        }
        if typ & !CLASS_MASK != 1 {
            bail!("Unknown STUN message type {typ:#x}");
        }

        let mut attrs = Vec::new();
        while !m.0.is_empty() {
            let (typ, len) = (m.u16(), m.u16());
            let Some(a) = m.take(len) else {
                bail!("Invalid STUN attribute length");
            };
            let Some(a) = Attr::read(id, typ, a) else {
                bail!("Invalid STUN attribute")
            };
            attrs.push(a);
        }
        if !m.is_ok() {
            bail!("Invalid STUN message");
        }

        Ok(match typ {
            0x0001 => Self::Request(id, attrs),
            0x0011 => Self::Indication(id, attrs),
            0x0101 => Self::Success(id, attrs),
            0x0111 => Self::Error(id, attrs),
            _ => unreachable!(),
        })
    }
}

/// STUN attribute.
#[expect(dead_code)] // TODO: Remove
#[derive(Debug)]
#[repr(u16)]
pub enum Attr {
    MappedAddress(SocketAddr) = 0x0001,
    ErrorCode(u16, String) = 0x0009,
    XorMappedAddress(SocketAddr) = 0x0020,
    Software(String) = 0x8022,
    Fingerprint(u32) = 0x8028,
}

impl Attr {
    fn read(id: TxId, typ: u16, mut m: Msg<'_>) -> Option<Self> {
        use Attr::*;
        let a = match typ {
            0x0001 => MappedAddress(Self::sock_addr(&mut m, TxId(0))?),
            0x0009 => ErrorCode(m.read(), str::from_utf8(m.0).ok()?.to_owned()),
            0x0020 => XorMappedAddress(Self::sock_addr(&mut m, id)?),
            0x8022 => Software(str::from_utf8(m.0).ok()?.to_owned()),
            0x8028 => Fingerprint(u32::from_be(m.read())),
            _ => return None,
        };
        (m.is_ok() && m.0.is_empty()).then_some(a)
    }

    fn write(&self, mut w: impl Write) -> io::Result<()> {
        let mut pad = 0;
        let mut hdr = |len: usize| {
            pad = len.next_multiple_of(4) - len;
            w.write_all(&self.typ().to_be_bytes())?;
            w.write_all(&u16::try_from(len).unwrap().to_be_bytes())
        };
        match *self {
            Self::Software(ref s) => {
                hdr(s.len())?;
                w.write_all(s.as_bytes())?;
            }
            _ => unimplemented!(),
        }
        if pad > 0 {
            w.write_all(&[0; 4][..pad])?;
        }
        Ok(())
    }

    fn sock_addr(m: &mut Msg<'_>, id: TxId) -> Option<SocketAddr> {
        let (af, port) = (u16::from_be(m.read()), id.x16(m));
        Some(match af {
            0x01 => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from_bits(id.x32(m)), port)),
            0x02 => SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from_bits(id.x128(m)),
                port,
                0,
                0,
            )),
            _ => return None,
        })
    }

    fn typ(&self) -> u16 {
        // SAFETY: valid conversion for `repr(u16)` enum.
        unsafe { *<*const _>::from(self).cast() }
    }
}

/// Transaction ID field, including the magic cookie added by RFC 5389.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct TxId(u128); // TODO: Hide?

impl TxId {
    const MAGIC_COOKIE: u128 = 0x2112_A442_u128 << 96;

    /// Returns a random transaction ID.
    fn rand() -> Self {
        let mut b = [0; size_of::<u128>()];
        getrandom::fill(&mut b).expect("getrandom failed");
        Self(Self::MAGIC_COOKIE | (u128::from_ne_bytes(b) >> u32::BITS))
    }

    const fn has_magic_cookie(self) -> bool {
        (self.0 & (u128::MAX << 96)) == Self::MAGIC_COOKIE
    }

    fn x16(self, m: &mut Msg<'_>) -> u16 {
        m.u16() ^ ((self.0 >> 112) as u16)
    }

    fn x32(self, m: &mut Msg<'_>) -> u32 {
        m.u32() ^ ((self.0 >> 96) as u32)
    }

    fn x128(self, m: &mut Msg<'_>) -> u128 {
        m.u128() ^ self.0
    }
}

/// Message reader.
#[derive(Debug)]
struct Msg<'a>(&'a [u8]);

impl Msg<'_> {
    fn u16(&mut self) -> u16 {
        u16::from_be(self.read())
    }

    fn u32(&mut self) -> u32 {
        u32::from_be(self.read())
    }

    fn u128(&mut self) -> u128 {
        u128::from_be(self.read())
    }

    fn take(&mut self, n: u16) -> Option<Self> {
        let n = usize::from(n);
        (self.0.split_at_checked(n.next_multiple_of(4))).map(|(b, tail)| {
            *self = Msg(tail);
            Self(&b[..n])
        })
    }

    fn read<T: Default>(&mut self) -> T {
        if let Some((v, tail)) = self.0.split_at_checked(size_of::<T>()) {
            self.0 = tail;
            // SAFETY: v is a valid T, but may not be aligned.
            unsafe { v.as_ptr().cast::<T>().read_unaligned() }
        } else {
            // SAFETY: valid creation of an empty slice.
            self.0 = unsafe { slice::from_raw_parts(NonNull::dangling().as_ptr(), 0) };
            T::default()
        }
    }

    fn is_ok(&self) -> bool {
        !ptr::eq(&raw const self.0, NonNull::dangling().as_ptr())
    }
}
