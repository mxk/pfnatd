use anyhow::bail;
use std::io::{Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::num::NonZeroUsize;
use std::ops::BitXor;
use std::ptr::NonNull;
use std::{io, mem};

const CLASS_MASK: u16 = 0x0110;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(dead_code)]
#[repr(u16)]
pub enum Class {
    Request = 0x0000,
    Indication = 0x0010,
    Success = 0x0100,
    Error = 0x0110,
}

/// STUN message writer.
pub struct Writer<T> {
    w: T,
    id: TxId,
    lp: u64,
}

impl<T: Write + Seek> Writer<T> {
    /// Starts writing a new STUN request to `w`.
    pub fn request(mut w: T) -> io::Result<Self> {
        w.write_all(&(Class::Request as u16 | 1).to_be_bytes())?;
        let lp = w.stream_position()?;
        let id = TxId::rand();
        w.write_all(&[0; 2])?;
        w.write_all(&id.0.to_be_bytes())?;
        Ok(Self { w, id, lp })
    }

    /// Returns the transaction ID.
    #[inline(always)]
    #[must_use]
    pub const fn id(&self) -> TxId {
        self.id
    }

    /// Writes a SOFTWARE attribute.
    pub fn software(&mut self, name: impl AsRef<str>) -> io::Result<()> {
        let lp = self.attr(0x8022)?;
        self.w.write_all(name.as_ref().as_bytes())?;
        self.len_at(lp)
    }

    /// Finalizes the message.
    pub fn finish(mut self) -> io::Result<T> {
        self.len_at(self.lp)?;
        Ok(self.w)
    }

    /// Begins a new attribute.
    fn attr(&mut self, typ: u16) -> io::Result<u64> {
        self.w.write_all(&typ.to_be_bytes())?;
        let lp = self.w.stream_position()?;
        self.w.write_all(&[0; 2])?;
        Ok(lp)
    }

    /// Writes the message or attribute length at the specified position.
    fn len_at(&mut self, at: u64) -> io::Result<()> {
        let end = self.w.stream_position()?;
        let len = u16::try_from(end - at - [2, 18][usize::from(at == self.lp)])
            .map_err(|_| io::Error::from(io::ErrorKind::FileTooLarge))?;
        self.w.seek(SeekFrom::Start(at))?;
        self.w.write_all(&len.to_be_bytes())?;
        self.w.seek(SeekFrom::Start(end))?;
        let pad = len.next_multiple_of(4) - len;
        if pad > 0 {
            self.w.write_all(&[0; 4][..usize::from(pad)])?;
        }
        Ok(())
    }
}

/// STUN message.
#[derive(Clone, Copy, Debug)]
pub struct Msg<'a> {
    cls: Class,
    id: TxId,
    attrs: Reader<'a>,
}

impl Msg<'_> {
    /// Returns message class.
    #[inline(always)]
    #[must_use]
    pub const fn class(&self) -> Class {
        self.cls
    }

    /// Returns message transaction ID.
    #[inline(always)]
    #[must_use]
    pub const fn id(&self) -> TxId {
        self.id
    }

    /// Returns the mapped address, if any.
    #[must_use]
    pub fn mapped_address(&self) -> Option<SocketAddr> {
        if self.cls != Class::Success {
            return None;
        }
        let mut r = self.attrs;
        loop {
            return match r.attr() {
                (0x0001, mut r) => r.sock_addr(TxId(0)),
                (0x0020, mut r) => r.sock_addr(self.id),
                (0, _) => None,
                _ => continue,
            };
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Msg<'a> {
    type Error = anyhow::Error;

    fn try_from(b: &'a [u8]) -> Result<Self, Self::Error> {
        let mut r = Reader::from(b);
        let (typ, len, id) = (r.u16(), r.u16(), TxId(r.u128()));
        if !r.is_ok() || usize::from(len) != r.len() || !id.has_magic_cookie() {
            bail!("Invalid STUN message header");
        }
        if typ & !CLASS_MASK != 1 {
            bail!("Non-binding STUN method: {typ:#x}");
        }
        let attrs = r;
        while !r.is_empty() {
            if r.attr().0 == 0 {
                bail!("Invalid STUN message attributes");
            }
        }
        // SAFETY: all possible values are a valid `repr(u16)` Class.
        let cls = unsafe { mem::transmute::<u16, Class>(typ & CLASS_MASK) };
        Ok(Self { cls, id, attrs })
    }
}

/// Transaction ID field, including the magic cookie added by RFC 5389.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct TxId(u128);

impl TxId {
    const MAGIC: u128 = 0x2112_A442_u128 << 96;

    /// Returns a random transaction ID.
    #[must_use]
    fn rand() -> Self {
        let mut b = [0; size_of::<u128>()];
        getrandom::fill(&mut b).expect("getrandom failed");
        Self(Self::MAGIC | (u128::from_ne_bytes(b) >> u32::BITS))
    }

    #[inline]
    #[must_use]
    const fn has_magic_cookie(self) -> bool {
        (self.0 & (u128::MAX << (u128::BITS - u32::BITS))) == Self::MAGIC
    }
}

impl BitXor<u16> for TxId {
    type Output = u16;

    #[inline(always)]
    fn bitxor(self, rhs: u16) -> Self::Output {
        (self.0 >> (u128::BITS - Self::Output::BITS)) as Self::Output ^ rhs
    }
}

impl BitXor<u32> for TxId {
    type Output = u32;

    #[inline(always)]
    fn bitxor(self, rhs: u32) -> Self::Output {
        (self.0 >> (u128::BITS - Self::Output::BITS)) as Self::Output ^ rhs
    }
}

/// STUN message reader.
#[derive(Clone, Copy, Debug)]
struct Reader<'a>(NonNull<u8>, NonNull<u8>, PhantomData<&'a [u8]>);

impl Reader<'_> {
    const ERR: Self = {
        let p = NonNull::without_provenance(NonZeroUsize::MAX);
        Self(p, p, PhantomData)
    };

    #[inline(always)]
    const fn len(&self) -> usize {
        // SAFETY: pointers either refer to the same address or slice.
        unsafe { self.1.offset_from(self.0) }.cast_unsigned()
    }

    #[inline(always)]
    const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline(always)]
    fn is_ok(&self) -> bool {
        self.0.cast::<()>().addr() != NonZeroUsize::MAX
    }

    #[inline]
    fn u16(&mut self) -> u16 {
        u16::from_be(self.read())
    }

    #[inline]
    fn u32(&mut self) -> u32 {
        u32::from_be(self.read())
    }

    #[inline]
    fn u128(&mut self) -> u128 {
        u128::from_be(self.read())
    }

    fn sock_addr(&mut self, id: TxId) -> Option<SocketAddr> {
        let (af, port) = (self.u16(), id ^ self.u16());
        let sock = match af {
            0x01 => SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from_bits(id ^ self.u32()),
                port,
            )),
            0x02 => SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from_bits(id.0 ^ self.u128()),
                port,
                0,
                0,
            )),
            _ => return None,
        };
        self.is_ok().then_some(sock)
    }

    fn attr(&mut self) -> (u16, Self) {
        let (typ, len) = (self.u16(), self.u16());
        let next = usize::from(len.next_multiple_of(4));
        if self.len() < next {
            *self = Self::ERR;
            return (0, Self::ERR);
        }
        // SAFETY: have m bytes remaining.
        unsafe {
            let p = self.0;
            self.0 = self.0.add(next);
            (typ, Self(p, p.add(usize::from(len)), PhantomData))
        }
    }

    fn read<T: Default>(&mut self) -> T {
        if self.len() < size_of::<T>() {
            *self = Self::ERR;
            return T::default();
        }
        // SAFETY: have a valid T that may not be aligned.
        unsafe {
            let (v, p) = (self.0.cast(), self.0.add(size_of::<T>()));
            self.0 = p;
            v.read_unaligned()
        }
    }
}

impl<'a> From<&'a [u8]> for Reader<'a> {
    fn from(b: &[u8]) -> Self {
        // SAFETY: a reference cannot be null.
        unsafe {
            let p = NonNull::new_unchecked(b.as_ptr().cast_mut());
            Self(p, p.add(b.len()), PhantomData)
        }
    }
}
