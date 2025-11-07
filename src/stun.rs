//! Minimal STUN protocol implementation.
//!
//! This module provides tools for reading and writing STUN messages.
//!
//! References:
//! * [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489)
//! * [RFC 5769](https://datatracker.ietf.org/doc/html/rfc5769)
//! * [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389)
//! * [RFC 3489](https://datatracker.ietf.org/doc/html/rfc3489)

use anyhow::bail;
use std::fmt::Debug;
use std::io::{Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::num::NonZeroUsize;
use std::ops::BitXor;
use std::ptr::NonNull;
use std::{io, mem, slice};

/// STUN [message class].
///
/// [message class]: https://datatracker.ietf.org/doc/html/rfc8489#appendix-A
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(dead_code)]
#[repr(u16)]
pub enum Class {
    Request = 0x0000,
    Indication = 0x0010,
    Success = 0x0100,
    Error = 0x0110,
}

impl Class {
    const MASK: u16 = Self::Error as _;
}

/// 128-bit STUN [transaction ID], including the magic cookie.
///
/// [transaction ID]: https://datatracker.ietf.org/doc/html/rfc8489#section-5
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct TxId(u128);

impl TxId {
    const MAGIC: u128 = 0x2112_A442_u128 << 96;

    /// Returns a cryptographically random transaction ID.
    #[must_use]
    fn rand() -> Self {
        let mut b = u128::MIN.to_ne_bytes();
        getrandom::fill(&mut b).expect("getrandom failed");
        Self(Self::MAGIC | (u128::from_ne_bytes(b) >> u32::BITS))
    }

    /// Returns whether the transaction ID starts with the magic cookie.
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

/// STUN message writer.
pub struct Writer<T> {
    w: T,
    id: TxId,
    lp: u64,
}

impl<T: Seek + Write> Writer<T> {
    /// Creates a new writer and writes a request message header to `w`.
    pub fn request(w: T) -> io::Result<Self> {
        let id = TxId::rand();
        let mut this = Self { w, id, lp: 0 };
        this.lp = this.typ(Msg::BINDING | Class::Request as u16)?;
        this.u128(this.id.0)?;
        Ok(this)
    }

    /// Returns the transaction ID.
    #[must_use]
    pub const fn id(&self) -> TxId {
        self.id
    }

    /// Writes a [SOFTWARE] attribute.
    ///
    /// [SOFTWARE]: https://datatracker.ietf.org/doc/html/rfc8489#section-14.14
    pub fn software(&mut self, v: impl AsRef<str>) -> io::Result<()> {
        let lp = self.typ(0x8022)?;
        self.w.write_all(v.as_ref().as_bytes())?;
        self.len_at(lp)
    }

    /// Updates the total message length and flushes the writer.
    pub fn flush(mut self) -> io::Result<T> {
        self.len_at(self.lp)?;
        self.w.flush()?;
        Ok(self.w)
    }

    /// Writes a 32-bit type-length header with zero length and returns the
    /// position of the length field.
    fn typ(&mut self, typ: u16) -> io::Result<u64> {
        self.u32(u32::from(typ) << u16::BITS)?;
        Ok(self.w.stream_position()?.wrapping_sub(2))
    }

    /// Fills-in the length field at the specified position and appends any
    /// required [padding].
    ///
    /// [padding]: https://datatracker.ietf.org/doc/html/rfc8489#section-14
    fn len_at(&mut self, at: u64) -> io::Result<()> {
        let end = self.w.stream_position()?;
        let len = u16::try_from(end - at - [2, 18][usize::from(at == self.lp)])
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        self.w.seek(SeekFrom::Start(at))?;
        self.u16(len)?;
        self.w.seek(SeekFrom::Start(end))?;
        match len.next_multiple_of(4) - len {
            0 => Ok(()),
            n => self.w.write_all(&[0; 3][..usize::from(n)]),
        }
    }

    /// Writes a u16 field.
    fn u16(&mut self, v: u16) -> io::Result<()> {
        self.w.write_all(&v.to_be_bytes())
    }

    /// Writes a u32 field.
    fn u32(&mut self, v: u32) -> io::Result<()> {
        self.w.write_all(&v.to_be_bytes())
    }

    /// Writes a u128 field.
    fn u128(&mut self, v: u128) -> io::Result<()> {
        self.w.write_all(&v.to_be_bytes())
    }
}

/// STUN message decoder.
#[derive(Clone, Copy, Debug)]
pub struct Msg<'a> {
    cls: Class,
    id: TxId,
    attrs: Reader<'a>,
}

impl<'a> TryFrom<&'a [u8]> for Msg<'a> {
    type Error = anyhow::Error;

    fn try_from(b: &'a [u8]) -> Result<Self, Self::Error> {
        let Some((hdr, attrs)) = b.split_at_checked(20) else {
            bail!("Missing STUN message header");
        };
        let Some((cls, len, id)) = Msg::header(hdr) else {
            bail!("Invalid STUN message header");
        };
        if usize::from(len) != attrs.len() {
            bail!("Incomplete STUN message or invalid length");
        }
        let attrs = Reader::from(attrs);
        let mut r = attrs;
        while !r.is_empty() {
            if r.attr().0 == 0 {
                bail!("Invalid STUN message attributes");
            }
        }
        Ok(Self { cls, id, attrs })
    }
}

impl Msg<'_> {
    const BINDING: u16 = 0x0001;

    /// Decodes the STUN header without validating message or attribute lengths.
    #[inline]
    pub fn header(b: &[u8]) -> Option<(Class, u16, TxId)> {
        let mut r = Reader::from(b);
        let (typ, len, id) = (r.u16(), r.u16(), TxId(r.u128()));
        // SAFETY: all possible values are a valid `repr(u16)` Class.
        let cls = unsafe { mem::transmute::<u16, Class>(typ & Class::MASK) };
        (r.is_ok() && typ & !Class::MASK == Self::BINDING && id.has_magic_cookie())
            .then_some((cls, len, id))
    }

    /// Returns the message class.
    #[inline(always)]
    #[must_use]
    pub const fn class(&self) -> Class {
        self.cls
    }

    /// Returns the transaction ID.
    #[inline(always)]
    #[must_use]
    pub const fn id(&self) -> TxId {
        self.id
    }

    /// Returns the address from the first [MAPPED-ADDRESS] or
    /// [XOR-MAPPED-ADDRESS] attribute.
    ///
    /// [MAPPED-ADDRESS]: https://datatracker.ietf.org/doc/html/rfc8489#section-14.1
    /// [XOR-MAPPED-ADDRESS]: https://datatracker.ietf.org/doc/html/rfc8489#section-14.2
    #[must_use]
    pub fn mapped_address(&self) -> Option<SocketAddr> {
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

/// STUN message reader represented as start and end pointers to `&[u8]`.
#[derive(Clone, Copy, Debug)]
struct Reader<'a>(NonNull<u8>, NonNull<u8>, PhantomData<&'a [u8]>);

impl<'a> From<&'a [u8]> for Reader<'a> {
    #[inline(always)]
    fn from(b: &[u8]) -> Self {
        // SAFETY: a reference cannot be null.
        let p = unsafe { NonNull::new_unchecked(b.as_ptr().cast_mut()) };
        // SAFETY: always safe.
        Self(p, unsafe { p.add(b.len()) }, PhantomData)
    }
}

impl Reader<'_> {
    /// Sentinel value indicating an invalid read (see [`std::rc::Weak::new`]).
    const ERR: Self = {
        let p = NonNull::without_provenance(NonZeroUsize::MAX);
        Self(p, p, PhantomData)
    };

    #[inline(always)]
    #[must_use]
    const fn len(&self) -> usize {
        // SAFETY: pointers refer to either the same address or allocation.
        unsafe { self.1.offset_from(self.0) }.cast_unsigned()
    }

    #[inline(always)]
    #[must_use]
    fn is_empty(&self) -> bool {
        self.0.cast::<()>().addr() == self.1.cast::<()>().addr()
    }

    #[inline(always)]
    #[must_use]
    fn is_ok(&self) -> bool {
        self.0.cast::<()>().addr() != NonZeroUsize::MAX
    }

    #[inline(always)]
    #[must_use]
    fn u16(&mut self) -> u16 {
        u16::from_be(self.read())
    }

    #[inline(always)]
    #[must_use]
    fn u32(&mut self) -> u32 {
        u32::from_be(self.read())
    }

    #[inline(always)]
    #[must_use]
    fn u128(&mut self) -> u128 {
        u128::from_be(self.read())
    }

    #[must_use]
    fn sock_addr(&mut self, id: TxId) -> Option<SocketAddr> {
        let sock = match (self.u16(), id ^ self.u16()) {
            (0x01, port) => SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from_bits(id ^ self.u32()),
                port,
            )),
            (0x02, port) => SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from_bits(id.0 ^ self.u128()),
                port,
                0,
                0,
            )),
            _ => return None,
        };
        self.is_ok().then_some(sock)
    }

    #[must_use]
    fn attr(&mut self) -> (u16, Self) {
        let (typ, len) = (self.u16(), usize::from(self.u16()));
        let next = len.next_multiple_of(4);
        if self.len() < next {
            *self = Self::ERR;
            return (0, Self::ERR);
        }
        // SAFETY: have a complete attribute within the same allocation.
        unsafe {
            let p = self.0;
            self.0 = self.0.add(next);
            (typ, Self(p, p.add(len), PhantomData))
        }
    }

    #[must_use]
    fn read<T: Default>(&mut self) -> T {
        if self.len() < size_of::<T>() {
            *self = Self::ERR;
            return T::default();
        }
        // SAFETY: have a valid T within the same allocation. Byte arrays may
        // not be aligned on a 32-bit boundary, so have to use unaligned reads
        // for all values.
        unsafe {
            let p = self.0.cast();
            self.0 = self.0.add(size_of::<T>());
            p.read_unaligned()
        }
    }
}

impl AsRef<[u8]> for Reader<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self.len() {
            0 => Default::default(),
            // SAFETY: have a non-empty slice with n bytes.
            n => unsafe { slice::from_raw_parts(self.0.as_ptr(), n) },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn request() {
        let mut w = Writer::request(Cursor::new(Vec::new())).unwrap();
        w.software("test").unwrap();
        w.software("x").unwrap();

        let (id, b) = (w.id(), w.flush().unwrap().into_inner());
        let mut m = Msg::try_from(b.as_ref()).unwrap();
        assert_eq!(m.class(), Class::Request);
        assert_eq!(m.id(), id);

        let (typ, v) = m.attrs.attr();
        assert_eq!((typ, v.as_ref()), (0x8022, b"test".as_ref()));
        let (typ, v) = m.attrs.attr();
        assert_eq!((typ, v.as_ref()), (0x8022, b"x".as_ref()));
    }

    #[test]
    fn rfc_5769_test_vectors() {
        // https://datatracker.ietf.org/doc/html/rfc5769#appendix-A
        let respv4 = b"\x01\x01\x00\x3c\x21\x12\xa4\x42\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae\x80\x22\x00\x0b\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20\x00\x20\x00\x08\x00\x01\xa1\x47\xe1\x12\xa6\x43\x00\x08\x00\x14\x2b\x91\xf5\x99\xfd\x9e\x90\xc3\x8c\x74\x89\xf9\x2a\xf9\xba\x53\xf0\x6b\xe7\xd7\x80\x28\x00\x04\xc0\x7d\x4c\x96";
        assert_eq!(
            Msg::try_from(respv4.as_slice()).unwrap().mapped_address(),
            Some("192.0.2.1:32853".parse().unwrap())
        );
        let respv6 = b"\x01\x01\x00\x48\x21\x12\xa4\x42\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae\x80\x22\x00\x0b\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20\x00\x20\x00\x14\x00\x02\xa1\x47\x01\x13\xa9\xfa\xa5\xd3\xf1\x79\xbc\x25\xf4\xb5\xbe\xd2\xb9\xd9\x00\x08\x00\x14\xa3\x82\x95\x4e\x4b\xe6\x7b\xf1\x17\x84\xc9\x7c\x82\x92\xc2\x75\xbf\xe3\xed\x41\x80\x28\x00\x04\xc8\xfb\x0b\x4c";
        assert_eq!(
            Msg::try_from(respv6.as_slice()).unwrap().mapped_address(),
            Some(("[2001:db8:1234:5678:11:2233:4455:6677]:32853".parse()).unwrap())
        );
    }
}
