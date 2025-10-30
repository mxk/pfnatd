use anyhow::{Context as _, Result};
use std::ffi::CStr;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::os::raw::{c_char, c_ulong};
use std::{io, mem, ptr, slice};

#[expect(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unnameable_types,
    unused_qualifications
)]
#[expect(clippy::all, clippy::nursery, clippy::pedantic, clippy::restriction)]
mod bindgen {
    include!(concat!(env!("OUT_DIR"), "/bindgen.rs"));
}

pub use bindgen::*;

impl From<in_addr> for Ipv4Addr {
    #[inline]
    fn from(a: in_addr) -> Self {
        Self::from(a.s_addr.to_ne_bytes()) // s_addr is already big-endian
    }
}

impl From<in_addr> for IpAddr {
    #[inline]
    fn from(a: in_addr) -> Self {
        Self::V4(a.into())
    }
}

impl From<in6_addr> for Ipv6Addr {
    #[inline]
    fn from(a: in6_addr) -> Self {
        // SAFETY: safe to read.
        Self::from(unsafe { a.__u6_addr.__u6_addr8 })
    }
}

impl From<in6_addr> for IpAddr {
    #[inline]
    fn from(a: in6_addr) -> Self {
        Self::V6(a.into())
    }
}

impl pf_addr {
    /// Converts `pf_addr` to an [`IpAddr`].
    #[must_use]
    pub fn to_ip(self, af: sa_family_t) -> IpAddr {
        match af {
            // SAFETY: this is an IPv4 address.
            AF_INET => unsafe { self.pfa.v4 }.into(),
            // SAFETY: this is an IPv6 address.
            AF_INET6 => unsafe { self.pfa.v6 }.into(),
            _ => unimplemented!(),
        }
    }

    /// Converts `pf_addr` and port to a [`SocketAddr`].
    #[must_use]
    pub fn to_sock(self, af: sa_family_t, port: u_int16_t) -> SocketAddr {
        SocketAddr::new(self.to_ip(af), u16::from_be(port))
    }
}

impl Default for pf_pool {
    fn default() -> Self {
        // SAFETY: all-zero value is valid.
        let mut p: Self = unsafe { mem::zeroed() };
        p.addr.type_ = PF_ADDR_NONE;
        p
    }
}

impl Default for pf_rule {
    fn default() -> Self {
        // SAFETY: all-zero value is valid.
        let mut r: Self = unsafe { mem::zeroed() };
        r.onrdomain = -1;
        r.rtableid = -1;
        r.nat.addr.type_ = PF_ADDR_NONE;
        r.rdr.addr.type_ = PF_ADDR_NONE;
        r.route.addr.type_ = PF_ADDR_NONE;
        r
    }
}

/// Provides ioctl method for file descriptors.
pub trait Ioctl {
    /// Executes ioctl with the specified request and argument.
    fn ioctl<T>(&self, req: c_ulong, arg: *mut T) -> io::Result<()>;
}

impl<F: AsRawFd> Ioctl for F {
    #[inline]
    fn ioctl<T>(&self, req: c_ulong, arg: *mut T) -> io::Result<()> {
        // SAFETY: caller ensures that the ioctl is correct, but no benefit in
        // wrapping every call site with unsafe.
        if unsafe { ioctl(self.as_raw_fd(), req, arg) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Returns the last OS error for the current thread.
#[expect(dead_code)]
#[inline]
#[must_use]
pub fn errno() -> i32 {
    // SAFETY: returned value is always Some.
    unsafe { io::Error::last_os_error().raw_os_error().unwrap_unchecked() }
}

/// Returns an errno-derived [`Err`] with the specified context.
#[inline]
pub fn errno_err<T>(context: impl Display + Send + Sync + 'static) -> Result<T> {
    Err(io::Error::last_os_error()).context(context)
}

/// Converts a C string into a fixed-size array.
#[inline]
#[must_use]
pub fn carray<const N: usize>(src: impl AsRef<CStr>) -> [c_char; N] {
    let src = src.as_ref().to_bytes_with_nul();
    assert!(src.len() <= N, "string too long");
    let mut dst = [0_i8; N];
    // SAFETY: dst is valid and has enough capacity. Overlap is not possible.
    unsafe { ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr().cast(), src.len()) }
    dst
}

/// Creates a C string from a char slice.
#[inline]
#[must_use]
pub fn cstr(src: &impl AsRef<[c_char]>) -> &CStr {
    let src = src.as_ref();
    // SAFETY: conversion from *const i8 to *const u8.
    let b = unsafe { slice::from_raw_parts(src.as_ptr().cast(), src.len()) };
    CStr::from_bytes_until_nul(b).unwrap()
}
