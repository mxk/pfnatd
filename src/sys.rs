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

impl From<Ipv4Addr> for in_addr {
    #[inline]
    fn from(v: Ipv4Addr) -> Self {
        Self {
            s_addr: u32::from_ne_bytes(v.octets()),
        }
    }
}

impl From<in6_addr> for Ipv6Addr {
    #[inline]
    fn from(a: in6_addr) -> Self {
        // SAFETY: safe to read.
        Self::from(unsafe { a.__u6_addr.__u6_addr8 })
    }
}

impl From<Ipv6Addr> for in6_addr {
    #[inline]
    fn from(v: Ipv6Addr) -> Self {
        Self {
            __u6_addr: in6_addr__bindgen_ty_1 {
                __u6_addr8: v.octets(),
            },
        }
    }
}

impl From<IpAddr> for pf_addr {
    #[inline]
    fn from(v: IpAddr) -> Self {
        Self {
            pfa: match v {
                IpAddr::V4(v) => pf_addr__bindgen_ty_1 {
                    v4: in_addr::from(v),
                },
                IpAddr::V6(v) => pf_addr__bindgen_ty_1 {
                    v6: in6_addr::from(v),
                },
            },
        }
    }
}

impl From<IpAddr> for pf_addr_wrap {
    fn from(v: IpAddr) -> Self {
        Self {
            v: pf_addr_wrap__bindgen_ty_1 {
                a: pf_addr_wrap__bindgen_ty_1__bindgen_ty_1 {
                    addr: pf_addr::from(v),
                    mask: pf_addr {
                        pfa: pf_addr__bindgen_ty_1 {
                            addr8: u128::MAX.to_ne_bytes(),
                        },
                    },
                },
            },
            p: pf_addr_wrap__bindgen_ty_2::default(),
            type_: PF_ADDR_ADDRMASK,
            iflags: 0,
        }
    }
}

impl From<SocketAddr> for pf_rule_addr {
    fn from(s: SocketAddr) -> Self {
        Self {
            addr: pf_addr_wrap::from(s.ip()),
            port: [s.port().to_be(), 0],
            neg: 0,
            port_op: PF_OP_EQ,
            weight: 0,
        }
    }
}

impl From<SocketAddr> for pf_pool {
    fn from(s: SocketAddr) -> Self {
        let port = s.port(); // proxy_port uses native byte order
        Self {
            addr: pf_addr_wrap::from(s.ip()),
            proxy_port: [port, port],
            ..Default::default()
        }
    }
}

impl pf_addr {
    /// Converts `pf_addr` and port to a [`SocketAddr`].
    #[must_use]
    pub fn to_sock(self, af: sa_family_t, port: u_int16_t) -> SocketAddr {
        SocketAddr::new(self.to_ip(af), u16::from_be(port))
    }

    /// Converts `pf_addr` to an [`IpAddr`].
    #[must_use]
    fn to_ip(self, af: sa_family_t) -> IpAddr {
        match af {
            // SAFETY: this is an IPv4 address.
            AF_INET => IpAddr::V4(Ipv4Addr::from(unsafe { self.pfa.v4 })),
            // SAFETY: this is an IPv6 address.
            AF_INET6 => IpAddr::V6(Ipv6Addr::from(unsafe { self.pfa.v6 })),
            _ => unimplemented!(),
        }
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

/// Returns an errno-derived [`Err`] with the specified context.
#[inline]
pub fn errno_err<T>(context: impl Display + Send + Sync + 'static) -> Result<T> {
    Err(io::Error::last_os_error()).context(context)
}

/// Converts a C string into a fixed-size array.
#[inline]
#[must_use]
pub const fn carray<const N: usize>(src: &CStr) -> [c_char; N] {
    let src = src.to_bytes_with_nul();
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

/// Returns [`sa_family_t`] of the specified `ip`.
#[inline]
#[must_use]
pub const fn sa_family(ip: IpAddr) -> sa_family_t {
    match ip {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    }
}
