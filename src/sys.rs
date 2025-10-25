use anyhow::Context as _;
use std::ffi::CStr;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::c_char;
use std::{io, ptr, slice};

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
    fn from(a: in_addr) -> Self {
        Self::from(a.s_addr.to_ne_bytes()) // s_addr is already big-endian
    }
}

impl From<in_addr> for IpAddr {
    fn from(a: in_addr) -> Self {
        Self::V4(a.into())
    }
}

impl From<in6_addr> for Ipv6Addr {
    fn from(a: in6_addr) -> Self {
        // SAFETY: safe to read.
        Self::from(unsafe { a.__u6_addr.__u6_addr8 })
    }
}

impl From<in6_addr> for IpAddr {
    fn from(a: in6_addr) -> Self {
        Self::V6(a.into())
    }
}

/// Returns an errno-derived [`Err`] with the specified context.
pub fn errno<T>(context: impl Display + Send + Sync + 'static) -> anyhow::Result<T> {
    Err(io::Error::last_os_error()).context(context)
}

/// Copies C string from src to dst.
pub fn cstrcpy<const N: usize>(dst: *mut [c_char; N], src: impl AsRef<CStr>) {
    let src = src.as_ref().to_bytes_with_nul();
    assert!(!dst.is_null() && src.len() <= N, "dst is null or too short");
    // SAFETY: dst is valid and has enough capacity. Overlap is not possible
    // because reference and pointer accesses cannot be interleaved.
    unsafe { ptr::copy_nonoverlapping(src.as_ptr(), dst.cast(), src.len()) }
}

pub fn cstr(src: &impl AsRef<[c_char]>) -> &CStr {
    let src = src.as_ref();
    // SAFETY: conversion from *const i8 to *const u8.
    let b = unsafe { slice::from_raw_parts(src.as_ptr().cast(), src.len()) };
    CStr::from_bytes_until_nul(b).unwrap()
}
