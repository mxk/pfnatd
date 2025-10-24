#![expect(missing_docs)]

use bindgen::callbacks::{IntKind, ParseCallbacks};
use std::path::PathBuf;
use std::str::FromStr as _;
use std::{env, fs};

fn main() {
    ensure_libclang_path();
    println!("cargo:rustc-link-lib=pcap");

    if cfg!(target_os = "openbsd") {
        bindgen::builder()
    } else {
        bindgen::builder().clang_args(&["-Iinclude"])
    }
    .header("wrapper.h")
    .allowlist_file(r".*[/\\]if_pflog\.h") // pflog data types
    .allowlist_file(r".*[/\\]pfvar\.h") // pf API
    .allowlist_file(r".*[/\\]sockio\.h") // SIO* ioctls and _IO* macros
    .allowlist_file(r".*[/\\]ip6?\.h") // struct ip and ip6_hdr
    .allowlist_file(r".*[/\\]udp.h") // struct udphdr
    .allowlist_file("wrapper.h") // struct udphdr
    .allowlist_var("AF_INET6?")
    .allowlist_var("DLT_PFLOG")
    .allowlist_var("IFF_UP")
    .allowlist_var("IPPROTO_UDP")
    .allowlist_var("O_RDWR")
    .allowlist_var("PCAP_.*")
    .allowlist_var("SIG_BLOCK")
    .allowlist_var("SOCK_DGRAM")
    .allowlist_type("if_clonereq")
    .allowlist_type("ifreq")
    .allowlist_function("ioctl")
    .allowlist_function("pcap_.*")
    .allowlist_function("pthread_sigmask")
    .allowlist_function("sigfillset")
    .allowlist_function("socket")
    .generate_inline_functions(true)
    .derive_default(true)
    .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
    .parse_callbacks(Box::new(Callbacks))
    .clang_macro_fallback() // https://github.com/rust-lang/rust-bindgen/issues/753
    .generate()
    .expect("Failed to generate bindings")
    .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindgen.rs"))
    .expect("Failed to write bindings");
}

#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
        let signed = |name| IntKind::Custom {
            name,
            is_signed: true,
        };
        let unsigned = |name| IntKind::Custom {
            name,
            is_signed: false,
        };
        [
            ("AF_", unsigned("sa_family_t")),
            ("DIOC", IntKind::ULong),
            ("DLT_", IntKind::Int),
            ("IFF_UP", IntKind::Short),
            ("IPPROTO_", IntKind::U8),
            ("NO_PID", signed("pid_t")),
            ("O_", IntKind::Int),
            ("PCAP_ERRBUF_SIZE", unsigned("usize")),
            ("PFLOG_HDRLEN", unsigned("usize")),
            ("SIG_", IntKind::Int),
            ("SIOC", IntKind::ULong),
            ("SOCK_DGRAM", IntKind::Int),
        ]
        .into_iter()
        .find_map(|(p, k)| name.starts_with(p).then_some(k))
    }
}

/// Ensures that `LIBCLANG_PATH` is set. On OpenBSD, tries to locate the most
/// recent version of llvm.
fn ensure_libclang_path() {
    const PATH: &str = "LIBCLANG_PATH";
    if env::var_os(PATH).is_some() {
        return;
    }
    if cfg!(target_os = "openbsd") {
        fs::read_dir("/usr/local").ok().and_then(|dir| {
            dir.filter_map(Result::ok)
                .filter(|f| f.file_type().is_ok_and(|t| t.is_dir()))
                .filter_map(|f| {
                    f.file_name()
                        .to_str()
                        .and_then(|s| s.strip_prefix("llvm"))
                        .and_then(|v| u32::from_str(v).ok())
                })
                .max()
                // SAFETY: single-threaded program.
                .map(|v| unsafe { env::set_var(PATH, format!("/usr/local/llvm{v}/lib")) })
        });
    } else if cfg!(target_os = "windows")
        && let Some(mut path) = env::var_os("PROGRAMFILES")
    {
        path.push(r"\LLVM\bin");
        // SAFETY: single-threaded program.
        unsafe { env::set_var(PATH, path) };
    }
}
