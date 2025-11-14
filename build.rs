#![expect(missing_docs)]

use bindgen::Formatter;
use bindgen::callbacks::{IntKind, ItemInfo, ParseCallbacks, Token};
use cexpr::token::Kind;
use std::fs::{File, OpenOptions};
use std::io::BufWriter;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::OnceLock;
use std::{env, fs, io};

fn main() {
    ensure_libclang_path();
    let bindings = if cfg!(target_os = "openbsd") {
        println!("cargo:rustc-link-lib=pcap");
        bindgen::builder()
    } else {
        if !fs::metadata("include").is_ok_and(|m| m.is_dir()) {
            return;
        }
        bindgen::builder().clang_args(&["-Iinclude", "-D__PCC__", "-D_SIZE_T_DEFINED_"])
    }
    .header("wrapper.h")
    .allowlist_file(r".*sys/errno\.h")
    .allowlist_file("wrapper.h")
    .allowlist_var("AF_INET6?")
    .allowlist_var("CTL_KERN")
    .allowlist_var("DIOC.*")
    .allowlist_var("DLT_PFLOG")
    .allowlist_var("IFF_UP")
    .allowlist_var("IFNAMSIZ")
    .allowlist_var("IPPROTO_.*")
    .allowlist_var("KERN_OSREV")
    .allowlist_var("LOG_.*")
    .allowlist_var("PCAP_.*")
    .allowlist_var("PF_.*")
    .allowlist_var("PFRES_.*")
    .allowlist_var("SIG_BLOCK")
    .allowlist_var("SIOC.*")
    .allowlist_var("SOCK_DGRAM")
    .allowlist_type("ifreq")
    .allowlist_type("ip")
    .allowlist_type("ip6_(?:hdr|frag)")
    .allowlist_type("pf_status")
    .allowlist_type("pfioc_rule")
    .allowlist_type("pfioc_state_kill")
    .allowlist_type("pfioc_states?")
    .allowlist_type("pfioc_trans")
    .allowlist_type("pfloghdr")
    .allowlist_type("udphdr")
    .allowlist_function("ioctl")
    .allowlist_function("pcap_.*")
    .allowlist_function("pthread_sigmask")
    .allowlist_function("sigfillset")
    .allowlist_function("socket")
    .allowlist_function("sysctl")
    .allowlist_function("sendsyslog")
    .layout_tests(false)
    .impl_debug(true)
    .no_debug("ip6_hdr") // https://github.com/rust-lang/rust-bindgen/issues/2221
    .no_debug("pfioc_state")
    .no_debug("pfsync_state")
    .derive_default(true)
    .no_default("pf_pool")
    .no_default("pf_rule")
    .generate_inline_functions(true) // For sigfillset
    .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
    .parse_callbacks(Box::new(Callbacks))
    .clang_macro_fallback() // https://github.com/rust-lang/rust-bindgen/issues/753
    .formatter(Formatter::Prettyplease)
    .generate()
    .expect("Failed to generate bindings");

    let mut w = Writer::open("bindgen.rs").expect("Failed to open bindgen.rs");
    (bindings.write(Box::new(&mut w))).expect("Failed to write bindings");

    if let Some(names) = PFRES_NAMES.get() {
        writeln!(w.0, "pub static PFRES_NAMES: [&str; {}] = [", names.len()).unwrap();
        for name in names {
            writeln!(w.0, "    {name},").unwrap();
        }
        writeln!(w.0, "];").unwrap();
    }
    w.flush().expect("Failed to flush bindings");
}

/// Workaround for bindgen not handling macro arrays:
/// <https://github.com/rust-lang/rust-bindgen/issues/1266>
static PFRES_NAMES: OnceLock<Vec<String>> = OnceLock::new();

#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn modify_macro(&self, name: &str, tokens: &mut Vec<Token>) {
        if name != "PFRES_NAMES" {
            return;
        }
        PFRES_NAMES.get_or_init(|| {
            let mut v = Vec::with_capacity(32);
            for t in tokens {
                if t.kind == Kind::Literal {
                    v.push(str::from_utf8(&t.raw).unwrap().to_owned());
                }
            }
            v
        });
    }

    fn int_macro(&self, name: &str, val: i64) -> Option<IntKind> {
        if name.starts_with('E') && name.chars().all(|c| c.is_ascii_uppercase()) {
            return Some(IntKind::I32); // errno
        }
        if name.starts_with("IPPROTO_") {
            return (val <= u8::MAX.into()).then_some(IntKind::U8);
        }
        let signed = |name| IntKind::Custom {
            name,
            is_signed: true,
        };
        let unsigned = |name| IntKind::Custom {
            name,
            is_signed: false,
        };
        [
            ("AF_*", unsigned("sa_family_t")),
            ("CTL_*", IntKind::Int),
            ("DIOC*", IntKind::ULong),
            ("DLT_*", IntKind::Int),
            ("IFF_*", IntKind::Short),
            ("IFNAMSIZ", unsigned("usize")),
            ("KERN_*", IntKind::Int),
            ("LOG_*", IntKind::Int),
            ("NO_PID", signed("pid_t")),
            ("PCAP_ERRBUF_SIZE", unsigned("usize")),
            ("PF_LOG_*", IntKind::U8),
            ("PF_*_SIZE", unsigned("usize")),
            ("PFLOG_HDRLEN", unsigned("usize")),
            ("PFRES_*", IntKind::U8),
            ("SIG_*", IntKind::Int),
            ("SIOC*", IntKind::ULong),
            ("SOCK_*", IntKind::Int),
        ]
        .into_iter()
        .find_map(|(p, k)| match p.split_once('*') {
            None => (name == p).then_some(k),
            Some((l, r)) => (name.starts_with(l) && name.ends_with(r)).then_some(k),
        })
    }

    fn item_name(&self, it: ItemInfo<'_>) -> Option<String> {
        // Remove longest duplicated prefix (e.g. pfioc_trans_pfioc_trans_e ->
        // pfioc_trans_e).
        it.name.rmatch_indices('_').find_map(|(i, _)| {
            let (l, r) = it.name.split_at_checked(i + 1)?;
            r.starts_with(l).then(|| r.to_owned())
        })
    }
}

/// A writer that edits generated code to fix anonymous PF_ enum types that
/// [can't be changed][2392] via callbacks.
///
/// [2392]: https://github.com/rust-lang/rust-bindgen/issues/2392
struct Writer(BufWriter<File>);

impl Writer {
    fn open(name: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self(BufWriter::new(
            (OpenOptions::new().write(true).truncate(true).create(true))
                .open(PathBuf::from(env::var("OUT_DIR").unwrap()).join(name))?,
        )))
    }
}

impl io::Write for Writer {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        unimplemented!("write_all bypassed")
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        for ln in str::from_utf8(buf).unwrap().lines() {
            if ln.starts_with("pub type _bindgen_ty_") {
                continue;
            }
            if let Some(ln) = ln.strip_prefix("pub const PF_")
                && let Some((name, r)) = ln.split_once(": _bindgen_ty_")
                && let Some((_, val)) = r.split_once("= ")
            {
                let typ = [
                    ("CHANGE_", "u_int32_t"),
                    ("GET_", "u_int32_t"),
                    ("SK_", "usize"),
                    ("TRANS_", "::std::os::raw::c_int"),
                ]
                .into_iter()
                .find_map(|(p, t)| name.starts_with(p).then_some(t))
                .unwrap_or("u_int8_t");
                writeln!(self.0, "pub const PF_{name}: {typ} = {val}")?;
            } else {
                writeln!(self.0, "{ln}")?;
            }
        }
        Ok(())
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
