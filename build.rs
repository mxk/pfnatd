use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=pcap");

    if cfg!(target_os = "openbsd") {
        bindgen::builder()
    } else {
        bindgen::builder().clang_args(&["-Iinclude"])
    }
    .header("wrapper.h")
    .allowlist_file(r".*[/\\]if_pflog\.h") // pflog data types
    .allowlist_file(r".*[/\\]pcap\.h") // pcap API
    .allowlist_file(r".*[/\\]pfvar\.h") // pf API
    .allowlist_file(r".*[/\\]sockio\.h") // SIO* ioctls and _IO* macros
    .allowlist_file(r".*[/\\]ip6?\.h") // struct ip and ip6_hdr
    .allowlist_file(r".*[/\\]udp.h") // struct udphdr
    .allowlist_file(r"wrapper.h") // struct udphdr
    .allowlist_type("if_clonereq")
    .allowlist_item("DLT_PFLOG")
    .generate_inline_functions(true)
    .derive_default(true)
    .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
    .clang_macro_fallback() // https://github.com/rust-lang/rust-bindgen/issues/753
    .generate()
    .expect("Failed to generate bindings")
    .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindgen.rs"))
    .expect("Failed to write bindings");
}
