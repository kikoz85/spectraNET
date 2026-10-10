//! On Linux, compiles the eBPF programs (ebpf/spectranet.bpf.c, ebpf/block.bpf.c) with clang
//! into OUT_DIR.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let source_dir = manifest.join("../../ebpf");
    println!(
        "cargo:rerun-if-changed={}",
        source_dir.join("vmlinux_min.h").display()
    );
    println!("cargo:rerun-if-env-changed=CLANG");
    let clang = std::env::var("CLANG").unwrap_or_else(|_| "clang".into());
    // The traffic probe, and the blocks (attached only while blocks are in force).
    for name in ["spectranet", "block"] {
        let source = source_dir.join(format!("{name}.bpf.c"));
        let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join(format!("{name}.bpf.o"));
        println!("cargo:rerun-if-changed={}", source.display());
        let status = Command::new(&clang)
            .args(["-O2", "-g", "-target", "bpf", "-Wall", "-Werror", "-c"])
            .arg(&source)
            .arg("-o")
            .arg(&out)
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => panic!("compiling the eBPF program {name} with {clang} failed ({s})"),
            Err(e) => panic!(
                "building spectraNET for Linux needs clang to compile its eBPF programs ({clang}: {e}); \
                 install clang (e.g. apt install clang) or set CLANG"
            ),
        }
    }
}
