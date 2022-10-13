use std::{
    fs::{create_dir_all, File},
    io::Write,
};

use libbpf_cargo::SkeletonBuilder;
use memmap2::Mmap;

static INCLUDE_PATH: &str = "src/core/probe/type/bpf/include";

// Not super fail safe (not using Path).
fn get_paths(source: &str) -> (String, String) {
    let (dir, file) = source.rsplit_once('/').unwrap();
    let (name, _) = file.split_once('.').unwrap();

    let out = format!("{}/.out", dir);
    create_dir_all(out.as_str()).unwrap();

    (out, name.to_string())
}

fn build_bpf(source: &str) {
    let (out, name) = get_paths(source);
    let skel = format!("{}/{}.skel.rs", out, name);

    if let Err(e) = SkeletonBuilder::new()
        .source(source)
        .clang_args(format!("-I{}", INCLUDE_PATH))
        .build_and_generate(skel)
    {
        panic!("{}", e);
    }

    println!("cargo:rerun-if-changed={}", source);
}

fn build_hook(source: &str) {
    let (out, name) = get_paths(source);
    let output = format!("{}/{}.o", out.as_str(), name);
    let skel = format!("{}/{}.rs", out.as_str(), name);

    if let Err(e) = SkeletonBuilder::new()
        .source(source)
        .obj(output.as_str())
        .clang_args(format!("-I{}", INCLUDE_PATH))
        .build()
    {
        panic!("{}", e);
    }

    let obj = File::open(output).unwrap();
    let obj: &[u8] = &*unsafe { Mmap::map(&obj).unwrap() };

    let mut rs = File::create(skel).unwrap();
    write!(
        rs,
        r#"
           pub(crate) const DATA: &[u8] = &{:?};
           "#,
        obj
    )
    .unwrap();
}

fn main() {
    // core::probe
    build_bpf("src/core/probe/type/bpf/fexit.bpf.c");
    build_bpf("src/core/probe/type/bpf/kprobe.bpf.c");
    build_bpf("src/core/probe/type/bpf/raw_tracepoint.bpf.c");

    // collector::skb
    build_hook("src/collector/skb/bpf/hook.bpf.c");
    build_hook("src/collector/net/bpf/hook.bpf.c");

    println!("cargo:rerun-if-changed={}", INCLUDE_PATH);
}
