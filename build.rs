#![allow(dead_code)] // FIXME

use std::{
    fs::{create_dir_all, File},
    io::Write,
};

use libbpf_cargo::SkeletonBuilder;
use memmap2::Mmap;

static INCLUDE_PATHS: &[&str] = &[
    "src/core/probe/kernel/bpf/include",
    "src/core/events/bpf/include",
];

// Not super fail safe (not using Path).
fn get_paths(source: &str) -> (String, String) {
    let (dir, file) = source.rsplit_once('/').unwrap();
    let (name, _) = file.split_once('.').unwrap();

    let out = format!("{}/.out", dir);
    create_dir_all(out.as_str()).unwrap();

    (out, name.to_string())
}

fn build_hook(source: &str) {
    let (out, name) = get_paths(source);
    let output = format!("{}/{}.o", out.as_str(), name);
    let skel = format!("{}/{}.rs", out.as_str(), name);

    if let Err(e) = SkeletonBuilder::new()
        .source(source)
        .obj(output.as_str())
        .clang_args(
            INCLUDE_PATHS
                .iter()
                .map(|x| format!("-I{} ", x))
                .collect::<String>(),
        )
        .build()
    {
        panic!("{}", e);
    }

    let obj = File::open(output).unwrap();
    let obj: &[u8] = &unsafe { Mmap::map(&obj).unwrap() };

    let mut rs = File::create(skel).unwrap();
    write!(
        rs,
        r#"
           pub(crate) const DATA: &[u8] = &{:?};
           "#,
        obj
    )
    .unwrap();

    println!("cargo:rerun-if-changed={}", source);
}

fn build_probe(source: &str) {
    let (out, name) = get_paths(source);
    let skel = format!("{}/{}.skel.rs", out, name);

    if let Err(e) = SkeletonBuilder::new()
        .source(source)
        .clang_args(
            INCLUDE_PATHS
                .iter()
                .map(|x| format!("-I{} ", x))
                .collect::<String>(),
        )
        .build_and_generate(skel)
    {
        panic!("{}", e);
    }

    println!("cargo:rerun-if-changed={}", source);
}

fn main() {
    // core::probe::kernel
    build_probe("src/core/probe/kernel/bpf/kprobe.bpf.c");
    build_probe("src/core/probe/kernel/bpf/raw_tracepoint.bpf.c");

    // collector::skb_tracking
    build_hook("src/collector/skb_tracking/bpf/tracking_hook.bpf.c");

    for inc in INCLUDE_PATHS.iter() {
        println!("cargo:rerun-if-changed={}", inc);
    }
}
