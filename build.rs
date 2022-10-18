use std::fs::create_dir_all;

use libbpf_cargo::SkeletonBuilder;

static INCLUDE_PATH: &str = "src/core/probe/kernel/bpf/include";

// Not super fail safe (not using Path).
fn get_paths(source: &str) -> (String, String) {
    let (dir, file) = source.rsplit_once('/').unwrap();
    let (name, _) = file.split_once('.').unwrap();

    let out = format!("{}/.out", dir);
    create_dir_all(out.as_str()).unwrap();

    (out, name.to_string())
}

fn build_probe(source: &str) {
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

fn main() {
    // core::probe::kernel
    build_probe("src/core/probe/kernel/bpf/kprobe.bpf.c");

    println!("cargo:rerun-if-changed={}", INCLUDE_PATH);
}
