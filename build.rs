use std::{
    env,
    fmt::Write,
    fs::{self, create_dir_all, File},
    path::Path,
};

use libbpf_cargo::SkeletonBuilder;
use memmap2::Mmap;

const BINDGEN_HEADER: &str = "src/core/bpf_sys/include/bpf-sys.h";
const INCLUDE_PATHS: &[&str] = &[
    "src/core/events/bpf/include",
    "src/core/filters/meta/bpf/include",
    "src/core/filters/packets/bpf/include",
    "src/core/probe/bpf/include",
    "src/core/probe/kernel/bpf/include",
    "src/core/probe/user/bpf/include",
    "src/core/tracking/bpf/include",
    // Taking errno.h from libc instead of linux headers.
    // TODO: Remove when we fix proper header dependencies.
    "/usr/include/x86_64-linux-gnu",
    "vendor/linux/include",
    "vendor/linux/asm/x86/include",
];
const OVS_INCLUDES: &[&str] = &["src/module/ovs/bpf/include"];
const CLANG_ARGS: &[&str] = &["-Werror"];

fn get_probe_clang_args(extra_includes: Option<&[&str]>) -> String {
    let mut args: Vec<String> = CLANG_ARGS.iter().map(|x| x.to_string()).collect();
    args.push(INCLUDE_PATHS.iter().fold(String::new(), |mut output, x| {
        write!(output, "-I{x} ").unwrap();
        output
    }));

    args.push(
        extra_includes
            .unwrap_or_default()
            .iter()
            .fold(String::new(), |mut output, x| {
                write!(output, "-I{x} ").unwrap();
                output
            }),
    );
    args.join(" ")
}

// Not super fail safe (not using Path).
fn get_paths(source: &str) -> (String, String) {
    let (dir, file) = source.rsplit_once('/').unwrap();
    let (name, _) = file.split_once('.').unwrap();

    let out = format!("{dir}/.out");
    create_dir_all(out.as_str()).unwrap();

    (out, name.to_string())
}

fn build_hook(source: &str, extra_includes: Option<&[&str]>) {
    let (out, name) = get_paths(source);
    let output = format!("{}/{}.o", out.as_str(), name);
    let skel = format!("{}/{}.rs", out.as_str(), name);

    if let Err(e) = SkeletonBuilder::new()
        .source(source)
        .obj(output.as_str())
        .clang_args(get_probe_clang_args(extra_includes))
        .build()
    {
        panic!("{:?}", e);
    }

    let obj = File::open(output).unwrap();
    let obj: &[u8] = &unsafe { Mmap::map(&obj).unwrap() };
    let hook_skel = format!(
        r#" pub(crate) const
           DATA: &[u8] = &{obj:?}; "#
    );

    if let Err(e) = fs::write(skel, hook_skel) {
        panic!("{:?}", e);
    }

    println!("cargo:rerun-if-changed={source}");
    for inc in extra_includes.unwrap_or_default().iter() {
        println!("cargo:rerun-if-changed={inc}");
    }
}

fn build_probe(source: &str) {
    let (out, name) = get_paths(source);
    let output = format!("{}/{}.o", out.as_str(), name);
    let skel = format!("{out}/{name}.skel.rs");

    if let Err(e) = SkeletonBuilder::new()
        .source(source)
        .obj(output)
        .clang_args(get_probe_clang_args(None))
        .build_and_generate(skel)
    {
        panic!("{:?}", e);
    }

    println!("cargo:rerun-if-changed={source}");
}

fn gen_bindings() {
    let (inc_path, _) = BINDGEN_HEADER.rsplit_once('/').unwrap();

    bindgen::Builder::default()
        .header(BINDGEN_HEADER)
        .clang_arg(format!("-I{inc_path}"))
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .layout_tests(cfg!(feature = "test_bindgen_layout"))
        .fit_macro_constants(true)
        .generate()
        .expect("Failed during bindings generation")
        .write_to_file(format!("{}/bpf_gen.rs", env::var("OUT_DIR").unwrap()))
        .expect("Failed writing bindings");
}

fn main() {
    gen_bindings();

    // core::probe::kernel
    build_probe("src/core/probe/kernel/bpf/kprobe.bpf.c");
    build_probe("src/core/probe/kernel/bpf/kretprobe.bpf.c");
    build_probe("src/core/probe/kernel/bpf/raw_tracepoint.bpf.c");
    build_probe("src/core/probe/user/bpf/usdt.bpf.c");

    build_hook("src/module/skb/bpf/skb_hook.bpf.c", None);
    build_hook("src/module/skb_drop/bpf/skb_drop_hook.bpf.c", None);
    build_hook("src/module/skb_tracking/bpf/tracking_hook.bpf.c", None);
    build_hook(
        "src/module/ovs/bpf/kernel_enqueue.bpf.c",
        Some(OVS_INCLUDES),
    );
    build_hook(
        "src/module/ovs/bpf/kernel_exec_actions.bpf.c",
        Some(OVS_INCLUDES),
    );
    build_hook(
        "src/module/ovs/bpf/kernel_exec_actions_ret.bpf.c",
        Some(OVS_INCLUDES),
    );
    build_hook(
        "src/module/ovs/bpf/kernel_exec_tp.bpf.c",
        Some(OVS_INCLUDES),
    );
    build_hook(
        "src/module/ovs/bpf/kernel_upcall_tp.bpf.c",
        Some(OVS_INCLUDES),
    );
    build_hook(
        "src/module/ovs/bpf/kernel_upcall_ret.bpf.c",
        Some(OVS_INCLUDES),
    );
    build_hook(
        "src/module/ovs/bpf/user_recv_upcall.bpf.c",
        Some(OVS_INCLUDES),
    );
    build_hook("src/module/ovs/bpf/user_op_exec.bpf.c", Some(OVS_INCLUDES));
    build_hook("src/module/ovs/bpf/user_op_put.bpf.c", Some(OVS_INCLUDES));
    build_hook("src/module/nft/bpf/nft.bpf.c", None);
    build_hook("src/module/ct/bpf/ct.bpf.c", None);

    for inc in INCLUDE_PATHS.iter() {
        // Useful to avoid to always rebuild on systems that don't use
        // triplet multi-arch paths. This is harmless, but can be
        // removed once the header dependency gets rearranged.
        if Path::new(inc).exists() {
            println!("cargo:rerun-if-changed={inc}");
        }
    }

    println!("cargo:rerun-if-changed={BINDGEN_HEADER}");
}
