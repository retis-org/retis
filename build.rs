use std::{env, fs::File, io::Write, path::Path};

use libbpf_cargo::SkeletonBuilder;
use memmap2::Mmap;

const BINDGEN_HEADER: &str = "src/core/bpf_sys/include/bpf-sys.h";

// Not super fail safe (not using Path).
fn get_paths(fpath: &str) -> (String, String) {
    let (dir, file) = fpath.rsplit_once('/').unwrap();
    let split: Vec<_> = file.split_terminator('.').collect();

    if let Some(basename) = split.first() {
        (dir.to_string(), basename.to_string())
    } else {
        panic!("Failed to find base name for {}", fpath);
    }
}

fn gen_hook_skel(source: &str) {
    let (dir, base) = get_paths(source);
    let skel = format!("{}/{}.rs", dir.as_str(), base);
    let obj_f = File::open(source).unwrap();
    let obj_f: &[u8] = &unsafe { Mmap::map(&obj_f).unwrap() };

    let mut rs = File::create(skel).unwrap();
    write!(
        rs,
        r#"
           pub(crate) const DATA: &[u8] = &{obj_f:?};
           "#
    )
    .unwrap();

    println!("cargo:rerun-if-changed={source}");
}

fn gen_probe_skel(source: &str) {
    let (dir, base) = get_paths(source);

    let skel = format!("{}/{}.skel.rs", dir.as_str(), base);
    if let Err(e) = SkeletonBuilder::new()
        .obj(source)
        .generate(Path::new(&skel))
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
    gen_probe_skel("src/core/probe/kernel/bpf/.out/kprobe.bpf.o");
    gen_probe_skel("src/core/probe/kernel/bpf/.out/kretprobe.bpf.o");
    gen_probe_skel("src/core/probe/kernel/bpf/.out/raw_tracepoint.bpf.o");
    gen_probe_skel("src/core/probe/user/bpf/.out/usdt.bpf.o");

    gen_hook_skel("src/module/skb/bpf/.out/skb_hook.bpf.o");
    gen_hook_skel("src/module/skb_drop/bpf/.out/skb_drop_hook.bpf.o");
    gen_hook_skel("src/module/skb_tracking/bpf/.out/tracking_hook.bpf.o");
    gen_hook_skel("src/module/ovs/bpf/.out/kernel_enqueue.bpf.o");
    gen_hook_skel("src/module/ovs/bpf/.out/kernel_exec_actions.bpf.o");
    gen_hook_skel("src/module/ovs/bpf/.out/kernel_exec_actions_ret.bpf.o");
    gen_hook_skel("src/module/ovs/bpf/.out/kernel_exec_tp.bpf.o");
    gen_hook_skel("src/module/ovs/bpf/.out/kernel_upcall_tp.bpf.o");
    gen_hook_skel("src/module/ovs/bpf/.out/kernel_upcall_ret.bpf.o");
    gen_hook_skel("src/module/ovs/bpf/.out/user_recv_upcall.bpf.o");
    gen_hook_skel("src/module/ovs/bpf/.out/user_op_exec.bpf.o");
    gen_hook_skel("src/module/ovs/bpf/.out/user_op_put.bpf.o");
    gen_hook_skel("src/module/nft/bpf/.out/nft.bpf.o");
    gen_hook_skel("src/module/ct/bpf/.out/ct.bpf.o");

    println!("cargo:rerun-if-changed={BINDGEN_HEADER}");
}
