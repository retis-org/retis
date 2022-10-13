use std::fs::create_dir_all;
use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "./src/core/probe/type/bpf";
const OUT: &str = "./src/core/probe/type/bpf/.out";

fn core_probe_type_bpf_build() {
    create_dir_all(OUT).unwrap();

    // List all BPF objects to build. Their names must follow the rule
    // <name>.bpf.c and be located in the SRC directory.
    build("fexit");
    build("kprobe");
    build("raw_tracepoint");
}

fn build(target: &str) {
    let source_file = format!("{}/{}.bpf.c", SRC, target);
    let output_file = format!("{}/{}.skel.rs", OUT, target);

    if let Err(e) = SkeletonBuilder::new()
            .source(source_file.as_str()).build_and_generate(output_file) {
        panic!("{}", e);
    }
    // FIXME: take headers into account and uncomment
    //println!("cargo:rerun-if-changed={}", source_file);
}
