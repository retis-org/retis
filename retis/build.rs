use std::{env, fs::File, io, io::ErrorKind, io::Write, path::Path};

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
    let obj_f = File::open(source).unwrap_or_else(|error| {
        if error.kind() == ErrorKind::NotFound {
            panic!("Unable to find {source}, please try 'make ebpf' first\n");
        } else {
            panic!("Error opening file: {:?}", error);
        }
    });
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
        match e.downcast_ref::<io::Error>() {
            Some(io_error) if io_error.kind() == ErrorKind::NotFound => {
                panic!("Unable to find {skel}, please try 'make ebpf' first\n");
            }
            _ => {
                panic!("{:?}", e);
            }
        }
    }

    println!("cargo:rerun-if-changed={source}");
}

// This establishes a naming convention. eBPF objs MUST be suffixed with
// .bpf.o.
fn walk_gen_skels<F>(dir: &str, cb: &F)
where
    F: Fn(&str),
{
    for entry in Path::new(dir).read_dir().expect("Failed to read {dir}") {
        let entry = entry.expect("Invalid entry in {dir}");
        if entry.path().is_dir() {
            walk_gen_skels(entry.path().to_str().expect("cannot convert {entry}"), cb);
            continue;
        }

        let entry_path = entry.path();
        let entry_str = entry_path.to_str().expect("cannot convert {entry}");
        if entry_str.ends_with(".bpf.o") {
            // Skip targets out of the expected directories.
            if !entry_str.contains("/bpf/.out/") {
                continue;
            }

            cb(entry_str);
        }
    }
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

    println!("cargo:rerun-if-changed={BINDGEN_HEADER}");
}

fn main() {
    gen_bindings();

    walk_gen_skels("src/core/probe/", &gen_probe_skel);
    walk_gen_skels("src/collect/collector/", &gen_hook_skel);
}
