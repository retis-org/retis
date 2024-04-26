// Re-export nft.rs
#[allow(clippy::module_inception)]
pub(crate) mod nft;
pub(crate) use nft::*;

mod bpf;
mod nft_hook {
    include!("bpf/.out/nft.rs");
}
