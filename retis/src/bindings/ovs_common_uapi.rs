/* automatically generated by rust-bindgen 0.70.1 */

pub type __u32 = ::std::os::raw::c_uint;
pub type __u64 = ::std::os::raw::c_ulonglong;
pub type u32_ = __u32;
pub type u64_ = __u64;
pub type bool_ = bool;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct upcall_context {
    pub ts: u64_,
    pub cpu: u32_,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct execute_actions_ctx {
    pub skb: *mut ::std::os::raw::c_void,
    pub n_mask_hit: *mut u32_,
    pub n_cache_hit: *mut u32_,
    pub queue_id: u32_,
    pub command: bool_,
}
impl Default for execute_actions_ctx {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
