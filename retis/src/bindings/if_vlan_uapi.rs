/* automatically generated by rust-bindgen 0.70.1 */

pub type __u8 = ::std::os::raw::c_uchar;
pub type __u16 = ::std::os::raw::c_ushort;
pub type u8_ = __u8;
pub type u16_ = __u16;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct skb_vlan_event {
    pub proto: u16_,
    pub pcp: u8_,
    pub dei: u8_,
    pub vid: u16_,
}
