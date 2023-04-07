/// eBPF filter wrapper containing the sequence of bytes composing the eBPF program
#[derive(Clone)]
pub(crate) struct BpfFilter(pub(crate) Vec<u8>);

#[derive(Clone)]
pub(crate) enum Filter {
    Packet(BpfFilter),
}
