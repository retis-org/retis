use anyhow::{bail, Result};
use caps::{self, CapSet, Capability};
use log::warn;

use super::{inspect, kernel_version::KernelVersionReq};

/// Check various prerequisites for Retis to properly work, allowing to bail out
/// early and to explain what isn't compatible to the user. This helper can also
/// be used to show warning or information that do not prevent Retis from
/// starting.
pub(crate) fn collection_prerequisites() -> Result<()> {
    let inspector = inspect::inspector()?;
    let kver = inspector.kernel.version();

    // Check we have CAP_BPF.
    if !caps::has_cap(None, CapSet::Permitted, Capability::CAP_BPF)? {
        bail!("Retis does not have CAP_BPF: can't install probes.");
    }

    // Check for a potential incompatibility when CONFIG_X86_KERNEL_IBT=y on
    // old kernels. For a full explanation see
    // src/core/probe/kernel/bpf/include/helpers.h.
    if let Ok(ksym) = inspector.kernel.get_config_option("CONFIG_X86_KERNEL_IBT") {
        if ksym == Some("y") && KernelVersionReq::parse("< 6.1")?.matches(kver) {
            // get_entry_ip takes CONFIG_X86_KERNEL_IBT into account in
            // bpf_get_func_ip, if not found we might have a problem (but it
            // could have been inlined too...).
            if inspector
                .kernel
                .btf
                .resolve_type_by_name("get_entry_ip")
                .is_err()
            {
                warn!(
                    "It is possible Retis will fail to retrieve some events:
On kernels < 6.1, the BPF helper bpf_get_func_ip (used by Retis) might not take \
into account CONFIG_X86_KERNEL_IBT=y (which is set on the running kernel) \
resulting on *some* probes not being able to work properly."
                );
            }
        }
    }

    Ok(())
}
