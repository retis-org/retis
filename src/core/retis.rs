use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};

use crate::{
    core::{
        events::*,
        probe::{
            kernel::{config::init_stack_map, KernelEvent},
            ProbeManager,
        },
    },
    module::{ModuleId, Modules},
};

/// This is the main API entry point to access core functionalities, modules and
/// events.
///
/// We do not redefine all helpers provided by its different members and instead
/// let consumer directly access them.
pub(crate) struct Retis {
    /// Event factories. We currently only support a single instance but later
    /// additions might change this.
    pub(crate) factory: Box<dyn EventFactory>,
    /// Probe manager, used to install hooks & probes in the kernel and
    /// userspace. This might not be available for some commands.
    pub(crate) probes: Option<ProbeManager>,
}

impl Retis {
    pub(crate) fn new(factory: Box<dyn EventFactory>) -> Self {
        Retis {
            factory,
            probes: None,
        }
    }

    /// Enable the probing API.
    pub(crate) fn enable_probes(&mut self, modules: &mut Modules, event_map_fd: i32) -> Result<()> {
        let mut probes = ProbeManager::new()?;
        probes.reuse_map("events_map", event_map_fd)?;

        // Initialize the stack map and reuse it across probes.
        let sm = init_stack_map()?;
        probes.reuse_map("stack_map", sm.fd())?;
        match modules.get_section_factory::<KernelEvent>(ModuleId::Kernel)? {
            Some(kernel_factory) => kernel_factory.stack_map = Some(sm),
            None => bail!("Can't get kernel section factory"),
        }

        self.probes = Some(probes);
        Ok(())
    }

    /// Start the events factory.
    pub(crate) fn start_factory(
        &mut self,
        section_factories: HashMap<ModuleId, Box<dyn EventSectionFactory>>,
    ) -> Result<()> {
        self.factory.start(section_factories)
    }

    /// Get a mutable reference to the probes API.
    pub(crate) fn probes_mut(&mut self) -> Result<&mut ProbeManager> {
        self.probes
            .as_mut()
            .ok_or_else(|| anyhow!("Probe API is not enabled"))
    }
}
