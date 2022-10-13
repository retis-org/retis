use std::collections::{HashMap, HashSet};

use anyhow::{bail, Result};

mod config;
mod events;
mod kernel;
mod r#type;

// Re-export ProbeType.
use r#type::ProbeBuilder;
pub(crate) use r#type::ProbeType;

pub(crate) struct Probes<'a> {
    pub(crate) kernel: kernel::Kernel<'a>,
}

impl<'a> Probes<'a> {
    pub(crate) fn new() -> Result<Probes<'a>> {
        Ok(Probes {
            kernel: kernel::Kernel::new()?,
        })
    }

    pub(crate) fn attach(&mut self) -> Result<()> {
        self.kernel.attach()?;
        Ok(())
    }
}

/// Group of probes sharing a common target (e.g. kernel) and properties (e.g.
/// targetting functions having access to a "struct *sk_buff").
#[derive(Default)]
struct Group {
    /// Probe builders, used to create new probes of a give type.
    builders: HashMap<ProbeType, Box<dyn ProbeBuilder>>,
    /// List of targets we already have.
    targets: HashMap<ProbeType, HashSet<String>>,
    /// List of maps we already have.
    maps: HashMap<String, i32>,
    /// List of hooks.
    hooks: Vec<&'static [u8]>,
}

impl Group {
    fn new() -> Group {
        Group::default()
    }

    fn add_builder(&mut self, r#type: ProbeType, builder: Box<dyn ProbeBuilder>) -> Result<()> {
        if self.builders.contains_key(&r#type) {
            bail!("Prote type already in use");
        }

        self.builders.insert(r#type.clone(), builder);
        self.targets.insert(r#type, HashSet::new());
        Ok(())
    }

    fn reuse_map(&mut self, name: &str, fd: i32) -> Result<()> {
        let name = name.to_string();
        if self.maps.contains_key(&name) {
            bail!("Map {} already reused, or name is conflicting", name);
        }

        self.maps.insert(name, fd);
        Ok(())
    }

    fn add_probe(&mut self, r#type: ProbeType, target: &str) -> Result<()> {
        let target = target.to_string();

        let targets = match self.targets.get_mut(&r#type) {
            Some(t) => t,
            _ => bail!("Probe type not supported by this group"),
        };

        if !targets.contains(&target) {
            targets.insert(target);
        }

        Ok(())
    }

    fn add_hook(&mut self, hook: &'static [u8]) -> Result<()> {
        // FIXME: HARDCODED.
        if self.hooks.len() == 2 {
            bail!("Hooks list already full");
        }

        self.hooks.push(hook);

        Ok(())
    }

    fn attach(&mut self) -> Result<()> {
        let mut initialized = HashSet::new();
        for (r#type, targets) in self.targets.iter() {
            // There is a builder; the check was already done in
            // Self::add_probe.
            let builder = self.builders.get_mut(r#type).unwrap();

            // Initialize builders only once per type.
            if !initialized.contains(r#type) {
                let map_fds = self.maps.clone().into_iter().collect();
                builder.init(&map_fds, self.hooks.clone())?;
                initialized.insert(r#type);
            }

            // Attach all the targets.
            for target in targets.iter() {
                println!("Attaching to {}", target);
                builder.attach(target)?;
            }
        }

        Ok(())
    }
}
