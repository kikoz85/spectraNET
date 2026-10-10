//! CPU, memory, parent and owner of the processes in a snapshot, the same way on every
//! platform. Wraps any traffic source, so the backends stay about the network.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use spectranet_model::{Resources, Snapshot};
use sysinfo::{
    CpuRefreshKind, Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System, UpdateKind,
    Users,
};

use crate::{CaptureError, TrafficSource};

/// How often the account list is re-read when an unknown owner shows up.
const USERS_REFRESH: Duration = Duration::from_secs(60);

/// This machine's logical CPU count and total memory in bytes, to put a process's share
/// in proportion.
pub fn machine() -> (usize, u64) {
    let mut system = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::nothing())
            .with_memory(sysinfo::MemoryRefreshKind::nothing().with_ram()),
    );
    system.refresh_memory();
    (system.cpus().len().max(1), system.total_memory())
}

pub struct ResourceSampler {
    system: System,
    users: Users,
    users_read: Instant,
}

impl Default for ResourceSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceSampler {
    pub fn new() -> Self {
        Self {
            // The CPU list must be known: Windows scales process CPU by the number of CPUs
            // (and reports 0 without it).
            system: System::new_with_specifics(
                RefreshKind::nothing().with_cpu(CpuRefreshKind::nothing()),
            ),
            users: Users::new_with_refreshed_list(),
            users_read: Instant::now(),
        }
    }

    /// Resources of each PID. CPU is measured since the previous call, so the first
    /// sample of a process reports 0 %.
    pub fn sample(&mut self, pids: &[u32]) -> HashMap<u32, Resources> {
        let list: Vec<Pid> = pids.iter().map(|p| Pid::from_u32(*p)).collect();
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&list),
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_memory()
                .with_user(UpdateKind::OnlyIfNotSet),
        );
        let mut out = HashMap::with_capacity(pids.len());
        let mut unknown_owner = false;
        for pid in pids {
            let Some(p) = self.system.process(Pid::from_u32(*pid)) else {
                continue;
            };
            let user = p.user_id().and_then(|uid| {
                let name = self.users.get_user_by_id(uid).map(|u| u.name().to_string());
                unknown_owner |= name.is_none();
                name
            });
            out.insert(
                *pid,
                Resources {
                    ppid: p.parent().map(|pp| pp.as_u32()),
                    cpu_tenths: (p.cpu_usage().max(0.0) * 10.0).round() as u32,
                    memory: p.memory(),
                    user,
                },
            );
        }
        if unknown_owner && self.users_read.elapsed() > USERS_REFRESH {
            self.users.refresh();
            self.users_read = Instant::now();
        }
        out
    }
}

/// A traffic source whose snapshots carry each process's resources.
pub struct WithResources {
    inner: Box<dyn TrafficSource>,
    sampler: ResourceSampler,
}

impl WithResources {
    pub fn new(inner: Box<dyn TrafficSource>) -> Self {
        Self {
            inner,
            sampler: ResourceSampler::new(),
        }
    }
}

impl TrafficSource for WithResources {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn sample(&mut self) -> Result<Snapshot, CaptureError> {
        let mut snapshot = self.inner.sample()?;
        let pids: Vec<u32> = snapshot.processes.iter().map(|p| p.process.pid).collect();
        let mut resources = self.sampler.sample(&pids);
        for p in &mut snapshot.processes {
            p.resources = resources.remove(&p.process.pid);
        }
        Ok(snapshot)
    }

    fn notices(&self) -> Vec<String> {
        self.inner.notices()
    }

    fn first_sample_has_rates(&self) -> bool {
        self.inner.first_sample_has_rates()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_machine_has_cpus_and_memory() {
        let (cpus, memory) = super::machine();
        assert!(cpus >= 1);
        assert!(memory > 64 << 20);
    }

    use super::*;

    #[test]
    fn measures_this_process() {
        let me = std::process::id();
        let mut sampler = ResourceSampler::new();
        // Burn some CPU between samples. Windows needs one more sample than the others
        // before it reports CPU (the first only creates the process entry).
        let burn = || {
            let start = Instant::now();
            let mut x = 0u64;
            while start.elapsed() < Duration::from_millis(300) {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
            }
            std::hint::black_box(x);
        };
        let _ = sampler.sample(&[me]);
        burn();
        let _ = sampler.sample(&[me]);
        burn();
        let r = sampler.sample(&[me]).remove(&me).expect("this process");
        assert!(r.memory > 1_000_000, "resident memory: {}", r.memory);
        assert!(
            r.cpu_tenths > 100,
            "busy loop shows up as CPU: {}",
            r.cpu_tenths
        );
        assert!(r.ppid.is_some());
        assert!(r.user.is_some(), "owner resolved");
    }

    #[test]
    fn unknown_pids_are_skipped() {
        let mut sampler = ResourceSampler::new();
        assert!(sampler.sample(&[0xFFFF_FFF0]).is_empty());
        assert!(sampler.sample(&[]).is_empty());
    }
}
