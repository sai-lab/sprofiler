use crate::oci::LinuxSeccomp;
use anyhow::Result;

pub mod golang;

pub trait SeccompProfiler {
    fn analyze(&self) -> Result<LinuxSeccomp>;
    fn output(&self) -> Result<()>;
}
