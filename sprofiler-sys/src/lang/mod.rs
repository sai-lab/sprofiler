use anyhow::Result;
use oci_runtime_spec::LinuxSeccomp;

pub mod golang;

pub trait SeccompProfiler {
    fn analyze(&self) -> Result<LinuxSeccomp>;
    fn output(&self) -> Result<()>;
}
