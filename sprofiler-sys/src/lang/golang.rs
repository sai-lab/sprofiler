use std::path::PathBuf;

use anyhow::Result;

use crate::lang::SeccompProfiler;
use crate::oci::LinuxSeccomp;

#[derive(Default)]
pub struct GoSeccompProfiler {
    pub destination: PathBuf,
    pub target_bin: PathBuf,
}

impl SeccompProfiler for GoSeccompProfiler {
    fn analyze(&self) -> Result<LinuxSeccomp> {
        Ok(LinuxSeccomp::default())
    }
}
