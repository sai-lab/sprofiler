use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

pub fn create_seccomp_profile<P: AsRef<Path>>(base_dir: P, name: &str) -> Result<PathBuf>
where
    PathBuf: From<P>,
{
    let seccomp_dir = base_dir.as_ref().join("seccomp-profile.d");
    fs::create_dir_all(&seccomp_dir)?;

    Ok(seccomp_dir.join(format!("{name}.json")))
}
