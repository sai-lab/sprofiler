use anyhow::Result;
use sprofiler_sys;

fn main() -> Result<()> {
    let seccomp = sprofiler_sys::oci::LinuxSeccomp::default();
    serde_json::to_writer(std::io::stdout(), &seccomp)?;
    Ok(())
}
