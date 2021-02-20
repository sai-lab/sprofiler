use anyhow::Result;

use sprofiler_sys::lang::golang::GoSeccompProfiler;
use sprofiler_sys::lang::SeccompProfiler;

fn main() -> Result<()> {
    let sprofiler = GoSeccompProfiler::default();
    let seccomp = sprofiler.analyze()?;
    serde_json::to_writer(std::io::stdout(), &seccomp)?;
    Ok(())
}
