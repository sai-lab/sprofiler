use std::path::PathBuf;

use anyhow::Result;
use sprofiler_sys::lang::golang::GoSeccompProfiler;
use sprofiler_sys::lang::SeccompProfiler;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "sprofile")]
struct Command {
    /// Activate debug mode
    #[structopt(short, long)]
    debug: bool,

    /// Input binary file
    #[structopt(short, long, parse(from_os_str))]
    bin: PathBuf,

    /// Output seccomp profile path
    #[structopt(short, long, parse(from_os_str))]
    out: PathBuf,
    // TODO: Language Option
    // --go, --rust
}

fn main() -> Result<()> {
    let command = Command::from_args();

    let sprofiler = GoSeccompProfiler {
        target_bin: command.bin,
        destination: command.out,
    };

    sprofiler.output()?;

    Ok(())
}
