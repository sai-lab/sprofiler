use std::path::PathBuf;

use anyhow::Result;
use sprofiler_sys::lang::golang::GoSeccompProfiler;
use sprofiler_sys::lang::SeccompProfiler;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "sprofiler")]
enum Command {
    Run {
        /// Input binary file
        #[structopt(short, long, parse(from_os_str))]
        bin: PathBuf,

        /// Output seccomp profile path
        #[structopt(short, long, parse(from_os_str))]
        out: PathBuf,
        // TODO: Language Option
        // #[structopt(short, long)]
        // lang: String
    },
    Compare {},
    Merge {
        #[structopt(parse(from_os_str))]
        paths: Vec<PathBuf>,
    },
}

fn do_run(bin: PathBuf, out: PathBuf) -> Result<()> {
    let sprofiler = GoSeccompProfiler {
        target_bin: bin,
        destination: out,
    };

    sprofiler.output()?;

    Ok(())
}

fn main() -> Result<()> {
    let command = Command::from_args();

    match command {
        Command::Run { bin, out } => do_run(bin, out)?,
        Command::Compare { .. } => {}
        Command::Merge { .. } => {}
    };

    Ok(())
}
