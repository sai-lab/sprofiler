use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use sprofiler_sys::lang::golang::GoSeccompProfiler;
use sprofiler_sys::lang::SeccompProfiler;
use structopt::StructOpt;

mod profile_util;

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
        /// Source seccomp profile
        #[structopt(short, long, parse(from_os_str))]
        paths: Vec<PathBuf>,
        /// Output seccomp profile path
        #[structopt(short, long, parse(from_os_str))]
        out: PathBuf,
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

fn do_merge(paths: Vec<PathBuf>, out: PathBuf) -> Result<()> {
    let profiles = profile_util::read_seccomp_profiles(paths)?;
    let profile = profile_util::merge(profiles);

    let target_file = File::create(&out)?;
    serde_json::to_writer(target_file, &profile)?;

    Ok(())
}

fn main() -> Result<()> {
    let command = Command::from_args();

    match command {
        Command::Run { bin, out } => do_run(bin, out)?,
        Command::Compare { .. } => {}
        Command::Merge { paths, out } => do_merge(paths, out)?,
    };

    Ok(())
}
