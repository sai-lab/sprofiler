use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use sprofiler_sys::lang::golang::GoSeccompProfiler;
use sprofiler_sys::lang::SeccompProfiler;
use structopt::StructOpt;

mod profile_util;
use profile_util::DiffStatus;

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
    Diff {
        #[structopt(parse(from_os_str))]
        path1: PathBuf,
        #[structopt(parse(from_os_str))]
        path2: PathBuf,
    },
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

fn do_diff(path1: PathBuf, path2: PathBuf) -> Result<()> {
    let profile1 = profile_util::read_seccomp_profile(&path1)?;
    let profile2 = profile_util::read_seccomp_profile(&path2)?;

    let map = profile_util::diff(profile1, profile2);

    let mut profile1_only = vec![];
    let mut profile2_only = vec![];
    let mut both = vec![];

    for (k, v) in map.iter() {
        match v {
            DiffStatus::OnlyPath1 => profile1_only.push(k),
            DiffStatus::OnlyPath2 => profile2_only.push(k),
            DiffStatus::Both => both.push(k),
        }
    }

    profile1_only.sort();
    profile1_only.dedup();

    profile2_only.sort();
    profile2_only.dedup();

    both.sort();
    both.dedup();

    println!("{} only: {:?}", path1.display(), profile1_only);
    println!("{} only: {:?}", path2.display(), profile2_only);
    println!("Both allow syscalls: {:?}", both);

    println!(
        "{} only allow {} syscalls",
        path1.display(),
        profile1_only.len()
    );
    println!(
        "{} only allow {} syscalls",
        path2.display(),
        profile2_only.len()
    );
    println!("Both allow {} syscalls", both.len());

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
        Command::Diff { path1, path2 } => do_diff(path1, path2)?,
        Command::Merge { paths, out } => do_merge(paths, out)?,
    };

    Ok(())
}
