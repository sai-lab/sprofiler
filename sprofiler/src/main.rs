use std::process::{Command, Stdio};
use std::str;

mod command;
use command::tracer::{stop_tracing, trace_command};

mod ioutil;
mod ociutil;

mod bpf;
use bpf::*;

mod syscalls;

use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use sprofiler_sys::lang::{Language, SeccompProfilerBuilder};
use structopt::StructOpt;

mod profile_util;
use profile_util::DiffStatus;

#[derive(Debug, StructOpt)]
#[structopt(name = "sprofiler")]
enum Sprofiler {
    Static(Static),
    Dynamic(Dynamic),
}

#[derive(Debug, StructOpt)]
#[structopt(name = "static", about = "Static Analyzer")]
enum Static {
    /// Generate seccomp profile from ELF
    Run {
        /// Input binary file
        #[structopt(short, long, parse(from_os_str))]
        bin: PathBuf,
        /// Output seccomp profile path
        #[structopt(short, long, parse(from_os_str))]
        out: PathBuf,
        /// Mapped data for function to syscall name
        #[structopt(short = "m", long = "map", parse(from_os_str))]
        map: Option<PathBuf>,
        /// Analyze Binary Language (e.g. c, go)
        #[structopt(short, long)]
        lang: String,
    },
    /// Output the difference between the two profiles
    Diff {
        #[structopt(parse(from_os_str))]
        path1: PathBuf,
        #[structopt(parse(from_os_str))]
        path2: PathBuf,
    },
    /// Combine two profiles
    Merge {
        /// Source seccomp profile
        #[structopt(short, long, parse(from_os_str))]
        paths: Vec<PathBuf>,
        /// Output seccomp profile path
        #[structopt(short, long, parse(from_os_str))]
        out: PathBuf,
    },
}

#[derive(Debug, StructOpt)]
#[structopt(name = "dynamic", about = "Dynamic Analyzer")]
enum Dynamic {
    Start {},
    Stop {},
    Tracer {},
}

fn do_run(bin: PathBuf, out: PathBuf, map: Option<PathBuf>, lang: &str) -> Result<()> {
    let mut sprofiler_builder =
        SeccompProfilerBuilder::new(bin, out, Language::from_str(lang).unwrap());

    if let Some(map) = map {
        sprofiler_builder.set_syscall_map(map);
    }

    let sprofiler = sprofiler_builder.build();
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

fn handle_static_analyzer(static_: Static) -> Result<()> {
    match static_ {
        Static::Run {
            bin,
            out,
            lang,
            map,
        } => do_run(bin, out, map, &lang)?,
        Static::Diff { path1, path2 } => do_diff(path1, path2)?,
        Static::Merge { paths, out } => do_merge(paths, out)?,
    };

    Ok(())
}

fn handle_dynamic_analyzer(dynamic: Dynamic) -> Result<()> {
    match dynamic {
        Dynamic::Start {} => run_trace_command()?,
        Dynamic::Stop {} => stop_tracing()?,
        Dynamic::Tracer {} => trace_command()?,
    }
    Ok(())
}

fn run_trace_command() -> anyhow::Result<()> {
    Command::new("/proc/self/exe")
        .arg("tracer")
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    Ok(())
}

fn main() -> Result<()> {
    let sprofiler_cmd = Sprofiler::from_args();

    match sprofiler_cmd {
        Sprofiler::Static(static_) => handle_static_analyzer(static_)?,
        Sprofiler::Dynamic(dynamic_) => handle_dynamic_analyzer(dynamic_)?,
    }

    Ok(())
}
