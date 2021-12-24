use std::process::{Command, Stdio};
use std::str;

use structopt::StructOpt;

mod command;
use command::tracer::{stop_tracing, trace_command};

mod ioutil;
mod ociutil;

#[derive(StructOpt)]
#[structopt(name = "sprofiler-bpf", about = "Dynamic seccomp profiler with eBPF")]
enum SprofilerBPF {
    Start {
        #[structopt(long, short)]
        runtime_only: bool,
    },
    Stop {},
    Tracer {
        #[structopt(long, short)]
        runtime_only: bool,
    },
}

fn run_trace_command(runtime_only: bool) -> anyhow::Result<()> {
    if runtime_only {
        Command::new("/proc/self/exe")
            .arg("tracer")
            .arg("--runtime-only")
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
    } else {
        Command::new("/proc/self/exe")
            .arg("tracer")
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = SprofilerBPF::from_args();

    match args {
        SprofilerBPF::Start { runtime_only } => run_trace_command(runtime_only)?,
        SprofilerBPF::Stop {} => stop_tracing()?,
        SprofilerBPF::Tracer { runtime_only } => trace_command(runtime_only)?,
    }

    Ok(())
}
