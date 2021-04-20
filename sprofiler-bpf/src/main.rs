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
    Start {},
    Stop {},
    Tracer {},
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

fn main() -> anyhow::Result<()> {
    let args = SprofilerBPF::from_args();

    match args {
        SprofilerBPF::Start {} => run_trace_command()?,
        SprofilerBPF::Stop {} => stop_tracing()?,
        SprofilerBPF::Tracer {} => trace_command()?,
    }

    Ok(())
}
