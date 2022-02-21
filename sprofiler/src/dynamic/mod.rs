pub mod annotation;
pub mod process;

use std::process::{Command, Stdio};
use std::str;

use anyhow::Result;
use structopt::StructOpt;

use crate::command::tracer::{stop_tracing, trace_command};

#[derive(Debug, StructOpt)]
#[structopt(name = "dynamic", about = "Dynamic Analyzer")]
pub enum DynamicSubCommand {
    Start {},
    Stop {},
    Tracer {},
}

pub fn handle_dynamic_analyzer(dynamic: DynamicSubCommand) -> Result<()> {
    match dynamic {
        DynamicSubCommand::Start {} => run_trace_command()?,
        DynamicSubCommand::Stop {} => stop_tracing()?,
        DynamicSubCommand::Tracer {} => trace_command()?,
    }
    Ok(())
}

fn run_trace_command() -> anyhow::Result<()> {
    Command::new("/proc/self/exe")
        .arg("dynamic")
        .arg("tracer")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    Ok(())
}
