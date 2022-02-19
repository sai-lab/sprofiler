use anyhow::Result;
use structopt::StructOpt;

use sprofiler::dynamic::{handle_dynamic_analyzer, DynamicSubCommand};
use sprofiler::r#static::{handle_static_analyzer, StaticSubCommand};

#[derive(Debug, StructOpt)]
#[structopt(name = "sprofiler")]
enum SprofilerCommand {
    Static(StaticSubCommand),
    Dynamic(DynamicSubCommand),
}

fn main() -> Result<()> {
    let sprofiler_cmd = SprofilerCommand::from_args();

    match sprofiler_cmd {
        SprofilerCommand::Static(static_) => handle_static_analyzer(static_)?,
        SprofilerCommand::Dynamic(dynamic) => handle_dynamic_analyzer(dynamic)?,
    }

    Ok(())
}
