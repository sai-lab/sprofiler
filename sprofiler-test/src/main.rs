use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing::trace;

mod testing;
use testing::run_tests;

mod hooks;
mod seccomp;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    tests_file: PathBuf,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .without_time()
        .init();

    let args = Args::parse();
    let reader = File::open(args.tests_file)?;
    let testing = serde_yaml::from_reader(&reader)?;

    trace!("Starting test tool");
    run_tests(testing)?;

    Ok(())
}
