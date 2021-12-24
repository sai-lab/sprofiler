use std::path::PathBuf;
use std::str::FromStr;

use oci_runtime_spec::State;

const SPROFILER_PROFILE_PATH: &str = "io.sprofiler.output_seccomp_profile_path";
const SPROFILER_RUNTIME_CLASS: &str = "io.sprofiler.runtime_class";

pub enum RuntimeClass {
    Runc,
    Crun,
    Youki,
}

impl FromStr for RuntimeClass {
    type Err = ();
    fn from_str(kind: &str) -> Result<Self, Self::Err> {
        match kind {
            "crun" => Ok(RuntimeClass::Crun),
            "runc" => Ok(RuntimeClass::Runc),
            "youki" => Ok(RuntimeClass::Youki),
            _ => Err(()),
        }
    }
}

pub fn get_trace_target_path(state: &State) -> Option<PathBuf> {
    if let Some(annotations) = &state.annotations {
        annotations.get(SPROFILER_PROFILE_PATH).map(PathBuf::from)
    } else {
        None
    }
}

pub fn get_runtime_class(state: &State) -> RuntimeClass {
    let annotations = &state.annotations.as_ref().unwrap();
    match annotations.get(SPROFILER_RUNTIME_CLASS) {
        Some(runtime_class) => RuntimeClass::from_str(runtime_class).unwrap(),
        None => RuntimeClass::Crun,
    }
}
