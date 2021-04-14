use std::path::PathBuf;

use sprofiler_sys::oci::State;

pub fn get_trace_target_path(state: &State) -> Option<PathBuf> {
    if let Some(annotations) = &state.annotations {
        annotations
            .get("io.sprofiler.output_seccomp_profile_path")
            .map(PathBuf::from)
    } else {
        None
    }
}
