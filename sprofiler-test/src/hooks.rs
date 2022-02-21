use std::collections::HashMap;
use std::fs::{self, File};
use std::path::PathBuf;

use anyhow::Result;
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use tracing::trace;

#[derive(Builder, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[builder(default, pattern = "owned", setter(into, strip_option))]
pub struct HookConf {
    pub version: String,
    pub hook: Hook,
    pub when: When,
    pub stages: Vec<Stages>,
}

#[derive(Builder, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[builder(default, setter(into))]
pub struct Hook {
    pub path: PathBuf,
    pub args: Vec<String>,
}

#[derive(Builder, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[builder(default, setter(into))]
pub struct When {
    pub annotations: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub enum Stages {
    Prestart,
    Poststop,
    CreateRuntime,
    StartRuntime,
    PostStop,
}

pub fn create_hook_config(base_dir: PathBuf, sprofiler_path: PathBuf) -> Result<PathBuf> {
    let annotation = {
        let mut a = HashMap::new();
        a.insert(
            "^io\\.sprofiler\\.output_seccomp_profile_path$".to_string(),
            ".*".to_string(),
        );
        a
    };

    let prestart = HookConfBuilder::default()
        .version("1.0.0")
        .hook(
            HookBuilder::default()
                .path(&sprofiler_path)
                .args(vec![
                    "sprofiler".to_string(),
                    "dynamic".to_string(),
                    "start".to_string(),
                ])
                .build()?,
        )
        .when(
            WhenBuilder::default()
                .annotations(annotation.clone())
                .build()?,
        )
        .stages(vec![Stages::Prestart])
        .build()?;

    let poststop = HookConfBuilder::default()
        .version("1.0.0")
        .hook(
            HookBuilder::default()
                .path(&sprofiler_path)
                .args(vec![
                    "sprofiler".to_string(),
                    "dynamic".to_string(),
                    "stop".to_string(),
                ])
                .build()?,
        )
        .when(WhenBuilder::default().annotations(annotation).build()?)
        .stages(vec![Stages::Poststop])
        .build()?;

    let hooks_dir = base_dir.join("hooks.d");
    fs::create_dir_all(&hooks_dir)?;

    let prestart_path = hooks_dir.join("sprofiler-prestart.json");
    let file = File::create(&prestart_path)?;
    serde_json::to_writer(file, &prestart)?;
    trace!("{}", serde_json::to_string(&prestart)?);

    let poststop_path = hooks_dir.join("sprofiler-poststop.json");
    let file = File::create(&poststop_path)?;
    serde_json::to_writer(file, &poststop)?;
    trace!("{}", serde_json::to_string(&poststop)?);

    Ok(hooks_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_json() {
        let json = r#"
        {
          "version": "1.0.0",
          "hook": {
            "path": "/usr/bin/sprofiler",
            "args": ["sprofiler", "dynamic", "start"]
          },
          "when": {
            "annotations": {
                    "^io\\.sprofiler\\.output_seccomp_profile_path$": ".*"
                }
          },
          "stages": ["prestart"]
        }"#;
        let hook_conf: HookConf = serde_json::from_str(json).unwrap();

        assert_eq!(hook_conf.version, "1.0.0");
        assert_eq!(hook_conf.hook.path, PathBuf::from("/usr/bin/sprofiler"));
        assert_eq!(hook_conf.hook.args, vec!["sprofiler", "dynamic", "start"]);
        assert_eq!(hook_conf.when.annotations.len(), 1);
        assert_eq!(
            hook_conf
                .when
                .annotations
                .get("^io\\.sprofiler\\.output_seccomp_profile_path$"),
            Some(&".*".to_string())
        );

        assert_eq!(hook_conf.stages, vec![Stages::Prestart]);
    }
}
