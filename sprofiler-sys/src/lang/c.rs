use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;

use anyhow::{Context, Result};
use object::{Object, ObjectSymbol};
use oci_runtime_spec::{Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSyscall};

use crate::lang::SeccompProfiler;

#[derive(Default)]
pub struct CSeccompProfiler {
    pub destination: PathBuf,
    pub target_bin: PathBuf,
    pub syscall_map: PathBuf,
}

impl SeccompProfiler for CSeccompProfiler {
    fn analyze(&self) -> Result<LinuxSeccomp> {
        let syscall: LinuxSyscall = self.run()?;

        Ok(LinuxSeccomp {
            syscalls: Some(vec![syscall]),
            default_action: LinuxSeccompAction::SCMP_ACT_ERRNO,
            architectures: Some(vec![Arch::SCMP_ARCH_X86_64]),
        })
    }

    fn output(&self) -> Result<()> {
        let file = File::create(&self.destination)?;
        let seccomp = self.analyze()?;
        serde_json::to_writer(file, &seccomp)?;
        Ok(())
    }
}

fn allow_syscall_list_from_symbols(
    symbols: Vec<String>,
    fn_to_syscall_table: HashMap<String, Vec<String>>,
) -> Vec<String> {
    let mut syscalls = Vec::<String>::new();
    for symbol in symbols {
        if let Some(allow_syscalls) = fn_to_syscall_table.get(&symbol) {
            syscalls.extend::<Vec<String>>(allow_syscalls.to_vec());
        }
    }
    syscalls
}

impl CSeccompProfiler {
    fn run(&self) -> Result<LinuxSyscall> {
        let bin_data = std::fs::read(&self.target_bin)?;
        let obj_file = object::File::parse(&*bin_data)?;

        let fnames: Vec<&str> = obj_file
            .dynamic_symbols()
            .filter_map(|symbol| symbol.name().ok())
            .collect();

        fnames.iter().for_each(|name| println!("{}", name));

        let fn_to_syscall_table = self.read_syscall_map()?;

        let syscalls = allow_syscall_list_from_symbols(
            fnames.into_iter().map(String::from).collect(),
            fn_to_syscall_table,
        );

        println!("{:?}", syscalls);

        Ok(LinuxSyscall {
            names: syscalls,
            action: LinuxSeccompAction::SCMP_ACT_ALLOW,
            args: None,
        })
    }

    fn read_syscall_map(&self) -> Result<HashMap<String, Vec<String>>> {
        let file = File::open(&self.syscall_map)?;
        let map = serde_json::from_reader(file)
            .with_context(|| format!("json deserialize error: {}", self.syscall_map.display()))?;

        println!("{:?}", map);

        Ok(map)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_allow_syscall_list_from_symbols() {
        let mut fn_to_syscall = HashMap::new();
        fn_to_syscall.insert("puts".to_string(), vec!["write".to_string()]);
        let symbols = vec!["puts".to_string()];

        let syscalls = allow_syscall_list_from_symbols(symbols, fn_to_syscall);
        assert_eq!(syscalls, vec!["write".to_string()])
    }
}
