use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use sprofiler_sys::oci::{Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSyscall};

fn extract_syscall_names(profile: LinuxSeccomp) -> Vec<String> {
    let syscalls = match profile.syscalls {
        Some(syscalls) => syscalls,
        None => vec![],
    };

    let names_list: Vec<Vec<String>> = syscalls.into_iter().map(|syscall| syscall.names).collect();

    let mut names = names_list.into_iter().flatten().collect::<Vec<_>>();
    names.sort();

    names
}

pub fn read_seccomp_profiles(paths: Vec<PathBuf>) -> Result<Vec<LinuxSeccomp>> {
    let mut profiles = Vec::<LinuxSeccomp>::new();

    for path in paths {
        let file = File::open(path)?;
        let profile: LinuxSeccomp = serde_json::from_reader(&file)?;
        profiles.push(profile);
    }

    Ok(profiles)
}

pub fn merge(profiles: Vec<LinuxSeccomp>) -> LinuxSeccomp {
    if profiles.is_empty() {
        return LinuxSeccomp::default();
    }

    let mut names: Vec<String> = profiles
        .into_iter()
        .map(|profile| extract_syscall_names(profile))
        .flatten()
        .collect();

    names.sort();

    LinuxSeccomp {
        default_action: LinuxSeccompAction::SCMP_ACT_ERRNO,
        architectures: Some(vec![Arch::SCMP_ARCH_X86, Arch::SCMP_ARCH_X86_64]),
        syscalls: Some(vec![LinuxSyscall {
            names: names,
            action: LinuxSeccompAction::SCMP_ACT_ALLOW,
            args: None,
        }]),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn gen_seccomp_profile(allow_syscalls: Vec<&str>) -> LinuxSeccomp {
        let mut names: Vec<String> = allow_syscalls.into_iter().map(String::from).collect();
        names.sort();

        LinuxSeccomp {
            default_action: LinuxSeccompAction::SCMP_ACT_ERRNO,
            architectures: Some(vec![Arch::SCMP_ARCH_X86, Arch::SCMP_ARCH_X86_64]),
            syscalls: Some(vec![LinuxSyscall {
                names,
                action: LinuxSeccompAction::SCMP_ACT_ALLOW,
                args: None,
            }]),
        }
    }

    #[test]
    fn extract_syscall_names_give_single_syscall_name() {
        let profile = gen_seccomp_profile(vec!["mkdir"]);
        let syscall_names = extract_syscall_names(profile);

        assert_eq!(syscall_names, vec!["mkdir".to_string()])
    }

    #[test]
    fn extract_syscall_names_give_2_syscall_name() {
        let profile = gen_seccomp_profile(vec!["mkdir", "chdir"]);
        let syscall_names = extract_syscall_names(profile);

        // syscalls names must be sorted
        assert_eq!(
            syscall_names,
            vec!["chdir".to_string(), "mkdir".to_string()]
        )
    }

    #[test]
    fn merge_profile_from_empty_data() {
        let profile = merge(Vec::new());

        assert_eq!(profile.default_action, LinuxSeccompAction::SCMP_ACT_ALLOW);
        assert_eq!(profile.syscalls, None);
        assert_eq!(profile.architectures, None);
    }

    #[test]
    fn merge_profile_from_2_profiles() {
        let profile1 = gen_seccomp_profile(vec!["mkdir"]);
        let profile2 = gen_seccomp_profile(vec!["chdir"]);

        let act = merge(vec![profile1, profile2]);

        let expect = gen_seccomp_profile(vec!["chdir", "mkdir"]);

        assert_eq!(act.default_action, LinuxSeccompAction::SCMP_ACT_ERRNO);
        assert_eq!(act.architectures, expect.architectures);
        assert_eq!(act.syscalls, expect.syscalls);
    }

    #[test]
    fn merge_profile_from_3_profiles() {
        let profile1 = gen_seccomp_profile(vec!["mkdir", "chdir"]);
        let profile2 = gen_seccomp_profile(vec!["accept", "bind"]);
        let profile3 = gen_seccomp_profile(vec!["getuid", "getgid"]);

        let act = merge(vec![profile1, profile2, profile3]);

        let expect =
            gen_seccomp_profile(vec!["accept", "bind", "chdir", "getgid", "getuid", "mkdir"]);

        assert_eq!(act.default_action, LinuxSeccompAction::SCMP_ACT_ERRNO);
        assert_eq!(act.architectures, expect.architectures);
        assert_eq!(act.syscalls, expect.syscalls);
    }
}
