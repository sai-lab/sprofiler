use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::Result;
use oci_runtime_spec::{Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSyscall};

#[derive(Debug, PartialEq)]
pub enum DiffStatus {
    OnlyPath1,
    OnlyPath2,
    Both,
}

fn extract_syscall_names(profile: LinuxSeccomp) -> Vec<String> {
    let syscalls = match profile.syscalls {
        Some(syscalls) => syscalls,
        None => vec![],
    };

    let mut names: Vec<String> = syscalls
        .into_iter()
        .map(|syscall| syscall.names)
        .flatten()
        .collect();

    names.sort();
    names.dedup();

    names
}

pub fn read_seccomp_profiles(paths: Vec<PathBuf>) -> Result<Vec<LinuxSeccomp>> {
    let mut profiles = Vec::<LinuxSeccomp>::new();

    for path in paths {
        let profile = read_seccomp_profile(&path)?;
        profiles.push(profile);
    }

    Ok(profiles)
}

pub fn read_seccomp_profile(path: &Path) -> Result<LinuxSeccomp> {
    let file = File::open(path)?;
    let profile: LinuxSeccomp = serde_json::from_reader(&file)?;
    Ok(profile)
}

pub fn merge(profiles: Vec<LinuxSeccomp>) -> LinuxSeccomp {
    if profiles.is_empty() {
        return LinuxSeccomp::default();
    }

    let mut names: Vec<String> = profiles
        .into_iter()
        .map(extract_syscall_names)
        .flatten()
        .collect();

    names.sort();
    names.dedup();

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

pub fn diff(profile1: LinuxSeccomp, profile2: LinuxSeccomp) -> HashMap<String, DiffStatus> {
    let syscalls_from_profile1 = extract_syscall_names(profile1);
    let syscalls_from_profile2 = extract_syscall_names(profile2);

    let mut diff_hash = HashMap::<String, DiffStatus>::new();

    for syscall in syscalls_from_profile1 {
        diff_hash.entry(syscall).or_insert(DiffStatus::OnlyPath1);
    }

    for syscall in syscalls_from_profile2 {
        if diff_hash.get(&*syscall).is_some() {
            diff_hash.insert(syscall.to_string(), DiffStatus::Both);
        } else {
            diff_hash.entry(syscall).or_insert(DiffStatus::OnlyPath2);
        }
    }

    diff_hash
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

    fn gen_duplicate_syscalls_profile(allow_syscalls: Vec<&str>) -> LinuxSeccomp {
        let mut names: Vec<String> = allow_syscalls.into_iter().map(String::from).collect();
        names.sort();

        let syscalls = LinuxSyscall {
            names,
            action: LinuxSeccompAction::SCMP_ACT_ALLOW,
            args: None,
        };

        LinuxSeccomp {
            default_action: LinuxSeccompAction::SCMP_ACT_ERRNO,
            architectures: Some(vec![Arch::SCMP_ARCH_X86, Arch::SCMP_ARCH_X86_64]),
            syscalls: Some(vec![syscalls.clone(), syscalls.clone()]),
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
    fn merge_profile_from_duplicated_syscalls() {
        let profile1 = gen_duplicate_syscalls_profile(vec!["ptrace"]);
        let profile2 = gen_duplicate_syscalls_profile(vec!["chroot"]);

        let act = merge(vec![profile1, profile2]);

        let expect = gen_seccomp_profile(vec!["chroot", "ptrace"]);

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

    #[test]
    fn merge_profile_duplicated_syscall() {
        let profile1 = gen_seccomp_profile(vec!["mkdir", "chdir"]);
        let profile2 = gen_seccomp_profile(vec!["chdir", "getpid"]);

        let act = merge(vec![profile1, profile2]);

        let expect = gen_seccomp_profile(vec!["chdir", "getpid", "mkdir"]);

        assert_eq!(act.default_action, LinuxSeccompAction::SCMP_ACT_ERRNO);
        assert_eq!(act.architectures, expect.architectures);
        assert_eq!(act.syscalls, expect.syscalls);
    }

    #[test]
    fn diff_equal_profile() {
        let profile1 = gen_seccomp_profile(vec!["mkdir"]);
        let profile2 = gen_seccomp_profile(vec!["mkdir"]);
        let map = diff(profile1, profile2);

        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&"mkdir".to_string()), Some(&DiffStatus::Both));
    }

    #[test]
    fn diff_equal_profile_3_syscalls() {
        let profile1 = gen_seccomp_profile(vec!["getpid", "mkdir", "unshare"]);
        let profile2 = gen_seccomp_profile(vec!["getpid", "mkdir", "unshare"]);
        let map = diff(profile1, profile2);

        assert_eq!(map.len(), 3);
        assert_eq!(map.get(&"getpid".to_string()), Some(&DiffStatus::Both));
        assert_eq!(map.get(&"mkdir".to_string()), Some(&DiffStatus::Both));
        assert_eq!(map.get(&"unshare".to_string()), Some(&DiffStatus::Both));
    }

    #[test]
    fn diff_only_profile1_syscalls() {
        let profile1 = gen_seccomp_profile(vec!["getpid", "mkdir", "unshare"]);
        let profile2 = gen_seccomp_profile(vec!["getuid"]);
        let map = diff(profile1, profile2);

        assert_eq!(map.len(), 4);
        assert_eq!(map.get(&"getpid".to_string()), Some(&DiffStatus::OnlyPath1));
        assert_eq!(map.get(&"mkdir".to_string()), Some(&DiffStatus::OnlyPath1));
        assert_eq!(
            map.get(&"unshare".to_string()),
            Some(&DiffStatus::OnlyPath1)
        );
        assert_eq!(map.get(&"getuid".to_string()), Some(&DiffStatus::OnlyPath2));
    }

    #[test]
    fn diff_only_profile2_syscalls() {
        let profile1 = gen_seccomp_profile(vec!["getuid"]);
        let profile2 = gen_seccomp_profile(vec!["getpid", "mkdir", "unshare"]);
        let map = diff(profile1, profile2);

        assert_eq!(map.len(), 4);
        assert_eq!(map.get(&"getpid".to_string()), Some(&DiffStatus::OnlyPath2));
        assert_eq!(map.get(&"mkdir".to_string()), Some(&DiffStatus::OnlyPath2));
        assert_eq!(
            map.get(&"unshare".to_string()),
            Some(&DiffStatus::OnlyPath2)
        );
        assert_eq!(map.get(&"getuid".to_string()), Some(&DiffStatus::OnlyPath1));
    }
}
