use std::path::PathBuf;

use anyhow::Result;

use crate::lang::SeccompProfiler;
use crate::oci::{LinuxSeccomp, LinuxSeccompAction, LinuxSyscall};

#[derive(Default)]
pub struct GoSeccompProfiler {
    pub destination: PathBuf,
    pub target_bin: PathBuf,
}

impl SeccompProfiler for GoSeccompProfiler {
    fn analyze(&self) -> Result<LinuxSeccomp> {
        let mut seccomp = LinuxSeccomp::default();
        let syscalls = LinuxSyscall {
            names: DEFAULT_ALLOW_SYSCALLS
                .to_vec()
                .into_iter()
                .map(String::from)
                .collect(),
            action: LinuxSeccompAction::SCMP_ACT_ALLOW,
            args: None,
        };
        seccomp.syscalls = Some(vec![syscalls]);
        Ok(seccomp)
    }
}

static DEFAULT_ALLOW_SYSCALLS: &[&'static str; 58] = &[
    "bind",
    "capget",
    "capset",
    "chdir",
    "clone",
    "close",
    // debug {{{
    "dup",
    "dup2",
    "dup3",
    // }}}
    "execve",
    "epoll_wait",
    "fchdir",
    "fchmodat",
    "fchown",
    "fchownat",
    "fcntl",
    "fstat",
    "fstatfs",
    "futex",
    "getdents",
    "getdents64",
    "getppid",
    "getsockname",
    "gettid",
    "getuid",
    "keyctl",
    "mkdirat",
    "mknodat",
    "mmap",
    "mount",
    "mprotect",
    "newfstatat",
    "openat",
    "prctl",
    "read",
    "readlinkat",
    "recvfrom",
    "sendto",
    "setgid",
    "setgroups",
    "sethostname",
    "setsid",
    "setuid",
    "sigaltstack",
    "socket",
    "statfs",
    "symlinkat",
    "umask",
    "unlinkat",
    "write",
    // Go Runtime
    "arch_prctl",
    "epoll_pwait",
    "epoll_create",
    "epoll_ctl",
    "openat",
    "uname",
    "rt_sigaction",
    "rt_sigprocmask",
];
