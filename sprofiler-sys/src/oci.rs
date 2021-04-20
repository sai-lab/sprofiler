use serde_derive::{Deserialize, Serialize};

use std::collections::HashMap;
use std::path::PathBuf;

pub static OCI_VERSION: &str = "1.0.1-dev";

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    #[serde(rename = "creating")]
    Creating,
    #[serde(rename = "created")]
    Created,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "stopped")]
    Stopped,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub oci_version: String,
    pub id: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    pub bundle: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    pub oci_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,
    pub root: Root,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub mounts: Vec<Mount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hooks: Option<Hooks>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux: Option<Linux>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub solaris: Option<Solaris>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows: Option<Windows>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm: Option<VM>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_size: Option<Box>,
    pub user: User,
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    pub cwd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<LinuxCapabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rlimits: Option<Vec<POSIXRlimit>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_new_privileges: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apparmor_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_score_adj: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selinux_label: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bounding: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inheritable: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permitted: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ambient: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Box {
    height: u64,
    width: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readonly: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Mount {
    pub destination: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Hook {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Hooks {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prestart: Option<Vec<Hook>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_runtime: Option<Vec<Hook>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_container: Option<Vec<Hook>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_container: Option<Vec<Hook>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poststart: Option<Vec<Hook>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poststop: Option<Vec<Hook>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Linux {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid_mappings: Option<Vec<LinuxIDMapping>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid_mappings: Option<Vec<LinuxIDMapping>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sysctl: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<LinuxResources>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroups_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<Vec<LinuxNamespace>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<LinuxDevice>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<LinuxSeccomp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rootfs_propagation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub masked_paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readonly_paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mount_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intel_rdt: Option<LinuxIntelRdt>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxIDMapping {
    #[serde(rename = "containerID")]
    pub container_id: u32,
    #[serde(rename = "hostID")]
    pub host_id: u32,
    pub size: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxResources {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<LinuxDeviceCgroup>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<LinuxMemory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<LinuxCPU>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids: Option<LinuxPids>,
    #[serde(rename = "blockIO", skip_serializing_if = "Option::is_none")]
    pub block_io: Option<LinuxBlockIO>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hugepage_limits: Option<Vec<LinuxHugepageLimit>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<LinuxNetwork>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdma: Option<HashMap<String, LinuxRdma>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxDevice {
    pub path: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub major: i64,
    pub minor: i64,
    // TODO: FileMode
    // Golang FileMode *os.FileMode
    // -> Rust file_mode Option<T>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxDeviceCgroup {
    pub allow: bool,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub major: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minor: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
}

// pub type Arch = String;
// pub type LinuxSeccompAction = String;
pub type LinuxSeccompOperator = String;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum Arch {
    SCMP_ARCH_X86,
    SCMP_ARCH_X86_64,
    SCMP_ARCH_X86_X32,
    SCMP_ARCH_ARM,
    SCMP_ARCH_AARCH64,
    SCMP_ARCH_MIPS,
    SCMP_ARCH_MIPS64,
    SCMP_ARCH_MIPS64N32,
    SCMP_ARCH_MIPSEL,
    SCMP_ARCH_MIPSEL64,
    SCMP_ARCH_MIPSEL64N32,
    SCMP_ARCH_PPC,
    SCMP_ARCH_PPC64,
    SCMP_ARCH_PPC64LE,
    SCMP_ARCH_S390,
    SCMP_ARCH_S390X,
    SCMP_ARCH_PARISC,
    SCMP_ARCH_PARISC64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum LinuxSeccompAction {
    SCMP_ACT_KILL,
    SCMP_ACT_TRAP,
    SCMP_ACT_ERRNO,
    SCMP_ACT_TRACE,
    SCMP_ACT_ALLOW,
    SCMP_ACT_LOG,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxSeccomp {
    pub default_action: LinuxSeccompAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architectures: Option<Vec<Arch>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscalls: Option<Vec<LinuxSyscall>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxSyscall {
    pub names: Vec<String>,
    pub action: LinuxSeccompAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<LinuxSeccompArg>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxSeccompArg {
    pub index: u64,
    pub value: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_two: Option<u64>,
    pub op: LinuxSeccompOperator,
}

impl Default for LinuxSeccomp {
    fn default() -> Self {
        Self {
            default_action: LinuxSeccompAction::SCMP_ACT_ALLOW,
            architectures: None,
            syscalls: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxMemory {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservation: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<i64>,
    #[serde(rename = "kernelTCP", skip_serializing_if = "Option::is_none")]
    pub kernel_tcp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swappiness: Option<u64>,
    #[serde(rename = "disableOOMKiller", skip_serializing_if = "Option::is_none")]
    pub disable_oom_killer: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxCPU {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shares: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realtime_runtime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realtime_period: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpus: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mems: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxPids {
    limit: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxBlockIO {
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf_weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight_device: Option<Vec<LinuxWeightDevice>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    throttle_read_bps_device: Option<Vec<LinuxThrottleDevice>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    throttle_write_bps_device: Option<Vec<LinuxThrottleDevice>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    throttle_read_iops_device: Option<Vec<LinuxThrottleDevice>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    throttle_write_iops_device: Option<Vec<LinuxThrottleDevice>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxWeightDevice {
    major: i64,
    minor: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf_weight: Option<u16>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxThrottleDevice {
    major: i64,
    minor: i64,
    rate: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxNetwork {
    #[serde(rename = "classID", skip_serializing_if = "Option::is_none")]
    class_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priorities: Option<Vec<LinuxInterfacePriority>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxInterfacePriority {
    name: String,
    priority: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxRdma {
    #[serde(skip_serializing_if = "Option::is_none")]
    hca_handles: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hca_objects: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxIntelRdt {
    #[serde(rename = "closID", skip_serializing_if = "Option::is_none")]
    clos_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    l3_cache_schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mem_bw_schema: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_gids: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct POSIXRlimit {
    #[serde(rename = "type")]
    pub type_: String,
    pub hard: u64,
    pub soft: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxHugepageLimit {
    page_size: String,
    limit: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LinuxNamespace {
    #[serde(rename = "type")]
    pub type_: LinuxNamespaceType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug)]
#[serde(rename_all = "camelCase")]
pub enum LinuxNamespaceType {
    Mount = 0x0002_0000,
    Cgroup = 0x0200_0000,
    Uts = 0x0400_0000,
    Ipc = 0x0800_0000,
    User = 0x1000_0000,
    Pid = 0x2000_0000,
    Network = 0x4000_0000,
}

// TODO
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Solaris {}

// TODO
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Windows {}

// TODO
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VM {}

impl Default for Spec {
    fn default() -> Self {
        Self::new(false)
    }
}

impl Spec {
    pub fn new(is_rootless: bool) -> Self {
        Spec {
            oci_version: OCI_VERSION.into(),
            root: Root {
                path: "rootfs".into(),
                readonly: Some(true),
            },
            process: Some(Process {
                terminal: Some(false),
                console_size: None,
                user: User {
                    uid: 0,
                    gid: 0,
                    additional_gids: None,
                    username: None,
                },
                args: vec!["echo".into(), "hello".into()],
                env: Some(vec![
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
                    "TERM=xterm".into(),
                ]),
                cwd: "/".into(),
                command_line: None,
                no_new_privileges: Some(true),
                capabilities: Some(LinuxCapabilities {
                    bounding: Some(vec![
                        "CAP_AUDIT_WRITE".into(),
                        "CAP_KILL".into(),
                        "CAP_NET_BIND_SERVICE".into(),
                    ]),
                    permitted: Some(vec![
                        "CAP_AUDIT_WRITE".into(),
                        "CAP_KILL".into(),
                        "CAP_NET_BIND_SERVICE".into(),
                    ]),
                    inheritable: Some(vec![
                        "CAP_AUDIT_WRITE".into(),
                        "CAP_KILL".into(),
                        "CAP_NET_BIND_SERVICE".into(),
                    ]),
                    ambient: Some(vec![
                        "CAP_AUDIT_WRITE".into(),
                        "CAP_KILL".into(),
                        "CAP_NET_BIND_SERVICE".into(),
                    ]),
                    effective: Some(vec![
                        "CAP_AUDIT_WRITE".into(),
                        "CAP_KILL".into(),
                        "CAP_NET_BIND_SERVICE".into(),
                    ]),
                }),
                rlimits: Some(vec![POSIXRlimit {
                    type_: "RLIMIT_NOFILE".into(),
                    hard: 1024,
                    soft: 1024,
                }]),
                apparmor_profile: None,
                oom_score_adj: None,
                selinux_label: None,
            }),
            hostname: None,
            mounts: vec![
                Mount {
                    destination: "/proc".into(),
                    type_: "proc".into(),
                    source: "proc".into(),
                    options: None,
                },
                Mount {
                    destination: "/dev".into(),
                    type_: "tmpfs".into(),
                    source: "tmpfs".into(),
                    options: Some(vec![
                        "nosuid".into(),
                        "strictatime".into(),
                        "mode=755".into(),
                        "size=65536k".into(),
                    ]),
                },
                Mount {
                    destination: "/dev/pts".into(),
                    type_: "devpts".into(),
                    source: "devpts".into(),
                    options: Some(vec![
                        "nosuid".into(),
                        "noexec".into(),
                        "newinstance".into(),
                        "ptmxmode=0666".into(),
                        "mode=0620".into(),
                        "gid=5".into(),
                    ]),
                },
                Mount {
                    destination: "/dev/shm".into(),
                    type_: "tmpfs".into(),
                    source: "shm".into(),
                    options: Some(vec![
                        "nosuid".into(),
                        "noexec".into(),
                        "nodev".into(),
                        "mode=1777".into(),
                        "size=65536k".into(),
                    ]),
                },
                Mount {
                    destination: "/dev/mqueue".into(),
                    type_: "mqueue".into(),
                    source: "mqueue".into(),
                    options: Some(vec![
                        "nosuid".into(),
                        "noexec".into(),
                        "nodev".into(),
                        "ro".into(),
                    ]),
                },
            ],
            linux: Some(Spec::linux(is_rootless)),
            hooks: None,
            annotations: None,
            solaris: None,
            windows: None,
            vm: None,
        }
    }

    fn linux(is_rootless: bool) -> Linux {
        let mut namespace_types = vec![
            LinuxNamespaceType::Ipc,
            LinuxNamespaceType::Mount,
            LinuxNamespaceType::Uts,
            LinuxNamespaceType::Pid,
            LinuxNamespaceType::Network,
        ];
        if is_rootless {
            namespace_types.push(LinuxNamespaceType::User);
        }

        let namespaces: Vec<LinuxNamespace> = namespace_types
            .iter()
            .map(|type_| LinuxNamespace {
                type_: *type_,
                path: None,
            })
            .collect();

        Linux {
            masked_paths: Some(vec![
                "/proc/kcore".into(),
                "/proc/latency_stats".into(),
                "/proc/timer_list".into(),
                "/proc/timer_stats".into(),
                "/proc/sched_debug".into(),
                "/sys/firmware".into(),
                "/proc/scsi".into(),
            ]),
            readonly_paths: Some(vec![
                "/proc/asound".into(),
                "/proc/bus".into(),
                "/proc/fs".into(),
                "/proc/irq".into(),
                "/proc/sys".into(),
                "/proc/sysrq-trigger".into(),
            ]),
            resources: Some(LinuxResources {
                devices: Some(vec![LinuxDeviceCgroup {
                    allow: false,
                    access: Some("rwm".into()),
                    type_: None,
                    major: None,
                    minor: None,
                }]),
                block_io: None,
                cpu: None,
                memory: None,
                network: None,
                hugepage_limits: None,
                pids: None,
                rdma: None,
            }),
            namespaces: Some(namespaces),
            cgroups_path: None,
            devices: None,
            uid_mappings: None,
            gid_mappings: None,
            intel_rdt: None,
            mount_label: None,
            seccomp: None,
            rootfs_propagation: None,
            sysctl: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state() {
        let status_string = serde_json::to_string(&Status::Created).unwrap();

        assert_eq!(status_string, "\"created\"");
    }

    #[test]
    fn test_user_convert_json() {
        let user = User {
            uid: 0,
            gid: 0,
            additional_gids: Some(vec![1000, 1001, 1002]),
            username: Some("root".into()),
        };
        let json_string = serde_json::to_string(&user).unwrap();
        assert_eq!(
            r#"{"uid":0,"gid":0,"additionalGids":[1000,1001,1002],"username":"root"}"#,
            json_string
        )
    }

    #[test]
    fn test_linux_id_mapping_convert_json() {
        let user = LinuxIDMapping {
            container_id: 0,
            host_id: 1000,
            size: 1,
        };
        let json_string = serde_json::to_string(&user).unwrap();
        assert_eq!(r#"{"containerID":0,"hostID":1000,"size":1}"#, json_string)
    }
}
