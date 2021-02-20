use serde_derive::{Deserialize, Serialize};

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
