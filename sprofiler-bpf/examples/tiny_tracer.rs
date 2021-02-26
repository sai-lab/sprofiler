use std::collections::HashSet;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;
use libbpf_rs::PerfBufferBuilder;
use plain::Plain;

use sprofiler_bpf::*;

#[repr(C)]
#[derive(Default, Debug)]
struct SysEnterEvent {
    pub uid: u32,
    pub cgid: u64,
    pub syscall_nr: u32,
    pub comm: [u8; 32],
}

unsafe impl Plain for SysEnterEvent {}

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = SysEnterEvent::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short or invalid");

    // let comm = str::from_utf8(&event.comm).unwrap().trim_end_matches('\0');

    let syscall_name = syscalls::SYSCALLS
        .get(&(*&event.syscall_nr as u32))
        .unwrap_or(&"unknown");

    if syscall_name != &"unknown" {
        let mut syscall_list = SYSCALL_LIST.lock().unwrap();
        syscall_list.insert(syscall_name);
    }

    // println!("syscall: {}", syscall_name);
}

fn handle_lost_event(cpu: i32, count: u64) {
    eprintln!("Lost event (CPU: {}, COUNT: {})", cpu, count);
}

lazy_static! {
    static ref SYSCALL_LIST: Mutex<HashSet<&'static str>> = Mutex::new(HashSet::new());
}

fn show_syscalls() {
    let syscall_list = SYSCALL_LIST.lock().unwrap();
    let mut syscall_list: Vec<&'static str> = syscall_list.clone().into_iter().collect();
    syscall_list.sort();
    let s = syscall_list.join(", ");
    println!("{}", s);
}

/// only work when cgroup driver is systemd & v2
fn get_contianer_cgroup_id(container_id: &str) -> anyhow::Result<u64> {
    let path = format!("/sys/fs/cgroup/system.slice/docker-{}.scope/", container_id);
    let path = PathBuf::from(path);
    let meta = fs::metadata(&path)?;
    Ok(meta.ino())
}

fn main() -> anyhow::Result<()> {
    let mut skel_builder = SystraceSkelBuilder::default();
    let mut systrace_skel = skel_builder.open()?;

    systrace_skel.rodata().target_cgid = get_contianer_cgroup_id("container-id")?;

    let mut skel = systrace_skel.load()?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("ctrl-c interrupt");

    skel.attach()?;

    let perf = PerfBufferBuilder::new(skel.maps().sys_enter_events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_event)
        .build()?;

    println!("PID: {}", std::process::id());
    println!("Press Ctrl-C to exit");

    while running.load(Ordering::SeqCst) {
        if let Err(err) = perf.poll(std::time::Duration::from_millis(100)) {
            eprintln!("{}", err);
            break;
        }
    }

    show_syscalls();

    Ok(())
}
