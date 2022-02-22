# Sprofiler

**This project is not maintained.
Sprofiler is maintained in this repository.**
https://github.com/guni1192/sprofiler

Sprofiler generate seccomp profiles for OCI Container

## Environment

**sprofiler-bpf**
- Ubuntu >= 20.10
- Podman >= 3.0
- Cgroup v2

## Getting Started

### Build

```
sudo apt install libelf-dev libgcc-s1 libbpf-dev clang curl linux-tools-generic linux-tools-common make pkg-config podman
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./sprofiler-bpf/src/bpf/vmlinux.h
cargo libbpf make
```

### Run

```
# Run container with dynamic analyzer
sudo podman run \
    --annotation "io.sprofiler.output_seccomp_profile_path=$(pwd)/seccomp-profile.json" \
    ghcr.io/sai-lab/hello-c:latest

# Run container enable no-new-privileges with dynamic analyzer 
sudo podman run --security-opt=no-new-privileges \
    --annotation "io.sprofiler.output_seccomp_profile_path=$(pwd)/seccomp-profile.json" \
    ghcr.io/sai-lab/hello-c:latest

# check
sudo podman run --rm --security-opt seccomp=$(pwd)/seccomp-profile.json guni1192/clang-app
```

## Testing

```
cargo libbpf make
sudo -E ./target/debug/sprofiler-test ./integration_test/sprofiler-test.yaml
```

## Vagrant for develop environment

```
vagrant up --provider=libvirt
```

## License

Apache License Version 2.0
