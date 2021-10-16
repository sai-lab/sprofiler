# Sprofiler

[![CI](https://github.com/sai-lab/sprofiler/actions/workflows/ci.yaml/badge.svg)](https://github.com/sai-lab/sprofiler/actions/workflows/ci.yaml)

Sprofiler generate seccomp profiles for OCI Container

## Environment

**sprofiler-bpf**
- Ubuntu >= 20.10

## Getting Started

### sprofiler

```
cargo build
```

### sprofiler-bpf

```
sudo apt install libelf-dev libgcc-s1 libbpf-dev clang
cargo libbpf make
```

## License
