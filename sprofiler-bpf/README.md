# Sprofiler-BPF


## Prepare build environtment

TBD

## Installation

```
cargo deb --install
```

## Usage

```
sudo podman --hooks-dir /usr/share/containers/oci/hooks.d \
    run --rm --annotation "io.sprofiler.output_seccomp_profile_path=/tmp/seccomp-profile.json" \
    hello_world
```
