IMAGE=ghcr.io/sai-lab/hello-c
PROFILES=profiles


mkdir -p profiles/$IMAGE

sudo podman --hooks-dir ./integration_test/sprofiler-bpf/hooks \
    run \
    --annotation "io.sprofiler.output_seccomp_profile_path=$(pwd)/profiles/$IMAGE.json" \
    $IMAGE
