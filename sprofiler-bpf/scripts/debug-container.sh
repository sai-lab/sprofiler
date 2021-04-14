#!/bin/bash

set -eux

function run() {
    podman \
        --hooks-dir $(pwd)/hooks \
        run -d --cidfile=/tmp/debug-container.cid \
        -p 8081:80 \
        --annotation "io.sprofiler.output_seccomp_profile_path=/tmp/seccomp-profile.json" \
        docker.io/library/nginx
}

function stop() {
    podman \
        --hooks-dir $(pwd)/hooks \
        stop $(cat /tmp/debug-container.cid)
    rm /tmp/debug-container.cid
}

function state() {
    crun --root /run/crun state $(cat /tmp/debug-container.cid)
}

function trace-stop() {
    bundle=$(crun --root /run/crun state $(cat /tmp/debug-container.cid) | jq .bundle | sed -e 's/^"//' -e 's/"$//' )
    # pkill -SIGUSR1 $(cat $bundle/sprofiler.pid)
    pkill -SIGTERM $(cat $bundle/sprofiler.pid)
}

function trace-kill-all() {
    /bin/kill -SIGKILL $(pidof sprofiler-bpf)
}

$1
