#!/bin/bash

set -eux

PROFILE=/tmp/seccomp-profile.json
TRACE_CONTAINER_ID_FILE=/tmp/nginx.cid
CONTAIN_SCMP_CONTAINER_ID_FILE=/tmp/nginx-with-seccomp.cid

function run() {
    podman \
        --hooks-dir $(pwd)/hooks \
        run -d \
        --cidfile $TRACE_CONTAINER_ID_FILE \
        -p 8081:80 \
        --annotation "io.sprofiler.output_seccomp_profile_path=${PROFILE}" \
        docker.io/library/nginx:1.19
}

function enter() {
    podman \
        exec -it $(cat $TRACE_CONTAINER_ID_FILE) /bin/bash
}

function stop() {
    podman \
        --hooks-dir $(pwd)/hooks \
        stop $(cat $TRACE_CONTAINER_ID_FILE)

    rm $TRACE_CONTAINER_ID_FILE
    cat $PROFILE | jq .
}

function state() {
    crun --root /run/crun state $(cat $TRACE_CONTAINER_ID_FILE)
}

function trace-stop() {
    bundle=$(crun --root /run/crun state $(cat $TRACE_CONTAINER_ID_FILE) | jq .bundle | sed -e 's/^"//' -e 's/"$//' )
    # pkill -SIGUSR1 $(cat $bundle/sprofiler.pid)
    pkill -SIGTERM $(cat $bundle/sprofiler.pid)
}

function trace-kill-all() {
    /bin/kill -SIGKILL $(pidof sprofiler-bpf)
}

function run-with-seccomp() {
    podman \
        run -d  \
        --cidfile=$CONTAIN_SCMP_CONTAINER_ID_FILE \
        -p 8080:80 \
        --security-opt seccomp=/tmp/seccomp-profile.json \
        docker.io/library/nginx:1.19
}

function stop-seccomp-container() {
    podman \
        stop $(cat $CONTAIN_SCMP_CONTAINER_ID_FILE)

    rm $CONTAIN_SCMP_CONTAINER_ID_FILE
}

$1
