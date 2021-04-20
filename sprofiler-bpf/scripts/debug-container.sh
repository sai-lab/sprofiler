#!/bin/bash

set -u

PROFILE=/tmp/seccomp-profile.json
TRACE_CONTAINER_ID_FILE=/tmp/nginx.cid
CONTAIN_SCMP_CONTAINER_ID_FILE=/tmp/nginx-with-seccomp.cid
IMAGE=docker.io/library/nginx:1.19
# IMAGE=docker.io/guni1192/sprofiler-demo-app

function run() {
    if [ -f $PROFILE ]; then
        rm -rf $PROFILE
    fi

    podman \
        --hooks-dir $(pwd)/hooks \
        run -d \
        --rm \
        --cidfile $TRACE_CONTAINER_ID_FILE \
        -p 8081:80 \
        --annotation "io.sprofiler.output_seccomp_profile_path=${PROFILE}" \
        $IMAGE
}

function enter() {
    podman \
        exec -it $(cat $TRACE_CONTAINER_ID_FILE) /bin/bash
}

function stop() {
    podman \
        --hooks-dir $(pwd)/hooks \
        stop $(cat $TRACE_CONTAINER_ID_FILE)

    rm -rf $TRACE_CONTAINER_ID_FILE
}

function state() {
    crun --root /run/crun state $(cat $TRACE_CONTAINER_ID_FILE)
}

function trace-stop() {
    bundle=$(crun --root /run/crun state $(cat $TRACE_CONTAINER_ID_FILE) | jq .bundle | sed -e 's/^"//' -e 's/"$//' )
    pkill -SIGTERM $(cat $bundle/sprofiler.pid)
}

function trace-kill-all() {
    /bin/kill -SIGKILL $(pidof sprofiler-bpf)
}

function run-with-seccomp() {
    podman \
        run -d  \
        --rm \
        --cidfile=$CONTAIN_SCMP_CONTAINER_ID_FILE \
        -p 8080:80 \
        --security-opt seccomp=/tmp/seccomp-profile.json \
        $IMAGE
}

function stop-seccomp-container() {
    podman \
        stop $(cat $CONTAIN_SCMP_CONTAINER_ID_FILE)

    rm -rf $CONTAIN_SCMP_CONTAINER_ID_FILE
}

$1
