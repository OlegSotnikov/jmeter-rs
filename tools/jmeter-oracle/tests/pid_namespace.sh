#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# This is the only launcher for the ignored oracle process-group test.  The
# inner shell proves the user/PID namespace, PID 1, and namespace-local /proc
# before inheriting a proof token into the one exact Cargo test.  It has no
# cleanup or signal path of its own.

set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
host_pid_namespace=$(readlink /proc/self/ns/pid 2>/dev/null || true)
host_user_namespace=$(readlink /proc/self/ns/user 2>/dev/null || true)
unshare_path=$(command -v unshare 2>/dev/null || true)
if [[ -z "$host_pid_namespace" || -z "$host_user_namespace" ]]; then
    echo "caller PID/user namespace identity is unavailable; refusing to run" >&2
    exit 78
fi
if [[ -z "$unshare_path" ]]; then
    echo "unshare is unavailable; refusing to run process-group tests" >&2
    exit 78
fi

cd "$repo_root"
export JMT_HOST_PID_NAMESPACE="$host_pid_namespace"
export JMT_HOST_USER_NAMESPACE="$host_user_namespace"
exec "$unshare_path" --user --map-root-user --pid --fork --mount-proc sh -eu -c '
    inner_pid_namespace=$(readlink /proc/self/ns/pid 2>/dev/null || true)
    inner_user_namespace=$(readlink /proc/self/ns/user 2>/dev/null || true)
    if [ -z "$inner_pid_namespace" ] || [ -z "$inner_user_namespace" ]; then
        echo "inner namespace identity is unavailable; refusing to run" >&2
        exit 78
    fi
    if [ "$inner_pid_namespace" = "$JMT_HOST_PID_NAMESPACE" ]; then
        echo "PID namespace isolation was not established; refusing to run" >&2
        exit 78
    fi
    namespace_escape_probe=$(readlink /proc/self/ns/pid 2>/dev/null || true)
    if [ -z "$namespace_escape_probe" ] || [ "$namespace_escape_probe" = "$JMT_HOST_PID_NAMESPACE" ]; then
        echo "namespace escape probe failed; refusing to run" >&2
        exit 78
    fi
    if [ "$inner_user_namespace" = "$JMT_HOST_USER_NAMESPACE" ]; then
        echo "user namespace isolation was not established; refusing to run" >&2
        exit 78
    fi
    if [ "$$" -ne 1 ]; then
        echo "namespace init PID is not 1; refusing to run" >&2
        exit 78
    fi

    pid_one_namespace=$(readlink /proc/1/ns/pid 2>/dev/null || true)
    if [ -z "$pid_one_namespace" ] || [ "$pid_one_namespace" != "$inner_pid_namespace" ]; then
        echo "namespace PID 1 identity is not local; refusing to run" >&2
        exit 78
    fi

    nspid_line=
    while IFS= read -r line; do
        case "$line" in
            NSpid:*) nspid_line=${line#NSpid:} ;;
        esac
    done < /proc/self/status
    set -- $nspid_line
    if [ "$#" -lt 2 ]; then
        echo "nested NSpid identity is unavailable; refusing to run" >&2
        exit 78
    fi
    namespace_pid_last=
    for value in "$@"; do
        namespace_pid_last=$value
    done
    if [ "$namespace_pid_last" -ne 1 ]; then
        echo "NSpid does not report namespace PID 1; refusing to run" >&2
        exit 78
    fi

    pid_one_nspid_line=
    while IFS= read -r line; do
        case "$line" in
            NSpid:*) pid_one_nspid_line=${line#NSpid:} ;;
        esac
    done < /proc/1/status
    set -- $pid_one_nspid_line
    if [ "$#" -lt 1 ]; then
        echo "PID 1 NSpid identity is unavailable; refusing to run" >&2
        exit 78
    fi
    pid_one_namespace_pid_last=
    for value in "$@"; do
        pid_one_namespace_pid_last=$value
    done
    if [ "$pid_one_namespace_pid_last" -ne 1 ]; then
        echo "PID 1 is not the namespace reaper; refusing to run" >&2
        exit 78
    fi

    proc_mount_line=
    while IFS= read -r line; do
        case "$line" in
            *" - proc /proc "*) proc_mount_line=$line ;;
        esac
    done < /proc/self/mountinfo
    if [ -z "$proc_mount_line" ]; then
        echo "namespace-local /proc is unavailable; refusing to run" >&2
        exit 78
    fi

    uid_map_line=
    while IFS= read -r line; do uid_map_line=$line; done < /proc/self/uid_map
    set -- $uid_map_line
    if [ "$#" -lt 3 ] || [ "$1" -ne 0 ] || [ "$2" -ne 0 ]; then
        echo "user namespace mapping is not root-mapped; refusing to run" >&2
        exit 78
    fi
    gid_map_line=
    while IFS= read -r line; do gid_map_line=$line; done < /proc/self/gid_map
    set -- $gid_map_line
    if [ "$#" -lt 3 ] || [ "$1" -ne 0 ] || [ "$2" -ne 0 ]; then
        echo "group namespace mapping is not root-mapped; refusing to run" >&2
        exit 78
    fi

    proof_nonce=
    while IFS= read -r line; do proof_nonce=$line; done < /proc/sys/kernel/random/uuid
    case "$proof_nonce" in
        ""|*[!0-9a-f-]*)
            echo "opaque namespace proof nonce is unavailable; refusing to run" >&2
            exit 78
            ;;
    esac
    if [ "${#proof_nonce}" -ne 36 ]; then
        echo "opaque namespace proof nonce is malformed; refusing to run" >&2
        exit 78
    fi
    namespace_proof_validated=1
    JMT_PID_NAMESPACE_PROOF_TOKEN="jmeter-rs-pidns-v1:${inner_pid_namespace}:${namespace_pid_last}:${proof_nonce}"
    export JMT_PID_NAMESPACE_PROOF_TOKEN
    exec cargo test --locked -p jmeter-oracle --lib timeout_returns_error_after_process_group_cleanup -- --exact --ignored --nocapture
'
