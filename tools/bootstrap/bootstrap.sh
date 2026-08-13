#!/bin/sh
# Reproducible, project-local development bootstrap.
#
# This small POSIX entrypoint always starts the Bash implementation through the
# locked, sanitized launcher. The Python launcher establishes an ephemeral
# inherited FD/cookie handoff and holds the cache lock before re-executing the
# internal Bash payload; every invocation is validated and runs exactly once
# with a fixed environment.
set -eu

script_dir=${0%/*}
if [ "$script_dir" = "$0" ]; then
    script_dir=.
elif [ -z "$script_dir" ]; then
    script_dir=/
fi
script_dir=$(CDPATH= cd -- "$script_dir" && pwd -P) || {
    printf 'bootstrap error: could not resolve script directory\n' >&2
    exit 1
}
exec /usr/bin/python3 -E -S "$script_dir/bootstrap-lock.py" \
    "$script_dir/bootstrap.bash" "$@"
