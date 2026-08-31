# Shared helpers for the abandonauth scripts. Source this; do not execute it.
# shellcheck shell=sh

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
API_DIR="$REPO_ROOT/src/api"

COMPOSE_TEST_FILE="$REPO_ROOT/compose.test.yml"

# Well under Go's 10 minute default: run_stage only prints when a stage ends, so
# a deadlocked test would show as ten silent minutes rather than a failure.
TEST_TIMEOUT="300s"

MINIMUM_COVERAGE=80

# Reproduced on every run and not committed, so not held to the coverage rule.
GENERATED_PACKAGES='/internal/database/query$|/docs$'

# Constants and type declarations only, so there are no statements to cover.
STATEMENT_FREE_PACKAGES='/internal/buildmode$|/internal/web/models$'

info() { printf '==> %s\n' "$*"; }
ok() { printf '==> %s ... ok\n' "$*"; }
die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

# require_command <program> <hint>
require_command() {
    command -v "$1" >/dev/null 2>&1 || die "$1 is not installed. $2"
}

# run_stage <name> <command...>
# Quiet on success, dumps captured output on failure. VERBOSE=1 streams instead.
run_stage() {
    name=$1
    shift
    if [ "${VERBOSE:-0}" = "1" ]; then
        info "$name"
        "$@" || exit $?
        return 0
    fi
    # The `if` wrapper is load-bearing: under `set -e` a bare `out=$(...)` exits
    # the shell the instant the command fails, losing the captured output.
    if out=$("$@" 2>&1); then
        ok "$name"
        return 0
    fi
    status=$?
    printf '==> %s ... FAILED\n' "$name" >&2
    printf '%s\n' "$out" >&2
    exit $status
}

# stream_stage <name> <command...>
# For stages slow enough that captured output would look like a hang.
stream_stage() {
    name=$1
    shift
    info "$name"
    "$@" || exit $?
    ok "$name"
}

compose() {
    (cd "$REPO_ROOT" && docker compose -f "$COMPOSE_TEST_FILE" "$@")
}
