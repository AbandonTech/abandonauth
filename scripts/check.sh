#!/usr/bin/env sh
# The validate pipeline. CI runs this same script, so local and CI cannot drift.
#
#   scripts/check.sh                 codegen + fmt + tidy + build + lint + unit tests
#   scripts/check.sh --quick         skip codegen and tidy (no SQL or annotation change)
#   scripts/check.sh --gen-only      only sqlc + swag + tidy, then stop
#   scripts/check.sh --fix-fmt       format the source, then run the default checks
#   scripts/check.sh --integration   also run the database, race and coverage checks
#   scripts/check.sh --verbose       stream each stage's output instead of capturing it
#
# Quiet on success. On failure the offending stage's output is dumped.
set -eu

. "$(dirname -- "$0")/lib.sh"

quick=0
gen_only=0
fix_fmt=0
integration=0

while [ $# -gt 0 ]; do
    case "$1" in
    --quick) quick=1 ;;
    --gen-only) gen_only=1 ;;
    --fix-fmt) fix_fmt=1 ;;
    --integration) integration=1 ;;
    -v | --verbose)
        VERBOSE=1
        export VERBOSE
        ;;
    -h | --help)
        sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *) die "unknown flag: $1 (see --help)" ;;
    esac
    shift
done

if [ "$quick" -eq 1 ] && [ "$gen_only" -eq 1 ]; then
    die "--quick and --gen-only are mutually exclusive"
fi

if [ "$fix_fmt" -eq 1 ] && [ "$gen_only" -eq 1 ]; then
    die "--fix-fmt and --gen-only are mutually exclusive"
fi

require_command go 'Install the Go toolchain from https://go.dev/dl/.'
require_command git 'Install git.'

cd "$API_DIR"

# Both variants are built and tested, because the production build's job is to
# not contain password sign-in or the documentation UI.
DEVTOOLS_TAG=devtools

fmt_stage() {
    unformatted=$(gofmt -l . 2>&1)
    if [ -z "$unformatted" ]; then
        ok "go fmt check"
        return 0
    fi
    if [ "$fix_fmt" -eq 1 ]; then
        run_stage "go fmt" gofmt -w .
        ok "go fmt check (reformatted $(printf '%s\n' "$unformatted" | wc -l | tr -d ' ') file(s))"
        return 0
    fi
    printf '==> go fmt check ... FAILED\n' >&2
    printf 'Not gofmt-formatted. Run scripts/check.sh --fix-fmt and commit the result:\n%s\n' \
        "$unformatted" >&2
    exit 1
}

# go.mod and go.sum are tracked and must not move under a check.
tidy_is_clean() {
    git -C "$REPO_ROOT" diff --quiet -- src/api/go.mod src/api/go.sum
}

if [ "$quick" -eq 0 ]; then
    # Tool versions come from the tool directives in go.mod, so `go tool` runs
    # the same sqlc and swag here, in CI and in the container.
    run_stage "sqlc generate" go tool sqlc generate
    run_stage "swag init" go tool swag init \
        --v3.1 \
        --generalInfo cmd/abandonauth.go \
        --dir . \
        --output docs \
        --outputTypes go,json \
        --parseDependency=false \
        --quiet
    run_stage "go mod tidy" go mod tidy
    tidy_is_clean || die "go mod tidy changed go.mod or go.sum; commit the result"
fi

if [ "$gen_only" -eq 1 ]; then
    info "codegen done"
    exit 0
fi

fmt_stage
run_stage "go build" go build ./...
run_stage "go build (-tags=$DEVTOOLS_TAG)" go build -tags="$DEVTOOLS_TAG" ./...
run_stage "revive" go tool revive -config revive.toml -set_exit_status ./...
run_stage "go vet" go vet ./...
run_stage "go vet (-tags=$DEVTOOLS_TAG)" go vet -tags="$DEVTOOLS_TAG" ./...
# Not gated on --integration: this type-checks the integration files without a
# database, so a break in one does not stay invisible until the container runs.
run_stage "go vet (-tags=integration)" go vet -tags=integration ./...

# -count=1 disables the test cache, which can conceal a failure caused by state
# outside a package's compiled Go inputs.
run_stage "go test" go test -count=1 -timeout "$TEST_TIMEOUT" ./...
run_stage "go test (-tags=$DEVTOOLS_TAG)" \
    go test -count=1 -timeout "$TEST_TIMEOUT" -tags="$DEVTOOLS_TAG" ./...

if [ "$integration" -eq 0 ]; then
    info "all checks passed (the database, race and coverage checks need --integration)"
    exit 0
fi

require_command docker 'Install Docker from https://docs.docker.com/get-docker/.'

# Streams rather than going quiet, because building and pulling take long enough
# that silence looks like a hang.
stream_stage "container checks" compose run --rm --build check

info "all checks passed"
