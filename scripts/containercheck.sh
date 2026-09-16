#!/usr/bin/env sh
# The checks that need a database and a C toolchain, so they cannot run on the
# host. Started by scripts/check.sh --integration.
set -eu

. "$(dirname -- "$0")/lib.sh"

cd "$API_DIR"

[ -n "${TEST_DATABASE_URL:-}" ] || die "TEST_DATABASE_URL is not set inside the container"

COVERAGE_PROFILE=/tmp/coverage.out

# The deployment integration files are constrained to `integration && !devtools`,
# so this run carries the development unit and integration packages without
# repeating the deployment journeys below.
stream_stage "go test -race (-tags='integration devtools')" \
    go test -race -count=1 -timeout "$TEST_TIMEOUT" -tags='integration devtools' ./...

# -covermode=atomic is required whenever coverage and -race are combined.
#
# -coverpkg covers the whole module from every test binary. The suite drives
# endpoints, so the services and the persistence behind them are reached through
# internal/web; measuring each package only from its own tests would score that
# work zero and push the suite towards testing units nobody calls.
stream_stage "go test -race (-tags=integration, with coverage)" \
    go test \
    -race \
    -count=1 \
    -timeout "$TEST_TIMEOUT" \
    -tags=integration \
    -covermode=atomic \
    -coverpkg=./... \
    -coverprofile="$COVERAGE_PROFILE" \
    ./...

# Sums the profile's real statement counts per package. Averaging the
# per-function percentages that `go tool cover -func` prints is not equivalent:
# a one-statement function would weigh as much as a fifty-statement one.
#
# Every test binary reports on the whole module, so a block appears once per
# binary. It is counted once, and as reached if any binary reached it.
package_coverage() {
    awk '
        NR > 1 {
            block = $1
            size[block] = $2
            if ($3 > 0) {
                reached[block] = 1
            }
        }
        END {
            for (block in size) {
                package = block
                sub(/:.*$/, "", package)
                sub(/\/[^\/]*$/, "", package)
                statements[package] += size[block]
                if (block in reached) {
                    covered[package] += size[block]
                }
            }
            for (package in statements) {
                printf "%s %.1f\n", package, 100 * covered[package] / statements[package]
            }
        }
    ' "$COVERAGE_PROFILE" | sort
}

info "coverage"

below=""

# Listed from `go list` rather than from the profile, so a package with no test
# of its own cannot pass by never appearing in it.
for package in $(go list -tags=integration ./...); do
    if printf '%s\n' "$package" | grep -qE "$GENERATED_PACKAGES"; then
        continue
    fi
    if printf '%s\n' "$package" | grep -qE "$STATEMENT_FREE_PACKAGES"; then
        continue
    fi

    measured=$(package_coverage | awk -v want="$package" '$1 == want { print $2 }')

    if [ -z "$measured" ]; then
        printf '    %s: no statements were covered\n' "$package"
        below="$below $package"
        continue
    fi

    printf '    %s: %s%%\n' "$package" "$measured"

    if awk -v have="$measured" -v want="$MINIMUM_COVERAGE" 'BEGIN { exit !(have < want) }'; then
        below="$below $package"
    fi
done

if [ -n "$below" ]; then
    printf '==> coverage ... FAILED\n' >&2
    printf 'below %s%% statement coverage:\n' "$MINIMUM_COVERAGE" >&2
    for package in $below; do
        printf '  %s\n' "$package" >&2
    done
    exit 1
fi

ok "coverage"

info "container checks passed"
