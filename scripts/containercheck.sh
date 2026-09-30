#!/usr/bin/env sh
# The checks that need a database and a C toolchain, so they cannot run on the
# host. Started by scripts/check.sh --integration.
set -eu

. "$(dirname -- "$0")/lib.sh"

cd "$API_DIR"

[ -n "${TEST_DATABASE_URL:-}" ] || die "TEST_DATABASE_URL is not set inside the container"
[ -n "${TEST_TEMPLATE_DATABASE:-}" ] || die "TEST_TEMPLATE_DATABASE is not set inside the container"
[ -n "${GOOSE_DBSTRING:-}" ] || die "GOOSE_DBSTRING is not set inside the container"

COVERAGE_PROFILE=/tmp/coverage.out

# Runs against the template the tests clone, and ends by rebuilding it, so every
# test schema is one this lifecycle has just produced. The DSN carries no
# password and is never printed; PGPASSWORD supplies it.
sql() {
    psql "$GOOSE_DBSTRING" -v ON_ERROR_STOP=1 -tAq -c "$1"
}

expect_sql() {
    found=$(sql "$1") || die "migration lifecycle: query failed: $1"
    [ "$found" = "$2" ] || die "migration lifecycle: $3 (found '$found', want '$2')"
}

goose_run() {
    if ! out=$(goose -env=none -no-color "$@" 2>&1); then
        printf '%s\n' "$out" >&2
        die "migration lifecycle: goose $* failed"
    fi
}

migration_lifecycle() {
    history="SELECT count(*) FROM goose_db_version"
    recorded=$(sql "$history") || die "migration lifecycle: the template has no migration history"

    goose_run up
    expect_sql "$history" "$recorded" "a second up was not a no-op"
    expect_sql "SELECT count(*) FROM (SELECT version_id FROM goose_db_version
        GROUP BY version_id HAVING count(*) > 1) repeated" 0 "a version is recorded twice"

    sql "INSERT INTO \"User\" (id, username) VALUES ('00000000-0000-4000-8000-000000000001', 'seeded');
        INSERT INTO \"DeveloperApplication\" (id, owner_id, refresh_token)
            VALUES ('00000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-000000000001', 'placeholder');
        INSERT INTO \"CallbackUri\" (developer_application_id, uri)
            VALUES ('00000000-0000-4000-8000-000000000002', 'https://relying.example.test/return');
        INSERT INTO jwt_revocation (jti, auth_epoch, expires_at)
            SELECT gen_random_uuid(), epoch, now() + interval '1 hour' FROM auth_epoch;
        INSERT INTO rate_limit_bucket (bucket_key, endpoint_group, window_start, expires_at, count)
            VALUES (decode(repeat('ab', 32), 'hex'), 'burn_token', now(), now() + interval '1 minute', 1);" \
        >/dev/null || die "migration lifecycle: seeding failed"

    goose_run down
    expect_sql "SELECT concat_ws(',', to_regclass('auth_epoch'), to_regclass('jwt_revocation'),
        to_regclass('rate_limit_bucket'), to_regclass('browser_session'), to_regclass('oauth_exchange_code'),
        to_regclass('oauth_authorization_state'))" "" "down left auth-state tables behind"
    expect_sql "SELECT count(*) FROM information_schema.columns
        WHERE table_name = 'DeveloperApplication' AND column_name = 'credential_version'" 0 \
        "down left the developer credential version behind"
    expect_sql "SELECT (SELECT count(*) FROM \"User\") || ',' || (SELECT count(*) FROM \"DeveloperApplication\")
        || ',' || (SELECT count(*) FROM \"CallbackUri\")" "1,1,1" "down removed baseline data"

    goose_run down-to 0
    expect_sql "SELECT concat_ws(',', to_regclass('\"User\"'), to_regclass('\"DeveloperApplication\"'),
        to_regclass('\"CallbackUri\"'), to_regclass('\"PasswordAccount\"'), to_regclass('\"DiscordAccount\"'),
        to_regclass('\"GitHubAccount\"'), to_regclass('\"GoogleAccount\"'))" "" "down-to 0 left baseline tables behind"

    goose_run up
    expect_sql "SELECT max(version_id) FROM goose_db_version WHERE is_applied" \
        "$(ls /migrations | sed -n 's/^\([0-9]*\)_.*/\1/p' | sort -n | tail -1)" "up did not reach the newest migration"
    expect_sql "SELECT (SELECT count(*) FROM auth_epoch) || ',' || (SELECT count(*) FROM \"User\")" "1,0" \
        "the rebuilt template is not a fresh schema"
}

stream_stage "migration lifecycle (up, no-op up, down, down-to 0, up)" migration_lifecycle

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
