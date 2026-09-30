#!/usr/bin/env sh
# The Compose migration controller, checked in a project of its own. Started by
# scripts/check.sh --integration. No environment value is ever printed.
set -eu

. "$(dirname -- "$0")/lib.sh"

require_command docker 'Install Docker from https://docs.docker.com/get-docker/.'

PROJECT=abandonauth-migration-check
TEMPLATE=abandonauth_template
ALLOWED_NAMES='GOOSE_DBSTRING GOOSE_DRIVER GOOSE_MIGRATION_DIR PGPASSWORD'

project() {
    (cd "$REPO_ROOT" && docker compose -p "$PROJECT" -f "$COMPOSE_TEST_FILE" --profile migration-gate "$@")
}

cleanup() {
    project down -v --remove-orphans -t 0 >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM

container_of() {
    project ps -a -q "$1"
}

history_query() {
    project exec -T database psql -U abandonauth -d "$TEMPLATE" -v ON_ERROR_STOP=1 -tAq -c "$1"
}

converge() {
    project up -d --wait database >/dev/null 2>&1 || die "the database did not start"

    project up migrations >/dev/null 2>&1 &
    first=$!
    project up migrations >/dev/null 2>&1 &
    second=$!

    first_status=0
    second_status=0
    wait "$first" || first_status=$?
    wait "$second" || second_status=$?

    if [ "$first_status" -ne 0 ] && [ "$second_status" -ne 0 ]; then
        die "neither concurrent up request migrated the database"
    fi

    [ "$(container_of migrations | wc -l | tr -d ' ')" = 1 ] ||
        die "concurrent up requests created more than one migration container"

    repeated=$(history_query "SELECT count(*) FROM (SELECT version_id FROM goose_db_version
        GROUP BY version_id HAVING count(*) > 1) repeated")
    [ "$repeated" = 0 ] || die "a migration version is recorded more than once"

    applied=$(history_query "SELECT count(DISTINCT version_id) FROM goose_db_version
        WHERE is_applied AND version_id > 0")
    carried=$(ls "$API_DIR/migrations" | grep -c '^[0-9][0-9]*_.*\.sql$')
    [ "$applied" = "$carried" ] || die "history records $applied migrations, the directory carries $carried"
}

gate() {
    # A wrong password, so the failure is the database refusing the migration.
    sentinel="migration-check-sentinel-$$-$(date +%s)"

    if MIGRATION_CHECK_PASSWORD="$sentinel" project up -d migration-gate-api >/dev/null 2>&1; then
        die "Compose reported success although the migration could not authenticate"
    fi

    migration=$(container_of migrations)
    [ -n "$migration" ] || die "the failing migration left no container to inspect"

    [ "$(docker inspect -f '{{.State.ExitCode}}' "$migration")" != 0 ] ||
        die "the migration with a wrong password exited successfully"

    api=$(container_of migration-gate-api)
    if [ -n "$api" ]; then
        started=$(docker inspect -f '{{.State.StartedAt}}' "$api")
        case "$started" in
        0001-01-01T00:00:00*) ;;
        *) die "the API was started although its migration failed" ;;
        esac
    fi

    logs=$(project logs --no-color migrations 2>&1)
    case "$logs" in
    *"$sentinel"*) die "the database password reached the migration log" ;;
    esac
    case "$logs" in
    *"authentication failed"*) ;;
    *) die "the migration did not fail on authentication, so the gate was not what failed it" ;;
    esac

    arguments=$(docker inspect -f '{{.Path}} {{join .Args " "}} {{join .Config.Entrypoint " "}} {{join .Config.Cmd " "}}' "$migration")
    case "$arguments" in
    *"$sentinel"*) die "the database password reached the migration's arguments" ;;
    esac
    case "$arguments" in
    *"-env=none"*) ;;
    *) die "Goose is not started with -env=none" ;;
    esac

    image_names=$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' \
        "$(docker inspect -f '{{.Image}}' "$migration")" | sed 's/=.*//')

    for variable in $(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$migration" | sed 's/=.*//'); do
        case " $ALLOWED_NAMES " in
        *" $variable "*) continue ;;
        esac
        if printf '%s\n' "$image_names" | grep -qx "$variable"; then
            continue
        fi
        die "the migration container receives $variable, which is not on its allowlist"
    done

    project up -d migration-gate-api >/dev/null 2>&1 ||
        die "the API was not started once its migration succeeded"

    [ "$(docker inspect -f '{{.State.Running}}' "$(container_of migration-gate-api)")" = true ] ||
        die "the API is not running after a successful migration"
}

stream_stage "migration controller: concurrent up converges" converge
stream_stage "migration controller: a failed migration starts no API and leaks no password" gate
