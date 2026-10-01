#!/usr/bin/env sh
# The Compose migration controller, checked in a project of its own. Started by
# scripts/check.sh --integration. No environment value is ever printed.
set -eu

. "$(dirname -- "$0")/lib.sh"

require_command docker 'Install Docker from https://docs.docker.com/get-docker/.'

PROJECT=abandonauth-migration-check
TEMPLATE=abandonauth_template
ALLOWED_NAMES='GOOSE_DBSTRING GOOSE_DRIVER GOOSE_MIGRATION_DIR PGPASSWORD'
PROVISIONING_ALLOWED_NAMES='DATABASE_URL DEBUG'
APPLICATION_ID=6f5902ac-237a-4ba0-8a51-1ed0b6c1c0f0
SECOND_APPLICATION_ID=0b0e5a3c-6a52-4e57-9d5c-6c1bd5ab0a8e
SITE_CALLBACK=https://auth.example.test/api/ui
# The provisioning container's connection carries the database password as this
# text; it must reach neither the container's arguments nor its log.
DATABASE_CREDENTIAL='abandonauth:placeholder@'

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

    never_started migration-gate-api "the API was started although its migration failed"
    never_started provisioning "provisioning was started although its migration failed"

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

    require_allowlist "$migration" "$ALLOWED_NAMES" migration
}

# never_started <service> <message>
never_started() {
    container=$(container_of "$1")
    if [ -n "$container" ]; then
        started=$(docker inspect -f '{{.State.StartedAt}}' "$container")
        case "$started" in
        0001-01-01T00:00:00*) ;;
        *) die "$2" ;;
        esac
    fi
}

# require_allowlist <container> <allowed names> <label>
# Names only: no environment value is read or printed.
require_allowlist() {
    image_names=$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' \
        "$(docker inspect -f '{{.Image}}' "$1")" | sed 's/=.*//')

    for variable in $(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$1" | sed 's/=.*//'); do
        case " $2 " in
        *" $variable "*) continue ;;
        esac
        if printf '%s\n' "$image_names" | grep -qx "$variable"; then
            continue
        fi
        die "the $3 container receives $variable, which is not on its allowlist"
    done
}

provisioned_rows() {
    history_query 'SELECT (SELECT count(*) FROM "User") || '"' '"' ||
        (SELECT count(*) FROM "DeveloperApplication") || '"' '"' ||
        (SELECT count(*) FROM "CallbackUri")'
}

# refuse_provisioning <label> <reason> <run arguments...>
# Runs the deployment image's provisioning alone and requires it to fail for
# the stated reason, so a run that could not start is not mistaken for one.
refuse_provisioning() {
    label=$1
    reason=$2
    shift 2
    if refusal=$(project run --rm --no-deps "$@" 2>&1); then
        die "provisioning accepted $label"
    fi
    case "$refusal" in
    *"$DATABASE_CREDENTIAL"*) die "refusing $label repeated the database password" ;;
    *"$reason"*) ;;
    *) die "provisioning failed on $label, but not because it refused it" ;;
    esac
}

provisioning_gate() {
    # A plain HTTP origin off the loopback interface, distinctive enough that
    # finding it in a log proves it was repeated.
    sentinel="http://provisioning-sentinel-$$-$(date +%s).example.test"

    if PROVISIONING_CHECK_SITE_URL="$sentinel" project up -d migration-gate-api >/dev/null 2>&1; then
        die "Compose reported success although provisioning was refused its site origin"
    fi

    [ "$(docker inspect -f '{{.State.ExitCode}}' "$(container_of migrations)")" = 0 ] ||
        die "the migration did not succeed, so the provisioning gate was not what stopped the API"

    provisioning=$(container_of provisioning)
    [ -n "$provisioning" ] || die "the refused provisioning left no container to inspect"

    [ "$(docker inspect -f '{{.State.ExitCode}}' "$provisioning")" != 0 ] ||
        die "provisioning with an unsafe site origin exited successfully"

    never_started migration-gate-api "the API was started although provisioning failed"

    logs=$(project logs --no-color provisioning 2>&1)
    case "$logs" in
    *"$sentinel"* | *"$DATABASE_CREDENTIAL"*) die "the provisioning log repeats a refused or secret value" ;;
    esac
    case "$logs" in
    *"must use https"*) ;;
    *) die "provisioning did not fail on its site origin, so the gate was not what failed it" ;;
    esac

    refuse_provisioning "loopback HTTP in a deployment build" "must use https" provisioning provision \
        "--application-id=$APPLICATION_ID" --site-url=http://localhost:3000
    refuse_provisioning "the nil UUID" "nil UUID" provisioning provision \
        --application-id=00000000-0000-0000-0000-000000000000 --site-url=https://auth.example.test
    refuse_provisioning "a malformed UUID" "must be a UUID" provisioning provision \
        --application-id=not-a-uuid --site-url=https://auth.example.test
    refuse_provisioning "DEBUG in a deployment build" "does not support debug mode" -e DEBUG=true \
        provisioning provision "--application-id=$APPLICATION_ID" --site-url=https://auth.example.test

    [ "$(provisioned_rows)" = "0 0 0" ] || die "refused provisioning left accounts, applications or callbacks"
}

provisioning_order() {
    project up -d migration-gate-api >/dev/null 2>&1 ||
        die "the API was not started once its migration and provisioning succeeded"

    provisioning=$(container_of provisioning)
    api=$(container_of migration-gate-api)

    [ "$(docker inspect -f '{{.State.ExitCode}}' "$provisioning")" = 0 ] ||
        die "provisioning did not succeed"
    [ "$(docker inspect -f '{{.State.Running}}' "$api")" = true ] ||
        die "the API is not running after a successful migration and provisioning"

    finished=$(docker inspect -f '{{.State.FinishedAt}}' "$provisioning")
    started=$(docker inspect -f '{{.State.StartedAt}}' "$api")
    [ "$(printf '%s\n%s\n' "$finished" "$started" | sort | head -n 1)" = "$finished" ] ||
        die "the API started before provisioning finished"

    [ "$(provisioned_rows)" = "1 1 1" ] || die "provisioning did not leave exactly one owner, application and callback"

    created=$(history_query "SELECT u.\"username\" || ' ' || a.\"name\" || ' ' || c.\"uri\"
        FROM \"DeveloperApplication\" a
        JOIN \"User\" u ON u.\"id\" = a.\"owner_id\"
        JOIN \"CallbackUri\" c ON c.\"developer_application_id\" = a.\"id\"
        WHERE a.\"id\" = '$APPLICATION_ID'")
    [ "$created" = "abandonauth AbandonAuth $SITE_CALLBACK" ] ||
        die "provisioning did not create the site's owner, application and exact callback"

    accounts=$(history_query 'SELECT (SELECT count(*) FROM "DiscordAccount") + (SELECT count(*) FROM "GitHubAccount") +
        (SELECT count(*) FROM "GoogleAccount") + (SELECT count(*) FROM "PasswordAccount")')
    [ "$accounts" = 0 ] || die "provisioning created an account someone can sign in with"

    arguments=$(docker inspect -f '{{.Path}} {{join .Args " "}} {{join .Config.Entrypoint " "}} {{join .Config.Cmd " "}}' "$provisioning")
    case "$arguments" in
    *"$DATABASE_CREDENTIAL"* | *postgres://*) die "the database connection reached provisioning's arguments" ;;
    esac

    logs=$(project logs --no-color provisioning 2>&1)
    case "$logs" in
    *"$DATABASE_CREDENTIAL"*) die "the database password reached the provisioning log" ;;
    esac

    require_allowlist "$provisioning" "$PROVISIONING_ALLOWED_NAMES" provisioning

    project run --rm --no-deps provisioning >/dev/null 2>&1 ||
        die "provisioning an identifier already provisioned failed"
    [ "$(provisioned_rows)" = "1 1 1" ] || die "provisioning again changed the rows it created"

    project run --rm --no-deps provisioning provision \
        "--application-id=$SECOND_APPLICATION_ID" --site-url=https://auth.example.test >/dev/null 2>&1 ||
        die "provisioning an origin without a trailing slash failed"
    same=$(history_query "SELECT count(DISTINCT \"uri\") || ' ' || min(\"uri\") FROM \"CallbackUri\"")
    [ "$same" = "1 $SITE_CALLBACK" ] ||
        die "origins with and without a trailing slash produced different callbacks"
}

stream_stage "migration controller: concurrent up converges" converge
stream_stage "migration controller: a failed migration starts neither provisioning nor API, and leaks no password" gate
stream_stage "provisioning: a refused input starts no API, writes nothing and repeats nothing" provisioning_gate
stream_stage "provisioning: runs before the API, once, with no secret beyond the database" provisioning_order
