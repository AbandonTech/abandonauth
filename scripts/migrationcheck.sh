#!/usr/bin/env sh
# The Compose migration controller, checked in a project of its own. Started by
# scripts/check.sh --integration. No environment value is ever printed.
set -eu

. "$(dirname -- "$0")/lib.sh"

require_command docker 'Install Docker from https://docs.docker.com/get-docker/.'
require_command openssl 'Install OpenSSL from your distribution; Git for Windows already includes it.'

PROJECT=abandonauth-migration-check
TEMPLATE=abandonauth_template
ALLOWED_NAMES='GOOSE_DBSTRING GOOSE_DRIVER GOOSE_MIGRATION_DIR PGPASSWORD'
PROVISIONING_ALLOWED_NAMES='DATABASE_URL DEBUG'
APPLICATION_ID=00000000-0000-0000-0000-000000000001
SECOND_APPLICATION_ID=00000000-0000-0000-0000-000000000002
SITE_ORIGIN=https://auth.example.test
SITE_CALLBACK="$SITE_ORIGIN/api/ui"
# The trailing slash lets provisioning_order show an origin without one gives
# the same callback.
export PROVISIONING_CHECK_APPLICATION_ID="$APPLICATION_ID"
export PROVISIONING_CHECK_SITE_URL="$SITE_ORIGIN/"
# The provisioning container's connection carries the database password as this
# text; it must reach neither the container's arguments nor its log.
DATABASE_CREDENTIAL='abandonauth:placeholder@'

# The deployment image's declared account, which the signing key files are
# group-readable by.
API_ACCOUNT=65532

# Development signing keys made for this run, outside the repository.
KEY_DIRECTORY=$(mktemp -d)
KEY_VOLUME="abandonauth-key-ownership-$$"

project() {
    (cd "$REPO_ROOT" && docker compose -p "$PROJECT" -f "$COMPOSE_TEST_FILE" --profile migration-gate "$@")
}

cleanup() {
    project down -v --remove-orphans -t 0 >/dev/null 2>&1 || true
    docker volume rm -f "$KEY_VOLUME-served" "$KEY_VOLUME-host" >/dev/null 2>&1 || true
    rm -rf "$KEY_DIRECTORY"
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
        --application-id=00000000-0000-0000-0000-000000000000 "--site-url=$SITE_ORIGIN"
    refuse_provisioning "a malformed UUID" "must be a UUID" provisioning provision \
        --application-id=not-a-uuid "--site-url=$SITE_ORIGIN"
    refuse_provisioning "DEBUG in a deployment build" "does not support debug mode" -e DEBUG=true \
        provisioning provision "--application-id=$APPLICATION_ID" "--site-url=$SITE_ORIGIN"

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

    [ "$(docker inspect -f '{{.Path}} {{join .Args " "}}' "$api")" = "/usr/local/bin/abandonauth serve" ] ||
        die "the gated API is not the service binary's serve command"

    published=$(docker inspect -f '{{len .HostConfig.PortBindings}} {{.HostConfig.PublishAllPorts}}{{range $port, $bindings := .NetworkSettings.Ports}}{{if $bindings}} {{$port}}{{end}}{{end}}' "$api")
    [ "$published" = "0 false" ] || die "the gated API publishes a port on the host"

    # The event is logged once the database is open and the address is bound.
    attempts=0
    until project logs --no-color migration-gate-api 2>&1 | grep -q '"message":"serving"'; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 30 ] || die "the gated API never reported that it is serving"
        [ "$(docker inspect -f '{{.State.Running}}' "$api")" = true ] ||
            die "the gated API stopped before it reported that it is serving"
        sleep 1
    done

    [ "$(provisioned_rows)" = "1 1 1" ] || die "provisioning did not leave exactly one owner, application and callback"

    created=$(history_query "SELECT u.\"username\" || ' ' || a.\"name\" || ' ' || c.\"uri\"
        FROM \"DeveloperApplication\" a
        JOIN \"User\" u ON u.\"id\" = a.\"owner_id\"
        JOIN \"CallbackUri\" c ON c.\"developer_application_id\" = a.\"id\"
        WHERE a.\"id\" = '$APPLICATION_ID'")
    [ "$created" = "abandonauth AbandonAuth $SITE_CALLBACK" ] ||
        die "provisioning did not create the site's owner, application and exact callback"

    accounts=$(history_query 'SELECT (SELECT count(*) FROM "DiscordAccount") + (SELECT count(*) FROM "GitHubAccount") +
        (SELECT count(*) FROM "GoogleAccount") + (SELECT count(*) FROM "SteamAccount") +
        (SELECT count(*) FROM "PasswordAccount")')
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
        "--application-id=$SECOND_APPLICATION_ID" "--site-url=$SITE_ORIGIN" >/dev/null 2>&1 ||
        die "provisioning an origin without a trailing slash failed"
    same=$(history_query "SELECT count(DISTINCT \"uri\") || ' ' || min(\"uri\") FROM \"CallbackUri\"")
    [ "$same" = "1 $SITE_CALLBACK" ] ||
        die "origins with and without a trailing slash produced different callbacks"
}

# native_path names a file the way a Windows program and Docker Desktop expect,
# and leaves every other host's path alone.
native_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -m "$1"
    else
        printf '%s\n' "$1"
    fi
}

# Throwaway keys made the way README.md tells every deployment to make its own.
# A run of the ID key's private body, past the prefix every key shares, stands
# in for the keys when looking for a leak.
signing_keys() {
    OIDC_ID_SIGNING_KEY_FILE=$(native_path "$KEY_DIRECTORY/oidc-id-signing-key.pem")
    OAUTH_ACCESS_SIGNING_KEY_FILE=$(native_path "$KEY_DIRECTORY/oauth-access-signing-key.pem")
    export OIDC_ID_SIGNING_KEY_FILE OAUTH_ACCESS_SIGNING_KEY_FILE

    for file in "$OIDC_ID_SIGNING_KEY_FILE" "$OAUTH_ACCESS_SIGNING_KEY_FILE"; do
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$file" 2>/dev/null ||
            die "openssl could not make a signing key"
    done

    # Opened by the image's own account through a bind mount.
    chmod 0444 "$OIDC_ID_SIGNING_KEY_FILE" "$OAUTH_ACCESS_SIGNING_KEY_FILE"

    KEY_SENTINEL=$(sed -n '12s/^\(.\{32\}\).*/\1/p' "$OIDC_ID_SIGNING_KEY_FILE")
    [ -n "$KEY_SENTINEL" ] || die "no private key body was found to look for"
}

# Compose builds only a missing image, so without this a check would run
# whatever image another run left behind.
build_images() {
    if ! built=$(project build migrations provisioning migration-gate-api 2>&1); then
        printf '%s\n' "$built" >&2
        die "the deployment image did not build"
    fi
}

deployment_identity() {
    image=$(docker inspect -f '{{.Image}}' "$(container_of migration-gate-api)")
    [ "$(docker image inspect -f '{{.Config.User}}' "$image")" = "$API_ACCOUNT" ] ||
        die "the deployment image does not run as its declared account $API_ACCOUNT"
}

# validate_config runs the gated API's real validate-config, under the given
# account, with the given ownership volume mounted where the API reads its keys.
validate_config() {
    directory=$1
    shift

    MSYS_NO_PATHCONV=1 docker run --rm --network none "$@" -v "$KEY_VOLUME-$directory:/run/secrets:ro" \
        --env-file "$(native_path "$KEY_DIRECTORY/gate.env")" \
        "$GATE_IMAGE" validate-config 2>&1
}

# The key files as a production host holds them: root:65532 mode 0440, in a
# root-only directory, and the same files where a direct bind mount places them.
# The deployment image's account reads them; any other account, even one in the
# image's group, cannot reach them through the root-only directory.
key_file_ownership() {
    GATE_IMAGE=$(docker inspect -f '{{.Image}}' "$(container_of migration-gate-api)")
    docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$(container_of migration-gate-api)" |
        grep -v '^PATH=\|^SSL_CERT_FILE=' |
        grep . >"$KEY_DIRECTORY/gate.env"

    for directory in served host; do
        docker volume create "$KEY_VOLUME-$directory" >/dev/null || die "the ownership volume could not be created"
    done

    for secret in abandonauth_oidc_id_signing_keys abandonauth_oauth_access_signing_keys; do
        source=$OIDC_ID_SIGNING_KEY_FILE
        [ "$secret" = abandonauth_oidc_id_signing_keys ] || source=$OAUTH_ACCESS_SIGNING_KEY_FILE

        MSYS_NO_PATHCONV=1 docker run --rm -i -v "$KEY_VOLUME-served:/served" --entrypoint sh postgres:15 \
            -c "cat >/served/$secret" <"$source" ||
            die "a key file could not be placed in the ownership volume"
    done

    MSYS_NO_PATHCONV=1 docker run --rm -v "$KEY_VOLUME-served:/served" -v "$KEY_VOLUME-host:/host" \
        --entrypoint sh postgres:15 -c "
        cp /served/abandonauth_* /host/ &&
        chown 0:$API_ACCOUNT /served/abandonauth_* /host/abandonauth_* &&
        chmod 0440 /served/abandonauth_* /host/abandonauth_* &&
        chown 0:0 /served /host &&
        chmod 0755 /served && chmod 0700 /host" ||
        die "the ownership volume could not be prepared"

    [ "$(validate_config served)" = "configuration valid" ] ||
        die "the deployment image's account cannot read root:$API_ACCOUNT mode 0440 key files"

    for refused in "--user 65533:65533 served" "--user 65533:65533 --group-add $API_ACCOUNT host" \
        "--user 65533:$API_ACCOUNT host"; do
        directory=${refused##* }
        account=${refused% *}

        # shellcheck disable=SC2086
        if outcome=$(validate_config "$directory" $account); then
            die "an account other than the image's own read the key files ($account)"
        fi

        case "$outcome" in
        *"cannot be opened"*) ;;
        *) die "reading the key files as $account failed for another reason" ;;
        esac

        case "$outcome" in
        *"$KEY_SENTINEL"*) die "a refused read repeated key material" ;;
        esac
    done
}

# Only the API receives the key files, read-only at their fixed paths, and no
# private member reaches another service, an argument, Compose's resolved
# configuration, a log or a file in the repository.
signing_key_isolation() {
    api=$(container_of migration-gate-api)

    mounts=$(docker inspect -f '{{range .Mounts}}{{.Destination}}={{.RW}} {{end}}' "$api")
    for secret in abandonauth_oidc_id_signing_keys abandonauth_oauth_access_signing_keys; do
        case " $mounts " in
        *" /run/secrets/$secret=false "*) ;;
        *) die "the API does not receive $secret read-only" ;;
        esac
    done

    for service in migrations provisioning database; do
        container=$(container_of "$service")
        case "$(docker inspect -f '{{range .Mounts}}{{.Destination}} {{end}}' "$container")" in
        *abandonauth_oidc* | *abandonauth_oauth*) die "$service receives a signing key file" ;;
        esac
    done

    for service in migrations provisioning migration-gate-api database; do
        container=$(container_of "$service")
        inspected=$(docker inspect -f '{{.Path}} {{join .Args " "}} {{range .Config.Env}}{{println .}}{{end}}' "$container")
        case "$inspected" in
        *"$KEY_SENTINEL"*) die "key material reached $service's arguments or environment" ;;
        esac
        case "$(project logs --no-color "$service" 2>&1)" in
        *"$KEY_SENTINEL"*) die "key material reached $service's log" ;;
        esac
    done

    case "$(project config 2>&1)" in
    *"$KEY_SENTINEL"*) die "key material reached Compose's resolved configuration" ;;
    esac

    if (cd "$REPO_ROOT" && git grep -q -F -e "$KEY_SENTINEL" -- . 2>/dev/null); then
        die "key material reached a file in the repository"
    fi

    validated=$(project run --rm --no-deps migration-gate-api validate-config 2>/dev/null) ||
        die "validate-config refused the gated API's configuration"
    [ "$validated" = "configuration valid" ] || die "validate-config printed more than that the configuration is valid"
}

# compose.yml gives the API, and nothing else, the two key files. It is read
# with the sample environment standing in for a deployment's, so no real
# setting is resolved or printed.
deployment_compose_isolation() {
    sample=$(mktemp -d)
    cp "$REPO_ROOT/.env.sample" "$sample/.env"

    if ! resolved=$(OIDC_ID_SIGNING_KEY_FILE="$OIDC_ID_SIGNING_KEY_FILE" \
        OAUTH_ACCESS_SIGNING_KEY_FILE="$OAUTH_ACCESS_SIGNING_KEY_FILE" \
        docker compose -f "$(native_path "$REPO_ROOT/compose.yml")" --project-directory "$(native_path "$sample")" \
        --env-file "$(native_path "$sample/.env")" config --format json 2>/dev/null); then
        rm -rf "$sample"
        die "compose.yml could not be resolved with the sample environment"
    fi

    rm -rf "$sample"

    case "$resolved" in
    *"$KEY_SENTINEL"*) die "key material reached compose.yml's resolved configuration" ;;
    esac

    printf '%s' "$resolved" | grep -q '"source": "abandonauth_oidc_id_signing_keys"' ||
        die "compose.yml does not give the API the ID token key file"

    if printf '%s' "$resolved" | awk '
        /^    "[a-z_-]*": \{$/ { service = $1 }
        /"source": "abandonauth_(oidc|oauth)/ && service != "\"abandonauth\":" { found = 1 }
        END { exit !found }'; then
        die "compose.yml gives a signing key file to a service other than the API"
    fi
}

stream_stage "signing keys: throwaway keys made with openssl outside the repository" signing_keys
stream_stage "deployment image: built from this tree" build_images
stream_stage "migration controller: concurrent up converges" converge
stream_stage "migration controller: a failed migration starts neither provisioning nor API, and leaks no password" gate
stream_stage "provisioning: a refused input starts no API, writes nothing and repeats nothing" provisioning_gate
stream_stage "provisioning: runs before the API, once, with no secret beyond the database" provisioning_order
stream_stage "signing keys: the deployment image runs as its declared account" deployment_identity
stream_stage "signing keys: only the image's account reads root:$API_ACCOUNT mode 0440 key files" key_file_ownership
stream_stage "signing keys: only the API receives them, and nothing repeats them" signing_key_isolation
stream_stage "signing keys: compose.yml gives them to the API alone" deployment_compose_isolation
