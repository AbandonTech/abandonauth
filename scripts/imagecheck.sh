#!/usr/bin/env sh
# The checks that need built images and the composed stack. Started by
# scripts/check.sh --images.
#
# What a build tag produces is proven here; what each variant then serves is
# proven by the endpoint suite, which runs against both tag sets.
set -eu

. "$(dirname -- "$0")/lib.sh"

require_command docker 'Install Docker from https://docs.docker.com/get-docker/.'

DEPLOYMENT_IMAGE=abandonauth-api:check
DEVELOPMENT_IMAGE=abandonauth-api-devtools:check

COMPOSE_FILE="$REPO_ROOT/compose.yml"

VERSION_LABEL=org.opencontainers.image.version

run_stage "build the deployment image" \
    docker build --file "$API_DIR/Dockerfile" --tag "$DEPLOYMENT_IMAGE" "$API_DIR"

run_stage "build the development image" \
    docker build --file "$API_DIR/Dockerfile" --target development \
    --tag "$DEVELOPMENT_IMAGE" "$API_DIR"

inspect() {
    docker image inspect --format "$2" "$1" | tr -d '\r'
}

info "the deployment image runs as an account that is not root"
account=$(inspect "$DEPLOYMENT_IMAGE" '{{.Config.User}}')
case "$account" in
"" | root | 0 | 0:*)
    die "the image runs as ${account:-root}"
    ;;
esac
ok "the deployment image runs as an account that is not root ($account)"

info "the deployment image exposes the port the proxy forwards to"
exposed=$(inspect "$DEPLOYMENT_IMAGE" '{{range $port, $_ := .Config.ExposedPorts}}{{$port}} {{end}}')
case " $exposed " in
*" 8000/tcp "*) ;;
*) die "the image exposes '$exposed', not 8000/tcp" ;;
esac
ok "the deployment image exposes the port the proxy forwards to"

# An image whose label disagrees with the binary in it misidentifies whatever is
# actually running, so the two are compared rather than each being read alone.
info "the version label names the binary the image holds"
labelled=$(inspect "$DEPLOYMENT_IMAGE" "{{index .Config.Labels \"$VERSION_LABEL\"}}")
[ -n "$labelled" ] || die "the image carries no $VERSION_LABEL label"
reported=$(docker run --rm "$DEPLOYMENT_IMAGE" --version | tr -d '\r')
case "$reported" in
*" $labelled") ;;
*) die "the image is labelled $labelled but the binary reports '$reported'" ;;
esac
ok "the version label names the binary the image holds ($labelled)"

# Exported rather than listed through a shell, because the image deliberately
# has no shell to list it with.
contents=$(mktemp)
container=$(docker create "$DEPLOYMENT_IMAGE")
docker export "$container" | tar -tf - >"$contents"
docker rm "$container" >/dev/null

holds() { grep -qE "$1" "$contents"; }

info "the deployment image holds what the service needs and nothing else"
holds '^usr/local/bin/abandonauth$' || die "the binary is not at /usr/local/bin/abandonauth"
holds '^etc/ssl/certs/ca-certificates\.crt$' ||
    die "there is no certificate bundle, so no provider API could be reached"
# The schema travels inside the binary and the service is one Go program, so a
# .sql file, an interpreter or a package directory in here is something that was
# copied in by mistake.
for unwanted in '(^|/)python' '(^|/)poetry' '(^|/)prisma' '(^|/)node' '\.sql$' '(^|/)\.env'; do
    if holds "$unwanted"; then
        die "the image holds files matching $unwanted"
    fi
done
ok "the deployment image holds what the service needs and nothing else"

rm -f "$contents"

# Placeholders, not credentials: the signing secret is a repeated word long
# enough to satisfy the length rule and the client secrets name themselves. The
# database address refuses connections immediately, so a run that gets as far as
# opening one fails at once instead of waiting.
placeholder_settings=$(mktemp)
cat >"$placeholder_settings" <<'SETTINGS'
DEBUG=true
DATABASE_URL=postgres://abandonauth:placeholder@127.0.0.1:1/abandonauth
JWT_SECRET=placeholder-signing-secret-placeholder-signing-secret-placeholder
JWT_HASHING_ALGO=HS512
JWT_EXPIRES_IN_SECONDS_SHORT_LIVED=120
JWT_EXPIRES_IN_SECONDS_LONG_LIVED=2592000
ABANDON_AUTH_DEVELOPER_APP_ID=6f5902ac-237a-4ba0-8a51-1ed0b6c1c0f0
ABANDON_AUTH_SITE_URL=https://auth.example.test
ABANDON_AUTH_URL=https://api.auth.example.test
DISCORD_CLIENT_ID=discord-client-id
DISCORD_CLIENT_SECRET=discord-client-secret-placeholder
ABANDON_AUTH_DISCORD_CALLBACK=https://auth.example.test/api/ui/discord-callback
GITHUB_CLIENT_ID=github-client-id
GITHUB_CLIENT_SECRET=github-client-secret-placeholder
ABANDON_AUTH_GITHUB_CALLBACK=https://auth.example.test/api/ui/github-callback
GOOGLE_CLIENT_ID=google-client-id
GOOGLE_CLIENT_SECRET=google-client-secret-placeholder
GOOGLE_CALLBACK=https://auth.example.test/api/google
SETTINGS

serve_with_debug() {
    docker run --rm --env-file "$placeholder_settings" "$1" serve 2>&1 || true
}

info "the deployment image refuses debug mode"
refusal=$(serve_with_debug "$DEPLOYMENT_IMAGE")
case "$refusal" in
*"DEBUG"*) ;;
*) die "the deployment image did not refuse DEBUG=true: $refusal" ;;
esac
ok "the deployment image refuses debug mode"

# The same settings on the development image must get past configuration, which
# is what proves the two images were compiled from different build tags rather
# than tagged differently from one build.
info "the development image accepts debug mode"
accepted=$(serve_with_debug "$DEVELOPMENT_IMAGE")
case "$accepted" in
*"DEBUG"*) die "the development image refused DEBUG=true: $accepted" ;;
*"the database did not answer"*) ;;
*) die "the development image stopped before it reached the database: $accepted" ;;
esac
ok "the development image accepts debug mode"

rm -f "$placeholder_settings"

run_stage "docker compose config" docker compose --file "$COMPOSE_FILE" config --quiet

info "the API waits for a healthy database"
if ! docker compose --file "$COMPOSE_FILE" config 2>/dev/null |
    tr -d ' \r' | grep -q '^condition:service_healthy$'; then
    die "the composed API does not wait for the database to report healthy"
fi
ok "the API waits for a healthy database"

info "image checks passed"
