#!/usr/bin/env sh
# Lifecycle of the throwaway database the checks run against.
#
#   scripts/db.sh up      start it and wait for it to accept connections
#   scripts/db.sh down    stop it and delete everything in it
#   scripts/db.sh psql    interactive psql shell
#   scripts/db.sh url     print the connection string as seen from the container
#   scripts/db.sh logs    show the server's log
#
# Never point TEST_DATABASE_URL at a database holding real accounts: the tests
# create, drop and rewrite schemas.
set -eu

. "$(dirname -- "$0")/lib.sh"

require_command docker 'Install Docker from https://docs.docker.com/get-docker/.'

DATABASE_USER=abandonauth
DATABASE_NAME=abandonauth_test

case "${1:-}" in
up)
    run_stage "database up" compose up -d --wait database
    ;;
down)
    run_stage "database down" compose down
    ;;
psql)
    compose exec database psql -U "$DATABASE_USER" -d "$DATABASE_NAME"
    ;;
url)
    compose config --format json |
        sed -n 's/.*"TEST_DATABASE_URL": *"\([^"]*\)".*/\1/p' |
        head -1
    ;;
logs)
    compose logs database
    ;;
*)
    die "usage: scripts/db.sh <up|down|psql|url|logs>"
    ;;
esac
