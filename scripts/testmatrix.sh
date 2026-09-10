#!/usr/bin/env sh
# What each build's test run is allowed to contain. Started by scripts/check.sh
# before any test executes, because the run selects the development tests by
# name, and a convention nothing checks is one that has already been broken.
#
# Two invariants:
#   every test only the devtools build carries is named TestDevtools..., and
#   every test named TestDevtools... is one only that build carries;
#   the inexpensive credential hasher is compiled under the integration tag and
#   under no other.
set -eu

. "$(dirname -- "$0")/lib.sh"

cd "$API_DIR"

DEVTOOLS_SELECTOR='^TestDevtools'

CREDENTIALS_PACKAGE="./internal/services/credentials"
SERVERTEST_PACKAGE="./internal/web/servertest"

# difference <lines> <lines to remove>
difference() {
    printf '%s\n' "$1" | awk -v remove="$2" '
        BEGIN {
            count = split(remove, held, "\n")
            for (i = 1; i <= count; i++) {
                dropped[held[i]] = 1
            }
        }
        $0 != "" && !($0 in dropped) { print }
    '
}

# holds <line> <lines>
holds() {
    printf '%s\n' "$2" | grep -qxF -- "$1"
}

# The Go files a tag set compiles, as "<package> <file>" lines. A build tag
# decides which hasher constructor exists at all, so the boundary is a question
# about source selection rather than about behaviour at run time.
compiled_hasher_files() {
    go list -tags="$1" -f '{{$package := .Name}}{{range .GoFiles}}{{$package}} {{.}}
{{end}}' "$CREDENTIALS_PACKAGE" "$SERVERTEST_PACKAGE" |
        grep -E ' (hasher|credentialhasher)_' |
        sort
}

# hasher_boundary_violations <integration 0|1> <compiled files>
# Names every hasher file compiled where it must not be, or absent where it is
# required. Text in, text out, so the self-check below can drive it.
hasher_boundary_violations() {
    with_integration=$1
    compiled=$2

    for required in \
        "credentials hasher_integration.go" \
        "servertest credentialhasher_integration.go" \
        "servertest credentialhasher_default.go"; do
        case "$required" in
        *_integration.go) wanted=$with_integration ;;
        *) wanted=$((1 - with_integration)) ;;
        esac

        if holds "$required" "$compiled"; then
            present=1
        else
            present=0
        fi

        if [ "$present" -eq "$wanted" ]; then
            continue
        fi

        if [ "$wanted" -eq 0 ]; then
            printf '%s is compiled where it must not be\n' "$required"
        else
            printf '%s is not compiled where it is required\n' "$required"
        fi
    done
}

# The top-level tests a tag set carries, package-qualified. -list compiles the
# test binaries and prints the names in them; nothing is executed.
test_inventory() {
    listed=$(go test -list "$2" -tags="$1" ./... 2>&1) || {
        printf '%s\n' "$listed" >&2
        die "the tests could not be listed for -tags='$1'"
    }

    printf '%s\n' "$listed" | awk '
        $1 == "ok" {
            for (i = 1; i <= held; i++) {
                print $2 "." names[i]
            }
            held = 0
            next
        }
        /^Test/ { names[++held] = $1 }
    ' | sort
}

# inventory_violations <deployment tests> <devtools tests> <selected tests>
# The tests the devtools build adds must be exactly the ones the selector picks.
# Anything else means the run either skips a development test or repeats a
# shared one.
inventory_violations() {
    added=$(difference "$2" "$1")

    if [ -z "$3" ]; then
        printf 'the selector matches no test, so the development build would run nothing\n'
    fi

    difference "$added" "$3" | while read -r name; do
        printf '%s runs only in the development build but the selector misses it\n' "$name"
    done

    difference "$3" "$added" | while read -r name; do
        printf '%s is selected as development-only but both builds run it\n' "$name"
    done
}

# The two checks above decide what the pipeline runs, so they are driven against
# sets whose answer is known before they are trusted with the real ones.
self_check() {
    disagreements=0

    expect() {
        if [ "$2" != "$3" ]; then
            printf 'self-check %s:\n  got:  %s\n  want: %s\n' "$1" "${2:-<nothing>}" "${3:-<nothing>}" >&2
            disagreements=$((disagreements + 1))
        fi
    }

    shared="pkg.TestShared"
    development="pkg.TestDevtoolsSeeding"

    expect "an inventory that agrees" \
        "$(inventory_violations "$shared" "$shared
$development" "$development")" \
        ""

    expect "a selector that matches nothing" \
        "$(inventory_violations "$shared" "$shared" "")" \
        "the selector matches no test, so the development build would run nothing"

    expect "a development test outside the selector" \
        "$(inventory_violations "$shared" "$shared
$development
pkg.TestSeeding" "$development")" \
        "pkg.TestSeeding runs only in the development build but the selector misses it"

    expect "a shared test inside the selector" \
        "$(inventory_violations "$shared
$development" "$shared
$development" "$development")" \
        "$development is selected as development-only but both builds run it"

    product_source="servertest credentialhasher_default.go"
    integration_source="credentials hasher_integration.go
servertest credentialhasher_integration.go"

    expect "a product source set that agrees" \
        "$(hasher_boundary_violations 0 "$product_source")" \
        ""

    expect "an integration source set that agrees" \
        "$(hasher_boundary_violations 1 "$integration_source")" \
        ""

    expect "the inexpensive hasher in a product source set" \
        "$(hasher_boundary_violations 0 "$product_source
credentials hasher_integration.go")" \
        "credentials hasher_integration.go is compiled where it must not be"

    expect "the inexpensive hasher missing from an integration source set" \
        "$(hasher_boundary_violations 1 "servertest credentialhasher_integration.go")" \
        "credentials hasher_integration.go is not compiled where it is required"

    [ "$disagreements" -eq 0 ] ||
        die "the test matrix checks disagree with sets whose answer is known"
}

report() {
    if [ -z "$2" ]; then
        ok "$1"
        return 0
    fi

    printf '==> %s ... FAILED\n' "$1" >&2
    printf '%s\n' "$2" >&2
    exit 1
}

self_check
ok "test matrix self-check"

for tags in "" "devtools" "integration" "integration devtools"; do
    case " $tags " in
    *" integration "*) with_integration=1 ;;
    *) with_integration=0 ;;
    esac

    report "credential hasher source (-tags='$tags')" \
        "$(hasher_boundary_violations "$with_integration" "$(compiled_hasher_files "$tags")")"
done

for product_tags in "" "integration"; do
    if [ -z "$product_tags" ]; then
        development_tags="devtools"
    else
        development_tags="$product_tags devtools"
    fi

    report "test inventory (-tags='$development_tags')" \
        "$(inventory_violations \
            "$(test_inventory "$product_tags" '^Test')" \
            "$(test_inventory "$development_tags" '^Test')" \
            "$(test_inventory "$development_tags" "$DEVTOOLS_SELECTOR")")"
done

info "each test is selected by exactly one run"
