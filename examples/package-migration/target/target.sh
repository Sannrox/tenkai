#!/bin/sh
# Bounded local fixture target for the package-migration recovery drill.
# Tenkai owns receipts and recovery; this script owns synthetic records and
# durable effect deduplication. It is not a delivery backend.
set -eu

usage() {
    echo "usage: target.sh apply|remove|health|observe" >&2
    exit 2
}

cmd=${1:-}
[ -n "$cmd" ] || usage

env_name=${TENKAI_ENVIRONMENT:?}
state_root=${TMPDIR:?}/tenkai-stateful-drill/${env_name}
target_dir=$state_root/target
control_dir=$state_root/control
ledger_dir=$target_dir/ledger
mkdir -p "$target_dir/records" "$ledger_dir" "$control_dir"

payload_file=payload.txt
version=""
record=""
if [ -f "$payload_file" ]; then
    version=$(awk -F= '/^VERSION=/{print $2; exit}' "$payload_file")
    record=$(awk -F= '/^FIXTURE_RECORD=/{print $2; exit}' "$payload_file")
fi
product=${TENKAI_PRODUCT:-pkg}

mutation_file=$target_dir/mutation_count
version_file=$target_dir/current_version
seed_file=$target_dir/records/seed

read_count() {
    if [ -f "$mutation_file" ]; then
        cat "$mutation_file"
    else
        echo 0
    fi
}

bump_mutations() {
    current=$(read_count)
    printf '%s\n' $((current + 1)) >"$mutation_file"
}

control_matches() {
    name=$1
    expected=$2
    file=$control_dir/$name
    [ -f "$file" ] || return 1
    value=$(tr -d ' \n' <"$file")
    [ -z "$value" ] || [ "$value" = "$expected" ] || [ "$value" = "1" ]
}

case "$cmd" in
apply)
    [ -n "$version" ] || {
        echo "payload.txt is missing VERSION" >&2
        exit 1
    }
    key=$ledger_dir/${product}@${version}
    if [ -f "$key" ]; then
        printf 'replay\n' >>"$key"
        printf '%s\n' "$version" >"$version_file"
        exit 0
    fi
    if [ ! -f "$seed_file" ]; then
        [ -n "$record" ] || {
            echo "payload.txt is missing FIXTURE_RECORD" >&2
            exit 1
        }
        printf '%s\n' "$record" >"$seed_file"
    fi
    printf '%s\n' "$version" >"$version_file"
    printf 'accepted\n' >"$key"
    bump_mutations
    if control_matches crash-after-accept "$version"; then
        sleep 30
    fi
    ;;
remove)
    rm -f "$version_file"
    ;;
health)
    [ -f "$version_file" ] || exit 1
    installed=$(tr -d ' \n' <"$version_file")
    if control_matches fail-health "$installed"; then
        exit 1
    fi
    [ -n "$version" ] && [ "$installed" = "$version" ]
    ;;
observe)
    installed="absent"
    [ -f "$version_file" ] && installed=$(tr -d ' \n' <"$version_file")
    fixture_record=""
    [ -f "$seed_file" ] && fixture_record=$(tr -d '\n' <"$seed_file")
    printf '{"version":"%s","record":"%s","mutations":%s}\n' \
        "$installed" "$fixture_record" "$(read_count)"
    ;;
*)
    usage
    ;;
esac
