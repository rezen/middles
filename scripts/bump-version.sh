#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s [MAJOR.MINOR.PATCH]\n' "${0##*/}"
  printf 'Without a version, increment the patch version.\n'
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  usage
  exit 0
fi
if (( $# > 1 )); then
  usage >&2
  exit 2
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
manifest="$root/Cargo.toml"
lockfile="$root/Cargo.lock"

current=$(perl -0777 -ne 'print $1 if /\[package\]\nname = "middles"\nversion = "([^"]+)"/' "$manifest")
locked=$(perl -0777 -ne 'print $1 if /\[\[package\]\]\nname = "middles"\nversion = "([^"]+)"/' "$lockfile")
if [[ -z $current || $current != "$locked" ]]; then
  printf 'Cargo.toml and Cargo.lock must contain the same middles version.\n' >&2
  exit 1
fi
if [[ ! $current =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  printf 'Current version is not MAJOR.MINOR.PATCH: %s\n' "$current" >&2
  exit 1
fi

if (( $# == 0 )); then
  next="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$(( BASH_REMATCH[3] + 1 ))"
else
  next=${1#v}
  if [[ ! $next =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    printf 'Version must be MAJOR.MINOR.PATCH: %s\n' "$1" >&2
    exit 2
  fi
fi

if [[ $next == "$current" ]]; then
  printf 'Version is already %s.\n' "$current" >&2
  exit 1
fi

OLD_VERSION=$current NEW_VERSION=$next perl -0pi -e '
  BEGIN { $old = $ENV{OLD_VERSION}; $new = $ENV{NEW_VERSION} }
  s{(\[package\]\nname = "middles"\nversion = ")\Q$old\E(")}{$1$new$2}
    or die "Could not update Cargo.toml\n";
' "$manifest"
OLD_VERSION=$current NEW_VERSION=$next perl -0pi -e '
  BEGIN { $old = $ENV{OLD_VERSION}; $new = $ENV{NEW_VERSION} }
  s{(\[\[package\]\]\nname = "middles"\nversion = ")\Q$old\E(")}{$1$new$2}
    or die "Could not update Cargo.lock\n";
' "$lockfile"

printf 'Bumped middles from %s to %s.\n' "$current" "$next"
