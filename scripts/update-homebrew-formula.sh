#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'Usage: %s [MAJOR.MINOR.PATCH]\n' "${0##*/}"
  printf 'Update Formula/middles.rb from a published, matching release tag.\n'
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
cd "$root"
version=${1:-}
version=${version#v}
if (( $# == 0 )); then
  version=$(perl -0777 -ne 'print $1 if /\[package\]\nname = "middles"\nversion = "([^"]+)"/' Cargo.toml)
fi
if [[ ! $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  printf 'Version must be MAJOR.MINOR.PATCH: %s\n' "$version" >&2
  exit 2
fi

tag="v$version"
if ! git rev-parse --verify --quiet "refs/tags/$tag^{commit}" >/dev/null; then
  printf 'Tag %s does not exist locally. Create and push it after the version bump.\n' "$tag" >&2
  exit 1
fi
tag_version=$(git show "$tag:Cargo.toml" | perl -0777 -ne 'print $1 if /\[package\]\nname = "middles"\nversion = "([^"]+)"/')
if [[ $tag_version != "$version" ]]; then
  printf 'Tag %s contains Cargo version %s; expected %s.\n' "$tag" "$tag_version" "$version" >&2
  exit 1
fi

archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
url="https://github.com/rezen/middles/archive/refs/tags/$tag.tar.gz"
curl --fail --location --silent --show-error --retry 3 --output "$archive" "$url"
archive_root=$(tar -tzf "$archive" | sed -n '1{s@/.*@@;p;}')
archive_version=$(tar -xOzf "$archive" "$archive_root/Cargo.toml" | perl -0777 -ne 'print $1 if /\[package\]\nname = "middles"\nversion = "([^"]+)"/')
if [[ $archive_version != "$version" ]]; then
  printf 'Downloaded archive contains Cargo version %s; expected %s.\n' "$archive_version" "$version" >&2
  exit 1
fi
sha256=$(shasum -a 256 "$archive" | awk '{print $1}')

FORMULA_URL=$url FORMULA_VERSION=$version FORMULA_SHA256=$sha256 perl -0pi -e '
  BEGIN {
    $url = $ENV{FORMULA_URL};
    $version = $ENV{FORMULA_VERSION};
    $sha = $ENV{FORMULA_SHA256};
  }
  s{^  url "[^"]+"\n  version "[^"]+"\n  sha256 "[0-9a-f]{64}"$}
   {  url "$url"\n  version "$version"\n  sha256 "$sha"}m
    or die "Could not update Formula/middles.rb\n";
' Formula/middles.rb

printf 'Updated Formula/middles.rb for %s (%s).\n' "$tag" "$sha256"
