#!/usr/bin/env bash
set -euo pipefail
binary=${1:?binary path required}
version=${2:?version without v required}
target=${3:?native target required}
output=${4:-dist}
case "$target" in x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;; *) echo "Unsupported target: $target" >&2; exit 1;; esac
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || exit 1
[[ "$("$binary" --version)" == "poortrace $version" ]] || { echo 'Binary version mismatch' >&2; exit 1; }
if readelf -d "$binary" | rg -q '\(NEEDED\)' || readelf -l "$binary" | rg -q INTERP; then
    echo 'Release binary must be fully static' >&2
    exit 1
fi
mkdir -p "$output"
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
name="poortrace-$version-$target"
mkdir -p "$staging/$name/docs" "$staging/$name/examples"
install -m 755 "$binary" "$staging/$name/poortrace"
cp README.md LICENSE CHANGELOG.md "$staging/$name/"
cp docs/choosing-mode.md "$staging/$name/docs/"
cp examples/*.pt "$staging/$name/examples/"
# Smoke-test the staged install, independent of the source and Cargo environment.
env -i PATH=/usr/bin:/bin "$staging/$name/poortrace" --check "$staging/$name/examples/counters.pt"
env -i PATH=/usr/bin:/bin "$staging/$name/poortrace" -q -e 'BEGIN { printf("%d\n", 6*7); exit(); }' | rg -qx 42
tar -C "$staging" -czf "$output/$name.tar.gz" "$name"
(cd "$output" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
