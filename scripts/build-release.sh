#!/usr/bin/env bash

set -euo pipefail

release_version=${1:-}
if [[ ! $release_version =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  printf 'Usage: %s v<major>.<minor>.<patch>\n' "${0##*/}" >&2
  exit 2
fi

output_dir=${OUTPUT_DIR:-dist}
mkdir -p -- "$output_dir"

build_root=$(mktemp -d "${TMPDIR:-/tmp}/setup-ssh-key-release.XXXXXX")
cleanup() {
  rm -rf -- "$build_root"
}
trap cleanup EXIT

targets=(
  linux/amd64
  linux/arm64
  darwin/amd64
  darwin/arm64
  windows/amd64
  windows/arm64
)
assets=()

for target in "${targets[@]}"; do
  platform=${target%/*}
  architecture=${target#*/}
  package_dir="$build_root/${platform}_${architecture}"
  mkdir -p -- "$package_dir"

  binary_name=setup-ssh-key
  if [[ $platform == windows ]]; then
    binary_name+=.exe
  fi

  CGO_ENABLED=0 GOOS=$platform GOARCH=$architecture \
    go build \
      -trimpath \
      -ldflags "-s -w -X main.version=$release_version" \
      -o "$package_dir/$binary_name" \
      .

  asset_base="setup-ssh-key_${platform}_${architecture}"
  if [[ $platform == windows ]]; then
    asset="$asset_base.zip"
    zip -j -q "$output_dir/$asset" "$package_dir/$binary_name"
    [[ $(unzip -Z1 "$output_dir/$asset") == setup-ssh-key.exe ]]
  else
    asset="$asset_base.tar.gz"
    tar -C "$package_dir" -czf "$output_dir/$asset" "$binary_name"
    [[ $(tar -tzf "$output_dir/$asset") == setup-ssh-key ]]
  fi
  assets+=("$asset")
done

(
  cd "$output_dir"
  sha256sum "${assets[@]}" > checksums.txt
)

printf 'Built release %s in %s\n' "$release_version" "$output_dir"
