#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $# != 2 || ! $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Usage: $0 VERSION OUTPUT_DIRECTORY" >&2
    exit 2
fi
version=$1
manifest_version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')
if [[ $version != "$manifest_version" ]]; then
    echo "Release version $version does not match Cargo.toml ($manifest_version)" >&2
    exit 1
fi
host=$(rustc -vV | sed -n 's/^host: //p')
case "$host" in
    x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
    *) echo "Unsupported release host: $host" >&2; exit 1 ;;
esac
mkdir -p "$2"
output=$(realpath "$2")
name="zondd-$version-$host"
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT
cargo build --locked --release -p zondd -p zondctl --target "$host"
install -Dm755 "target/$host/release/zondd" "$staging/$name/bin/zondd"
install -Dm755 "target/$host/release/zondctl" "$staging/$name/bin/zondctl"
install -m644 LICENSE readme.md config.example.toml zondd.service "$staging/$name/"
install -d "$staging/$name/adapters/python"
install -m644 adapters/readme.md adapters/credential-api-v1.schema.json "$staging/$name/adapters/"
install -m644 adapters/python/zond_interaction.py "$staging/$name/adapters/python/"
tar -C "$staging" -czf "$output/$name.tar.gz" "$name"
(cd "$output" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
