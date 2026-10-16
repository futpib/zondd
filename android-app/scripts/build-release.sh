#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $# != 3 || ! "$1" =~ ^[0-9][0-9A-Za-z.+-]*$ || ! "$2" =~ ^[1-9][0-9]{0,8}$ ]]; then
    echo 'Usage: build-release.sh VERSION_NAME VERSION_CODE OUTPUT_DIRECTORY' >&2
    exit 2
fi
: "${KEYSTORE_PATH:?Set KEYSTORE_PATH to the persistent release keystore}"
: "${KEYSTORE_PASSWORD:?Set KEYSTORE_PASSWORD}"
if [[ ! -f "$KEYSTORE_PATH" ]]; then
    echo 'KEYSTORE_PATH does not point to a keystore file' >&2
    exit 2
fi
export KEYSTORE_PATH
KEYSTORE_PATH=$(realpath "$KEYSTORE_PATH")
release_output=$(realpath -m "$3")
mkdir -p "$release_output"

flutter_bin=${FLUTTER:-flutter}
build_log=$(mktemp)
trap 'rm -f "$build_log"' EXIT
build_apk() {
    for attempt in 1 2 3; do
        if "$flutter_bin" build apk "$@" 2>&1 | tee "$build_log"; then
            return 0
        fi
        if (( attempt == 3 )) || ! grep -Eq 'Received status code 5[0-9][0-9]|Read timed out|Connection reset' "$build_log"; then
            return 1
        fi
        echo "Artifact download failed; retrying APK build ($attempt/3)" >&2
        sleep $((attempt * 10))
    done
}
build_apk --release --target lib/main.dart \
    --target-platform android-arm64,android-x64 --build-name="$1" --build-number="$2"
install -m644 build/app/outputs/flutter-apk/app-release.apk "$release_output/app-release.apk"
build_apk --release --target lib/main.dart --split-per-abi \
    --target-platform android-arm64,android-x64 --build-name="$1" --build-number="$2"
for abi in arm64-v8a x86_64; do
    install -m644 "build/app/outputs/flutter-apk/app-$abi-release.apk" "$release_output/app-$abi-release.apk"
done
(
    cd "$release_output"
    sha256sum app-release.apk app-arm64-v8a-release.apk app-x86_64-release.apk > SHA256SUMS
)
