#!/usr/bin/env bash
set -euo pipefail

OUTPUT="${1:-glob-client}"
IMAGE="glob-builder"
UID_GID="$(id -u):$(id -g)"

echo "[*] Building Docker image (cached after first run)..."
docker build -t "$IMAGE" -f Dockerfile.build . -q

echo "[*] Compiling static binary with musl..."
docker run --rm -v "$(pwd):/src:z" "$IMAGE" \
  sh -c "crystal build client.cr -o $OUTPUT -Oz --single-module --static --no-debug --link-flags '-Wl,--gc-sections -Wl,--build-id=none' && strip --strip-all $OUTPUT && chown $UID_GID $OUTPUT"

echo
echo "[+] Built: $OUTPUT"
file "$OUTPUT"
echo -n "    Size: "; du -h "$OUTPUT" | cut -f1
