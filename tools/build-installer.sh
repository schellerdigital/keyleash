#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Baut die Installationsdatei dist/keyleash-install.sh aus diesem Lab.
# Builds the installer dist/keyleash-install.sh from this lab.
set -euo pipefail
LAB=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-$LAB/dist/keyleash-install.sh}
VER=${KEYLEASH_VERSION:-$(date +%Y.%m.%d)}
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
bash "$LAB/tools/export-source.sh" --tree "$TMP/src" >/dev/null   # sauberer Quellstand, neutrale keyleash.env
tar czf "$TMP/payload.tgz" -C "$TMP/src" keyleash-lab
SUM=$(sha256sum "$TMP/payload.tgz" | cut -d' ' -f1)
mkdir -p "$(dirname "$OUT")"
sed -e "s/@VERSION@/$VER/g" -e "s/@SHA256@/$SUM/" "$LAB/tools/installer-head.sh" > "$OUT"
cat "$TMP/payload.tgz" >> "$OUT"
chmod +x "$OUT"
echo "$OUT  ($(du -h "$OUT" | cut -f1), Version $VER, sha256 Inhalt ${SUM:0:16}…)"
sha256sum "$OUT" | sed 's/^/sha256 Datei: /'
