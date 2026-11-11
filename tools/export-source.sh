#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Sauberer Quellstand des Labs für Weitergabe und Installationsdatei: nur Quelltexte und Doku,
# kein Zustand (state/), keine Logs, Videos, Upload-Zips oder Zugangsdaten. keyleash.env wird durch
# die neutrale Vorlage tools/keyleash.env.default ersetzt. Bricht ab, wenn ein Geheimnis oder ein
# persönlicher Pfad im Ergebnis auftaucht.
# Clean source tree for sharing and for the installer: sources and docs only, no state, logs,
# videos, upload archives or credentials. keyleash.env is replaced by tools/keyleash.env.default.
#
#   bash tools/export-source.sh                 -> dist/keyleash-src-DATUM.tar.gz
#   bash tools/export-source.sh --tree VERZ     nur den Baum nach VERZ/keyleash-lab schreiben (für build-installer.sh)
set -euo pipefail
LAB=$(cd "$(dirname "$0")/.." && pwd)
MODE=tar; DEST=""
[ "${1:-}" = --tree ] && { MODE=tree; DEST=${2:?Verzeichnis}; }
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
T=$WORK/keyleash-lab; mkdir -p "$T"
cd "$LAB"
# Positivliste: nur diese Verzeichnisse und Dateien
for d in agent demos harden labbox lib server tests tools verify webdemo; do
  [ -d "$d" ] && find "$d" -type f ! -path '*/__pycache__/*' ! -name '*.pyc' ! -name '*.bak' ! -name '*.sicherung-*' \
    -print0 | while IFS= read -r -d '' f; do mkdir -p "$T/$(dirname "$f")"; cp -p "$f" "$T/$f"; done
done
for f in README.md README.en.md DEMO-VM.en.md LICENSE NOTICE SECURITY.md CONTRIBUTING.md .gitignore setup.sh teardown.sh; do
  [ -f "$f" ] && cp -p "$f" "$T/$f"
done
cp -p tools/keyleash.env.default "$T/keyleash.env"
# Prüfung: keine Schlüssel, keine Zugangsdaten, keine persönlichen Pfade
hits=$( { grep -rnIE 'BEGIN [A-Z ]*PRIVATE KEY|ssh-(ed25519|rsa) AAAA|/home/[a-z][a-z0-9_-]*/|/Users/[A-Za-z]' "$T" \
            | grep -v '/tools/export-source.sh:';
          grep -rnIE '^[A-Z_]*(PASS|PASSWORD|SECRET|TOKEN)=[^$]' "$T" --include='*.env' --include='*.md' --include='keyleash.env' \
            | grep -v 'KEYLEASH_ENROLL_TOKEN=lab-enroll'; } || true)
if [ -n "$hits" ]; then echo "✘ Export abgebrochen, bitte prüfen / export aborted, please check:"; echo "$hits"; exit 1; fi
n=$(find "$T" -type f | wc -l)
if [ $MODE = tree ]; then
  mkdir -p "$DEST"; rm -rf "$DEST/keyleash-lab"; cp -a "$T" "$DEST/"; echo "✔ $n Dateien / files → $DEST/keyleash-lab"
else
  mkdir -p dist; OUT=dist/keyleash-src-$(date +%Y%m%d).tar.gz
  tar czf "$OUT" -C "$WORK" keyleash-lab
  echo "✔ $OUT ($n Dateien / files, sha256 $(sha256sum "$OUT" | cut -c1-16)…)"
fi
