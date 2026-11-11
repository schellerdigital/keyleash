# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Sprachumschaltung für Shell-Skripte (per "source" laden):  t "deutsch" "english"
# Sprache aus KEYLEASH_LANG oder keyleash.env, Standard: de
if [ -z "${KEYLEASH_LANG:-}" ]; then
  KEYLEASH_LANG=$(sed -n 's/^KEYLEASH_LANG=\([a-zA-Z]*\).*/\1/p' \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/keyleash.env" 2>/dev/null)
fi
export KEYLEASH_LANG=${KEYLEASH_LANG:-de}
t() { if [ "${KEYLEASH_LANG:0:2}" = en ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }
