#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Verteiler für Sperr-Hooks (KEYLEASH_REVOKE_HOOK=tools/revoke-hooks.sh):
# ruft jedes ausführbare Skript in state/hooks.d/ als  SKRIPT revoke|unrevoke HOST  auf.
# Distributor for revoke hooks: runs every executable in state/hooks.d/ as  SCRIPT revoke|unrevoke HOST.
LAB=$(cd "$(dirname "$0")/.." && pwd)
rc=0
for h in "$LAB"/state/hooks.d/*; do
  [ -x "$h" ] || continue
  out=$("$h" "$@" 2>&1) || rc=1
  echo "$(basename "$h"): $out"
done
exit $rc
