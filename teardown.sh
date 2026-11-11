#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Lab zurückbauen: Server/swtpm stoppen, Lab-Zustand löschen, TPM prüfen.
# Das Lab legt im TPM nichts dauerhaft ab (keine persistenten Handles, keine NV-Indizes):
# Schlüssel existieren nur als verschlüsselte Blobs in state/ und sind danach wertlos.
#   ./teardown.sh             Zustand löschen
#   sudo ./teardown.sh --tss  zusätzlich deinen Benutzer aus der Gruppe tss nehmen
set -uo pipefail
LAB=$(cd "$(dirname "$0")" && pwd); cd "$LAB"
source "$LAB/lib/i18n.sh"
"$LAB/tools/server.sh" stop 2>/dev/null
[ -d state/swtpm ] && tools/swtpm-start.sh stop >/dev/null 2>&1
if [ -c /dev/tpmrm0 ] && [ -r /dev/tpmrm0 ]; then
  export TPM2TOOLS_TCTI=device:/dev/tpmrm0
  echo "$(t 'Persistente Handles im TPM (Lab legt keine an; Einträge stammen vom System, z. B. EK):' 'Persistent handles in the TPM (the lab creates none; entries come from the system, e.g. EK):')"
  tpm2_getcap handles-persistent | sed 's/^/  /'
  echo "$(t NV-Indizes 'NV indices'): $(tpm2_getcap handles-nv-index | wc -l) ($(t 'unverändert durch das Lab' 'unchanged by the lab'))"
  tpm2_getcap properties-variable | grep LOCKOUT_COUNTER | sed 's/^/  /'
fi
if [ -d /opt/keyleash ]; then echo "$(t 'Härtung ist noch eingerichtet – zuerst:' 'Hardening is still installed – first:') sudo harden/unharden.sh"; fi
rm -rf state && echo "$(t 'Lab-Zustand (state/) gelöscht.' 'Lab state (state/) deleted.')"
if [ "${1:-}" = --tss ] && [ -n "${SUDO_USER:-}" ]; then gpasswd -d "$SUDO_USER" tss; fi
