#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Alle Demos nacheinander (ohne die Neustart-Demo auf echter Hardware)
cd "$(dirname "$0")"
set -e
./00-pruefen.sh; ./10-provisionieren.sh; ./20-signieren.sh; ./30-ablauf.sh; ./40-sperrung.sh
./50-manipulation.sh; ./60-parallel.sh; ./65-signaturen.sh; ./67-freigabe.sh
[ "${KEYLEASH_TPM:-$(grep -oP '^KEYLEASH_TPM=\K\w+' ../keyleash.env)}" = swtpm ] && ./70-neustart.sh && bash ./72-uhr.sh
./75-herzschlag.sh; ./80-siem.sh
