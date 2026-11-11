#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Ausbleibende Erneuerung wird zentral sichtbar
# A missing renewal becomes visible centrally
source "$(dirname "$0")/common.sh"
ensure_server; ensure_enrolled
title "$(t 'Herzschlag bleibt aus' 'Heartbeat goes silent')"
pause_min_interval
$AG renew --ttl 10
WAIT=$((10 + ${KEYLEASH_GRACE%.*} + 4))
step "$(t "Agent schweigt ${WAIT}s (z. B. Kommunikation unterdrückt) …" "Agent stays silent for ${WAIT}s (e.g. communication suppressed) …")"; sleep "$WAIT"
siem_tail 2
