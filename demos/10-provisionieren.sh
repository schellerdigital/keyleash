#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Schritt 1 des Konzepts: Provisionierung mit Key Attestation
# Step 1 of the concept: enrolment with key attestation
source "$(dirname "$0")/common.sh"
ensure_server
title "$(t Provisionierung Enrolment)"
if [ -f "$ST/agent.json" ] && [ "${1:-}" != --neu ]; then
  note "$(t 'Bereits provisioniert. Neu anlegen mit:' 'Already enrolled. Start over with:') $0 --neu"; exit 0; fi
[ "${1:-}" = --neu ] && { admin forget 2>/dev/null; rm -rf "$ST"; }
$AG enroll || exit 1
step "$(t 'Eigenschaften des Schlüssels laut TPM' 'Key properties as reported by the TPM')"
tpm2_print -t TPM2B_PUBLIC "$ST/key.pub" | grep -E 'attributes|value:|authorization policy' | head -4 | sed 's/^/  /'
note "$(t 'fixedtpm/fixedparent: nicht exportierbar · kein userwithauth: nur über die Policy nutzbar' 'fixedtpm/fixedparent: non-exportable · no userwithauth: usable only through the policy')"
siem_tail 2
