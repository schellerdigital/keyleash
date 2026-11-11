#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Gegenstelle: prüft eine Signatur wie bisher – Zertifikatskette + Signatur.
# Sie weiß nichts von TPM oder Tickets (Konzept: "Keine Änderung nötig").
# Aufruf: verify.sh DATEI SIGNATUR CERT.pem CA.pem
set -euo pipefail
source "$(dirname "$0")/../lib/i18n.sh"
data=$1 sig=$2 cert=$3 ca=$4
openssl verify -CAfile "$ca" "$cert" >/dev/null || { echo "  ✘ $(t 'Zertifikat nicht von der Verwaltungs-CA' 'Certificate not issued by the management CA')"; exit 1; }
openssl x509 -in "$cert" -pubkey -noout > "${TMPDIR:-/tmp}/kl-verify-pub.$$"
if openssl dgst -sha256 -verify "${TMPDIR:-/tmp}/kl-verify-pub.$$" -signature "$sig" "$data" >/dev/null; then
  echo "  ✔ $(t 'Gegenstelle: Signatur gültig' 'Relying party: signature valid') ($(openssl x509 -in "$cert" -noout -subject))"
  rc=0
else
  echo "  ✘ $(t 'Gegenstelle: Signatur ungültig' 'Relying party: signature invalid')"; rc=1
fi
rm -f "${TMPDIR:-/tmp}/kl-verify-pub.$$"; exit $rc
