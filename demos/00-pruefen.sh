#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Voraussetzungen und TPM-Zustand prüfen (ändert nichts am TPM)
# Check prerequisites and TPM state (changes nothing in the TPM)
source "$(dirname "$0")/common.sh"
title "$(t Voraussetzungen Prerequisites) ($KEYLEASH_TPM)"
for b in tpm2_createprimary tpm2_policycountertimer tpm2_makecredential openssl curl python3; do
  command -v $b >/dev/null && echo "  ✔ $b" || echo "  ${R}✘ $b $(t 'fehlt – setup.sh ausführen' 'missing – run setup.sh')${N}"
done
python3 -c "import cryptography" 2>/dev/null && echo "  ✔ python3-cryptography" || echo "  ${R}✘ python3-cryptography $(t fehlt missing)${N}"
if [ "$KEYLEASH_TPM" = hw ]; then
  [ -r /dev/tpmrm0 ] && [ -w /dev/tpmrm0 ] && echo "  ✔ /dev/tpmrm0 $(t 'les-/schreibbar' 'readable/writable')" \
    || echo "  ${R}✘ $(t 'kein Zugriff auf /dev/tpmrm0 (Gruppe tss? neu anmelden nach setup.sh)' 'no access to /dev/tpmrm0 (group tss? log in again after setup.sh)')${N}"
fi
title "TPM"
tpm2_getcap properties-fixed 2>/dev/null | awk -v m="$(t 'Hersteller:' 'Vendor:    ')" -v v="$(t 'Familie:   ' 'Family:    ')" '
  /TPM2_PT_MANUFACTURER:/{f="m"} /TPM2_PT_FAMILY_INDICATOR:/{f="v"} /TPM2_PT_FIRMWARE_VERSION_1:/{f="fw"}
  /value:/ && f!="" { gsub(/"/,""); $1=""; if(f=="m")print "  "m$0; if(f=="v")print "  "v$0; if(f=="fw")print "  Firmware:  "$0; f="" }'
tpm2_readclock | sed 's/^/  /'
echo "  PCR (${KEYLEASH_PCRS}):"; tpm2_pcrread "$KEYLEASH_PCRS" | sed 's/^/    /'
tpm2_getcap properties-variable | grep -A0 -E 'TPM2_PT_LOCKOUT_COUNTER|TPM2_PT_MAX_AUTH_FAIL' | sed 's/^/  /'
note "$(t 'Lockout-Zähler sollte 0 sein. Die Demos lösen keine Passwort-Fehlversuche aus.' 'The lockout counter should be 0. The demos never trigger failed password attempts.')"
