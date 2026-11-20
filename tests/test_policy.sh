#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Prüft, dass die Python-Policy-Berechnung des Servers exakt dem entspricht,
# was das TPM in Trial-Sessions berechnet. Ändert nichts am TPM.
# Comment added katopp-png
source "$(dirname "$0")/../demos/common.sh"
T=$(mktemp -d); trap 'rm -rf $T' EXIT
openssl genrsa -out $T/a.key 2048 2>/dev/null; openssl rsa -in $T/a.key -pubout -out $T/a.pub 2>/dev/null
tpm2_loadexternal -C o -G rsa -u $T/a.pub -c $T/a.ctx -n $T/a.name >/dev/null
echo -n "x" > $T/dummy
EXP=123456789; RES=7
tpm2_startauthsession -S $T/s.ctx
tpm2_policycountertimer -S $T/s.ctx --ule clock=$EXP >/dev/null
tpm2_policycountertimer -S $T/s.ctx --ule resets=$RES >/dev/null
tpm2_policycountertimer -S $T/s.ctx --eq safe >/dev/null
tpm2_policypcr -S $T/s.ctx -l "$KEYLEASH_PCRS" -L $T/appr.pol >/dev/null
tpm2_flushcontext $T/s.ctx
# Variante nach unsicherer Uhr: resetCount exakt, ohne safe
tpm2_startauthsession -S $T/s.ctx
tpm2_policycountertimer -S $T/s.ctx --ule clock=$EXP >/dev/null
tpm2_policycountertimer -S $T/s.ctx --eq resets=$RES >/dev/null
tpm2_policypcr -S $T/s.ctx -l "$KEYLEASH_PCRS" -L $T/pin.pol >/dev/null
tpm2_flushcontext $T/s.ctx
python3 -c "import hashlib;open('$T/ref','wb').write(hashlib.sha256(b'keyleash/v1/test').digest())"
tpm2_startauthsession -S $T/s.ctx
tpm2_policyauthorize -S $T/s.ctx -n $T/a.name -q $T/ref >/dev/null
tpm2_policyauthvalue -S $T/s.ctx -L $T/key.pol >/dev/null
tpm2_flushcontext $T/s.ctx
tpm2_pcrread "$KEYLEASH_PCRS" -o $T/pcrs.bin >/dev/null
python3 - "$T" <<'P'
import sys, hashlib
sys.path.insert(0, "lib")
from kl import tpmstruct as ts
from kl.common import cfg
from cryptography.hazmat.primitives import serialization
t = sys.argv[1]
pcrs = ts.parse_pcr_list(cfg("KEYLEASH_PCRS"))
dig = hashlib.sha256(open(f"{t}/pcrs.bin","rb").read()).digest()
ok = True
a = ts.approved_policy(123456789, 7, pcrs, dig)
ok &= a == open(f"{t}/appr.pol","rb").read(); print("approved_policy :", "✔" if a == open(f"{t}/appr.pol","rb").read() else "✘")
a = ts.approved_policy(123456789, 7, pcrs, dig, clock_safe=False, pin_resets=True)
r = a == open(f"{t}/pin.pol","rb").read(); ok &= r; print("pinned policy   :", "✔" if r else "✘")
pub = serialization.load_pem_public_key(open(f"{t}/a.pub","rb").read()).public_numbers()
name = ts.external_rsa_name(pub.n.to_bytes(256,"big"), pub.e)
r = name == open(f"{t}/a.name","rb").read(); ok &= r; print("authz name      :", "✔" if r else "✘")
k = ts.key_policy(name, hashlib.sha256(b"keyleash/v1/test").digest())
r = k == open(f"{t}/key.pol","rb").read(); ok &= r; print("key policy      :", "✔" if r else "✘")
sys.exit(0 if ok else 1)
P
