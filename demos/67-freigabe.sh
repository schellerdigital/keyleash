#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Freigabe durch ein zweites System: Signaturen für "release" nur mit
# kryptografischer Freigabe, vom TPM selbst erzwungen (PolicySigned + cpHash)
# Approval by a second system: signatures for "release" only with a
# cryptographic approval, enforced by the TPM itself (PolicySigned + cpHash)
source "$(dirname "$0")/common.sh"
ensure_server; ensure_enrolled
AP="python3 $LAB/tools/approve.py"
Z=$W/$(t zweites-system second-system); mkdir -p "$Z"
X_REQ=$(t anfrage request); X_APP=$(t freigabe approval)
FORGED="$W/$(t gefaelscht forged).$X_APP"
TAMPERED="$W/release-$(t manipuliert tampered).tar"

title "$(t 'Freigabe durch ein zweites System (Zweck: release)' 'Approval by a second system (purpose: release)')"
step "$(t 'Zweites System: Freigabeschlüssel erzeugen' 'Second system: create the approval key')"
$AP init release
step "$(t "Signierendes System: eigenen Schlüssel für 'release' im TPM erzeugen" "Signing system: create its own key for 'release' in the TPM")"
if [ -d "$ST/purpose-release" ]; then echo "  $(t 'bereits vorhanden' 'already exists')"; else $AG enroll-purpose release || exit 1; fi
pause_min_interval; $AG renew

echo "Release 1.4.2 – $(date -Is)" > "$W/release.tar"
cp "$W/release.tar" "$Z/release.tar"   # das zweite System hat seine eigene Kopie / the second system has its own copy

step "$(t '1. Signieren ohne Freigabe' '1. Sign without approval')"
expect_fail $AG sign "$W/release.tar" -o "$W/release.sig" --purpose release

step "$(t '2. Angriff: selbst erstellte Freigabe mit fremdem Schlüssel' '2. Attack: self-made approval with a foreign key')"
python3 - "$W" "$ST" "$FORGED" <<'P'
import json, sys, base64
sys.path.insert(0, sys.argv[2] + "/../../lib")
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from kl import tpmstruct as ts
w, st, out = sys.argv[1:]
d = ts.sha256(open(w + "/release.tar", "rb").read())
name = ts.parse_tpm2b_public(open(st + "/purpose-release/key.pub", "rb").read()).name
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
sig = k.sign(ts.approval_message(ts.sign_cphash(name, d), "release"), padding.PKCS1v15(), hashes.SHA256())
json.dump({"purpose": "release", "digest": d.hex(), "key_name": name.hex(),
           "signature": base64.b64encode(sig).decode()}, open(out, "w"))
P
expect_fail $AG sign "$W/release.tar" -o "$W/release.sig" --purpose release --approval "$FORGED"

step "$(t '3. Regulär: Anfrage → zweites System prüft eigene Kopie → Freigabe' '3. Regular flow: request → second system checks its own copy → approval')"
$AG request "$W/release.tar" --purpose release -o "$W/release.$X_REQ"
$AP approve "$W/release.$X_REQ" --file "$Z/release.tar" --yes -o "$W/release.$X_APP"
$AG sign "$W/release.tar" -o "$W/release.sig" --purpose release --approval "$W/release.$X_APP" && \
  verify/verify.sh "$W/release.tar" "$W/release.sig" "$ST/purpose-release/cert.pem" "$ST/purpose-release/ca.pem"

step "$(t '4. Echte Freigabe für eine manipulierte Datei wiederverwenden' '4. Reuse a genuine approval for a tampered file')"
cp "$W/release.tar" "$TAMPERED"; echo "backdoor" >> "$TAMPERED"
expect_fail $AG sign "$TAMPERED" -o "$W/x.sig" --purpose release --approval "$W/release.$X_APP"

step "$(t '5. Manipulierter Build: das zweite System vergleicht mit seiner eigenen Kopie' '5. Tampered build: the second system compares against its own copy')"
$AG request "$TAMPERED" --purpose release -o "$W/$(t manipuliert tampered).$X_REQ"
expect_fail $AP approve "$W/$(t manipuliert tampered).$X_REQ" --file "$Z/release.tar" --yes -o "$W/x.$X_APP"

step "$(t '6. Umgehung mit vollem Zugriff (Schlüsseldateien und Geheimnis), aber ohne Freigabe' '6. Bypass with full access (key files and secret), but without approval')"
LAB="$LAB" python3 - <<'P'
# Umgehungsversuche mit vollem Zugriff (Schlüsseldateien + Geheimnis), aber ohne Freigabe
import json, os, sys
sys.path.insert(0, os.environ["LAB"] + "/lib"); sys.path.insert(0, os.environ["LAB"] + "/agent")
import agent
from kl import tpm
from kl.common import read, write
from kl.i18n import T
s = agent.sd(); pdir = agent.purpose_dir("release")
t = json.load(open(os.path.join(s, "ticket.json")))
auth = read(os.path.join(pdir, "key.auth"), "r").strip()
def attempt(label, ticket):
    with tpm.Workdir() as w:
        write(w("d"), b"\x11" * 32)
        tpm.load_primary(w)
        tpm.run("tpm2_load", "-C", w("primary.ctx"), "-u", os.path.join(pdir, "key.pub"),
                "-r", os.path.join(pdir, "key.priv"), "-c", w("key.ctx"))
        try:
            sess = agent.policy_session(w, s, ticket)
            pw, pin = tpm.session_auth(sess, auth)
            tpm.run("tpm2_sign", "-c", w("key.ctx"), "-p", pw, "-g", "sha256",
                    "-d", "-f", "plain", "-o", w("sig"), w("d"), stdin=pin)
            print(T("  ✘ UNERWARTET signiert: ", "  ✘ UNEXPECTEDLY signed: ") + label)
        except tpm.TpmError as e:
            print(T("  ✔ verweigert", "  ✔ refused") + f" ({label}): {str(e)[:110]}")
attempt(T("Basis-Ticket auf release-Schlüssel", "base ticket on the release key"), t)
attempt(T("release-Ticket ohne PolicySigned", "release ticket without PolicySigned"), dict(t, **t["purpose_tickets"]["release"]))
P

note "$(t 'Die Freigabe prüft das TPM selbst: Ohne den privaten Freigabeschlüssel kann auch root' 'The TPM itself checks the approval: without the private approval key, even root')"
note "$(t "auf dem signierenden System für 'release' nicht signieren." "on the signing system cannot sign for 'release'.")"
siem_tail 2
