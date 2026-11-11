#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Normalbetrieb und drei Angriffe ohne gültiges Ticket
# Normal operation and three attacks without a valid ticket
source "$(dirname "$0")/common.sh"
ensure_server; ensure_enrolled
title "$(t 'Normalbetrieb: Ticket holen, signieren, Gegenstelle prüft' 'Normal operation: get a ticket, sign, relying party verifies')"
$AG renew
echo "$(t Bescheid Notice) $(date -Is)" > "$W/doc.txt"
$AG sign "$W/doc.txt" -o "$W/doc.sig" && verify/verify.sh "$W/doc.txt" "$W/doc.sig" "$ST/cert.pem" "$ST/ca.pem"

title "$(t 'Angriff 1: Schlüsselgeheimnis bekannt, aber ohne Policy (Passwort-Session)' 'Attack 1: key secret known, but no policy (password session)')"
note "$(t 'Selbst mit dem Geheimnis des Prozesses kann niemand am Ticket vorbei signieren.' 'Even with the process secret, nobody can sign without the ticket.')"
AUTH=$(cat "$ST/key.auth")
try_pw() {
  tpm2_createprimary -C o -G rsa -c "$W/p.ctx" >/dev/null &&
  tpm2_load -C "$W/p.ctx" -u "$ST/key.pub" -r "$ST/key.priv" -c "$W/k.ctx" >/dev/null &&
  echo -n "hex:$AUTH" | tpm2_sign -c "$W/k.ctx" -p file:- -g sha256 -o "$W/x.sig" "$W/doc.txt"
}
expect_fail try_pw

title "$(t 'Angriff 2: selbst ausgestelltes Ticket (fremder Signaturschlüssel)' 'Attack 2: self-issued ticket (foreign signing key)')"
forge() {
  openssl genrsa -out "$W/evil.key" 2048 2>/dev/null; openssl rsa -in "$W/evil.key" -pubout -out "$W/evil.pub" 2>/dev/null
  python3 - "$W" <<'P'
import json,sys,subprocess
w=sys.argv[1]; t=json.load(open(f"{w}/../agent/ticket.json"))
open(f"{w}/evil.msg","wb").write(bytes.fromhex(t["approved_policy"])+bytes.fromhex(t["policy_ref"]))
P
  openssl dgst -sha256 -sign "$W/evil.key" -out "$W/evil.sig" "$W/evil.msg"
  python3 - "$W" "$ST" <<'P'
import json,sys,base64,shutil
w,st=sys.argv[1:]; t=json.load(open(f"{st}/ticket.json"))
t["signature"]=base64.b64encode(open(f"{w}/evil.sig","rb").read()).decode()
import os; os.makedirs(f"{w}/evil",exist_ok=True)
for f in ("key.pub","key.priv","key.auth"): shutil.copy(f"{st}/{f}",f"{w}/evil/{f}")
shutil.copy(f"{w}/evil.pub",f"{w}/evil/authz_pub.pem")
json.dump(t,open(f"{w}/evil/ticket.json","w"))
P
  KEYLEASH_AGENT_STATE="$W/evil" $AG sign "$W/doc.txt" -o "$W/x.sig"
}
expect_fail forge

title "$(t 'Angriff 3: echtes Ticket, aber Ablaufzeit hochgesetzt' 'Attack 3: genuine ticket, but expiry pushed out')"
stretch() {
  mkdir -p "$W/str"; cp "$ST"/{key.pub,key.priv,key.auth,authz_pub.pem} "$W/str/"
  python3 -c "
import json; t=json.load(open('$ST/ticket.json')); t['expiry_clock']+=86400000
json.dump(t,open('$W/str/ticket.json','w'))"
  KEYLEASH_AGENT_STATE="$W/str" $AG sign "$W/doc.txt" -o "$W/x.sig"
}
expect_fail stretch
rm -rf "$W/evil" "$W/str"
