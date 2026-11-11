#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Signaturdienst für Systeme ohne TPM (z. B. Cloud-VMs ohne vTPM): Der Signaturschlüssel liegt im
# NetHSM hinter dem keyleash-Server, nie auf der VM. Der Server prüft jede Anfrage, zählt selbst
# und sperrt sofort.
# Signing service for systems without a TPM (e.g. cloud VMs without a vTPM): the signing key lives in
# the NetHSM behind the keyleash server, never on the VM. The server checks every request, counts
# by itself and revokes immediately.
#   88-signaturdienst.sh            nutzt den Schlüsselspeicher des Servers (NetHSM oder Datei)
source "$(dirname "$0")/common.sh"
ensure_server
VM=${KEYLEASH_REMOTE_HOST:-cloudvm}
CD=$LAB/state/remote-client
RC="python3 $LAB/agent/remote.py"
STORE=$(grep -oP '^KEYLEASH_KEYSTORE=\K\w+' keyleash.env 2>/dev/null || echo file)
LIMIT=$(grep -oP '^KEYLEASH_REMOTE_LIMIT=\K\d+' keyleash.env 2>/dev/null || echo 10)
now() { python3 -c 'import time;print(time.time())'; }
since() { python3 -c "import time;print(f'{(time.time()-$1)*1000:.0f}')"; }
rv() { curl -sf -X POST -H 'Content-Type: application/json' -d "{\"host\":\"$VM\"}" "$KEYLEASH_SERVER/admin/$1" >/dev/null; }
verify() {   # Prüfung wie bei jedem Empfänger: Zertifikatskette, dann Signatur
  openssl verify -CAfile state/server/ca_cert.pem "$2.crt" >/dev/null 2>&1 || { echo "  ${R}✘ $(t 'Zertifikat ungültig' 'certificate invalid')${N}"; return 1; }
  openssl x509 -in "$2.crt" -pubkey -noout > "$W/rpub.pem"
  openssl dgst -sha256 -verify "$W/rpub.pem" -signature "$2" "$1" >/dev/null 2>&1 \
    && echo "  ${G}✔${N} $(t 'Empfänger: Signatur gültig' 'Relying party: signature valid') ($(openssl x509 -in "$2.crt" -noout -subject | sed 's/subject=//'))" \
    || echo "  ${R}✘ $(t 'Signatur ungültig' 'signature invalid')${N}"
}

title "$(t 'Signaturdienst für Systeme ohne TPM (NetHSM)' 'Signing service for systems without a TPM (NetHSM)')"
if [ "$STORE" = nethsm ]; then echo "  $(t 'Schlüsselspeicher' 'Key store'): NetHSM ($(grep -oP '^KEYLEASH_NETHSM_URL=\K\S+' keyleash.env))"
else note "$(t 'Schlüsselspeicher: Datei auf dem Server (Lab). Mit NetHSM: tools/nethsm-setup.py import, dann Server neu starten.' 'Key store: file on the server (lab). With a NetHSM: tools/nethsm-setup.py import, then restart the server.')"; fi

# Neu eintragen, wenn die VM fehlt oder der Schlüsselspeicher gewechselt hat (Datei <-> NetHSM)
if ! grep -qs "^$STORE$" "$CD/store" || ! grep -qs "^$VM$" "$CD/host" || ! curl -sf "$KEYLEASH_SERVER/admin/hosts" | python3 -c "import json,sys;sys.exit(0 if json.load(sys.stdin).get('$VM') is not None else 1)"; then
  step "$(t "Einrichtung: VM '$VM' erzeugt ihren Anmeldeschlüssel, der Admin trägt sie ein" "Setup: VM '$VM' creates its sign-in key, the admin registers it")"
  $RC init --host "$VM" >/dev/null
  python3 tools/remote-setup.py add "$VM" --purpose deploy --client-pub "$CD/client_pub.pem" --ip 127.0.0.1 || exit 1
  echo "$STORE" > "$CD/store"
fi
rv sigreset   # Zählung für die Vorführung zurücksetzen

step "$(t 'Was auf der VM liegt' 'What is on the VM')"
ls -1 "$CD" | grep -v '\.sig' | sed 's/^/  /'
note "$(t 'Nur ein Anmeldeschlüssel. Der Signaturschlüssel für „deploy“ liegt nicht auf der VM.' 'Only a sign-in key. The signing key for "deploy" is not on the VM.')"

step "$(t 'Normalbetrieb: VM lässt ein Release signieren, ein Empfänger prüft' 'Normal operation: the VM has a release signed, a relying party verifies')"
echo "release $(date +%s)" > "$W/deploy.tar"
T0=$(now); $RC sign "$W/deploy.tar" --purpose deploy -o "$W/deploy.sig" --save-request "$W/remote.req" | sed 's/^/  /'
echo "  $(t 'Dauer' 'Duration'): $(since "$T0") ms"
verify "$W/deploy.tar" "$W/deploy.sig"

step "$(t 'Angriff 1: Anmeldeschlüssel gestohlen, Einsatz von einem anderen Rechner' 'Attack 1: sign-in key stolen, used from another machine')"
rm -rf "$W/stolen-rc"; cp -r "$CD" "$W/stolen-rc"
expect_fail $RC sign "$W/deploy.tar" --purpose deploy -o "$W/x.sig" --dir "$W/stolen-rc" --source 127.0.0.2

step "$(t 'Angriff 2: aufgezeichnete Anfrage wiederholen' 'Attack 2: replay a recorded request')"
expect_fail $RC replay "$W/remote.req"

step "$(t 'Angriff 3: Zweck, der für die VM nicht vorgesehen ist' 'Attack 3: a purpose not intended for this VM')"
expect_fail $RC sign "$W/deploy.tar" --purpose release -o "$W/x.sig"

step "$(t 'Sperre: wirkt bei der nächsten Anfrage – kein Ticket, das erst ablaufen muss' 'Revocation: effective on the next request – no ticket that has to expire first')"
T0=$(now); rv revoke; echo "  $(t gesperrt revoked): $VM"
expect_fail $RC sign "$W/deploy.tar" --purpose deploy -o "$W/x.sig"
echo "  $(t "erste abgelehnte Signatur $(since "$T0") ms nach der Sperre" "first refused signature $(since "$T0") ms after revocation")"
rv unrevoke; echo "  $(t entsperrt reinstated)"

step "$(t "Angriff 4: Angreifer auf der VM selbst signiert in Serie (Grenze $LIMIT pro Stunde)" "Attack 4: attacker on the VM itself signs in bulk (limit $LIMIT per hour)")"
rv sigreset; ok=0
for i in $(seq $((LIMIT + 3))); do
  if $RC sign "$W/deploy.tar" --purpose deploy -o "$W/b.sig" > "$W/b.out" 2>&1; then ok=$((ok + 1))
  else echo "  ${G}✔${N} $(t "Signatur $i abgelehnt" "signature $i refused"): $(sed 's/^✘ [^:]*: //' "$W/b.out")"; break; fi
done
echo "  $(t "$ok Signaturen erteilt, danach Schluss" "$ok signatures granted, then stop") ($(t 'der Server zählt selbst – die VM kann nichts schönen' 'the server counts by itself – the VM cannot falsify anything'))"
note "$(t 'Bis zur Grenze oder Sperre kann ein Angreifer auf der VM signieren lassen. Den Schlüssel mitnehmen kann er nicht.' 'Until the limit or revocation an attacker on the VM can have things signed. He cannot take the key with him.')"
rv sigreset
siem_tail 6
