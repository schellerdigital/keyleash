#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Privilegierte Konten an Admin-Arbeitsplätze binden: Der SSH-Server nimmt Admins nur mit einem
# SSH-Zertifikat für wenige Minuten an, das keyleash nur einem Arbeitsplatz mit gültigem TPM-Ticket
# ausstellt. Gestohlene Schlüssel nützen nichts, die Sperre beendet laufende Sitzungen.
# Bind privileged accounts to admin workstations: the SSH server admits admins only with an SSH
# certificate valid for a few minutes, which keyleash issues only to a workstation with a valid TPM
# ticket. Stolen keys are useless, revocation ends running sessions.
# Voraussetzung / prerequisite: bash tools/admindemo.sh setup
source "$(dirname "$0")/common.sh"
ensure_server; ensure_enrolled
AD=$LAB/state/admindemo; CERT=$AD/cert
PORT=${KEYLEASH_ADMIN_SSH_PORT:-2222}
title "$(t 'Privilegierte Konten an Admin-Arbeitsplätze binden (SSH)' 'Bind privileged accounts to admin workstations (SSH)')"
[ -f "$AD/sshd_config" ] || { note "$(t 'Zuerst einrichten:' 'Set it up first:') bash tools/admindemo.sh setup"; exit 1; }
bash tools/admindemo.sh start | sed 's/^/  /'
adm() { bash tools/admindemo.sh ssh "$@"; }
now() { python3 -c 'import time;print(time.time())'; }
since() { python3 -c "import time;print(f'{time.time()-$1:.1f}')"; }
left() { python3 - "$1" <<'P'
import sys, subprocess, datetime as dt, re
out = subprocess.run(["ssh-keygen", "-L", "-f", sys.argv[1]], capture_output=True, text=True).stdout
m = re.search(r"to (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", out)
end = dt.datetime.fromisoformat(m.group(1)) if m else dt.datetime.now()
print(max(0, int((end - dt.datetime.now()).total_seconds())))
P
}
HOOK=$(grep -oP '^KEYLEASH_REVOKE_HOOK=\K\S+' keyleash.env 2>/dev/null || true)
[ -x state/hooks.d/60-admindemo ] || HOOK=""

step "$(t 'Ein normaler SSH-Schlüssel – gestohlen oder vom Angreifer – kommt nicht herein' 'A plain SSH key – stolen or the attacker'"'"'s own – does not get in')"
rm -rf "$W/plainkey"; mkdir -p "$W/plainkey"; ssh-keygen -q -t ed25519 -N "" -f "$W/plainkey/id_ed25519"
expect_fail ssh -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
  -o IdentitiesOnly=yes -o ConnectTimeout=5 -i "$W/plainkey/id_ed25519" "$(id -un)@127.0.0.1" true
note "$(t 'Keine authorized_keys, keine Passwörter: der Server vertraut nur der SSH-CA des keyleash-Servers.' 'No authorized_keys, no passwords: the server trusts only the keyleash server'"'"'s SSH CA.')"

step "$(t 'Admin meldet sich vom Arbeitsplatz an (Kurzzeit-Zertifikat)' 'Admin signs in from the workstation (short-lived certificate)')"
for _ in $(seq 15); do adm true 2>/dev/null && break; sleep 1; done
ssh-keygen -L -f "$CERT/current/id_ed25519-cert.pub" | grep -E 'Key ID|Valid|keyleash-' | sed 's/^ */  /'
echo "  $(t 'noch gültig' 'remaining'): $(left "$CERT/current/id_ed25519-cert.pub") s"
RESP=$(adm 'echo "$(whoami)@$(hostname)"' 2>&1) && echo "  ${G}✔${N} $(t 'angemeldet' 'signed in'): $RESP" || { echo "  ${R}✘ $RESP${N}"; exit 1; }

step "$(t 'Admin-Sitzung läuft; Schadsoftware auf dem Arbeitsplatz kopiert Schlüssel und Zertifikat' 'Admin session running; malware on the workstation copies key and certificate')"
adm 'sleep 3600' > "$W/admin-session.out" 2>&1 &
SESS=$!; sleep 2
kill -0 $SESS 2>/dev/null && echo "  $(t 'offene Admin-Sitzung' 'open admin session') (PID $SESS)"
rm -rf "$W/stolen-ssh"; mkdir -p "$W/stolen-ssh"; cp -L "$CERT/current/"* "$W/stolen-ssh/"; chmod 600 "$W/stolen-ssh/id_ed25519"
RESP=$(ADMIN_KEYDIR=$W/stolen-ssh adm 'echo ok' 2>&1); echo "  $(t 'Mit der Kopie' 'With the copy'): $RESP"
note "$(t 'Für die Restlaufzeit des Zertifikats funktioniert die Kopie – deshalb gilt es nur Minuten.' 'For the rest of the certificate'"'"'s lifetime the copy works – which is why it lasts only minutes.')"

step "$(t 'Verdacht: Administrator sperrt den Arbeitsplatz' 'Suspicion: the administrator revokes the workstation')"
T0=$(now)
RESP=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"host\":\"$(jq_host)\"}" "$KEYLEASH_SERVER/admin/revoke")
echo "  $(t gesperrt revoked): $(jq_host)"
if [ -n "$HOOK" ]; then
  echo "  $(t 'Sperr-Hook' 'Revoke hook'): $(python3 -c "import json,sys;h=json.loads(sys.argv[1]).get('hook') or {};print(h.get('output','–').replace(chr(10),' | '), f\"({h.get('ms','?')} ms)\")" "$RESP")"
  for _ in $(seq 50); do kill -0 $SESS 2>/dev/null || break; sleep 0.1; done
  if kill -0 $SESS 2>/dev/null; then echo "  ${R}✘ $(t 'Admin-Sitzung läuft noch' 'admin session still running')${N}"; kill $SESS 2>/dev/null
  else echo "  ${G}✔${N} $(t "Admin-Sitzung beendet nach $(since "$T0") s" "admin session ended after $(since "$T0") s")"; fi
  step "$(t 'Und die gestohlene Kopie?' 'And the stolen copy?')"
  expect_fail env ADMIN_KEYDIR="$W/stolen-ssh" bash tools/admindemo.sh ssh true
  expect_fail $AG shortcert admin --ssh --dir "$W/new-ssh"
  note "$(t 'Das Zertifikat steht in der Widerrufsliste (KRL) des SSH-Servers; ein neues stellt keyleash nicht aus.' 'The certificate is on the SSH server'"'"'s revocation list (KRL); keyleash issues no new one.')"
else
  note "$(t 'Kein Sperr-Hook eingerichtet: Wirkung erst mit Ablauf des Zertifikats, laufende Sitzungen bleiben.' 'No revoke hook set up: effective only when the certificate expires; running sessions remain.')"
  expect_fail $AG shortcert admin --ssh --dir "$W/new-ssh"
  kill $SESS 2>/dev/null
fi

step "$(t 'Entsperren: der Agent holt beim nächsten Versuch (≤ 10 s) ein neues Zertifikat' 'Reinstate: the agent gets a new certificate on its next attempt (≤ 10 s)')"
OLD=$(readlink "$CERT/current")
admin unrevoke && echo "  $(t entsperrt reinstated)"
for _ in $(seq 40); do [ "$(readlink "$CERT/current")" != "$OLD" ] && adm true 2>/dev/null && break; sleep 1; done
RESP=$(adm 'echo ok' 2>&1); [ "$RESP" = ok ] && echo "  ${G}✔${N} $(t 'Admin wieder angemeldet' 'admin signed in again')" || echo "  ${R}✘ $RESP${N}"
if [ -n "$HOOK" ]; then
  echo "  $(t "Gestohlene Kopie (noch $(left "$W/stolen-ssh/id_ed25519-cert.pub") s gültig) bleibt gesperrt:" "Stolen copy (still valid for $(left "$W/stolen-ssh/id_ed25519-cert.pub") s) stays blocked:")"
  expect_fail env ADMIN_KEYDIR="$W/stolen-ssh" bash tools/admindemo.sh ssh true
fi
note "$(t 'Notzugang (Break-Glass) gehört getrennt davon: ein Offline-Schlüssel im Tresor, dessen Nutzung selbst Alarm auslöst.' 'Emergency access (break glass) belongs separately: an offline key in a safe whose use itself raises an alert.')"
siem_tail 5
