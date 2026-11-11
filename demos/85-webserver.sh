#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Webserver ohne kopierbare Geheimnisse: WordPress meldet sich bei MariaDB mit einem
# Kurzzeit-Zertifikat an. Ein Angreifer im Webserver (z. B. über eine PHP-Lücke) kann es kopieren
# und sogar eine Verbindung offen halten. Die Sperre beendet beides in Sekunden.
# Web server without copyable secrets: WordPress signs in to MariaDB with a short-lived
# certificate. An attacker inside the web server (e.g. via a PHP flaw) can copy it and even keep
# a connection open. Revocation ends both within seconds.
# Voraussetzung / prerequisite: bash tools/webdemo.sh setup
source "$(dirname "$0")/common.sh"
ensure_server; ensure_enrolled
WD=$LAB/state/webdemo; TLS=$WD/tls
WEB=${KEYLEASH_WEB_LISTEN:-127.0.0.1:8088}
DB=$(command -v mariadb || command -v mysql)
title "$(t 'Webserver ohne kopierbare Geheimnisse (WordPress + MariaDB)' 'Web server without copyable secrets (WordPress + MariaDB)')"
[ -f "$WD/wordpress/wp-content/db.php" ] || { note "$(t 'Zuerst einrichten:' 'Set it up first:') bash tools/webdemo.sh setup"; exit 1; }
bash tools/webdemo.sh start | sed 's/^/  /'
code() { curl -s -o "$W/page.html" -w '%{http_code}' "http://$WEB/"; }
left() { python3 - "$1" <<'P'
import sys, datetime as dt
from cryptography import x509
c = x509.load_pem_x509_certificate(open(sys.argv[1], "rb").read())
end = getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=dt.timezone.utc)
print(max(0, int((end - dt.datetime.now(dt.timezone.utc)).total_seconds())))
P
}
dbc() { "$DB" -h 127.0.0.1 -u wp --ssl-key="$1/key.pem" --ssl-cert="$1/cert.pem" --skip-ssl-verify-server-cert "${@:2}"; }
dbq() { dbc "$1" -N -e "SELECT CONCAT(COUNT(*), ' posts') FROM wpdemo.wp_posts"; }
now() { python3 -c 'import time;print(time.time())'; }
since() { python3 -c "import time;print(f'{time.time()-$1:.1f}')"; }
HOOK=$(grep -oP '^KEYLEASH_REVOKE_HOOK=\K\S+' keyleash.env 2>/dev/null || true)
[ "$HOOK" = tools/revoke-hooks.sh ] && [ ! -x state/hooks.d/50-webdemo ] && HOOK=""

step "$(t 'wp-config.php enthält kein Datenbank-Passwort' 'wp-config.php contains no database password')"
grep -E "DB_(USER|PASSWORD)|KEYLEASH" "$WD/wordpress/wp-config.php" | sed 's/^/  /'
note "$(t 'MariaDB lässt den Benutzer wp nur mit einem Zertifikat der keyleash-CA herein (REQUIRE SUBJECT … ISSUER …).' 'MariaDB admits user wp only with a certificate from the keyleash CA (REQUIRE SUBJECT … ISSUER …).')"

step "$(t 'Die Seite läuft' 'The site is up')"
for _ in $(seq 20); do [ "$(code)" = 200 ] && break; sleep 1; done
c=$(code); [ "$c" = 200 ] && echo "  ${G}✔${N} HTTP $c – $(grep -o '<title>[^<]*' "$W/page.html" | sed 's/<title>//')" || { echo "  ${R}✘ HTTP $c${N}"; exit 1; }
echo "  $(t 'Aktuelles Zertifikat' 'Current certificate'): $(openssl x509 -in "$TLS/current/cert.pem" -noout -subject | sed 's/subject=//'), $(t 'noch' 'remaining') $(left "$TLS/current/cert.pem") s"

step "$(t 'Angreifer im Webserver kopiert Schlüssel und Zertifikat (wie nach einer PHP-Lücke)' 'Attacker inside the web server copies key and certificate (as after a PHP flaw)')"
rm -rf "$W/stolen"; mkdir -p "$W/stolen"; cp -L "$TLS/current/"*.pem "$W/stolen/"
echo "  $(t 'Mit der Kopie sofort an die Datenbank' 'Straight to the database with the copy'): $(dbq "$W/stolen" 2>&1 | tail -1)"
# … und hält eine Verbindung offen: das Zertifikat wird nur beim Aufbau geprüft
dbc "$W/stolen" -N -e "DO SLEEP(3600);" > "$W/held.out" 2>&1 &
HELD=$!; sleep 2
if kill -0 $HELD 2>/dev/null; then
  echo "  $(t 'Hält zusätzlich eine Verbindung zur Datenbank offen' 'Also keeps a connection to the database open') (PID $HELD)"
  note "$(t 'MariaDB prüft das Zertifikat nur beim Verbindungsaufbau. Ohne Gegenmaßnahme bliebe diese Verbindung offen – auch nach Ablauf des Zertifikats.' 'MariaDB checks the certificate only when the connection is set up. Without a countermeasure this connection would stay open – even after the certificate expires.')"
fi

step "$(t 'Der Einbruch fällt auf: Administrator sperrt die Maschine' 'The intrusion is noticed: the administrator revokes the machine')"
T0=$(now)
RESP=$(curl -sf -X POST -H 'Content-Type: application/json' -d "{\"host\":\"$(jq_host)\"}" "$KEYLEASH_SERVER/admin/revoke")
echo "  $(t gesperrt revoked): $(jq_host)"
if [ -n "$HOOK" ]; then
  echo "  $(t 'Sperr-Hook' 'Revoke hook'): $(python3 -c "import json,sys;h=json.loads(sys.argv[1]).get('hook') or {};print(h.get('output','–').replace(chr(10),' | '), f\"({h.get('ms','?')} ms)\")" "$RESP")"
  for _ in $(seq 50); do kill -0 $HELD 2>/dev/null || break; sleep 0.1; done
  if kill -0 $HELD 2>/dev/null; then echo "  ${R}✘ $(t 'offene Verbindung läuft noch' 'open connection still running')${N}"; kill $HELD 2>/dev/null
  else echo "  ${G}✔${N} $(t "offene Verbindung des Angreifers beendet nach $(since "$T0") s" "attacker's open connection ended after $(since "$T0") s")"; fi
  for _ in $(seq 30); do [ "$(code)" = 503 ] && break; sleep 0.5; done
  c=$(code); [ "$c" = 503 ] && echo "  ${G}✔${N} HTTP $c $(t "nach $(since "$T0") s – die Datenbank verweigert WordPress" "after $(since "$T0") s – the database refuses WordPress")" \
    || echo "  ${R}✘ HTTP $c ($(t 'erwartet 503' 'expected 503'))${N}"
  step "$(t 'Und die gestohlene Kopie?' 'And the stolen copy?')"
  expect_fail dbq "$W/stolen"
  expect_fail $AG shortcert wpdb --dir "$W/new-cert"
  note "$(t "Zweite Linie ohne Hook: kein neues Zertifikat, das letzte läuft in $(left "$TLS/current/cert.pem") s ab; mit Ablauf des Tickets signiert auch das TPM nicht mehr." "Second line without the hook: no new certificate, the last one expires in $(left "$TLS/current/cert.pem") s; once the ticket runs out the TPM stops signing as well.")"
else
  note "$(t 'Kein Sperr-Hook eingerichtet (tools/webdemo.sh setup): Wirkung erst mit Ablauf des Zertifikats, offene Verbindungen bleiben.' 'No revoke hook set up (tools/webdemo.sh setup): effective only when the certificate expires; open connections remain.')"
  expect_fail $AG shortcert wpdb --dir "$W/new-cert"
  WAIT=$(( $(left "$TLS/current/cert.pem") + 3 ))
  step "$(t "Warte, bis das letzte Zertifikat abläuft ($WAIT s) …" "Waiting for the last certificate to expire ($WAIT s) …")"; sleep "$WAIT"
  c=$(code); [ "$c" = 503 ] && echo "  ${G}✔${N} HTTP $c" || echo "  ${R}✘ HTTP $c${N}"
  kill $HELD 2>/dev/null
fi

step "$(t 'Entsperren: Konto frei, der Agent holt beim nächsten Versuch (≤ 10 s) ein neues Zertifikat' 'Reinstate: account unlocked, the agent gets a new certificate on its next attempt (≤ 10 s)')"
admin unrevoke && echo "  $(t entsperrt reinstated)"
for _ in $(seq 40); do [ "$(code)" = 200 ] && break; sleep 1; done
c=$(code); [ "$c" = 200 ] && echo "  ${G}✔${N} HTTP $c – $(t 'Seite wieder da' 'site back')" || echo "  ${R}✘ HTTP $c${N}"
siem_tail 5
