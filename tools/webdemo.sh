#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Demo „Webserver ohne kopierbare Geheimnisse“: WordPress meldet sich bei MariaDB
# mit einem Kurzzeit-Zertifikat an, das nur mit gültigem keyleash-Ticket entsteht.
# Demo "web server without copyable secrets": WordPress signs in to MariaDB with a
# short-lived certificate that can only be obtained with a valid keyleash ticket.
#
#   bash tools/webdemo.sh setup    einmalig: Pakete, MariaDB mit TLS, WordPress (sudo)
#   bash tools/webdemo.sh start    Webserver (PHP) und Zertifikats-Erneuerung starten
#   bash tools/webdemo.sh stop     (vor demos/alle.sh stoppen: der laufende Agent erneuert Tickets parallel)
#   bash tools/webdemo.sh status
#   bash tools/webdemo.sh remove   Datenbank, MariaDB-Konfiguration und WordPress entfernen
#   bash tools/webdemo.sh hook revoke|unrevoke HOST   (ruft der keyleash-Server bei einer Sperre auf)
#
# Sperr-Hook: Bei einer Sperre sperrt der keyleash-Server sofort das Datenbankkonto und beendet
# offene Verbindungen. Ohne Hook endet der Zugang erst mit Ablauf des letzten Zertifikats.
#
# Einstellungen (keyleash.env): KEYLEASH_WEB_LISTEN (127.0.0.1:8088),
#   KEYLEASH_WEB_CERT_LIFETIME (60 s, Laufzeit der Zertifikate in der Demo)
set -uo pipefail
LAB=$(cd "$(dirname "$0")/.." && pwd); cd "$LAB"
source "$LAB/demos/common.sh" >/dev/null 2>&1 || true
cd "$LAB"
WD=$LAB/state/webdemo; mkdir -p "$WD"
WEB=${KEYLEASH_WEB_LISTEN:-127.0.0.1:8088}
LIFE=${KEYLEASH_WEB_CERT_LIFETIME:-60}
TLS=$WD/tls
ETC=/etc/keyleash-mariadb
NAME=wpdb
export PATH="$PATH:/usr/sbin:/sbin"
ok()   { echo "  ${G:-}✔${N:-} $*"; }
warn() { echo "  ${Y:-}!${N:-} $*"; }
die()  { echo "  ${R:-}✘ $*${N:-}" >&2; exit 1; }
sql()  { if command -v mariadb >/dev/null; then sudo mariadb "$@"; else sudo mysql "$@"; fi; }
guard() { if command -v mariadb >/dev/null; then mariadb "$@"; else mysql "$@"; fi; }   # als Lab-Benutzer per unix_socket, ohne sudo
alive() { [ -f "$WD/$1.pid" ] && kill -0 "$(cat "$WD/$1.pid")" 2>/dev/null; }

have_systemd() { [ -d /run/systemd/system ]; }
mariadb_up() { sql -e 'SELECT 1' >/dev/null 2>&1; }
mariadb_restart() {
  if have_systemd; then sudo systemctl enable mariadb >/dev/null 2>&1; sudo systemctl restart mariadb
  else  # ohne systemd (Container): direkt starten
    [ -d /var/lib/mysql/mysql ] || sudo mariadb-install-db --user=mysql >/dev/null 2>&1 || sudo mysql_install_db --user=mysql >/dev/null 2>&1
    sudo pkill -x mariadbd 2>/dev/null; sudo pkill -x mysqld 2>/dev/null; sleep 2
    sudo mkdir -p /run/mysqld && sudo chown mysql: /run/mysqld
    (sudo nohup mysqld_safe --user=mysql >/dev/null 2>&1 &)
  fi
  for _ in $(seq 30); do mariadb_up && return 0; sleep 1; done
  die "$(t 'MariaDB startet nicht' 'MariaDB does not start')"
}

start() {
  ensure_server; ensure_enrolled
  ensure_agent_loop   # Tickets laufend erneuern, sonst signiert das TPM nach Ablauf nicht mehr
  if ! alive certs; then
    nohup python3 agent/agent.py shortcert "$NAME" --dir "$TLS" --lifetime "$LIFE" --loop >> "$WD/certs.log" 2>&1 &
    echo $! > "$WD/certs.pid"
  fi
  for _ in $(seq 30); do [ -f "$TLS/current/cert.pem" ] && break; sleep 1; done
  [ -f "$TLS/current/cert.pem" ] || warn "$(t 'noch kein Kurzzeit-Zertifikat – siehe' 'no short-lived certificate yet – see') state/webdemo/certs.log"
  if ! alive php; then
    nohup php -S "$WEB" -t "$WD/wordpress" >> "$WD/php.log" 2>&1 &
    echo $! > "$WD/php.pid"; sleep 1
  fi
  ok "WordPress: http://$WEB   ($(t 'Zertifikate' 'certificates'): $LIFE s, Log: state/webdemo/certs.log)"
}

stop() {
  for p in php certs agent; do alive $p && kill "$(cat "$WD/$p.pid")"; rm -f "$WD/$p.pid"; done
  stop_agent_loop_unless "$LAB/state/admindemo/sshd.pid"
  ok "$(t gestoppt stopped)"
}

setup() {
  echo "▶ $(t 'Pakete' 'Packages')"
  if command -v apt-get >/dev/null; then PKGS="mariadb-server mariadb-client php-cli php-mysql php-xml curl"
    dpkg -s mariadb-server php-cli php-mysql php-xml >/dev/null 2>&1 || { sudo apt-get update -qq >/dev/null; sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $PKGS >/dev/null || die apt; }
    CNF=/etc/mysql/mariadb.conf.d/90-keyleash.cnf
  elif command -v dnf >/dev/null; then PKGS="mariadb-server php-cli php-mysqlnd php-xml curl"
    rpm -q mariadb-server php-cli php-mysqlnd php-xml >/dev/null 2>&1 || sudo dnf install -y -q $PKGS >/dev/null || die dnf
    CNF=/etc/my.cnf.d/90-keyleash.cnf
  else die "$(t 'nur apt oder dnf' 'apt or dnf only')"; fi
  ok "$PKGS"

  echo "▶ $(t 'keyleash-Server und Maschinenidentität' 'keyleash server and machine identity')"
  ensure_server
  [ -f "$ST/agent.json" ] || python3 agent/agent.py enroll || die enroll
  python3 agent/agent.py renew >/dev/null || die "$(t 'kein Ticket' 'no ticket')"
  HOSTID=$(jq_host)
  CA_PEM=$(curl -sf "$KEYLEASH_SERVER/authz" | python3 -c 'import json,sys;print(json.load(sys.stdin)["ca"])')
  ISSUER=$(printf '%s\n' "$CA_PEM" | python3 -c 'import sys
from cryptography import x509
c=x509.load_pem_x509_certificate(sys.stdin.read().encode())
print("".join("/%s=%s" % (a.oid._name if a.oid._name!="commonName" else "CN", a.value) for a in c.subject))')
  ok "$(t 'Host' 'host'): $HOSTID   CA: $ISSUER"

  echo "▶ $(t 'MariaDB: TLS mit der keyleash-CA, Anmeldung nur per Zertifikat' 'MariaDB: TLS with the keyleash CA, sign-in by certificate only')"
  sudo mkdir -p "$ETC"
  printf '%s\n' "$CA_PEM" | sudo tee "$ETC/ca.pem" >/dev/null
  if ! sudo test -f "$ETC/server.pem"; then   # Serverzertifikat der Datenbank (Demo: selbst signiert)
    sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 -subj "/CN=keyleash-demo-db" \
      -keyout "$ETC/server-key.pem" -out "$ETC/server.pem" 2>/dev/null
  fi
  sudo chown -R mysql: "$ETC" 2>/dev/null; sudo chmod 600 "$ETC/server-key.pem"
  sudo tee "$CNF" >/dev/null <<EOF
# keyleash Webdemo: Clients nur mit Zertifikat der keyleash-CA
[mariadb]
ssl_ca   = $ETC/ca.pem
ssl_cert = $ETC/server.pem
ssl_key  = $ETC/server-key.pem
bind-address = 127.0.0.1
EOF
  mariadb_restart
  sql -e "SHOW VARIABLES LIKE 'have_ssl'" | grep -q YES || die "$(t 'MariaDB ohne TLS' 'MariaDB without TLS')"
  sql <<EOF
CREATE DATABASE IF NOT EXISTS wpdemo;
DROP USER IF EXISTS 'wp'@'localhost';
DROP USER IF EXISTS 'wp'@'127.0.0.1';
CREATE USER 'wp'@'localhost' REQUIRE SUBJECT '/CN=$HOSTID/OU=$NAME' AND ISSUER '$ISSUER';
CREATE USER 'wp'@'127.0.0.1' REQUIRE SUBJECT '/CN=$HOSTID/OU=$NAME' AND ISSUER '$ISSUER';
GRANT ALL ON wpdemo.* TO 'wp'@'localhost';
GRANT ALL ON wpdemo.* TO 'wp'@'127.0.0.1';
EOF
  ok "$(t 'Benutzer wp ohne Passwort, nur mit Zertifikat' 'user wp without a password, certificate only'): /CN=$HOSTID/OU=$NAME"
  # Wächter-Konto für den Sperr-Hook: der Lab-Benutzer selbst, Anmeldung per unix_socket (kein Passwort)
  OSU=$(id -un)
  sql -e "CREATE USER IF NOT EXISTS '$OSU'@'localhost' IDENTIFIED VIA unix_socket" || die "unix_socket"
  sql -e "GRANT CREATE USER, PROCESS, CONNECTION ADMIN ON *.* TO '$OSU'@'localhost'" 2>/dev/null \
    || sql -e "GRANT CREATE USER, PROCESS, SUPER ON *.* TO '$OSU'@'localhost'" || die "GRANT"
  guard -N -e "SELECT 1" >/dev/null || die "$(t 'Wächter-Konto funktioniert nicht' 'guard account does not work')"
  register_hook 50-webdemo bash "$LAB/tools/webdemo.sh" hook
  ok "$(t 'Sperr-Hook aktiv: Sperre sperrt Konto wp und beendet offene Verbindungen' 'revoke hook active: revocation locks account wp and ends open connections') ($OSU@localhost, unix_socket)"

  echo "▶ WordPress"
  if [ ! -f "$WD/wordpress/wp-includes/version.php" ]; then
    curl -fsSL https://wordpress.org/latest.tar.gz -o "$WD/wordpress.tar.gz" || die "$(t 'Download fehlgeschlagen' 'download failed')"
    tar xzf "$WD/wordpress.tar.gz" -C "$WD" && rm -f "$WD/wordpress.tar.gz"
  fi
  SALTS=$(python3 -c "import secrets
for k in ['AUTH_KEY','SECURE_AUTH_KEY','LOGGED_IN_KEY','NONCE_KEY','AUTH_SALT','SECURE_AUTH_SALT','LOGGED_IN_SALT','NONCE_SALT']:
    print(\"define('%s', '%s');\" % (k, secrets.token_urlsafe(48)))")
  cat > "$WD/wordpress/wp-config.php" <<EOF
<?php
// keyleash Webdemo: kein Datenbank-Passwort. Die Anmeldung erfolgt mit einem
// Kurzzeit-Zertifikat (wp-content/db.php), das der keyleash-Agent laufend erneuert.
define( 'DB_NAME', 'wpdemo' );
define( 'DB_USER', 'wp' );
define( 'DB_PASSWORD', '' );
define( 'DB_HOST', '127.0.0.1' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );
define( 'KEYLEASH_DB_TLS_DIR', '$TLS' );
$SALTS
\$table_prefix = 'wp_';
define( 'WP_DEBUG', false );
if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }
require_once ABSPATH . 'wp-settings.php';
EOF
  cp "$LAB/webdemo/db.php" "$WD/wordpress/wp-content/db.php"
  cp "$LAB/webdemo/db-error.php" "$WD/wordpress/wp-content/db-error.php"
  chmod 600 "$WD/wordpress/wp-config.php"
  ok "wp-config.php ($(t 'ohne Passwort' 'no password')), wp-content/db.php"

  echo "▶ $(t 'Start und Einrichtung' 'Start and installation')"
  start
  if ! sql -N -e "SELECT 1 FROM wpdemo.wp_options LIMIT 1" >/dev/null 2>&1; then
    PW=$(python3 -c 'import secrets;print(secrets.token_urlsafe(12))'); umask 077; echo "$PW" > "$WD/admin.pass"
    curl -sf -o /dev/null --data-urlencode "weblog_title=keyleash Demo" --data-urlencode "user_name=admin" \
      --data-urlencode "admin_password=$PW" --data-urlencode "admin_password2=$PW" --data-urlencode "pw_weak=1" \
      --data-urlencode "admin_email=demo@example.org" --data-urlencode "blog_public=0" \
      "http://$WEB/wp-admin/install.php?step=2" || die "$(t 'WordPress-Installation fehlgeschlagen, siehe' 'WordPress installation failed, see') state/webdemo/php.log"
    ok "$(t 'WordPress eingerichtet, Anmeldung' 'WordPress installed, sign-in'): admin / $(t 'Passwort in' 'password in') state/webdemo/admin.pass"
  fi
  sleep 2; PAGE=$(curl -sfL "http://$WEB/" || true); [[ "$PAGE" == *"keyleash Demo"* ]] && ok "$(t 'Seite liefert Inhalte aus der Datenbank' 'page serves content from the database')" \
    || warn "$(t 'Seite liefert noch nichts – siehe' 'page returns nothing yet – see') state/webdemo/php.log"
  echo; echo "  $(t 'Vorführung' 'Demo'): demos/85-webserver.sh"
}

remove() {
  stop >/dev/null
  sql -e "DROP DATABASE IF EXISTS wpdemo; DROP USER IF EXISTS 'wp'@'localhost'; DROP USER IF EXISTS 'wp'@'127.0.0.1'; DROP USER IF EXISTS '$(id -un)'@'localhost';" 2>/dev/null
  sed -i '/^# Sperr-Hook der Webdemo/d; /^KEYLEASH_REVOKE_HOOK=tools\/webdemo-hook.sh/d' keyleash.env
  unregister_hook 50-webdemo
  sudo rm -f /etc/mysql/mariadb.conf.d/90-keyleash.cnf /etc/my.cnf.d/90-keyleash.cnf; sudo rm -rf "$ETC"
  have_systemd && sudo systemctl restart mariadb 2>/dev/null
  rm -rf "$WD"
  ok "$(t 'Webdemo entfernt (Pakete bleiben)' 'web demo removed (packages stay)')"
}

hook() {   # hook revoke|unrevoke HOST
  local action=${1:-} host=${2:-}
  [ -f "$ST/agent.json" ] && [ "$host" = "$(jq_host)" ] || { echo "$(t 'nicht betroffen' 'not affected'): $host"; return 0; }
  case "$action" in
    revoke)
      guard -e "ALTER USER 'wp'@'localhost' ACCOUNT LOCK; ALTER USER 'wp'@'127.0.0.1' ACCOUNT LOCK;" || exit 1
      local n=0 id
      for id in $(guard -N -e "SELECT id FROM information_schema.processlist WHERE user='wp'"); do
        guard -e "KILL CONNECTION $id" 2>/dev/null && n=$((n+1))
      done
      echo "$(t "Konto wp gesperrt, $n offene Verbindung(en) beendet" "account wp locked, $n open connection(s) ended")" ;;
    unrevoke)
      guard -e "ALTER USER 'wp'@'localhost' ACCOUNT UNLOCK; ALTER USER 'wp'@'127.0.0.1' ACCOUNT UNLOCK;" || exit 1
      echo "$(t 'Konto wp entsperrt' 'account wp unlocked')" ;;
    *) echo "hook revoke|unrevoke HOST"; exit 2 ;;
  esac
}

case "${1:-status}" in
  hook) shift; hook "$@" ;;
  setup) setup ;; start) start ;; stop) stop ;; remove) remove ;;
  status) agent_loop_alive && echo "agent: $(t läuft running), $(tail -n1 "$LAB/state/agentloop.log" 2>/dev/null)" || echo "agent: $(t aus stopped)"
          alive php && echo "php: $(t läuft running) (http://$WEB)" || echo "php: $(t aus stopped)"
          alive certs && echo "$(t Zertifikate certificates): $(t läuft running), $(tail -n1 "$WD/certs.log" 2>/dev/null)" || echo "$(t Zertifikate certificates): $(t aus stopped)" ;;
  *) sed -n 3,14p "$0" ;;
esac
