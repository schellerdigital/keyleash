<?php
// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Christian Scheller · keyleash
/**
 * keyleash: WordPress meldet sich bei MariaDB mit einem Kurzzeit-Zertifikat an.
 * keyleash: WordPress signs in to MariaDB with a short-lived certificate.
 *
 * Es gibt kein Datenbank-Passwort. Schlüssel und Zertifikat liegen unter
 * KEYLEASH_DB_TLS_DIR/current und werden vom keyleash-Agenten laufend erneuert –
 * aber nur, solange das TPM ein gültiges Ticket hat und der Server die Maschine
 * nicht gesperrt hat. Ein gestohlener Schlüssel taugt nur bis zum Ablauf des
 * Zertifikats (Demo: 60 s).
 */
class keyleash_wpdb extends wpdb {
	public function db_connect( $allow_bail = true ) {
		$this->is_mysql = true;
		// 'current' wird bei jeder Erneuerung umgehängt; PHP merkt sich aufgelöste
		// Pfade (realpath cache), daher die Generation jedes Mal selbst auflösen.
		clearstatcache( true );
		$gen = @readlink( KEYLEASH_DB_TLS_DIR . '/current' );
		$dir = KEYLEASH_DB_TLS_DIR . '/' . ( $gen ? basename( $gen ) : 'current' ) . '/';
		$this->dbh = mysqli_init();
		mysqli_ssl_set( $this->dbh, $dir . 'key.pem', $dir . 'cert.pem', $dir . 'ca.pem', null, null );
		mysqli_report( MYSQLI_REPORT_OFF );
		$ok = @mysqli_real_connect( $this->dbh, DB_HOST, DB_USER, DB_PASSWORD, null, 3306, null,
			MYSQLI_CLIENT_SSL | MYSQLI_CLIENT_SSL_DONT_VERIFY_SERVER_CERT );
		if ( ! $ok ) {
			$GLOBALS['keyleash_db_error'] = mysqli_connect_error();
			$this->dbh = null;
			if ( $allow_bail ) {
				dead_db();
			}
			return false;
		}
		$this->has_connected = true;
		$this->set_charset( $this->dbh );
		$this->ready = true;
		$this->set_sql_mode();
		$this->select( $this->dbname, $this->dbh );
		return true;
	}
}
$wpdb = new keyleash_wpdb( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
