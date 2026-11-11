<?php
// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (c) 2026 Christian Scheller · keyleash
// keyleash: Fehlerseite, wenn die Datenbank die Anmeldung verweigert
// keyleash: error page when the database refuses the sign-in
http_response_code( 503 );
$why = isset( $GLOBALS['keyleash_db_error'] ) ? $GLOBALS['keyleash_db_error'] : '';
?><!doctype html><html><head><meta charset="utf-8"><title>keyleash: database refused</title>
<style>body{font-family:system-ui,sans-serif;background:#fbebeb;color:#5c1010;margin:0;padding:48px}
h1{margin:0 0 12px}code{background:#fff;padding:2px 6px;border-radius:4px}</style></head>
<body><h1>Database refused the sign-in</h1>
<p>This server has no database password. Its short-lived certificate has expired and keyleash issues no new one: the machine was revoked or its TPM has no valid ticket.</p>
<p><code><?php echo htmlspecialchars( $why, ENT_QUOTES ); ?></code></p></body></html>
<?php exit;
