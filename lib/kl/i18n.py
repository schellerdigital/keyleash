# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""Sprachumschaltung für alle Ausgaben (KEYLEASH_LANG=de|en, Standard: de).

Intern bleiben alle Ereignis- und Ablehnungscodes deutsch; übersetzt wird
nur an der Ausgabe (Bildschirm, SIEM-Log, HTTP-Antwort). Die Erkennung
hängt damit nicht von der Sprache ab.
"""
from kl.common import cfg

LANG = (cfg("KEYLEASH_LANG", "de") or "de").strip().lower()[:2]
EN = LANG == "en"


def T(de: str, en: str) -> str:
    return en if EN else de


# Ereignisnamen, Ablehnungsgründe und Feldnamen im SIEM-Log
CODES = {
    # Ereignisse
    "enroll_gestartet": "enroll_started",
    "enroll_erfolgreich": "enroll_succeeded",
    "zweckschluessel_erstellt": "purpose_key_created",
    "referenz_aktualisiert": "baseline_updated",
    "viele_neustarts": "many_reboots",
    "ausserhalb_betriebsfenster": "outside_operating_window",
    "ticket_erteilt": "ticket_issued",
    "neuer_signaturzweck": "new_signing_purpose",
    "signaturvolumen_auffaellig": "signature_volume_anomaly",
    "erneuerung_ausgeblieben": "renewal_missed",
    "ticket_verweigert": "ticket_denied",
    "anfrage_verweigert": "request_denied",
    "anfrage_fehlerhaft": "request_malformed",
    # Ablehnungsgründe
    "signatur_ungueltig": "signature_invalid",
    "enrollment_token_falsch": "enrollment_token_wrong",
    "ak_attribute_ungueltig": "ak_attributes_invalid",
    "kein_offenes_enrollment": "no_pending_enrollment",
    "credential_falsch_ak_nicht_im_tpm": "credential_wrong_ak_not_in_tpm",
    "certify_ungueltig": "certify_invalid",
    "certify_falscher_schluessel": "certify_wrong_key",
    "quote_ungueltig": "quote_invalid",
    "pcr_auswahl_falsch": "pcr_selection_wrong",
    "schluessel_exportierbar_oder_extern": "key_exportable_or_external",
    "schluessel_umgeht_policy": "key_bypasses_policy",
    "schluessel_policy_falsch": "key_policy_wrong",
    "unbekanntes_system": "unknown_host",
    "zweck_ohne_freigabeschluessel": "purpose_without_approval_key",
    "nonce_ungueltig_replay": "nonce_invalid_replay",
    "system_gesperrt": "host_revoked",
    "unerwartetes_netzsegment": "unexpected_network_segment",
    "pcr_abweichung_manipulation": "boot_state_mismatch_tampering",
    "tpm_zaehler_ruecklaeufig": "tpm_counter_went_backwards",
    "anfrage_zu_haeufig_parallel": "too_frequent_parallel_instance",
    "tpm_uhr_unsicher": "tpm_clock_unsafe",
    "datenzugriff": "data_access",
    "datenzugriff_verweigert": "data_access_denied",
    "zertifikat_ungueltig": "certificate_invalid",
    "tpm_uhr_ruecksprung": "tpm_clock_rollback",
    "tpm_uhr_abweichung": "tpm_clock_drift",
    "admin_nur_lokal": "admin_local_only",
    "kurzzertifikat_ausgestellt": "short_cert_issued",
    "sperr_hook": "revoke_hook",
    "sperr_hook_fehler": "revoke_hook_failed",
    "kurzzertifikat_name_ungueltig": "short_cert_name_invalid",
    "unbekannte_aktion": "unknown_action",
    "ungueltiges_json": "invalid_json",
    "nicht gefunden": "not found",
    "remote_signiert": "remote_signed",
    "remote_eingerichtet": "remote_registered",
    "kein_remote_system": "not_a_remote_host",
    "remote_absender_falsch": "remote_sender_mismatch",
    "remote_anmeldung_falsch": "remote_client_signature_invalid",
    "remote_zweck_unbekannt": "remote_purpose_unknown",
    "remote_menge_ueberschritten": "remote_limit_exceeded",
    "remote_signieren_fehlgeschlagen": "remote_signing_failed",
}

KEYS = {
    "ablauf_tpm_clock": "expiry_tpm_clock",
    "signaturen": "signatures",
    "signaturzwecke": "signing_purposes",
    "zweck": "purpose",
    "zwecke": "purposes",
    "alt": "old",
    "neu": "new",
    "erwartet": "expected",
    "gemeldet": "reported",
    "zuletzt": "previous",
    "abstand_s": "interval_s",
    "neustarts": "reboots",
    "uhr_gesichert": "clock_safe",
    "nur_dieser_start": "this_boot_only",
    "wand_s": "wall_s",
    "zuletzt_clock": "previous_clock",
    "zuletzt_reset": "previous_reset",
    "fenster": "window",
    "grenze": "limit",
    "fenster_s": "window_s",
    "neuer_zweck": "new_purpose",
    "seit_s": "since_s",
    "grund": "reason",
    "pfad": "path",
    "fehler": "error",
    "laufzeit_s": "lifetime_s",
    "aktion": "action",
    "typ": "type",
    "dauer_ms": "duration_ms",
    "ausgabe": "output",
    "anzahl_fenster": "count_window",
    "schluessel": "key_store",
}

_REV = {v: k for k, v in CODES.items()}
_REV_KEYS = {v: k for k, v in KEYS.items()}


def code(c):
    """Interner (deutscher) Code -> Ausgabesprache."""
    return CODES.get(c, c) if EN and isinstance(c, str) else c


def fields(d: dict) -> dict:
    """Feldnamen und Code-Werte eines SIEM-Datensatzes in die Ausgabesprache."""
    if not EN:
        return d
    out = {}
    for k, v in d.items():
        if k == "grund":
            v = code(v)
        out[KEYS.get(k, k)] = v
    return out


def canonical(c):
    """Beliebige Sprache -> interner Code (für Auswertungen alter und neuer Logs)."""
    return _REV.get(c, c)


def canonical_key(k):
    return _REV_KEYS.get(k, k)

