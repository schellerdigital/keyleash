#!/usr/bin/env python3
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""keyleash Autorisierungsserver (Lab).

Aufgaben laut Konzept:
  * Provisionierung: EK/AK per MakeCredential prüfen, Key Attestation
    (TPM2_Certify) prüfen, Zertifikat aus der Verwaltungs-CA ausstellen.
  * Ticket-Ausstellung: Quote prüfen (Nonce, Boot-Zustand), Kontext
    prüfen (Sperre, Netzsegment, Häufigkeit, Betriebsfenster), befristetes
    Ticket signieren.
  * Protokollierung: jede Entscheidung als JSON-Zeile (SIEM-Ersatz),
    optional zusätzlich an syslog.

Das Lab hält alles in einem Prozess und einer JSON-Datei. Für einen Pilot
gehören Signaturschlüssel und CA in ein HSM, der Zustand in eine
replizierte Datenbank.
"""
import argparse
import datetime as dt
import ipaddress
import json
import logging
import logging.handlers
import os
import hashlib
import secrets
import shlex
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from cryptography import x509  # noqa: E402
from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from kl import tpmstruct as ts  # noqa: E402
from kl import keystore  # noqa: E402
from kl import remote as kremote  # noqa: E402
from kl.common import LAB_ROOT, b64d, b64e, cfg, state_dir, write  # noqa: E402
from kl.i18n import T, code, fields  # noqa: E402

LOCK = threading.RLock()


# ------------------------------------------------------------ Zustand ------

class State:
    def __init__(self, d):
        self.dir = d
        self.path = os.path.join(d, "hosts.json")
        self.hosts = {}
        self.pending = {}   # host -> Enrollment in Arbeit
        self.nonces = {}    # nonce hex -> (host, ablauf)
        self.cert_nonces = {}  # nonce hex -> (host, ablauf), nur für Kurzzeit-Zertifikate
        self.remote_nonces = {}  # nonce hex -> (host, ablauf), nur für den Signaturdienst
        if os.path.exists(self.path):
            self.hosts = json.load(open(self.path))

    def save(self):
        tmp = self.path + ".tmp"
        write(tmp, json.dumps(self.hosts, indent=2))
        os.replace(tmp, self.path)


def load_or_create_keys(d):
    def rsa_key(name):
        p = os.path.join(d, name)
        if not os.path.exists(p):
            k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            write(p, k.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
        return serialization.load_pem_private_key(open(p, "rb").read(), None)

    authz, ca = keystore.server_keys(d, rsa_key)   # Datei oder NetHSM (KEYLEASH_KEYSTORE)
    ca_path = os.path.join(d, "ca_cert.pem")
    if not os.path.exists(ca_path):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, T("keyleash Lab Verwaltungs-CA", "keyleash Lab Management CA"))])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(ca.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .sign(ca, hashes.SHA256()))
        write(ca_path, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    ca_cert = x509.load_pem_x509_certificate(open(ca_path, "rb").read())
    pub = authz.public_key()
    write(os.path.join(d, "authz_pub.pem"),
          pub.public_bytes(serialization.Encoding.PEM,
                           serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)
    return authz, ca, ca_cert


# ------------------------------------------------------------ SIEM ---------

class Siem:
    def __init__(self, path, use_syslog):
        self.path = path
        self.syslog = None
        if use_syslog:
            self.syslog = logging.getLogger("keyleash")
            self.syslog.setLevel(logging.INFO)
            h = logging.handlers.SysLogHandler(address="/dev/log")
            h.setFormatter(logging.Formatter("keyleash: %(message)s"))
            self.syslog.addHandler(h)

    def log(self, event, host=None, src=None, severity="info", **details):
        # Interne Codes sind deutsch; ausgegeben wird in KEYLEASH_LANG
        event, details = code(event), fields(details)
        rec = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
               "event": event, "severity": severity, "host": host, "src_ip": src}
        rec.update(details)
        line = json.dumps(rec, ensure_ascii=False)
        with LOCK, open(self.path, "a") as f:
            f.write(line + "\n")
        if self.syslog:
            self.syslog.info(line)
        tag = {"alarm": "ALARM", "warn": "WARN "}.get(severity, "     ")
        print(f"[{tag}] {event:<22} host={host} {json.dumps(details, ensure_ascii=False)}",
              flush=True)


# ------------------------------------------------------------ Prüfungen ----

class Denied(Exception):
    def __init__(self, reason, severity="warn", **details):
        super().__init__(reason)
        self.reason = reason
        self.severity = severity
        self.details = details


def verify_rsa(pub_tpm: ts.RsaPublic, msg: bytes, sig: bytes):
    key = rsa.RSAPublicNumbers(pub_tpm.exponent, int.from_bytes(pub_tpm.modulus, "big")).public_key()
    try:
        key.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise Denied("signatur_ungueltig", "alarm")


def in_window(spec: str) -> bool:
    """'06:00-22:00' (lokale Zeit). Leer oder '00:00-24:00' = immer."""
    if not spec or spec == "00:00-24:00":
        return True
    a, b = spec.split("-")
    now = dt.datetime.now().strftime("%H:%M")
    return a <= now < b if a < b else (now >= a or now < b)


class Server:
    def __init__(self, args):
        self.args = args
        d = state_dir("server")
        self.state = State(d)
        self.authz, self.ca, self.ca_cert = load_or_create_keys(d)
        n = self.authz.public_key().public_numbers()
        self.authz_name = ts.external_rsa_name(n.n.to_bytes(256, "big"), n.e)
        self.siem = Siem(os.path.join(d, "siem.jsonl"), args.syslog)
        self.pcrs = ts.parse_pcr_list(args.pcrs)
        self.cidrs = [ipaddress.ip_network(c) for c in args.allowed_cidrs.split(",") if c]
        self.remote = kremote.RemoteKeys(d)

    # ---- Provisionierung --------------------------------------------------

    def enroll_start(self, req, src):
        host = req["host"]
        if req.get("token") != self.args.enroll_token:
            raise Denied("enrollment_token_falsch", "alarm")
        ak = ts.parse_tpm2b_public(b64d(req["ak_pub"]))
        need = ts.A_FIXED_TPM | ts.A_FIXED_PARENT | ts.A_SENSITIVE_DATA_ORIGIN | ts.A_RESTRICTED | ts.A_SIGN
        if ak.attrs & need != need or ak.has(ts.A_DECRYPT):
            raise Denied("ak_attribute_ungueltig", "alarm", attrs=hex(ak.attrs))
        secret = secrets.token_bytes(32)
        d = state_dir("server", "tmp")
        ekp, sp, cp = (os.path.join(d, f"{host}.{x}") for x in ("ek.pub", "secret", "cred"))
        write(ekp, b64d(req["ek_pub"]))
        write(sp, secret)
        # MakeCredential braucht kein TPM: das Geheimnis wird für den EK
        # verschlüsselt und an den AK-Namen gebunden.
        subprocess.run(["tpm2_makecredential", "-T", "none", "-u", ekp, "-s", sp,
                        "-n", ak.name.hex(), "-o", cp], check=True, capture_output=True)
        cred = open(cp, "rb").read()
        for p in (ekp, sp, cp):
            os.unlink(p)
        nonce = secrets.token_bytes(16)
        self.state.pending[host] = {"secret": secret, "ak_pub": req["ak_pub"],
                                    "nonce": nonce, "until": time.time() + 120}
        self.siem.log("enroll_gestartet", host, src, ak_name=ak.name.hex())
        return {"credential": b64e(cred), "nonce": nonce.hex(),
                "authz_name": self.authz_name.hex(), "pcrs": self.args.pcrs}

    def enroll_finish(self, req, src):
        host = req["host"]
        p = self.state.pending.pop(host, None)
        if not p or p["until"] < time.time():
            raise Denied("kein_offenes_enrollment")
        if not secrets.compare_digest(b64d(req["secret"]), p["secret"]):
            raise Denied("credential_falsch_ak_nicht_im_tpm", "alarm")
        ak = ts.parse_tpm2b_public(b64d(p["ak_pub"]))
        key = ts.parse_tpm2b_public(b64d(req["key_pub"]))

        # Key Attestation: AK bestätigt, dass genau dieser Schlüssel im TPM liegt
        cert_raw = b64d(req["certify_attest"])
        verify_rsa(ak, cert_raw, b64d(req["certify_sig"]))
        att = ts.parse_attest(cert_raw)
        # (tpm2_certify in tpm2-tools 5.x setzt keine Qualifying Data; die
        # Frische liefert der Quote unten, die Bindung der Name-Vergleich.)
        if att.type != ts.TPM_ST_ATTEST_CERTIFY:
            raise Denied("certify_ungueltig", "alarm")
        if att.cert_name != key.name:
            raise Denied("certify_falscher_schluessel", "alarm")
        policy_ref = ts.policy_ref_for(host)
        self.check_key(key, policy_ref)

        # Referenz-Boot-Zustand aus einem Quote mit derselben Nonce
        q_raw = b64d(req["quote_attest"])
        verify_rsa(ak, q_raw, b64d(req["quote_sig"]))
        q = ts.parse_attest(q_raw)
        if q.type != ts.TPM_ST_ATTEST_QUOTE or q.extra != p["nonce"]:
            raise Denied("quote_ungueltig", "alarm")
        if q.pcr_select != ts.pcr_selection(self.pcrs):
            raise Denied("pcr_auswahl_falsch")

        cert = self.issue_cert(host, key, T("TPM-gebunden", "TPM-bound"))
        self.state.hosts[host] = {
            "ak_pub": p["ak_pub"], "key_name": key.name.hex(),
            "policy_ref": policy_ref.hex(), "pcr_digest": q.pcr_digest.hex(),
            "revoked": False, "rebaseline": False, "cert_serial": hex(cert.serial_number),
            "last": {"ts": 0, "clock": q.clock, "reset": q.reset_count, "ip": src},
            "expires_ts": 0, "missed_alarm": False,
        }
        self.state.save()
        self.siem.log("enroll_erfolgreich", host, src, key_name=key.name.hex(),
                      pcr_digest=q.pcr_digest.hex(), cert_serial=hex(cert.serial_number))
        return {"cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
                "ca": self.ca_cert.public_bytes(serialization.Encoding.PEM).decode()}

    # ---- Hilfen für Schlüssel und Zertifikate ------------------------------

    def check_key(self, key, policy_ref):
        need = ts.A_FIXED_TPM | ts.A_FIXED_PARENT | ts.A_SENSITIVE_DATA_ORIGIN | ts.A_SIGN
        if key.attrs & need != need:
            raise Denied("schluessel_exportierbar_oder_extern", "alarm", attrs=hex(key.attrs))
        if key.has(ts.A_USER_WITH_AUTH):
            # sonst wäre der Schlüssel auch ohne Ticket per Passwort nutzbar
            raise Denied("schluessel_umgeht_policy", "alarm")
        if key.auth_policy != ts.key_policy(self.authz_name, policy_ref):
            raise Denied("schluessel_policy_falsch", "alarm")

    def issue_cert(self, host, key, ou):
        pub = rsa.RSAPublicNumbers(key.exponent, int.from_bytes(key.modulus, "big")).public_key()
        now = dt.datetime.now(dt.timezone.utc)
        return (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host),
                                         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou)]))
                .issuer_name(self.ca_cert.subject).public_key(pub)
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False,
                                             False, False), critical=True)
                .sign(self.ca, hashes.SHA256()))

    def approvers(self):
        """Zwecke mit Freigabepflicht: KEYLEASH_APPROVAL="release=pfad/zum/pub.pem,…".

        Wird bei jedem Aufruf neu gelesen, damit ein neuer Freigabeschlüssel
        ohne Neustart des Servers wirkt.
        """
        out = {}
        for item in filter(None, self.args.approval.split(",")):
            purpose, _, path = item.partition("=")
            path = path if os.path.isabs(path) else os.path.join(LAB_ROOT, path)
            if not os.path.exists(path):
                continue
            pem = open(path).read()
            n = serialization.load_pem_public_key(pem.encode()).public_numbers()
            out[purpose.strip()] = {"name": ts.external_rsa_name(n.n.to_bytes(256, "big"), n.e),
                                    "pem": pem}
        return out

    # ---- Zweckschlüssel mit Freigabepflicht -------------------------------

    def enroll_purpose(self, req, src):
        """Zusätzlicher Schlüssel eines Systems, nur mit Freigabe nutzbar."""
        host, purpose = req["host"], req["purpose"]
        h = self.state.hosts.get(host)
        if not h:
            raise Denied("unbekanntes_system", "alarm")
        if purpose not in self.approvers():
            raise Denied("zweck_ohne_freigabeschluessel")
        ak = ts.parse_tpm2b_public(b64d(h["ak_pub"]))
        key = ts.parse_tpm2b_public(b64d(req["key_pub"]))
        raw = b64d(req["certify_attest"])
        verify_rsa(ak, raw, b64d(req["certify_sig"]))
        att = ts.parse_attest(raw)
        if att.type != ts.TPM_ST_ATTEST_CERTIFY or att.cert_name != key.name:
            raise Denied("certify_ungueltig", "alarm")
        ref = ts.purpose_policy_ref(host, purpose)
        self.check_key(key, ref)
        cert = self.issue_cert(host, key, T(f"Zweck {purpose} (mit Freigabe)", f"purpose {purpose} (approval required)"))
        h.setdefault("purpose_keys", {})[purpose] = {"key_name": key.name.hex(), "policy_ref": ref.hex(),
                                                     "cert_serial": hex(cert.serial_number)}
        self.state.save()
        self.siem.log("zweckschluessel_erstellt", host, src, zweck=purpose, key_name=key.name.hex())
        return {"cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
                "ca": self.ca_cert.public_bytes(serialization.Encoding.PEM).decode()}

    def purpose_tickets(self, h, expiry, max_resets, pcr_digest, clock_safe=True, pin_resets=False):
        out = {}
        appr = self.approvers()
        for purpose, pk in h.get("purpose_keys", {}).items():
            if purpose not in appr:
                continue  # ohne Freigabeschlüssel kein Ticket: Zweck gesperrt
            approved = ts.approved_policy_with_approval(expiry, max_resets, self.pcrs, pcr_digest,
                                                        appr[purpose]["name"], purpose,
                                                        clock_safe, pin_resets)
            ref = bytes.fromhex(pk["policy_ref"])
            out[purpose] = {"approved_policy": approved.hex(), "policy_ref": pk["policy_ref"],
                            "signature": b64e(self.authz.sign(approved + ref, padding.PKCS1v15(),
                                                              hashes.SHA256())),
                            "approver_pub": appr[purpose]["pem"],
                            "approval_ref": ts.approval_ref(purpose).hex()}
        return out

    # ---- Tickets ----------------------------------------------------------

    def nonce(self, req, src):
        n = secrets.token_bytes(16)
        now = time.time()
        self.state.nonces = {k: v for k, v in self.state.nonces.items() if v[1] > now}
        self.state.nonces[n.hex()] = (req["host"], now + 60)
        return {"nonce": n.hex()}

    # ---- Kurzzeit-Zertifikate ("kein kopierbares Geheimnis") ----------------
    #
    # Der Agent erzeugt einen frischen Software-Schlüssel und lässt dessen
    # öffentlichen Teil vom TPM-Maschinenschlüssel signieren. Das TPM signiert
    # nur mit gültigem Ticket; der Server prüft zusätzlich die Sperre und stellt
    # ein Zertifikat für wenige Minuten aus. Ein gestohlener Software-Schlüssel
    # ist damit nur bis zu diesem Ablauf etwas wert.

    def cert_nonce(self, req, src):
        n = secrets.token_bytes(16)
        now = time.time()
        self.state.cert_nonces = {k: v for k, v in self.state.cert_nonces.items() if v[1] > now}
        self.state.cert_nonces[n.hex()] = (req["host"], now + 60)
        return {"nonce": n.hex()}

    def short_cert(self, req, src):
        host, name = req["host"], req.get("name", "")
        h = self.state.hosts.get(host)
        if not h:
            raise Denied("unbekanntes_system", "alarm")
        n = self.state.cert_nonces.pop(req.get("nonce", ""), None)
        if not n or n[0] != host or n[1] < time.time():
            raise Denied("nonce_ungueltig_replay", "alarm")
        if not name.replace("-", "").isalnum() or len(name) > 32:
            raise Denied("kurzzertifikat_name_ungueltig", "warn")
        if h["revoked"]:
            raise Denied("system_gesperrt", "warn")
        ip = ipaddress.ip_address(src)
        if self.cidrs and not any(ip in c for c in self.cidrs):
            raise Denied("unerwartetes_netzsegment", "alarm")
        # Maschinenzertifikat: von dieser CA, für diesen Host, die zuletzt ausgestellte Seriennummer
        mc = x509.load_pem_x509_certificate(req["machine_cert"].encode())
        try:
            self.ca_cert.public_key().verify(mc.signature, mc.tbs_certificate_bytes,
                                             padding.PKCS1v15(), mc.signature_hash_algorithm)
        except Exception:
            raise Denied("zertifikat_ungueltig", "alarm")
        cn = mc.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn or cn[0].value != host or hex(mc.serial_number) != h.get("cert_serial"):
            raise Denied("zertifikat_ungueltig", "alarm")
        kind = req.get("kind", "x509")
        if kind == "ssh":
            parts = req["pub"].split()
            if len(parts) < 2 or parts[0] not in ("ssh-ed25519", "ecdsa-sha2-nistp256"):
                raise Denied("kurzzertifikat_name_ungueltig", "warn")
            blob = b64d(parts[1])
        else:
            new_pub = serialization.load_pem_public_key(req["pub"].encode())
            blob = new_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        msg = f"keyleash-kurzzertifikat|{host}|{name}|{req['nonce']}|{hashlib.sha256(blob).hexdigest()}".encode()
        try:
            mc.public_key().verify(b64d(req["sig"]), msg, padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            raise Denied("signatur_ungueltig", "alarm")
        life = max(30, min(int(req.get("lifetime", 300)), self.args.shortcert_max))
        if kind == "ssh":
            return self.ssh_cert(host, name, parts[0] + " " + parts[1], life, src)
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host),
                                         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, name)]))
                .issuer_name(self.ca_cert.subject).public_key(new_pub)
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(seconds=30))
                .not_valid_after(now + dt.timedelta(seconds=life))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(self.ca, hashes.SHA256()))
        self.siem.log("kurzzertifikat_ausgestellt", host, src, name=name, laufzeit_s=life,
                      serial=hex(cert.serial_number))
        return {"cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
                "ca": self.ca_cert.public_bytes(serialization.Encoding.PEM).decode(), "lifetime": life}

    def ssh_ca(self):
        """SSH-CA des Servers (Ed25519, Lab: Datei in state/server/ssh_ca)."""
        p = os.path.join(self.state.dir, "ssh_ca")
        if not os.path.exists(p):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "keyleash-ssh-ca", "-f", p], check=True)
        return p

    def ssh_ca_pub(self):
        try:
            return open(self.ssh_ca() + ".pub").read()
        except Exception:  # noqa: BLE001  (ssh-keygen fehlt: keine SSH-Zertifikate)
            return ""

    def ssh_cert(self, host, name, publine, life, src):
        """SSH-Benutzerzertifikat für wenige Minuten: Prinzipal keyleash-NAME, Schlüssel-ID = Host."""
        import tempfile
        principal = f"keyleash-{name}"
        serial = secrets.randbits(63)
        with tempfile.TemporaryDirectory() as d:
            pf = os.path.join(d, "k.pub")
            write(pf, publine + "\n", 0o644)
            subprocess.run(["ssh-keygen", "-q", "-s", self.ssh_ca(), "-I", host, "-n", principal,
                            "-V", f"-30s:+{life}s", "-z", str(serial), pf], check=True, capture_output=True)
            cert = open(os.path.join(d, "k-cert.pub")).read()
        # Ausgestellte Seriennummern merken: nach einer Entsperrung bleiben die Zertifikate aus der
        # Zeit vor der Sperre widerrufen (Spalten: Host, Serial, gültig bis, ausgestellt – Unix-Zeit)
        with LOCK, open(os.path.join(state_dir("server"), "ssh-serials.tsv"), "a") as f:
            f.write(f"{host}\t{serial}\t{int(time.time()) + life}\t{time.time():.3f}\n")
        self.siem.log("kurzzertifikat_ausgestellt", host, src, name=name, laufzeit_s=life, serial=hex(serial), typ="ssh")
        return {"cert": cert, "ca": open(self.ssh_ca() + ".pub").read(), "lifetime": life, "principal": principal}

    def ticket(self, req, src):
        host = req["host"]
        h = self.state.hosts.get(host)
        if not h:
            raise Denied("unbekanntes_system", "alarm")
        n = self.state.nonces.pop(req.get("nonce", ""), None)
        if not n or n[0] != host or n[1] < time.time():
            raise Denied("nonce_ungueltig_replay", "alarm")
        ak = ts.parse_tpm2b_public(b64d(h["ak_pub"]))
        raw = b64d(req["quote_attest"])
        verify_rsa(ak, raw, b64d(req["quote_sig"]))
        q = ts.parse_attest(raw)
        if q.type != ts.TPM_ST_ATTEST_QUOTE or q.extra.hex() != req["nonce"]:
            raise Denied("quote_ungueltig", "alarm")
        last = h["last"]
        now = time.time()
        ctx = {"clock": q.clock, "reset": q.reset_count}

        # 1. Sperre
        if h["revoked"]:
            raise Denied("system_gesperrt", "warn", **ctx)
        # 2. Netzsegment
        ip = ipaddress.ip_address(src)
        if self.cidrs and not any(ip in c for c in self.cidrs):
            raise Denied("unerwartetes_netzsegment", "alarm", **ctx)
        # 3. Boot-Zustand
        if q.pcr_digest.hex() != h["pcr_digest"]:
            if h.get("rebaseline"):
                self.siem.log("referenz_aktualisiert", host, src, "warn",
                              alt=h["pcr_digest"], neu=q.pcr_digest.hex())
                h["pcr_digest"] = q.pcr_digest.hex()
                h["rebaseline"] = False
            else:
                raise Denied("pcr_abweichung_manipulation", "alarm", **ctx,
                             erwartet=h["pcr_digest"], gemeldet=q.pcr_digest.hex())
        # 4. Uhr/Zähler laufen rückwärts -> Replay, Snapshot oder geklontes TPM.
        #    resetCount fällt nie, und innerhalb eines Systemstarts läuft clock
        #    nur vorwärts. Beides zusammen ist ein zweiter, älterer TPM-Zustand.
        if q.reset_count < last["reset"] or (q.reset_count == last["reset"] and q.clock < last["clock"]):
            raise Denied("tpm_zaehler_ruecklaeufig", "alarm", **ctx, zuletzt=last)
        pin = False
        # 4a. Neuer Systemstart, clock liegt unter dem zuletzt gesehenen Wert, das TPM
        #     meldet aber safe = YES. Nach Spezifikation darf das nicht vorkommen
        #     (safe = YES heißt: kein größerer Wert wurde je gemeldet). Ursachen:
        #     älterer Zustand, der mehrfach neu gestartet wurde (Klon), oder ein
        #     Software-TPM, das seine Uhr nach hartem Abbruch zu früh als gesichert meldet.
        if q.reset_count > last["reset"] and q.clock < last["clock"] and q.safe:
            if self.args.clock_rollback == "deny":
                raise Denied("tpm_uhr_ruecksprung", "alarm", **ctx, zuletzt=last)
            self.siem.log("tpm_uhr_ruecksprung", host, src, "alarm", **ctx,
                          zuletzt_clock=last["clock"], zuletzt_reset=last["reset"])
            pin = True
        # 4b. Uhr unsicher (Stromausfall): Ticket nur für diesen Systemstart
        if not q.safe:
            if self.args.unsafe_clock == "deny":
                raise Denied("tpm_uhr_unsicher", "alarm", **ctx)
            self.siem.log("tpm_uhr_unsicher", host, src, "warn", **ctx)
            pin = True
        # 4c. Gang der TPM-Uhr gegen die Serveruhr (gleicher Systemstart, kein Ruhezustand).
        #     Steht oder springt sie, lief der Zustand woanders weiter oder wurde
        #     angehalten: VM-Snapshot, Klon, Migration. Nur Alarm, keine Verweigerung.
        if (last["ts"] and q.reset_count == last["reset"]
                and q.restart_count == last.get("restart", q.restart_count)):
            wall = now - last["ts"]
            tick = (q.clock - last["clock"]) / 1000
            if abs(tick - wall) > max(self.args.clock_tolerance, wall * self.args.clock_drift):
                self.siem.log("tpm_uhr_abweichung", host, src, "warn", **ctx,
                              tpm_s=round(tick, 1), wand_s=round(wall, 1))
        # 5. Häufigkeit: parallele Instanz oder Umgehungsversuch
        if now - last["ts"] < self.args.min_interval:
            raise Denied("anfrage_zu_haeufig_parallel", "alarm", **ctx,
                         abstand_s=round(now - last["ts"], 1))
        # 6. Ungewöhnlich viele Neustarts seit dem letzten Ticket
        if last["ts"] and q.reset_count - last["reset"] > self.args.max_resets:
            self.siem.log("viele_neustarts", host, src, "alarm",
                          neustarts=q.reset_count - last["reset"])
        # 7. Betriebsfenster (Alarm, keine Verweigerung)
        if not in_window(self.args.window):
            self.siem.log("ausserhalb_betriebsfenster", host, src, "warn", fenster=self.args.window)

        # 8. Signaturzählung: Menge und Zwecke seit der letzten Erneuerung
        sig_count, sig_purposes = self.check_signatures(host, h, req, src)

        ttl = int(self.args.ttl)
        if req.get("ttl"):
            ttl = min(ttl, max(5, int(req["ttl"])))  # kürzer darf der Client immer
        expiry = q.clock + ttl * 1000
        clock_safe = bool(q.safe)
        pin_resets = pin
        max_resets = q.reset_count if pin_resets else q.reset_count + self.args.max_resets
        approved = ts.approved_policy(expiry, max_resets, self.pcrs, q.pcr_digest, clock_safe, pin_resets)
        ref = bytes.fromhex(h["policy_ref"])
        sig = self.authz.sign(approved + ref, padding.PKCS1v15(), hashes.SHA256())

        h["last"] = {"ts": now, "clock": q.clock, "reset": q.reset_count,
                     "restart": q.restart_count, "ip": src}
        h["expires_ts"] = now + ttl
        h["missed_alarm"] = False
        self.state.save()
        self.siem.log("ticket_erteilt", host, src, ttl_s=ttl, ablauf_tpm_clock=expiry,
                      max_reset_count=max_resets, uhr_gesichert=clock_safe,
                      nur_dieser_start=pin_resets, signaturen=sig_count,
                      signaturzwecke=sig_purposes, **ctx)
        purpose_tickets = self.purpose_tickets(h, expiry, max_resets, q.pcr_digest, clock_safe, pin_resets)
        return {"purpose_tickets": purpose_tickets,
                "approved_policy": approved.hex(), "policy_ref": h["policy_ref"],
                "signature": b64e(sig), "expiry_clock": expiry, "max_resets": max_resets,
                "clock_safe": clock_safe, "pin_resets": pin_resets,
                "pcrs": self.args.pcrs, "ttl": ttl, "authz_name": self.authz_name.hex()}

    def check_signatures(self, host, h, req, src):
        """Erkennt auffällige Signaturmengen und neue Signaturzwecke.

        Grundlage ist die Zahl der Signaturen seit der letzten Erneuerung.
        Lernphase: Bis KEYLEASH_SIG_MIN_SAMPLES Meldungen vorliegen, gilt
        eine feste Obergrenze (KEYLEASH_SIG_CAP). Danach ist alles
        auffällig, was über max(Median × KEYLEASH_SIG_FACTOR,
        KEYLEASH_SIG_MIN_ALARM) liegt. Auffällige Werte fließen nicht in die
        Referenz ein. Mit KEYLEASH_SIG_DENY=1 wird das Ticket verweigert.
        """
        if req.get("sig_count") is None:
            return None, None
        count = int(req["sig_count"])
        purposes = {str(k): int(v) for k, v in (req.get("sig_purposes") or {}).items()}
        hist = h.setdefault("sig_hist", [])
        known = h.setdefault("sig_purposes_known", [])
        first = h.setdefault("sig_purpose_first", {})
        now = time.time()
        new = sorted(p for p in purposes if p not in known)
        if new and (hist or known):
            self.siem.log("neuer_signaturzweck", host, src, "warn", zwecke=new)
        for p in new:
            known.append(p)
            first[p] = now
        accept = h.pop("sig_accept_next", False)
        window_alarm = self.check_new_purpose_window(host, h, purposes, now, accept, src)

        if accept:
            anomaly, limit, median = False, None, None
        elif len(hist) >= self.args.sig_min_samples:
            median = sorted(hist)[len(hist) // 2]
            limit = max(self.args.sig_min_alarm, median * self.args.sig_factor)
            anomaly = count > limit
        else:
            median, limit = None, self.args.sig_cap
            anomaly = count > limit
        if anomaly:
            if not window_alarm:   # schon gemeldet: kein zweiter Alarm für dieselbe Serie
                details = {"gemeldet": count, "grenze": limit, "median": median, "zwecke": purposes}
                if self.args.sig_deny:
                    raise Denied("signaturvolumen_auffaellig", "alarm", **details)
                self.siem.log("signaturvolumen_auffaellig", host, src, "alarm", **details)
        elif not window_alarm:
            hist.append(count)
            del hist[:-20]
        return count, purposes

    def check_new_purpose_window(self, host, h, purposes, now, accept, src):
        """Neue Zwecke über ein Zeitfenster zählen, nicht pro Erneuerung.

        Ein Zweck gilt ab seiner ersten Meldung KEYLEASH_SIG_WINDOW Sekunden lang als neu. In dieser
        Zeit wird seine Summe über alle Erneuerungen im Fenster gebildet; über KEYLEASH_SIG_MIN_ALARM
        gibt es einen Alarm (einmal pro Zweck und Fenster). So fällt eine Serie auch dann auf, wenn sie
        sich auf mehrere Erneuerungen verteilt. Zwecke „cert-…“ zählt der Server selbst (Ausstellung).
        Grenze: Die Zählung meldet der Agent selbst; root auf dem System kann sie fälschen.
        """
        win = self.args.sig_window
        pwin = [e for e in h.get("sig_pwin", []) if e[0] > now - win]
        if not accept:
            pwin += [[now, p, n] for p, n in purposes.items() if n > 0]
        h["sig_pwin"] = pwin
        first = h.get("sig_purpose_first", {})
        palarm = h.setdefault("sig_palarm", {})
        hits = {}
        for p in purposes:
            if p.startswith("cert-") or p not in first or now - first[p] > win:
                continue
            total = sum(e[2] for e in pwin if e[1] == p)
            if total > self.args.sig_min_alarm and palarm.get(p, 0) < now:
                hits[p] = total
                palarm[p] = now + win
        if not hits:
            return False
        details = {"zwecke": hits, "grenze": self.args.sig_min_alarm, "fenster_s": int(win), "neuer_zweck": True}
        if self.args.sig_deny:
            raise Denied("signaturvolumen_auffaellig", "alarm", **details)
        self.siem.log("signaturvolumen_auffaellig", host, src, "alarm", **details)
        return True

    # ---- Signaturdienst für Systeme ohne TPM (NetHSM) ---------------------

    def remote_nonce(self, req, src):
        h = self.state.hosts.get(req["host"])
        if not h or not h.get("remote"):
            raise Denied("kein_remote_system", "alarm")
        n = secrets.token_bytes(16).hex()
        now = time.time()
        self.state.remote_nonces = {k: v for k, v in self.state.remote_nonces.items() if v[1] > now}
        self.state.remote_nonces[n] = (req["host"], now + 30)
        return {"nonce": n}

    def remote_sign(self, req, src):
        """Signieren im Auftrag eines Systems ohne TPM. Reihenfolge der Prüfungen: bekannt, gesperrt,
        Absender, Nonce, Anmeldesignatur, Zweck, Betriebsfenster, Menge (vom Server gezählt)."""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        host, purpose, digest_hex = req["host"], str(req["purpose"]), str(req["digest"]).lower()
        h = self.state.hosts.get(host)
        if not h or not h.get("remote"):
            raise Denied("kein_remote_system", "alarm")
        if h["revoked"]:
            raise Denied("system_gesperrt")
        if h.get("ip") and src != h["ip"]:
            raise Denied("remote_absender_falsch", "alarm", erwartet=h["ip"])
        n = self.state.remote_nonces.pop(req.get("nonce", ""), None)
        if not n or n[0] != host or n[1] < time.time():
            raise Denied("nonce_ungueltig_replay", "alarm")
        if len(digest_hex) != 64 or any(c not in "0123456789abcdef" for c in digest_hex):
            raise ValueError("digest")
        pub = serialization.load_pem_public_key(h["client_pub"].encode())
        if not isinstance(pub, ed25519.Ed25519PublicKey):
            raise Denied("remote_anmeldung_falsch", "alarm")
        try:
            pub.verify(b64d(req["sig"]), kremote.request_message(host, purpose, req["nonce"], digest_hex))
        except Exception:
            raise Denied("remote_anmeldung_falsch", "alarm")
        p = h["purposes"].get(purpose)
        if not p:
            raise Denied("remote_zweck_unbekannt", "alarm", zweck=purpose)
        if not in_window(self.args.window):
            raise Denied("ausserhalb_betriebsfenster", "alarm")
        now = time.time()
        win = [e for e in h.get("rsig", []) if e[0] > now - self.args.sig_window]
        used = sum(1 for e in win if e[1] == purpose)
        if used >= self.args.remote_limit:
            h["rsig"] = win
            raise Denied("remote_menge_ueberschritten", "alarm", zweck=purpose, grenze=self.args.remote_limit,
                         fenster_s=int(self.args.sig_window))
        t0 = time.time()
        try:
            sig = self.remote.sign(p["kid"], bytes.fromhex(digest_hex))
        except Exception as e:   # NetHSM gesperrt, nicht erreichbar oder falsche Antwort
            raise Denied("remote_signieren_fehlgeschlagen", "alarm", fehler=str(e)[:200])
        ms = int((time.time() - t0) * 1000)
        win.append([now, purpose])
        h["rsig"] = win
        h["last"] = {"ts": now, "ip": src}
        self.state.save()
        self.siem.log("remote_signiert", host, src, zweck=purpose, anzahl_fenster=used + 1,
                      grenze=self.args.remote_limit, schluessel=self.remote.where, dauer_ms=ms)
        return {"signature": b64e(sig), "cert": p["cert"], "count": used + 1, "limit": self.args.remote_limit}

    def remote_add(self, req, src):
        """Admin: System ohne TPM eintragen. Die Schlüssel legt tools/remote-setup.py vorher an."""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        host = req["host"]
        if host in self.state.hosts and not self.state.hosts[host].get("remote"):
            raise Denied("unbekannte_aktion")   # TPM-System nicht überschreiben
        pub = serialization.load_pem_public_key(req["client_pub"].encode())
        if not isinstance(pub, ed25519.Ed25519PublicKey):
            raise ValueError("client_pub: Ed25519")
        if req.get("ip"):
            ipaddress.ip_address(req["ip"])
        purposes = {}
        for purpose in req["purposes"]:
            kid = kremote.key_id(host, purpose)
            kpub = self.remote.public(kid)
            now = dt.datetime.now(dt.timezone.utc)
            cert = (x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host),
                                             x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                                                                f"keyleash remote: {purpose}")]))
                    .issuer_name(self.ca_cert.subject).public_key(kpub)
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - dt.timedelta(minutes=5))
                    .not_valid_after(now + dt.timedelta(days=365))
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                                   critical=True)
                    .sign(self.ca, hashes.SHA256()))
            purposes[purpose] = {"kid": kid, "cert": cert.public_bytes(serialization.Encoding.PEM).decode()}
        old = self.state.hosts.get(host, {})
        self.state.hosts[host] = {"remote": True, "client_pub": req["client_pub"], "ip": req.get("ip") or None,
                                  "purposes": purposes, "revoked": old.get("revoked", False), "expires_ts": None,
                                  "missed_alarm": False, "last": old.get("last"), "rsig": old.get("rsig", [])}
        self.state.save()
        self.siem.log("remote_eingerichtet", host, src, "warn", zwecke=sorted(purposes), ip=req.get("ip"),
                      schluessel=self.remote.where)
        return {"ok": True, "purposes": purposes, "ca": self.ca_cert.public_bytes(serialization.Encoding.PEM).decode()}

    # ---- Verwaltung -------------------------------------------------------

    def admin(self, action, req, src):
        if not ipaddress.ip_address(src).is_loopback:
            raise Denied("admin_nur_lokal", "alarm")
        if action == "remote-add":
            return self.remote_add(req, src)
        if action == "hosts":
            return {k: {kk: v[kk] for kk in ("revoked", "rebaseline", "last", "expires_ts",
                                               "cert_serial", "pcr_digest", "sig_hist")
                        if kk in v}
                    for k, v in self.state.hosts.items()}
        host = req["host"]
        h = self.state.hosts.get(host)
        if not h:
            raise Denied("unbekanntes_system")
        if action == "revoke":
            h["revoked"] = True
        elif action == "unrevoke":
            h["revoked"] = False
        elif action == "rebaseline":
            h["rebaseline"] = True
        elif action == "sigreset":
            h["sig_hist"] = []
            h["sig_accept_next"] = True
            h.pop("rsig", None)
            for k in ("sig_purposes_known", "sig_purpose_first", "sig_pwin", "sig_palarm"):
                h.pop(k, None)
        elif action == "forget":
            del self.state.hosts[host]
        else:
            raise Denied("unbekannte_aktion")
        self.state.save()
        self.siem.log(f"admin_{action}", host, src, "warn")
        hook = self.run_hook(action, host, src) if action in ("revoke", "unrevoke") else None
        return {"ok": True, "hook": hook} if hook else {"ok": True}

    def run_hook(self, action, host, src):
        """Sperr-Hook: Gegenstellen sofort informieren (z. B. Datenbankkonto sperren, Sitzungen beenden).

        KEYLEASH_REVOKE_HOOK="tools/webdemo.sh hook" wird als  HOOK revoke|unrevoke HOST  aufgerufen.
        Ohne Hook bleibt es beim Prinzip: keine neuen Tickets/Zertifikate, Wirkung mit Ablauf.
        """
        cmd = cfg("KEYLEASH_REVOKE_HOOK")
        if not cmd:
            return None
        argv = shlex.split(cmd)
        if not os.path.isabs(argv[0]) and os.path.exists(os.path.join(LAB_ROOT, argv[0])):
            argv = ["bash" if argv[0].endswith(".sh") else sys.executable, os.path.join(LAB_ROOT, argv[0])] + argv[1:]
        t0 = time.time()
        try:
            r = subprocess.run(argv + [action, host], capture_output=True, text=True, timeout=20, cwd=LAB_ROOT)
            ok, out = r.returncode == 0, (r.stdout + r.stderr).strip()[-300:]
        except Exception as e:  # noqa: BLE001
            ok, out = False, str(e)
        ms = int((time.time() - t0) * 1000)
        self.siem.log("sperr_hook" if ok else "sperr_hook_fehler", host, src, "info" if ok else "alarm",
                      aktion=action, dauer_ms=ms, ausgabe=out)
        return {"ok": ok, "ms": ms, "output": out}

    # ---- Herzschlag-Überwachung -------------------------------------------

    def watchdog(self):
        while True:
            time.sleep(2)
            with LOCK:
                now = time.time()
                for host, h in self.state.hosts.items():
                    if (h["expires_ts"] and not h["revoked"] and not h["missed_alarm"]
                            and now > h["expires_ts"] + self.args.grace):
                        h["missed_alarm"] = True
                        self.siem.log("erneuerung_ausgeblieben", host, h["last"]["ip"], "alarm",
                                      seit_s=round(now - h["last"]["ts"]))
                self.state.save()


def make_handler(srv: Server):
    routes = {"/enroll/start": srv.enroll_start, "/enroll/finish": srv.enroll_finish,
              "/ticket/nonce": srv.nonce, "/ticket": srv.ticket,
              "/enroll/purpose": srv.enroll_purpose,
              "/cert/nonce": srv.cert_nonce, "/cert/short": srv.short_cert,
              "/remote/nonce": srv.remote_nonce, "/remote/sign": srv.remote_sign}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def reply(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            src = self.client_address[0]
            try:
                if self.path == "/authz":
                    return self.reply(200, {
                        "authz_name": srv.authz_name.hex(), "pcrs": srv.args.pcrs,
                        "authz_pub": open(os.path.join(srv.state.dir, "authz_pub.pem")).read(),
                        "ca": srv.ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
                        "ssh_ca": srv.ssh_ca_pub()})
                if self.path == "/admin/hosts":
                    with LOCK:
                        return self.reply(200, srv.admin("hosts", {}, src))
                self.reply(404, {"error": T("nicht gefunden", "not found")})
            except Denied as d:
                self.reply(403, {"error": code(d.reason)})

        def do_POST(self):
            src = self.client_address[0]
            try:
                n = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                return self.reply(400, {"error": code("ungueltiges_json")})
            host = req.get("host")
            try:
                with LOCK:
                    if self.path.startswith("/admin/"):
                        return self.reply(200, srv.admin(self.path[7:], req, src))
                    fn = routes.get(self.path)
                    if not fn:
                        return self.reply(404, {"error": T("nicht gefunden", "not found")})
                    return self.reply(200, fn(req, src))
            except Denied as d:
                ev = "ticket_verweigert" if self.path == "/ticket" else "anfrage_verweigert"
                srv.siem.log(ev, host, src, d.severity, grund=d.reason, pfad=self.path, **d.details)
                self.reply(403, {"error": code(d.reason)})
            except (KeyError, ValueError) as e:
                srv.siem.log("anfrage_fehlerhaft", host, src, "warn", fehler=str(e), pfad=self.path)
                self.reply(400, {"error": T(f"fehlerhaft: {e}", f"malformed: {e}")})

    return H


def main():
    ap = argparse.ArgumentParser(description=T("keyleash Autorisierungsserver (Lab)", "keyleash authorisation server (lab)"))
    ap.add_argument("--listen", default=cfg("KEYLEASH_LISTEN", "127.0.0.1:8740"))
    ap.add_argument("--ttl", type=int, default=int(cfg("KEYLEASH_TTL", "600")),
                    help=T("Ticket-Laufzeit in Sekunden (TPM-Uhr)", "ticket lifetime in seconds (TPM clock)"))
    ap.add_argument("--shortcert-max", type=int, default=int(cfg("KEYLEASH_SHORTCERT_MAX", "600")),
                    help=T("längste Laufzeit für Kurzzeit-Zertifikate (s)", "longest lifetime for short-lived certificates (s)"))
    ap.add_argument("--max-resets", type=int, default=int(cfg("KEYLEASH_MAX_RESETS", "2")),
                    help=T("erlaubte Neustarts pro Ticket", "reboots allowed per ticket"))
    ap.add_argument("--min-interval", type=float, default=float(cfg("KEYLEASH_MIN_INTERVAL", "5")),
                    help=T("Mindestabstand zwischen Anfragen eines Systems (s)", "minimum interval between requests from one host (s)"))
    ap.add_argument("--unsafe-clock", choices=("pin", "deny"), default=cfg("KEYLEASH_UNSAFE_CLOCK", "pin"),
                    help=T("TPM meldet safe = NO: pin = Ticket nur für diesen Systemstart, deny = verweigern",
                           "TPM reports safe = NO: pin = ticket for this boot only, deny = refuse"))
    ap.add_argument("--clock-rollback", choices=("pin", "deny"), default=cfg("KEYLEASH_CLOCK_ROLLBACK", "pin"),
                    help=T("clock nach Neustart unter letztem Wert trotz safe = YES: pin = Alarm und Ticket nur für "
                           "diesen Systemstart, deny = verweigern",
                           "clock below the last value after a reboot despite safe = YES: pin = alert and ticket "
                           "for this boot only, deny = refuse"))
    ap.add_argument("--clock-tolerance", type=float, default=float(cfg("KEYLEASH_CLOCK_TOLERANCE", "30")),
                    help=T("erlaubte Abweichung TPM-Uhr zu Serveruhr zwischen zwei Erneuerungen (s)",
                           "allowed difference between TPM clock and server clock between two renewals (s)"))
    ap.add_argument("--clock-drift", type=float, default=float(cfg("KEYLEASH_CLOCK_DRIFT", "0.05")),
                    help=T("zusätzlich erlaubte relative Abweichung (Anteil)", "additionally allowed relative difference (fraction)"))
    ap.add_argument("--grace", type=float, default=float(cfg("KEYLEASH_GRACE", "10")),
                    help=T("Toleranz, bevor ausbleibende Erneuerung alarmiert (s)", "grace period before a missed renewal raises an alert (s)"))
    ap.add_argument("--pcrs", default=cfg("KEYLEASH_PCRS", "sha256:7,16"))
    ap.add_argument("--allowed-cidrs", default=cfg("KEYLEASH_ALLOWED_CIDRS",
                                                   "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"))
    ap.add_argument("--window", default=cfg("KEYLEASH_WINDOW", "00:00-24:00"),
                    help=T("Betriebsfenster, z. B. 06:00-22:00", "operating window, e.g. 06:00-22:00"))
    ap.add_argument("--enroll-token", default=cfg("KEYLEASH_ENROLL_TOKEN", "lab-enroll"))
    ap.add_argument("--syslog", action="store_true", default=cfg("KEYLEASH_SYSLOG") == "1")
    ap.add_argument("--approval", default=cfg("KEYLEASH_APPROVAL", "release=state/approver/release_pub.pem"),
                    help=T("Zwecke mit Freigabepflicht: zweck=pfad/zum/oeffentlichen_schluessel.pem,…", "purposes requiring approval: purpose=path/to/public_key.pem,…"))
    ap.add_argument("--sig-factor", type=float, default=float(cfg("KEYLEASH_SIG_FACTOR", "5")),
                    help=T("Vielfaches des Medians, ab dem eine Signaturmenge auffällt", "multiple of the median above which a signature volume is flagged"))
    ap.add_argument("--sig-min-alarm", type=int, default=int(cfg("KEYLEASH_SIG_MIN_ALARM", "10")),
                    help=T("Mindestmenge, ab der überhaupt alarmiert wird", "minimum volume before any alert is raised"))
    ap.add_argument("--sig-min-samples", type=int, default=int(cfg("KEYLEASH_SIG_MIN_SAMPLES", "3")),
                    help=T("Meldungen, bevor der Median als Referenz gilt", "reports needed before the median is used as baseline"))
    ap.add_argument("--sig-cap", type=int, default=int(cfg("KEYLEASH_SIG_CAP", "100")),
                    help=T("feste Obergrenze in der Lernphase", "fixed upper limit during the learning phase"))
    ap.add_argument("--sig-window", type=float, default=float(cfg("KEYLEASH_SIG_WINDOW", "3600")),
                    help=T("Zeitfenster in Sekunden, in dem neue Zwecke summiert werden", "time window in seconds over which new purposes are summed"))
    ap.add_argument("--remote-limit", type=int, default=int(cfg("KEYLEASH_REMOTE_LIMIT", "10")),
                    help=T("Signaturdienst: höchstens so viele Signaturen je System und Zweck im Zeitfenster",
                           "signing service: at most this many signatures per host and purpose within the time window"))
    ap.add_argument("--sig-deny", action="store_true", default=cfg("KEYLEASH_SIG_DENY") == "1",
                    help=T("Ticket bei auffälliger Signaturmenge verweigern statt nur alarmieren", "deny the ticket on an anomalous signature volume instead of only alerting"))
    args = ap.parse_args()

    srv = Server(args)
    threading.Thread(target=srv.watchdog, daemon=True).start()
    host, port = args.listen.rsplit(":", 1)
    httpd = ThreadingHTTPServer((host, int(port)), make_handler(srv))
    print(T(f"keyleash Autorisierungsserver auf http://{args.listen}  "
            f"(TTL {args.ttl}s, Neustarts/Ticket {args.max_resets}, PCR {args.pcrs})",
            f"keyleash authorisation server on http://{args.listen}  "
            f"(TTL {args.ttl}s, reboots/ticket {args.max_resets}, PCR {args.pcrs})"), flush=True)
    print(T("Authz-Schlüsselname: ", "authz key name: ") + srv.authz_name.hex(), flush=True)
    print(T("SIEM-Log: ", "SIEM log: ") + srv.siem.path, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
