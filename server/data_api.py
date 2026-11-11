#!/usr/bin/env python3
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""keyleash Daten-Schnittstelle (Lab): Statistiken und Protokolle nur für Maschinen mit gültigem Ticket.

Die geschützte Anwendung (Dashboard auf labbox-1) meldet sich hier mit ihrer
Maschinenidentität an: Sie holt eine Einmal-Nonce, lässt sie vom TPM signieren
und schickt Signatur und Zertifikat. Diese Schnittstelle weiß nichts von Tickets
oder Sperren. Sie prüft nur, was jede Gegenstelle prüfen würde: Zertifikat von
der keyleash-CA, Signatur über die frische Nonce. Ob signiert werden darf,
entscheidet allein das TPM der Maschine.

  data_api.py [--listen 0.0.0.0:8741]
"""
import argparse
import collections
import datetime as dt
import json
import os
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(LAB, "lib"))
from kl.common import cfg, b64d  # noqa: E402
from kl.i18n import T, code, fields, canonical  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402

SDIR = os.path.join(cfg("KEYLEASH_STATE", os.path.join(LAB, "state")), "server")
SIEM = os.path.join(SDIR, "siem.jsonl")
LOCK = threading.Lock()
NONCES = {}  # nonce -> Ablauf


def siem(event, host, src, severity="info", **details):
    rec = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
           "event": code(event), "severity": severity, "host": host, "src_ip": src}
    rec.update(fields(details))
    with LOCK, open(SIEM, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


class Refused(Exception):
    pass


def check(req):
    """Zertifikat der keyleash-CA + Signatur über eine frische, unbenutzte Nonce."""
    nonce = req.get("nonce", "")
    with LOCK:
        exp = NONCES.pop(nonce, 0)
    if exp < time.time():
        raise Refused("nonce_ungueltig_replay")
    ca = x509.load_pem_x509_certificate(open(os.path.join(SDIR, "ca_cert.pem"), "rb").read())
    try:
        cert = x509.load_pem_x509_certificate(req["cert"].encode())
        if cert.issuer != ca.subject:
            raise ValueError
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                               padding.PKCS1v15(), cert.signature_hash_algorithm)
        now = dt.datetime.now(dt.timezone.utc)
        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=dt.timezone.utc)
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=dt.timezone.utc)
        if not (nb <= now <= na):
            raise ValueError
    except Exception:
        raise Refused("zertifikat_ungueltig")
    host = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    try:
        cert.public_key().verify(b64d(req["signature"]), nonce.encode(),
                                 padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        raise Refused("signatur_ungueltig")
    return host


def stats():
    recs = []
    if os.path.exists(SIEM):
        with open(SIEM) as f:
            for line in f:
                try:
                    recs.append(json.loads(line))
                except ValueError:
                    pass
    now = dt.datetime.now(dt.timezone.utc)
    day = [r for r in recs if dt.datetime.fromisoformat(r["ts"]) > now - dt.timedelta(hours=24)]
    by_event = collections.Counter(canonical(r["event"]) for r in day)
    hourly = collections.Counter()
    for r in day:
        if canonical(r["event"]) == "ticket_erteilt":
            age = int((now - dt.datetime.fromisoformat(r["ts"])).total_seconds() // 3600)
            if age < 12:
                hourly[age] += 1
    hosts = {}
    hp = os.path.join(SDIR, "hosts.json")
    if os.path.exists(hp):
        for name, h in json.load(open(hp)).items():
            hosts[name] = {"revoked": h.get("revoked", False),
                           "last_renewal": h.get("last", {}).get("ts", 0),
                           "expires_ts": h.get("expires_ts", 0),
                           "last_ip": h.get("last", {}).get("ip")}
    return {"generated": now.isoformat(timespec="seconds"),
            "events_24h": dict(by_event),
            "alarms_24h": sum(1 for r in day if r.get("severity") == "alarm"),
            "tickets_per_hour": [hourly.get(i, 0) for i in range(11, -1, -1)],
            "hosts": hosts,
            "recent": [dict(r, event=canonical(r["event"])) for r in recs[-40:]][::-1]}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/challenge":
            n = secrets.token_hex(32)
            with LOCK:
                now = time.time()
                for k in [k for k, v in NONCES.items() if v < now]:
                    del NONCES[k]
                NONCES[n] = now + 30
            return self.reply(200, {"nonce": n})
        self.reply(404, {"error": code("nicht gefunden")})

    def do_POST(self):
        src = self.client_address[0]
        if self.path != "/data":
            return self.reply(404, {"error": code("nicht gefunden")})
        try:
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            host = check(req)
        except Refused as e:
            siem("datenzugriff_verweigert", None, src, "warn", grund=str(e))
            return self.reply(403, {"error": code(str(e))})
        except Exception:
            return self.reply(400, {"error": code("ungueltiges_json")})
        siem("datenzugriff", host, src)
        self.reply(200, stats())


def main():
    ap = argparse.ArgumentParser(description=T("keyleash Daten-Schnittstelle (Lab)", "keyleash data API (lab)"))
    ap.add_argument("--listen", default=cfg("KEYLEASH_DATA_LISTEN", "0.0.0.0:8741"))
    a = ap.parse_args()
    host, port = a.listen.rsplit(":", 1)
    print(T(f"keyleash Daten-Schnittstelle auf http://{a.listen} (Anmeldung nur mit Maschinenidentität)",
            f"keyleash data API on http://{a.listen} (machine identity required)"), flush=True)
    ThreadingHTTPServer((host, int(port)), H).serve_forever()


if __name__ == "__main__":
    main()
