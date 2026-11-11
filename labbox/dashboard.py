#!/usr/bin/env python3
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""keyleash Dashboard – die geschützte Anwendung auf labbox-1.

Zeigt Statistiken und Protokolle des keyleash-Servers. Die Daten bekommt es nur,
wenn es sich mit der Maschinenidentität anmeldet: Nonce holen, vom TPM signieren
lassen (agent.py sign, braucht ein gültiges Ticket), Signatur + Zertifikat senden.
Ohne gültiges Ticket signiert das TPM nicht, und das Dashboard bleibt leer.

  dashboard.py [--listen 0.0.0.0:8080] [--data http://GMKBOX:8741]
"""
import argparse
import html
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(LAB, "lib"))
from kl.common import cfg, b64e  # noqa: E402
from kl.i18n import T  # noqa: E402

CACHE_S = 10
_cache = {"t": 0, "data": None, "err": None, "signed_at": None}
_lock = threading.Lock()


def fetch(data_url):
    """Anmeldung mit der Maschinenidentität und Abruf der Daten."""
    with urllib.request.urlopen(data_url + "/challenge", timeout=5) as r:
        nonce = json.load(r)["nonce"]
    with tempfile.TemporaryDirectory(prefix="kl-dash-") as d:
        nf, sf = os.path.join(d, "nonce"), os.path.join(d, "sig")
        open(nf, "w").write(nonce)
        p = subprocess.run([sys.executable, os.path.join(LAB, "agent", "agent.py"), "sign", nf, "-o", sf,
                            "--purpose", "dashboard"], capture_output=True, text=True, timeout=60)
        if p.returncode != 0:
            msg = [l.strip(" ✘") for l in (p.stdout + p.stderr).splitlines() if l.strip()]
            raise RuntimeError(T("TPM verweigert die Signatur: ", "TPM refuses to sign: ") + (msg[-1] if msg else "?"))
        sig = open(sf, "rb").read()
    cert = open(os.path.join(cfg("KEYLEASH_STATE", os.path.join(LAB, "state")), "agent", "cert.pem")).read()
    body = json.dumps({"nonce": nonce, "signature": b64e(sig), "cert": cert}).encode()
    req = urllib.request.Request(data_url + "/data", body, {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(T("Datenquelle lehnt ab: ", "data source refuses: ") + e.read().decode(errors="replace"))


def get(data_url):
    with _lock:
        if time.time() - _cache["t"] > CACHE_S:
            try:
                _cache.update(data=fetch(data_url), err=None, signed_at=time.strftime("%H:%M:%S"))
            except Exception as e:
                _cache.update(data=None, err=str(e))
            _cache["t"] = time.time()
        return dict(_cache)


def ticket_info():
    try:
        t = json.load(open(os.path.join(cfg("KEYLEASH_STATE", os.path.join(LAB, "state")), "agent", "ticket.json")))
        return t.get("ttl"), t.get("clock_safe"), t.get("pin_resets")
    except Exception:
        return None, None, None


CSS = """
:root{--bg:#f7f6f2;--card:#fff;--ink:#1d1f1e;--muted:#5d625f;--line:#e2e0d8;--acc:#1f4d3f;--soft:#e5efe9;--ok:#2f6b45;--bad:#b3261e;--badsoft:#fbe9e7;--warn:#9a6700}
@media (prefers-color-scheme:dark){:root{--bg:#141716;--card:#1b1f1d;--ink:#e6e8e6;--muted:#9aa29d;--line:#2c322f;--acc:#8fc7ad;--soft:#1f2d27;--ok:#8fc7ad;--bad:#f2b8b5;--badsoft:#3a1f1d;--warn:#e3b341}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:20px 16px 40px}
h1{font:700 26px/1.2 ui-monospace,Menlo,monospace;margin:0 0 4px}h1 span{color:var(--acc)}
.sub{color:var(--muted);margin:0 0 18px}
.banner{border-radius:10px;padding:14px 16px;margin:0 0 18px;border:1px solid var(--line)}
.banner.ok{background:var(--soft);border-color:var(--ok)}.banner.bad{background:var(--badsoft);border-color:var(--bad)}
.banner b{display:block;font-size:16px;margin-bottom:2px}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:0 0 18px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kpi .v{font:700 26px/1.1 ui-monospace,Menlo,monospace}.kpi .l{color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:0 0 18px;overflow-x:auto}
h2{font:600 13px/1.3 ui-monospace,Menlo,monospace;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 10px}
table{border-collapse:collapse;width:100%;font-size:13.5px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}td.mono{font-family:ui-monospace,Menlo,monospace;font-size:12.5px;white-space:nowrap}td.det{white-space:normal;word-break:break-word}
.sev-alarm{color:var(--bad);font-weight:600}.sev-warn{color:var(--warn);font-weight:600}
.bars{display:flex;align-items:flex-end;gap:6px;height:90px}.bars div{flex:1;background:var(--acc);border-radius:3px 3px 0 0;min-height:2px;opacity:.85}
.axis{display:flex;gap:6px;color:var(--muted);font-size:11px}.axis span{flex:1;text-align:center}
@media (max-width:640px){.kpis{grid-template-columns:repeat(2,1fr)}}
"""


def page(c, host):
    d, err = c["data"], c["err"]
    ttl, safe, pinned = ticket_info()
    e = html.escape
    out = [f"<!doctype html><html lang='{T('de', 'en')}'><head><meta charset='utf-8'>"
           "<meta name='viewport' content='width=device-width,initial-scale=1'><meta http-equiv='refresh' content='10'>"
           f"<title>keyleash Dashboard</title><style>{CSS}</style></head><body><div class='wrap'>"
           f"<h1>key<span>leash</span> Dashboard</h1><p class='sub'>{e(T('Geschützte Anwendung auf', 'Protected application on'))} {e(host)} · "
           f"{e(T('Daten nur mit Maschinenidentität aus dem TPM', 'data only with the machine identity from the TPM'))}</p>"]
    if err:
        out.append(f"<div class='banner bad'><b>{e(T('Keine Anmeldung möglich – Daten gesperrt', 'Sign-in not possible – data locked'))}</b>"
                   f"{e(err)}<br>{e(T('Ohne gültiges Ticket signiert das TPM nicht. Diese Anwendung bekommt deshalb keine Daten mehr.', 'Without a valid ticket the TPM does not sign. This application therefore gets no data.'))}</div>")
    else:
        extra = T("Ticket nur für diesen Systemstart (Uhr unsicher)", "ticket for this boot only (clock unsafe)") if pinned else \
            T("Ticket verlangt gesicherte TPM-Uhr", "ticket requires a safe TPM clock")
        out.append(f"<div class='banner ok'><b>{e(T('Angemeldet mit Maschinenidentität', 'Signed in with machine identity'))} {e(host)}</b>"
                   f"{e(T('TPM-Signatur über eine frische Nonce um', 'TPM signature over a fresh nonce at'))} {e(c['signed_at'] or '')} · "
                   f"{e(T('Ticket-Laufzeit', 'ticket lifetime'))} {e(str(ttl))} s · {e(extra)}</div>")
    if d:
        ev = d["events_24h"]
        kp = [(ev.get("ticket_erteilt", 0), T("Tickets (24 h)", "tickets (24 h)")),
              (ev.get("ticket_verweigert", 0), T("verweigert (24 h)", "denied (24 h)")),
              (d["alarms_24h"], T("Alarme (24 h)", "alerts (24 h)")),
              (ev.get("datenzugriff", 0), T("Datenzugriffe (24 h)", "data accesses (24 h)"))]
        out.append("<div class='kpis'>" + "".join(f"<div class='kpi'><div class='v'>{v}</div><div class='l'>{e(l)}</div></div>" for v, l in kp) + "</div>")
        tph = d["tickets_per_hour"]; mx = max(tph) or 1
        out.append(f"<div class='card'><h2>{e(T('Ausgestellte Tickets pro Stunde, letzte 12 h', 'Tickets issued per hour, last 12 h'))}</h2><div class='bars'>"
                   + "".join(f"<div title='{v}' style='height:{max(2, int(88 * v / mx))}px'></div>" for v in tph)
                   + "</div><div class='axis'>" + "".join(f"<span>{-11 + i if i < 11 else T('jetzt', 'now')}</span>" for i in range(12)) + "</div></div>")
        rows = []
        now = time.time()
        for name, h in sorted(d["hosts"].items()):
            if h["revoked"]:
                st = f"<span class='sev-alarm'>{e(T('gesperrt', 'revoked'))}</span>"
            elif h["expires_ts"] > now:
                st = e(T(f"Ticket gültig, noch {int(h['expires_ts'] - now)} s", f"ticket valid, {int(h['expires_ts'] - now)} s left"))
            else:
                st = f"<span class='sev-warn'>{e(T('kein gültiges Ticket', 'no valid ticket'))}</span>"
            last = time.strftime("%d.%m. %H:%M:%S", time.localtime(h["last_renewal"])) if h["last_renewal"] else "–"
            rows.append(f"<tr><td class='mono'>{e(name)}</td><td>{st}</td><td class='mono'>{e(last)}</td><td class='mono'>{e(str(h['last_ip'] or '–'))}</td></tr>")
        out.append(f"<div class='card'><h2>{e(T('Maschinenidentitäten', 'Machine identities'))}</h2><table><tr><th>{e(T('System', 'Host'))}</th><th>{e(T('Zustand', 'State'))}</th>"
                   f"<th>{e(T('Letzte Erneuerung', 'Last renewal'))}</th><th>{e(T('Adresse', 'Address'))}</th></tr>{''.join(rows)}</table></div>")
        rr = []
        for r in d["recent"]:
            det = {k: v for k, v in r.items() if k not in ("ts", "event", "severity", "host", "src_ip")}
            sev = r.get("severity", "info")
            rr.append(f"<tr><td class='mono'>{e(r['ts'][11:19])}</td><td class='sev-{e(sev)}'>{e(sev)}</td><td class='mono'>{e(r['event'])}</td>"
                      f"<td class='mono'>{e(str(r.get('host')))}</td><td class='mono det'>{e(json.dumps(det, ensure_ascii=False)[:160])}</td></tr>")
        out.append(f"<div class='card'><h2>{e(T('Letzte Ereignisse (SIEM)', 'Recent events (SIEM)'))}</h2><table><tr><th>UTC</th><th>{e(T('Stufe', 'Severity'))}</th>"
                   f"<th>{e(T('Ereignis', 'Event'))}</th><th>{e(T('System', 'Host'))}</th><th>Details</th></tr>{''.join(rr)}</table></div>")
    out.append(f"<p class='sub'>{e(T('Aktualisiert alle 10 s · Daten zwischengespeichert für 10 s', 'Refreshes every 10 s · data cached for 10 s'))}</p></div></body></html>")
    return "".join(out)


def main():
    ap = argparse.ArgumentParser(description="keyleash Dashboard")
    ap.add_argument("--listen", default=cfg("KEYLEASH_DASH_LISTEN", "0.0.0.0:8080"))
    ap.add_argument("--data", default=cfg("KEYLEASH_DATA_URL", "http://127.0.0.1:8741"))
    a = ap.parse_args()
    host = cfg("KEYLEASH_HOST_ID") or os.uname().nodename

    class H(BaseHTTPRequestHandler):
        def log_message(self, *x):
            pass

        def do_GET(self):
            c = get(a.data)
            if self.path == "/health":
                body = json.dumps({"ok": c["err"] is None, "error": c["err"]}).encode(); ct = "application/json"
            elif self.path in ("/", "/index.html"):
                body = page(c, host).encode(); ct = "text/html; charset=utf-8"
            else:
                self.send_response(404); self.end_headers(); return
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    h, p = a.listen.rsplit(":", 1)
    print(f"keyleash Dashboard: http://{a.listen}  ({T('Daten von', 'data from')} {a.data})", flush=True)
    ThreadingHTTPServer((h, int(p)), H).serve_forever()


if __name__ == "__main__":
    main()
