#!/usr/bin/env python3
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""keyleash Agent (Lab).

Laut Konzept nicht vertrauenswürdig: Er reicht Attestation und Tickets
nur weiter. Fälschen kann er nichts, weil das TPM die Policy erzwingt.

Befehle:
  enroll           EK/AK anlegen, Maschinenschlüssel im TPM erzeugen, Zertifikat holen
  renew [--ttl N]  Quote erstellen, Ticket holen
  loop             renew im Abstand Laufzeit/4 (Herzschlag)
  sign DATEI       Datei mit dem Maschinenschlüssel signieren (nur mit gültigem Ticket)
  status           TPM-Uhr, Neustart-Zähler, Restlaufzeit des Tickets
  shortcert NAME   Kurzzeit-Zertifikat für einen frischen Software-Schlüssel holen
                   (TPM signiert den Antrag nur mit gültigem Ticket); --loop erneuert laufend
"""
import argparse
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))

from kl import tpm  # noqa: E402
from kl import tpmstruct as ts  # noqa: E402
from kl.common import b64d, b64e, bad, cfg, get, info, ok, post, read, state_dir, write  # noqa: E402
from kl.i18n import T  # noqa: E402


def sd():
    return cfg("KEYLEASH_AGENT_STATE") or state_dir("agent")


def host_id():
    return cfg("KEYLEASH_HOST_ID") or socket.gethostname()


def die(msg):
    bad(msg)
    sys.exit(1)


# ------------------------------------------------------------------ enroll -

def enroll(args):
    s = sd()
    host = host_id()
    info(T(f"Provisionierung für '{host}' (TPM-Modus: {cfg('KEYLEASH_TPM', 'hw')})",
          f"Enrolling '{host}' (TPM mode: {cfg('KEYLEASH_TPM', 'hw')})"))
    srv = get("/authz")
    write(os.path.join(s, "authz_pub.pem"), srv["authz_pub"])
    authz_name = bytes.fromhex(srv["authz_name"])

    with tpm.Workdir() as w:
        # 1. EK und AK
        tpm.load_ek(w)
        tpm.run("tpm2_createak", "-C", w("ek.ctx"), "-c", w("ak.ctx"), "-G", "rsa", "-g", "sha256",
                "-s", "rsassa", "-u", os.path.join(s, "ak.pub"), "-r", os.path.join(s, "ak.priv"),
                "-n", w("ak.name"))
        ok(T("Attestation Key (AK) unter dem Endorsement Key erzeugt", "Attestation key (AK) created under the endorsement key"))

        r = post("/enroll/start", {"host": host, "token": cfg("KEYLEASH_ENROLL_TOKEN", "lab-enroll"),
                                   "ek_pub": b64e(read(w("ek.pub"))),
                                   "ak_pub": b64e(read(os.path.join(s, "ak.pub")))})
        if "error" in r:
            die(T("Server lehnt ab: ", "Server refuses: ") + r['error'])

        # 2. Nachweis, dass AK und EK im selben TPM liegen
        write(w("cred"), b64d(r["credential"]))
        ps = tpm.endorsement_session(w)
        tpm.run("tpm2_activatecredential", "-c", w("ak.ctx"), "-C", w("ek.ctx"), "-i", w("cred"),
                "-o", w("secret"), "-P", f"session:{ps}")
        tpm.flush(ps)
        ok(T("Credential mit dem EK entschlüsselt (AK ist TPM-resident)", "Credential decrypted with the EK (AK is TPM-resident)"))

        # 3. Maschinenschlüssel mit Policy: PolicyAuthorize(Server) + PolicyAuthValue
        ref = ts.policy_ref_for(host)
        write(w("key.policy"), ts.key_policy(authz_name, ref))
        auth = os.urandom(32).hex()
        write(os.path.join(s, "key.auth"), auth)
        tpm.load_primary(w)
        tpm.run("tpm2_create", "-C", w("primary.ctx"), "-G", "rsa2048:rsassa-sha256:null",
                "-a", "fixedtpm|fixedparent|sensitivedataorigin|sign",   # bewusst OHNE userwithauth
                "-L", w("key.policy"), "-p", f"hex:{auth}",
                "-u", os.path.join(s, "key.pub"), "-r", os.path.join(s, "key.priv"))
        tpm.run("tpm2_load", "-C", w("primary.ctx"), "-u", os.path.join(s, "key.pub"),
                "-r", os.path.join(s, "key.priv"), "-c", w("key.ctx"))
        ok(T("Maschinenschlüssel im TPM erzeugt (nicht exportierbar, nur mit Ticket nutzbar)", "Machine key created in the TPM (non-exportable, usable only with a ticket)"))

        # 4. Key Attestation und Referenz-Quote
        tpm.run("tpm2_certify", "-C", w("ak.ctx"), "-c", w("key.ctx"), "-P", "file:-",
                "-g", "sha256", "-o", w("certify.attest"), "-s", w("certify.sig"), "-f", "plain",
                stdin=f"hex:{auth}".encode())
        tpm.run("tpm2_quote", "-c", w("ak.ctx"), "-l", r["pcrs"], "-q", r["nonce"],
                "-m", w("quote.msg"), "-s", w("quote.sig"), "-f", "plain", "-g", "sha256")

        f = post("/enroll/finish", {
            "host": host, "secret": b64e(read(w("secret"))),
            "key_pub": b64e(read(os.path.join(s, "key.pub"))),
            "certify_attest": b64e(read(w("certify.attest"))), "certify_sig": b64e(read(w("certify.sig"))),
            "quote_attest": b64e(read(w("quote.msg"))), "quote_sig": b64e(read(w("quote.sig")))})
        if "error" in f:
            die(T("Server lehnt ab: ", "Server refuses: ") + f['error'])
    write(os.path.join(s, "cert.pem"), f["cert"], 0o644)
    write(os.path.join(s, "ca.pem"), f["ca"], 0o644)
    json.dump({"host": host, "pcrs": r["pcrs"], "authz_name": srv["authz_name"]},
              open(os.path.join(s, "agent.json"), "w"))
    ok(T("Zertifikat der Verwaltungs-CA erhalten: ", "Certificate received from the management CA: ") + os.path.join(s, 'cert.pem'))


# ------------------------------------------------------- Signaturzählung --
# Jede Signatur wird gezählt (gesamt, seit der letzten Meldung, je Zweck).
# Die Zahlen gehen mit jeder Erneuerung an den Server, der daraus Ausreißer
# erkennt. Im gehärteten Betrieb zählt der geschützte Signaturdienst; im
# Lab-Agent ist die Zählung selbst gemeldet und damit nur so vertrauens-
# würdig wie der Prozess, der sie führt.

def _count_path(s):
    return os.path.join(s, "sigcount.json")


def load_counts(s):
    p = _count_path(s)
    if os.path.exists(p):
        try:
            return json.load(open(p))
        except ValueError:
            pass
    return {"total": 0, "pending": 0, "purposes": {}}


def count_signature(s, purpose):
    c = load_counts(s)
    c["total"] += 1
    c["pending"] += 1
    c["purposes"][purpose] = c["purposes"].get(purpose, 0) + 1
    write(_count_path(s), json.dumps(c))


def clear_counts(s, sent):
    """Zieht die gemeldeten Zahlen ab (Signaturen während der Meldung bleiben erhalten)."""
    c = load_counts(s)
    c["pending"] = max(0, c["pending"] - sent["pending"])
    for k, v in sent["purposes"].items():
        rest = c["purposes"].get(k, 0) - v
        if rest > 0:
            c["purposes"][k] = rest
        else:
            c["purposes"].pop(k, None)
    write(_count_path(s), json.dumps(c))


# ------------------------------------------------------------------- renew -

def renew(args, quiet=False):
    s = sd()
    meta = json.load(open(os.path.join(s, "agent.json")))
    n = post("/ticket/nonce", {"host": meta["host"]})
    with tpm.Workdir() as w:
        msg, sig = tpm.quote(w, s, meta["pcrs"], n["nonce"])
    counts = load_counts(s)
    req = {"host": meta["host"], "nonce": n["nonce"], "quote_attest": b64e(msg), "quote_sig": b64e(sig),
           "sig_count": counts["pending"], "sig_purposes": counts["purposes"]}
    if getattr(args, "ttl", None):
        req["ttl"] = args.ttl
    t = post("/ticket", req)
    if "error" in t:
        bad(T("Ticket verweigert: ", "Ticket denied: ") + t['error'])
        return False
    clear_counts(s, counts)
    t["received"] = time.time()
    write(os.path.join(s, "ticket.json"), json.dumps(t, indent=2))
    if not quiet:
        ok(T(f"Ticket erhalten: Laufzeit {t['ttl']}s, gültig bis TPM-Uhr {t['expiry_clock']}, "
             f"bis Neustart-Zähler {t['max_resets']} (gemeldete Signaturen: {counts['pending']})",
             f"Ticket received: lifetime {t['ttl']}s, valid until TPM clock {t['expiry_clock']}, "
             f"up to reset count {t['max_resets']} (signatures reported: {counts['pending']})"))
    return t


def loop(args):
    while True:
        t = renew(args, quiet=True)
        ttl = t["ttl"] if t else int(args.ttl or cfg("KEYLEASH_TTL", "600"))
        stamp = time.strftime("%H:%M:%S")
        print(f"[{stamp}] " + (T("Ticket erneuert", "ticket renewed") if t else T("Erneuerung fehlgeschlagen", "renewal failed")), flush=True)
        time.sleep(max(5, ttl / 4))


# -------------------------------------------------------------------- sign -

def policy_session(w, s, t, approval=None):
    """Baut die Policy-Session auf, die das Ticket verlangt.

    Jede Bedingung prüft das TPM selbst; schlägt eine fehl, gibt es keine
    Signatur. Der Agent kann hier nichts abkürzen.
    """
    write(w("approved.pol"), bytes.fromhex(t["approved_policy"]))
    write(w("ref"), bytes.fromhex(t["policy_ref"]))
    write(w("tk.sig"), b64d(t["signature"]))
    write(w("tk.msg"), bytes.fromhex(t["approved_policy"]) + bytes.fromhex(t["policy_ref"]))
    tpm.run("tpm2_loadexternal", "-C", "o", "-G", "rsa", "-u", os.path.join(s, "authz_pub.pem"),
            "-c", w("authz.ctx"), "-n", w("authz.name"))
    tpm.run("tpm2_verifysignature", "-c", w("authz.ctx"), "-g", "sha256", "-m", w("tk.msg"),
            "-s", w("tk.sig"), "-f", "rsassa", "-t", w("tk.ticket"))
    tpm.run("tpm2_startauthsession", "--policy-session", "-S", w("s.ctx"))
    steps = [
        (T("Ablaufzeit (TPM-Uhr)", "expiry (TPM clock)"), ["tpm2_policycountertimer", "-S", w("s.ctx"), "--ule",
                                  f"clock={t['expiry_clock']}"]),
        (T("Neustart-Grenze", "reboot limit"), ["tpm2_policycountertimer", "-S", w("s.ctx"),
                             "--eq" if t.get("pin_resets") else "--ule", f"resets={t['max_resets']}"]),
    ]
    if t.get("clock_safe"):
        # Uhr darf seit dem letzten Sichern nicht zurückgefallen sein (kein Stromausfall-Trick)
        steps.append((T("Uhr gesichert (safe)", "clock safe"), ["tpm2_policycountertimer", "-S", w("s.ctx"),
                                                               "--eq", "safe"]))
    steps += [
        (T("Boot-Zustand (PCR)", "boot state (PCR)"), ["tpm2_policypcr", "-S", w("s.ctx"), "-l", t["pcrs"]]),
    ]
    if approval:
        # Freigabe eines zweiten Systems, gebunden an Schlüssel und Daten-Hash (cpHash)
        write(w("approver.pem"), t["approver_pub"])
        tpm.run("tpm2_loadexternal", "-C", "o", "-G", "rsa", "-u", w("approver.pem"), "-c", w("appr.ctx"))
        write(w("appr.sig"), approval["signature"])
        write(w("appr.ref"), bytes.fromhex(t["approval_ref"]))
        write(w("cphash"), len(approval["cphash"]).to_bytes(2, "big") + approval["cphash"])
        steps.append((T("Freigabe (PolicySigned)", "approval (PolicySigned)"), ["tpm2_policysigned", "-S", w("s.ctx"), "-g", "sha256",
                                                  "-s", w("appr.sig"), "-f", "rsassa", "-c", w("appr.ctx"),
                                                  "--cphash-input", w("cphash"), "-q", w("appr.ref")]))
    steps += [
        (T("Ticket-Signatur", "ticket signature"), ["tpm2_policyauthorize", "-S", w("s.ctx"), "-i", w("approved.pol"),
                             "-q", w("ref"), "-n", w("authz.name"), "-t", w("tk.ticket")]),
        (T("Prozessgeheimnis", "process secret"), ["tpm2_policyauthvalue", "-S", w("s.ctx")]),
    ]
    for label, cmd in steps:
        try:
            tpm.run(*cmd)
        except tpm.TpmError as e:
            tpm.flush(w("s.ctx"))
            raise tpm.TpmError(T(f"TPM verweigert bei '{label}': {e}", f"TPM refused at '{label}': {e}"))
    return w("s.ctx")


def tpm_sign(data_path, out_path, auth_hex, s=None, purpose="cli"):
    s = s or sd()
    tp = os.path.join(s, "ticket.json")
    if not os.path.exists(tp):
        raise tpm.TpmError(T("kein Ticket vorhanden", "no ticket available"))
    t = json.load(open(tp))
    with tpm.Workdir() as w:
        tpm.load_key(w, s)
        sess = policy_session(w, s, t)
        try:
            pw, pin = tpm.session_auth(sess, auth_hex)
            tpm.run("tpm2_sign", "-c", w("key.ctx"), "-p", pw, "-g", "sha256",
                    "-f", "plain", "-o", out_path, data_path, stdin=pin)
        finally:
            tpm.flush(sess)
    count_signature(s, purpose)


def sign(args):
    s = sd()
    if os.path.isdir(purpose_dir(args.purpose)):
        try:
            return sign_with_approval(args)
        except tpm.TpmError as e:
            die(str(e))
    auth = read(os.path.join(s, "key.auth"), "r").strip()
    try:
        tpm_sign(args.file, args.out, auth, purpose=args.purpose)
    except tpm.TpmError as e:
        die(str(e))
    ok(T("Signiert: ", "Signed: ") + args.out)


# ------------------------------------------------- Zwecke mit Freigabe --

def purpose_dir(purpose):
    return os.path.join(sd(), f"purpose-{purpose}")


def enroll_purpose(args):
    s, pdir = sd(), purpose_dir(args.purpose)
    meta = json.load(open(os.path.join(s, "agent.json")))
    os.makedirs(pdir, mode=0o700, exist_ok=True)
    ref = ts.purpose_policy_ref(meta["host"], args.purpose)
    auth = os.urandom(32).hex()
    write(os.path.join(pdir, "key.auth"), auth)
    with tpm.Workdir() as w:
        write(w("key.policy"), ts.key_policy(bytes.fromhex(meta["authz_name"]), ref))
        tpm.load_primary(w)
        tpm.run("tpm2_create", "-C", w("primary.ctx"), "-G", "rsa2048:rsassa-sha256:null",
                "-a", "fixedtpm|fixedparent|sensitivedataorigin|sign", "-L", w("key.policy"),
                "-p", f"hex:{auth}", "-u", os.path.join(pdir, "key.pub"), "-r", os.path.join(pdir, "key.priv"))
        tpm.run("tpm2_load", "-C", w("primary.ctx"), "-u", os.path.join(pdir, "key.pub"),
                "-r", os.path.join(pdir, "key.priv"), "-c", w("key.ctx"))
        tpm.load_ak(w, s)
        tpm.run("tpm2_certify", "-C", w("ak.ctx"), "-c", w("key.ctx"), "-P", "file:-", "-g", "sha256",
                "-o", w("c.attest"), "-s", w("c.sig"), "-f", "plain", stdin=f"hex:{auth}".encode())
        r = post("/enroll/purpose", {"host": meta["host"], "purpose": args.purpose,
                                     "key_pub": b64e(read(os.path.join(pdir, "key.pub"))),
                                     "certify_attest": b64e(read(w("c.attest"))),
                                     "certify_sig": b64e(read(w("c.sig")))})
    if "error" in r:
        die(T("Server lehnt ab: ", "Server refuses: ") + r['error'])
    write(os.path.join(pdir, "cert.pem"), r["cert"], 0o644)
    write(os.path.join(pdir, "ca.pem"), r["ca"], 0o644)
    ok(T(f"Zweckschlüssel '{args.purpose}' im TPM erzeugt; nutzbar nur mit Ticket UND Freigabe",
         f"Purpose key '{args.purpose}' created in the TPM; usable only with a ticket AND an approval"))


def purpose_key_name(purpose):
    return ts.parse_tpm2b_public(read(os.path.join(purpose_dir(purpose), "key.pub"))).name


def request(args):
    """Freigabe-Anfrage für ein zweites System erstellen."""
    meta = json.load(open(os.path.join(sd(), "agent.json")))
    digest = ts.sha256(read(args.file))
    req = {"host": meta["host"], "purpose": args.purpose, "file": os.path.basename(args.file),
           "digest": digest.hex(), "key_name": purpose_key_name(args.purpose).hex()}
    write(args.out, json.dumps(req, indent=2), 0o644)
    ok(T(f"Freigabe-Anfrage geschrieben: {args.out} (SHA-256 {digest.hex()[:16]}…)",
         f"Approval request written: {args.out} (SHA-256 {digest.hex()[:16]}…)"))


def sign_with_approval(args):
    s, pdir = sd(), purpose_dir(args.purpose)
    if not args.approval:
        die(T(f"Zweck '{args.purpose}' verlangt eine Freigabe (--approval DATEI)",
          f"Purpose '{args.purpose}' requires an approval (--approval FILE)"))
    a = json.load(open(args.approval))
    digest = ts.sha256(read(args.file))
    if a.get("purpose") != args.purpose:
        die(T("Freigabe gilt für einen anderen Zweck", "The approval is for a different purpose"))
    if a.get("digest") != digest.hex():
        bad(T("Hinweis: Freigabe passt nicht zu dieser Datei – das TPM wird ablehnen", "Note: the approval does not match this file – the TPM will refuse"))
    t = json.load(open(os.path.join(s, "ticket.json")))
    pt = t.get("purpose_tickets", {}).get(args.purpose)
    if not pt:
        die(T(f"kein Ticket für Zweck '{args.purpose}' (renew ausführen; Freigabeschlüssel am Server?)",
          f"no ticket for purpose '{args.purpose}' (run renew; approval key configured on the server?)"))
    t = dict(t, **pt)
    key_name = purpose_key_name(args.purpose)
    approval = {"signature": b64d(a["signature"]), "cphash": ts.sign_cphash(key_name, digest)}
    auth = read(os.path.join(pdir, "key.auth"), "r").strip()
    with tpm.Workdir() as w:
        write(w("digest"), digest)
        tpm.load_primary(w)
        tpm.run("tpm2_load", "-C", w("primary.ctx"), "-u", os.path.join(pdir, "key.pub"),
                "-r", os.path.join(pdir, "key.priv"), "-c", w("key.ctx"))
        sess = policy_session(w, s, t, approval)
        try:
            pw, pin = tpm.session_auth(sess, auth)
            tpm.run("tpm2_sign", "-c", w("key.ctx"), "-p", pw, "-g", "sha256",
                    "-d", "-f", "plain", "-o", args.out, w("digest"), stdin=pin)
        finally:
            tpm.flush(sess)
    count_signature(s, args.purpose)
    ok(T("Signiert mit Freigabe: ", "Signed with approval: ") + args.out)


# ------------------------------------------------ Kurzzeit-Zertifikate --

def shortcert_once(name, out_dir, lifetime, kind="x509"):
    """Frischer Software-Schlüssel + Zertifikat für wenige Minuten.

    Ergebnis unter OUT/current/{key,cert,ca}.pem; 'current' wird atomar
    umgehängt, damit Anwendungen nie Schlüssel und Zertifikat aus
    verschiedenen Generationen lesen.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    import base64
    import hashlib
    import tempfile
    s = sd()
    meta = json.load(open(os.path.join(s, "agent.json")))
    host = meta["host"]
    if kind == "ssh":   # SSH-Benutzerzertifikat (Ed25519)
        key = ed25519.Ed25519PrivateKey.generate()
        pub_pem = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                serialization.PublicFormat.OpenSSH).decode()
        spki = base64.b64decode(pub_pem.split()[1])
    else:
        key = ec.generate_private_key(ec.SECP256R1())
        pub_pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    n = post("/cert/nonce", {"host": host})
    if "nonce" not in n:
        raise tpm.TpmError(T("Server: ", "server: ") + str(n.get("error")))
    msg = f"keyleash-kurzzertifikat|{host}|{name}|{n['nonce']}|{hashlib.sha256(spki).hexdigest()}".encode()
    auth = read(os.path.join(s, "key.auth"), "r").strip()
    with tempfile.TemporaryDirectory() as tmp:
        mp, sp = os.path.join(tmp, "msg"), os.path.join(tmp, "sig")
        write(mp, msg)
        tpm_sign(mp, sp, auth, purpose=f"cert-{name}")   # TPM verweigert ohne gültiges Ticket
        sig = read(sp)
    r = post("/cert/short", {"host": host, "name": name, "nonce": n["nonce"], "pub": pub_pem,
                             "sig": b64e(sig), "lifetime": lifetime, "kind": kind,
                             "machine_cert": read(os.path.join(s, "cert.pem"), "r")})
    if "cert" not in r:
        raise tpm.TpmError(T("Server verweigert: ", "server refuses: ") + str(r.get("error")))
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    gen = os.path.join(out_dir, "gen-" + time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(gen, mode=0o700, exist_ok=True)
    if kind == "ssh":
        write(os.path.join(gen, "id_ed25519"), key.private_bytes(serialization.Encoding.PEM,
              serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()))
        write(os.path.join(gen, "id_ed25519.pub"), pub_pem + "\n", 0o644)
        write(os.path.join(gen, "id_ed25519-cert.pub"), r["cert"], 0o644)
        write(os.path.join(gen, "ssh_ca.pub"), r["ca"], 0o644)
    else:
        write(os.path.join(gen, "key.pem"), key.private_bytes(serialization.Encoding.PEM,
              serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        write(os.path.join(gen, "cert.pem"), r["cert"], 0o644)
        write(os.path.join(gen, "ca.pem"), r["ca"], 0o644)
    tmp_link = os.path.join(out_dir, ".current.tmp")
    if os.path.lexists(tmp_link):
        os.unlink(tmp_link)
    os.symlink(os.path.basename(gen), tmp_link)
    os.replace(tmp_link, os.path.join(out_dir, "current"))
    for old in sorted(d for d in os.listdir(out_dir) if d.startswith("gen-"))[:-2]:   # zwei Generationen behalten
        for f in os.listdir(os.path.join(out_dir, old)):
            os.unlink(os.path.join(out_dir, old, f))
        os.rmdir(os.path.join(out_dir, old))
    return r["lifetime"]


def shortcert(args):
    out = args.dir or os.path.join(sd(), f"shortcert-{args.name}")
    while True:
        stamp = time.strftime("%H:%M:%S")
        try:
            life = shortcert_once(args.name, out, args.lifetime, "ssh" if args.ssh else "x509")
            print(f"[{stamp}] " + T(f"Kurzzeit-Zertifikat '{args.name}' erneuert, gültig {life}s → {out}/current",
                                   f"short-lived certificate '{args.name}' renewed, valid {life}s → {out}/current"), flush=True)
            wait = max(10, life / 3)
        except (tpm.TpmError, OSError, KeyError) as e:
            print(f"[{stamp}] " + T("Kurzzeit-Zertifikat verweigert: ", "short-lived certificate refused: ") + str(e), flush=True)
            if not args.loop:
                sys.exit(1)
            wait = 10
        if not args.loop:
            return
        time.sleep(wait)


# ------------------------------------------------------------------ status -

def status(args):
    s = sd()
    c = tpm.read_clock()
    sf = T("ja", "yes") if c["safe"] else T("NEIN (Uhr nach Stromausfall evtl. zurückgefallen)",
                                              "NO (clock may have fallen back after a power loss)")
    info(T(f"TPM-Uhr: {c['clock']} ms   Neustart-Zähler (resetCount): {c['reset_count']}   gesichert (safe): {sf}",
           f"TPM clock: {c['clock']} ms   reset count (resetCount): {c['reset_count']}   safe: {sf}"))
    n = load_counts(s)
    info(T(f"Signaturen: {n['total']} gesamt, {n['pending']} noch nicht gemeldet",
           f"Signatures: {n['total']} total, {n['pending']} not yet reported"))
    tp = os.path.join(s, "ticket.json")
    if not os.path.exists(tp):
        info(T("kein Ticket", "no ticket"))
        return
    t = json.load(open(tp))
    rest = (t["expiry_clock"] - c["clock"]) / 1000
    resets_ok = (c["reset_count"] == t["max_resets"]) if t.get("pin_resets") else (c["reset_count"] <= t["max_resets"])
    safe_ok = c["safe"] or not t.get("clock_safe")
    if rest > 0 and resets_ok and safe_ok:
        if t.get("pin_resets"):
            ok(T(f"Ticket gültig: noch {rest:.0f}s, an diesen Systemstart gebunden (kein Neustart erlaubt)",
                 f"Ticket valid: {rest:.0f}s left, bound to this boot (no reboot allowed)"))
        else:
            ok(T(f"Ticket gültig: noch {rest:.0f}s, Neustarts bis zur Grenze: {t['max_resets'] - c['reset_count']}",
                 f"Ticket valid: {rest:.0f}s left, reboots until limit: {t['max_resets'] - c['reset_count']}"))
    elif rest <= 0:
        bad(T("Ticket abgelaufen", "Ticket expired"))
    elif not safe_ok:
        bad(T("Ticket verlangt gesicherte Uhr (safe), TPM meldet NEIN: erneuern",
              "Ticket requires a safe clock, TPM reports NO: renew"))
    else:
        bad(T("Neustart-Grenze überschritten", "Reboot limit exceeded"))


def main():
    ap = argparse.ArgumentParser(description=T("keyleash Agent (Lab)", "keyleash agent (lab)"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("enroll")
    r = sub.add_parser("renew"); r.add_argument("--ttl", type=int)
    lp = sub.add_parser("loop"); lp.add_argument("--ttl", type=int)
    sg = sub.add_parser("sign"); sg.add_argument("file"); sg.add_argument("-o", "--out", required=True)
    sg.add_argument("--purpose", default="cli", help=T("Zweck der Signatur (für die Zählung)", "purpose of the signature (for counting)"))
    sg.add_argument("--approval", help=T("Freigabedatei eines zweiten Systems (Zwecke mit Freigabepflicht)", "approval file from a second system (purposes requiring approval)"))
    ep = sub.add_parser("enroll-purpose"); ep.add_argument("purpose")
    rq = sub.add_parser("request"); rq.add_argument("file"); rq.add_argument("--purpose", required=True)
    rq.add_argument("-o", "--out", required=True)
    sub.add_parser("status")
    sc = sub.add_parser("shortcert"); sc.add_argument("name")
    sc.add_argument("--dir", help=T("Zielordner (Standard: state/agent/shortcert-NAME)", "target directory (default: state/agent/shortcert-NAME)"))
    sc.add_argument("--lifetime", type=int, default=int(cfg("KEYLEASH_SHORTCERT_LIFETIME", "300")))
    sc.add_argument("--ssh", action="store_true", help=T("SSH-Benutzerzertifikat statt X.509", "SSH user certificate instead of X.509"))
    sc.add_argument("--loop", action="store_true", help=T("laufend erneuern (alle Laufzeit/3)", "renew continuously (every lifetime/3)"))
    args = ap.parse_args()
    try:
        {"enroll": enroll, "renew": lambda a: renew(a) or sys.exit(1), "loop": loop,
         "sign": sign, "status": status, "enroll-purpose": enroll_purpose,
         "request": request, "shortcert": shortcert}[args.cmd](args)
    except tpm.TpmError as e:
        die(str(e))
    except OSError as e:
        die(T("Server nicht erreichbar oder Datei fehlt: ", "Server unreachable or file missing: ") + str(e))


if __name__ == "__main__":
    main()
