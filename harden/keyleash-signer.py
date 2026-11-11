#!/usr/bin/env python3
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""keyleash Signaturdienst – Härtung Stufe 1 (Prozess-Isolation).

Läuft als eigener Systembenutzer 'keyleash' unter systemd und AppArmor.
Nur dieser Prozess kennt das Schlüsselgeheimnis (PolicyAuthValue); es
liegt in Speicher aus memfd_secret, also außerhalb der direkten
Kernel-Abbildung, gesperrt gegen Auslagerung und Speicherabbilder.

Er übernimmt zwei Rollen:
  * Agent: erneuert das Ticket im Abstand Laufzeit/4 (Herzschlag)
  * Signaturentscheidung: signiert nur, was die lokale Regel erlaubt
    (Zweck auf der Erlaubnisliste, Größenlimit). Konzept: "Die
    Signaturentscheidung gehört in den geschützten Bereich."

Ehrliche Grenze dieses Lab-Prototyps: Python kopiert das Geheimnis beim
Weiterreichen an tpm2_sign kurz in normalen Heap-Speicher und in eine
Pipe. Für einen Pilot gehört der Signaturpfad in C/Rust direkt gegen
tss2-esys, damit das Geheimnis den geschützten Speicher nie verlässt.
"""
import base64
import ctypes
import json
import mmap
import os
import socket
import socketserver
import struct
import sys
import threading
import time

LAB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(LAB, "lib"))
sys.path.insert(0, os.path.join(LAB, "agent"))

from kl import tpm  # noqa: E402
from kl.common import cfg  # noqa: E402
from kl.i18n import T  # noqa: E402
import agent  # noqa: E402

SOCK = cfg("KEYLEASH_SIGNER_SOCK", "/run/keyleash/signer.sock")
STATE = cfg("KEYLEASH_AGENT_STATE", "/var/lib/keyleash")
PURPOSES = set(cfg("KEYLEASH_SIGN_PURPOSES", T("beleg,dienst-token", "receipt,service-token")).split(","))
MAX_BYTES = int(cfg("KEYLEASH_SIGN_MAX_BYTES", str(1 << 20)))
CLIENT_GROUP = cfg("KEYLEASH_CLIENT_GROUP", "keyleash-clients")

libc = ctypes.CDLL(None, use_errno=True)
PR_SET_DUMPABLE = 4
SYS_memfd_secret = 447    # x86_64 und arm64
MADV_DONTDUMP = 16


def log(msg):
    print(msg, flush=True)


class SecretBox:
    """Hält das Geheimnis in memfd_secret-Speicher (Fallback: mlock + DONTDUMP)."""

    def __init__(self, data: bytes):
        self.mode = "memfd_secret"
        fd = libc.syscall(SYS_memfd_secret, 0)
        if fd >= 0:
            os.ftruncate(fd, mmap.PAGESIZE)
            self.m = mmap.mmap(fd, mmap.PAGESIZE)
            os.close(fd)
        else:
            err = os.strerror(ctypes.get_errno())
            self.mode = f"mlock-fallback ({err}; " + T("secretmem im Kernel aus?)", "secretmem disabled in the kernel?)")
            self.m = mmap.mmap(-1, mmap.PAGESIZE)
            addr = ctypes.c_void_p.from_buffer(self.m)
            libc.mlock(ctypes.addressof(addr), mmap.PAGESIZE)
            libc.madvise(ctypes.addressof(addr), mmap.PAGESIZE, MADV_DONTDUMP)
        self.addr = ctypes.addressof(ctypes.c_char.from_buffer(self.m))
        self.len = len(data)
        self.m[:self.len] = data

    def get(self) -> str:
        return self.m[:self.len].decode()


def load_secret():
    path = os.path.join(STATE, "key.auth")
    buf = bytearray(open(path, "rb").read().strip())
    box = SecretBox(bytes(buf))
    for i in range(len(buf)):
        buf[i] = 0
    return box


def renew_loop(stop):
    class A:
        ttl = None
    while not stop.is_set():
        try:
            t = agent.renew(A, quiet=True)
            log(T("Ticket erneuert", "ticket renewed") if t else T("Ticket verweigert", "ticket denied"))
            ttl = t["ttl"] if t else int(cfg("KEYLEASH_TTL", "600"))
        except Exception as e:  # Server weg: weiterlaufen, Ticket läuft ab
            log(T("Erneuerung fehlgeschlagen: ", "renewal failed: ") + str(e))
            ttl = int(cfg("KEYLEASH_TTL", "600"))
        stop.wait(max(5, ttl / 4))


def make_handler(box):
    lock = threading.Lock()

    class H(socketserver.StreamRequestHandler):
        def handle(self):
            creds = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            pid, uid, gid = struct.unpack("3i", creds)
            try:
                req = json.loads(self.rfile.readline())
                if req.get("cmd") == "status":
                    return self.send({"ok": True, "secret_mode": box.mode, "secret_addr": hex(box.addr),
                                      "pid": os.getpid(), "purposes": sorted(PURPOSES)})
                purpose = req.get("purpose", "")
                data = base64.b64decode(req.get("data", ""))
                # --- Signaturentscheidung im geschützten Prozess ---
                if purpose not in PURPOSES:
                    log(T(f"ABGELEHNT uid={uid} pid={pid}: Zweck '{purpose}' nicht erlaubt", f"REFUSED uid={uid} pid={pid}: purpose '{purpose}' not allowed"))
                    return self.send({"ok": False, "error": T("zweck_nicht_erlaubt: ", "purpose_not_allowed: ") + purpose})
                if len(data) > MAX_BYTES:
                    return self.send({"ok": False, "error": T("zu_gross", "too_large")})
                with lock, tpm.Workdir() as w:
                    open(w("data"), "wb").write(data)
                    agent.tpm_sign(w("data"), w("sig"), box.get(), s=STATE, purpose=purpose)
                    sig = open(w("sig"), "rb").read()
                log(T("signiert", "signed") + f" uid={uid} pid={pid} " + T("zweck", "purpose") + f"={purpose} bytes={len(data)}")
                self.send({"ok": True, "signature": base64.b64encode(sig).decode()})
            except tpm.TpmError as e:
                log(T("TPM verweigert: ", "TPM refused: ") + str(e))
                self.send({"ok": False, "error": f"tpm: {e}"})
            except Exception as e:
                self.send({"ok": False, "error": T("fehler: ", "error: ") + str(e)})

        def send(self, obj):
            self.wfile.write((json.dumps(obj) + "\n").encode())

    return H


def main():
    # Keine Speicherabbilder, kein ptrace durch gleichrangige Prozesse
    libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    box = load_secret()
    log(T(f"keyleash-signer gestartet: Geheimnis in {box.mode}, Zwecke {sorted(PURPOSES)}", f"keyleash-signer started: secret in {box.mode}, purposes {sorted(PURPOSES)}"))

    stop = threading.Event()
    threading.Thread(target=renew_loop, args=(stop,), daemon=True).start()

    if os.path.exists(SOCK):
        os.unlink(SOCK)

    class Srv(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

    srv = Srv(SOCK, make_handler(box))
    try:
        import grp
        os.chown(SOCK, -1, grp.getgrnam(CLIENT_GROUP).gr_gid)
    except (KeyError, PermissionError) as e:
        log(T("Hinweis: Socket-Gruppe nicht gesetzt", "note: socket group not set") + f" ({e})")
    os.chmod(SOCK, 0o660)
    try:
        srv.serve_forever()
    finally:
        stop.set()


if __name__ == "__main__":
    main()
