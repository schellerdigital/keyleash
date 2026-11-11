# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""Gemeinsame Hilfsfunktionen: Konfiguration, Pfade, HTTP, Ausgabe."""
import base64
import json
import os
import shlex
import sys
import urllib.error
import urllib.request

LAB_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def load_env():
    """Liest keyleash.env (KEY=VALUE), ohne bereits gesetzte Variablen zu überschreiben."""
    path = os.environ.get("KEYLEASH_ENV", os.path.join(LAB_ROOT, "keyleash.env"))
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = " ".join(shlex.split(v, comments=True))
            os.environ.setdefault(k, v)


load_env()


def cfg(name, default=None):
    return os.environ.get(name, default)


def state_dir(*parts):
    base = cfg("KEYLEASH_STATE", os.path.join(LAB_ROOT, "state"))
    p = os.path.join(base, *parts)
    os.makedirs(p, mode=0o700, exist_ok=True)
    return p


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def read(path, mode="rb"):
    with open(path, mode) as f:
        return f.read()


def write(path, data, mode=0o600):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)


def post(path, payload: dict):
    url = cfg("KEYLEASH_SERVER", "http://127.0.0.1:8740") + path
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = {"error": str(e)}
        body["_status"] = e.code
        return body


def get(path):
    url = cfg("KEYLEASH_SERVER", "http://127.0.0.1:8740") + path
    with urllib.request.urlopen(url, timeout=15) as r:
        return json.loads(r.read())


# Farbige, knappe Ausgabe für die Demos
_TTY = sys.stdout.isatty()


def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if _TTY else s


def ok(msg):
    print(_c("32", "  ✔ ") + msg)


def bad(msg):
    print(_c("31", "  ✘ ") + msg)


def info(msg):
    print(_c("36", "  · ") + msg)
