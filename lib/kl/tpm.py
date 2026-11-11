# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""Dünner Wrapper um tpm2-tools.

Bewusst über die Kommandozeilenwerkzeuge statt über Bindings: Jeder
Schritt ist so im Terminal nachvollziehbar (KEYLEASH_TRACE=1 zeigt alle
Aufrufe).
"""
import os
import subprocess
import sys
import tempfile

from kl.i18n import T


class TpmError(RuntimeError):
    pass


def tcti() -> str:
    mode = os.environ.get("KEYLEASH_TPM", "hw")
    if mode == "hw":
        return os.environ.get("KEYLEASH_TCTI", "device:/dev/tpmrm0")
    if mode == "swtpm":
        return os.environ.get("KEYLEASH_TCTI", "tabrmd:bus_type=session")
    raise TpmError(T("unbekannter KEYLEASH_TPM-Modus: ", "unknown KEYLEASH_TPM mode: ") + mode)


def run(*args, stdin: bytes = None, check=True, quiet=False) -> str:
    env = dict(os.environ, TPM2TOOLS_TCTI=tcti())
    if os.environ.get("KEYLEASH_TRACE"):
        print("  $", " ".join(args), file=sys.stderr)
    p = subprocess.run(list(args), input=stdin, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode != 0:
        err = p.stderr.decode(errors="replace").strip().splitlines()
        # Die letzte aussagekräftige TPM-Meldung reicht meist
        msg = next((l for l in reversed(err) if "tpm:" in l), "")
        if not msg:   # keine TPM-Meldung (z. B. „Unable to run …“): die Zeilen davor enthalten die Ursache
            msg = " | ".join(l.strip() for l in err[-4:] if l.strip())
        raise TpmError(f"{args[0]} " + T("fehlgeschlagen", "failed") + f": {msg}")
    if not quiet and p.returncode != 0:
        pass
    return p.stdout.decode(errors="replace")


_TOOLS_VER = None


def tools_version():
    """Version der tpm2-tools als Tupel, z. B. (5, 6)."""
    global _TOOLS_VER
    if _TOOLS_VER is None:
        try:
            out = subprocess.run(["tpm2_sign", "--version"], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT).stdout.decode()
            v = out.split('version="', 1)[1].split('"', 1)[0]
            _TOOLS_VER = tuple(int(x) for x in v.split(".")[:2] if x.isdigit())
        except Exception:
            _TOOLS_VER = (0, 0)
    return _TOOLS_VER


def session_auth(session_ctx: str, auth_hex: str):
    """Policy-Session plus Schlüsselgeheimnis für -p/-P.

    Ab tpm2-tools 5.5 kommt das Geheimnis über stdin (nicht in der Prozessliste).
    Ältere Versionen (Debian 12: 5.4, RHEL 9: 5.2) kennen "session:…+file:-" nicht;
    dort steht das Geheimnis kurz in der Befehlszeile. Im Lab vertretbar, für
    die Härtung nicht: dann warnt keyleash.
    """
    if tools_version() >= (5, 5):
        return f"session:{session_ctx}+file:-", f"hex:{auth_hex}".encode()
    if not os.environ.get("KEYLEASH_QUIET_OLDTOOLS"):
        print(T("  ! tpm2-tools < 5.5: Schlüsselgeheimnis kurz in der Prozessliste sichtbar (nur Lab)",
                "  ! tpm2-tools < 5.5: key secret briefly visible in the process list (lab only)"), file=sys.stderr)
    return f"session:{session_ctx}+hex:{auth_hex}", None


def read_clock():
    out = run("tpm2_readclock")
    vals = {}
    for line in out.splitlines():
        k, _, v = line.strip().partition(":")
        vals[k] = v.strip()
    return {"clock": int(vals["clock"]), "reset_count": int(vals["reset_count"]),
            "restart_count": int(vals["restart_count"]),
            "safe": vals.get("safe", "yes").lower() in ("yes", "1", "true")}


class Workdir:
    """Temporäres Verzeichnis für Kontextdateien eines Vorgangs."""

    def __init__(self):
        self._d = tempfile.TemporaryDirectory(prefix="keyleash-")
        self.path = self._d.name

    def __call__(self, name):
        return os.path.join(self.path, name)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self._d.cleanup()


def load_ek(w: Workdir):
    """EK aus der Standardvorlage neu ableiten (deterministisch, nichts persistent)."""
    run("tpm2_createek", "-c", w("ek.ctx"), "-G", "rsa", "-u", w("ek.pub"))
    return w("ek.ctx")


def endorsement_session(w: Workdir, name="ps.ctx"):
    run("tpm2_startauthsession", "--policy-session", "-S", w(name))
    run("tpm2_policysecret", "-S", w(name), "-c", "e")
    return w(name)


def flush(ctx):
    run("tpm2_flushcontext", ctx, check=False)


def load_ak(w: Workdir, state_dir: str):
    """AK unter dem EK laden (EK verlangt PolicySecret auf die Endorsement-Hierarchie)."""
    load_ek(w)
    s = endorsement_session(w)
    try:
        run("tpm2_load", "-C", w("ek.ctx"), "-P", f"session:{s}",
            "-u", os.path.join(state_dir, "ak.pub"), "-r", os.path.join(state_dir, "ak.priv"),
            "-c", w("ak.ctx"))
    finally:
        flush(s)
    return w("ak.ctx")


def load_primary(w: Workdir):
    run("tpm2_createprimary", "-C", "o", "-G", "rsa", "-c", w("primary.ctx"))
    return w("primary.ctx")


def load_key(w: Workdir, state_dir: str):
    load_primary(w)
    run("tpm2_load", "-C", w("primary.ctx"), "-u", os.path.join(state_dir, "key.pub"),
        "-r", os.path.join(state_dir, "key.priv"), "-c", w("key.ctx"))
    return w("key.ctx")


def quote(w: Workdir, state_dir: str, pcrs: str, nonce_hex: str):
    load_ak(w, state_dir)
    run("tpm2_quote", "-c", w("ak.ctx"), "-l", pcrs, "-q", nonce_hex,
        "-m", w("quote.msg"), "-s", w("quote.sig"), "-f", "plain", "-g", "sha256")
    return open(w("quote.msg"), "rb").read(), open(w("quote.sig"), "rb").read()
