#!/usr/bin/env python3
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
"""Auswertung des SIEM-Logs (state/server/siem.jsonl).

  siem-report.py            Übersicht: Entscheidungen je System, alle Alarme
  siem-report.py --lines    JSON-Zeilen von stdin kompakt ausgeben
"""
import collections
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from kl.i18n import T, canonical, code  # noqa: E402

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "state", "server", "siem.jsonl")
TTY = sys.stdout.isatty()
COL = {"alarm": "31", "warn": "33", "info": "32"}


def fmt(r):
    sev = r.get("severity", "info")
    extra = {k: v for k, v in r.items() if k not in ("ts", "event", "severity", "host", "src_ip")}
    head = f"{r['ts'][11:19]} {sev.upper():<5} {r['event']:<26}"
    if TTY:
        head = f"\033[{COL.get(sev, '0')}m{head}\033[0m"
    return f"  {head} host={r.get('host')} {json.dumps(extra, ensure_ascii=False)}"


def main():
    if "--lines" in sys.argv:
        for line in sys.stdin:
            if line.strip():
                print(fmt(json.loads(line)))
        return
    recs = [json.loads(l) for l in open(LOG) if l.strip()]
    per = collections.defaultdict(collections.Counter)
    for r in recs:
        per[r.get("host")][r["event"]] += 1
    print(T(f"SIEM-Log: {len(recs)} Ereignisse\n", f"SIEM log: {len(recs)} events\n"))
    for host, c in per.items():
        print(T(f"System {host}:", f"Host {host}:"))
        for ev, n in c.most_common():
            print(f"  {n:>5}  {ev}")
    alarms = [r for r in recs if r.get("severity") == "alarm"]
    print(T(f"\nAlarme ({len(alarms)}):", f"\nAlerts ({len(alarms)}):"))
    for r in alarms[-30:]:
        print(fmt(r))
    # funktioniert mit deutschen und englischen Logs
    denied = collections.Counter(code(canonical(r.get("grund", r.get("reason")))) for r in recs
                                 if canonical(r["event"]) == "ticket_verweigert")
    if denied:
        print(T("\nAbgelehnte Ticket-Anfragen nach Grund:", "\nDenied ticket requests by reason:"))
        for g, n in denied.most_common():
            print(f"  {n:>5}  {g}")


if __name__ == "__main__":
    main()
