#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Auswertung aller Entscheidungen des Autorisierungsservers
# Report on all decisions of the authorisation server
source "$(dirname "$0")/common.sh"
python3 "$LAB/tools/siem-report.py"
