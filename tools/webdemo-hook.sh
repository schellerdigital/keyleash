#!/usr/bin/env bash
# Copyright (c) 2026 Christian Scheller · keyleash · SPDX-License-Identifier: AGPL-3.0-or-later
# Sperr-Hook für den keyleash-Server (KEYLEASH_REVOKE_HOOK): HOOK revoke|unrevoke HOST
exec bash "$(dirname "$0")/webdemo.sh" hook "$@"
