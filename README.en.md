# keyleash Lab – test environment for "sovereign misuse detection for machine identities"

Proof of concept on a single machine: a TPM-bound machine key, an authorisation server issuing
time-limited tickets, a management CA, a SIEM log and hardening level 1. Open source only:
tpm2-tools/tpm2-tss, OpenSSL, Python (stdlib + cryptography).

```
 lab machine
 ┌─────────────────────────────────────────────────────────────┐
 │  agent/agent.py ──quote+nonce──▶ server/authz_server.py      │
 │        │        ◀──ticket──────       │ CA · SIEM log         │
 │        ▼                              ▼                       │
 │   TPM 2.0 (/dev/tpmrm0)        state/server/siem.jsonl        │
 │   key + policy                                                │
 │        │ signature                                            │
 │        ▼                                                      │
 │  verify/verify.sh  (relying party: checks cert + sig only)    │
 └─────────────────────────────────────────────────────────────┘
```

## Language

All output, demos and SIEM events are available in German and English. Set
`KEYLEASH_LANG=en` in `keyleash.env` (or per command: `KEYLEASH_LANG=en demos/alle.sh`).
Internal codes stay the same; only the output is translated, so detection does not depend on the
language. `tools/siem-report.py` reads logs written in either language.

Script **file names** stay German. For orientation:

| File | Meaning |
|---|---|
| `00-pruefen.sh` | check prerequisites |
| `10-provisionieren.sh` | enrolment |
| `20-signieren.sh` | signing and three attacks |
| `30-ablauf.sh` | expiry |
| `40-sperrung.sh` | revocation |
| `50-manipulation.sh` | tampered boot state |
| `60-parallel.sh` | parallel instance and replay |
| `65-signaturen.sh` | signature counting |
| `67-freigabe.sh` | approval by a second system |
| `70-neustart.sh` | reboot limit |
| `75-herzschlag.sh` | missing heartbeat |
| `80-siem.sh` | SIEM report |
| `85-webserver.sh` | web server without copyable secrets |
| `86-admin-arbeitsplatz.sh` | admin accounts bound to workstations (SSH) |
| `87-rdp.sh` | RDP only through the keyleash tunnel |
| `88-signaturdienst.sh` | signing service for systems without a TPM |
| `90-haertung.sh` | hardening level 1 |
| `alle.sh` | run all demos |

## Single-file installer

`keyleash-install.sh` contains the whole lab, checks the prerequisites and installs missing packages
(apt: Debian, Ubuntu, Mint; dnf: Fedora, RHEL, Rocky, AlmaLinux). It uses `sudo` only for packages,
the `tss` group and the udev rule.

```bash
bash keyleash-install.sh --check            # only show what is missing
bash keyleash-install.sh --lang en          # lab on this machine (server + agent)
bash keyleash-install.sh --swtpm            # also the software TPM (offered if there is no TPM)
bash keyleash-install.sh --role server --listen 0.0.0.0:8740
bash keyleash-install.sh --role agent --server http://10.0.0.5:8740
bash keyleash-install.sh --help             # all options
```

The target is `~/keyleash-lab` (`--dir` changes it). On an existing installation it backs up the old
state as `.tar.gz`, leaves `state/`, `keyleash.env` and `keyleash.mail.env` untouched and puts a new
template next to it as `keyleash.env.neu`. The payload is SHA-256 checked; the installer aborts if it
was modified. Build: `tools/build-installer.sh` (→ `dist/`). Tested in containers with Ubuntu 24.04,
Debian 12, Fedora 40 and Rocky Linux 9 (software TPM).
With tpm2-tools older than 5.5 (Debian 12, RHEL 9) the key secret is briefly visible in the process list
while signing; the installer warns about it. Fine for the lab, not for hardening level 1.

## Trust anchors in a NetHSM (optional)

In the lab, the server's ticket signing key and CA key are files in `state/server/`. Whoever has them can
issue arbitrary tickets and certificates. With a Nitrokey NetHSM they no longer leave the hardware: the
server only sends digests for signing and verifies every response against the public key before using it.

```bash
python3 tools/nethsm-setup.py import --url https://NETHSM:8443 [--insecure]   # asks for the admin passphrase
tools/server.sh stop && tools/server.sh start
python3 tools/nethsm-setup.py check
```

`import` takes over the existing keys so that all enrolled machines stay valid. It creates a user with the
Operator role (may sign, may not export), stores its passphrase in `state/server/nethsm.pass` (600), sets
`KEYLEASH_KEYSTORE=nethsm` and the other `KEYLEASH_NETHSM_*` in `keyleash.env` and moves the key files to
`state/server/vor-nethsm/`. Back them up offline or delete them with `shred -u`. Use `--insecure` only for a
test NetHSM with a self-signed certificate; otherwise point `KEYLEASH_NETHSM_CA` to its certificate. Tested
against Nitrokey's public NetHSM demo (import, tickets, certificates for purpose keys, demos 20 and 67).
For a fresh test NetHSM in a container: `python3 tools/nethsm-setup.py provision --url … --insecure`.

## Demo: protected application on a VM (labbox-1)

A dashboard on the VM shows statistics and logs of the keyleash server. It gets the data only with its
machine identity: fetch a nonce, have the VM's TPM sign it, send signature and certificate to the data API
on gmkbox. The API (`server/data_api.py`, port 8741) checks only certificate and signature and knows
nothing about tickets. Whether signing is allowed is decided by the TPM.

```bash
bash tools/labbox-deploy.sh user@192.0.2.10   # set up (password once, then SSH key)
bash tools/labbox-deploy.sh revoke                # within a minute: the TPM stops signing, dashboard red
bash tools/labbox-deploy.sh unrevoke              # green again within 30 s
bash tools/labbox-deploy.sh status
```

On the VM: `keyleash-agent` (renews tickets, TTL 30 s), `keyleash-dashboard` (port 8080), without a vTPM
also `keyleash-swtpm`. Server and API listen on all addresses and speak HTTP without TLS: use them on the
internal VM network only.

## Demo: web server without copyable secrets (WordPress)

Motivation: PHP2Shell (Oct 2026), code execution inside the PHP process. keyleash does not stop the
intrusion, but the attacker finds nothing worth taking. WordPress has no database password; it signs in to
MariaDB with a **short-lived certificate** (60 s in the demo). The agent keeps creating a fresh software key
and has the TPM machine key sign the request. The TPM signs only with a valid ticket, and the server issues
only to machines that are not revoked (`/cert/nonce`, `/cert/short`). MariaDB admits the user only with
that certificate (`REQUIRE SUBJECT '/CN=HOST/OU=wpdb' AND ISSUER …`).

```bash
bash tools/webdemo.sh setup      # once: MariaDB with TLS, PHP, WordPress (sudo, internet)
demos/85-webserver.sh            # copy, revoke, let it expire, reinstate (~90 s)
bash tools/webdemo.sh stop       # stop before demos/alle.sh (it runs its own agent loop)
bash tools/webdemo.sh remove     # remove database, MariaDB config and WordPress
```

Sequence: site up → attacker copies key and certificate, reaches the database and keeps a connection open →
revocation → the **revoke hook** (`KEYLEASH_REVOKE_HOOK`, set up by `setup`) locks account `wp` and ends open
connections → WordPress shows "Database refused", the stolen copy is worthless → reinstate, site back within
10 s. MariaDB checks the certificate only when a connection is set up; without the hook a connection kept
open would survive, and revocation would only take effect when the last certificate expires. The hook is
called as `HOOK revoke|unrevoke HOST` and logged in the SIEM (`revoke_hook`). Limits: while the attacker sits in the web server, he gets whatever the
database gives WordPress; the salts in `wp-config.php` remain shared secrets. Database and keyleash server
need matching clocks (NTP). General agent command: `agent/agent.py shortcert NAME --lifetime S --loop`
(result in `state/agent/shortcert-NAME/current/`).

## Demo: bind privileged accounts to admin workstations (SSH)

Admin access is the most valuable loot. The SSH server admits admins only with an **SSH certificate valid
for 2 minutes** (`KEYLEASH_ADMIN_CERT_LIFETIME`), issued by the keyleash server only to a workstation with a
valid TPM ticket, principal `keyleash-admin`, key ID = host name. No `authorized_keys`, no passwords: a stolen
key or the attacker's own does not get in.

```bash
bash tools/admindemo.sh setup      # once: OpenSSH, SSH CA from the server, unprivileged sshd on 127.0.0.1:2222
demos/86-admin-arbeitsplatz.sh     # sign in, copy, revoke, reinstate (~40 s)
bash tools/admindemo.sh ssh        # sign in as admin yourself
bash tools/admindemo.sh remove
```

Sequence: plain key refused → admin signs in with the short-lived certificate and keeps a session open →
malware copies key and certificate, the copy works at first → revocation → the revoke hook adds the host to
the revocation list (KRL) and ends running admin sessions (measured 0.4 s) → copy and new certificate refused
→ reinstate: new certificate within 10 s, certificates issued before the revocation stay revoked until they
expire (`state/server/ssh-serials.tsv`). Several hooks are dispatched by `tools/revoke-hooks.sh` (every
executable in `state/hooks.d/`). Limits: in the demo the SSH server and the keyleash server share one machine;
in production the KRL and session termination are pushed to the target systems. Emergency access (break
glass) belongs separately: an offline key whose use itself raises an alert.

## Demo: RDP only through the keyleash tunnel (xrdp)

The same principle for RDP, without a Windows licence: xrdp listens on **no network port**, only on a local
socket. It can be reached only through the admin gateway from demo 86, i.e. only with a short-lived
certificate from the workstation: `tools/admindemo.sh tunnel` opens a local port, and every connection to it
becomes an SSH session that relays to the socket via `socat` (the gateway itself allows no forwarding,
`DisableForwarding yes`). On revocation the admin demo's hook cuts the gateway session and a second hook logs
the RDP session off – both measured at 0.5 s. Without it the session would only be *disconnected* and could be
resumed.

```bash
bash tools/admindemo.sh setup && bash tools/rdpdemo.sh setup   # xrdp, xorgxrdp, Xvfb, FreeRDP (sudo)
demos/87-rdp.sh                                                # tunnel, RDP, revoke, reinstate
bash tools/rdpdemo.sh remove
```

Note: FreeRDP 3 follows the proxy variables (`https_proxy`); the demo starts the client without them.
`setup` creates the user `kl-rdp` with a random password (`state/rdpdemo/pw`) and a sudo rule that allows only
`pkill -KILL -u kl-rdp`. A system xrdp freshly installed by `setup` is disabled, since it would otherwise listen
on 3389 on the network. On Windows the socket corresponds to a firewall rule "3389 only from the gateway", the
logoff to a hook running `logoff` or `Invoke-RDUserLogoff`. Tested on Ubuntu 24.04.

## Demo: signing service for systems without a TPM (NetHSM)

For machines without a TPM, such as cloud VMs without a vTPM (Hetzner Cloud offers none): the signing key
lives **in the NetHSM behind the keyleash server**, never on the VM. The VM only has a sign-in key (Ed25519)
and signs every request with it. The server checks in turn: known system, revocation, sender address,
one-time nonce, sign-in signature, permitted purpose, operating window and volume – which it counts
**itself** (`KEYLEASH_REMOTE_LIMIT`, default 10 per purpose within `KEYLEASH_SIG_WINDOW`). Only then does the
NetHSM sign (ECDSA P-256), with a keyleash CA certificate per purpose.

```bash
demos/88-signaturdienst.sh          # first run registers the VM "cloudvm" (purpose deploy)
python3 agent/remote.py init --host NAME            # on the VM: sign-in key
python3 tools/remote-setup.py add NAME --purpose deploy --client-pub client_pub.pem --ip 203.0.113.7
python3 agent/remote.py sign FILE --purpose deploy -o FILE.sig
```

Compared with the TPM: revocation takes effect on the next request (no ticket that has to expire) and the
count cannot be falsified. In exchange the VM's identity rests on a copyable sign-in key; sender binding, limit
and revocation contain the damage but do not stop an attacker *on* the VM from having things signed until then.
With `KEYLEASH_KEYSTORE=nethsm`, `remote-setup.py` creates the keys in the NetHSM (asks for the administrator
passphrase), otherwise as files under `state/server/remote/` (lab only).

## Quick start

```bash
cd ~/keyleash-lab
chmod +x *.sh */*.sh */*.py     # execute bits get lost when copying
sudo ./setup.sh                  # packages, group tss; then log out and in again
demos/00-pruefen.sh              # look at the TPM (read-only)
tools/server.sh foreground       # server in its own terminal, decisions live
demos/alle.sh                    # all scenarios in a second terminal
```

The default is the **real TPM** (`KEYLEASH_TPM=hw`). To try things safely first, or on a machine
without a TPM: `sudo ./setup.sh --swtpm`, set `KEYLEASH_TPM=swtpm` in `keyleash.env`, then
`tools/swtpm-start.sh` and `demos/alle.sh`.

## What happens in the TPM

| Element | Implementation | Purpose |
|---|---|---|
| Machine key | RSA-2048, `fixedtpm\|fixedparent\|sensitivedataorigin\|sign`, **without** `userwithauth` | non-exportable, usable only through the policy |
| Key policy | `PolicyAuthorize(authz server, policyRef=host)` → `PolicyAuthValue` | only with a signed authorisation; process secret for level 1 |
| Ticket (approved policy) | `PolicyCounterTimer(clock ≤ expiry)` → `PolicyCounterTimer(resetCount ≤ limit)` → `PolicyCounterTimer(safe = YES)` → `PolicyPCR(7,16)` | lifetime, reboot limit, safe clock, boot state |
| Ticket after an unsafe clock | `PolicyCounterTimer(clock ≤ expiry)` → `PolicyCounterTimer(resetCount = current)` → `PolicyPCR(7,16)` | valid for this boot only, see "The TPM clock as a sensor" |
| Enrolment | EK → AK, `MakeCredential/ActivateCredential`, `TPM2_Certify` of the key by the AK | key attestation towards the CA |
| Renewal | `TPM2_Quote` over PCRs with a server nonce; clock and resetCount come signed inside the quote | attestation + request |

The server needs no TPM itself: it computes policy digests in Python (`lib/kl/tpmstruct.py`).
`tests/test_policy.sh` cross-checks them against TPM trial sessions.

## Demos

| Script | Shows | Expected result |
|---|---|---|
| `00-pruefen.sh` | tools, vendor, clock, PCRs, lockout counter | read-only |
| `10-provisionieren.sh` | enrolment, key attestation, certificate | `--neu` starts over |
| `20-signieren.sh` | normal operation + 3 attacks: password instead of policy, forged ticket, stretched ticket | the TPM refuses all three |
| `30-ablauf.sh [s]` | ticket expires, no renewal | TPM refuses (PolicyCounterTimer) |
| `40-sperrung.sh [s]` | admin revokes; last ticket valid until expiry | renewal denied, then the TPM refuses |
| `50-manipulation.sh` | PCR 16 extended (simulated tampering) | ticket useless immediately, server alerts |
| `60-parallel.sh` | duplicate request, replay | alerts `too_frequent_parallel_instance`, `nonce_invalid_replay` |
| `65-signaturen.sh [n]` | signature counting: learning phase, then an outlier with a new purpose | warning `new_signing_purpose`, alert `signature_volume_anomaly` |
| `67-freigabe.sh` | purpose `release` only with approval from a second system: none, forged, regular, reused, tampered build, bypass with full access | only the regular path signs; the TPM checks the approval itself |
| `70-neustart.sh` | reboot limit | simulated with swtpm; real reboots on hardware, see below |
| `72-uhr.sh` | TPM clock as a sensor: power loss, snapshot/clone, paused VM (swtpm only) | old ticket refused, ticket for this boot only; alert `tpm_counter_went_backwards`; warning `tpm_clock_drift` |
| `75-herzschlag.sh` | agent goes silent | alert `renewal_missed` |
| `80-siem.sh` | report on all decisions | |
| `85-webserver.sh` | WordPress without a database password: copy the short-lived certificate, revoke, let it expire | copy usable only until expiry, then the site returns 503; after `tools/webdemo.sh setup` |
| `86-admin-arbeitsplatz.sh` | admin SSH only with a short-lived certificate from the workstation: copy, revoke, reinstate | session ended after 0.4 s, copy refused; after `tools/admindemo.sh setup` |
| `87-rdp.sh` | RDP only through the tunnel with a short-lived certificate: sign in, revoke, reinstate | tunnel cut, session logged off; after `tools/rdpdemo.sh setup` |
| `88-signaturdienst.sh` | signing service without a TPM: key in the NetHSM, server checks, counts, revokes | stolen sign-in key, replay, foreign purpose refused; immediate revocation; limit 10 |
| `90-haertung.sh` | hardening level 1 | after `sudo harden/harden.sh`, needs `/dev/tpmrm0` |

**Reboot limit on real hardware:** `demos/70-neustart.sh` saves a ticket with a 1 h lifetime.
After every reboot run `demos/70-neustart.sh check`. After `KEYLEASH_MAX_RESETS`+1 reboots the TPM
refuses. Keep the server stopped meanwhile, otherwise fresh tickets are issued.

Server administration: `tools/server.sh hosts | revoke HOST | unrevoke HOST | rebaseline HOST | sigreset HOST | siem`.
`rebaseline` after a legitimate firmware/Secure Boot update: the next quote becomes the new baseline.
`sigreset` clears the learned signature volume of a host and releases a host blocked because of an outlier.

## Signature counting

Agent and signing service count every signature and report count and purposes with each renewal.
The server learns the median of signatures per renewal and raises an alert when a report exceeds
`KEYLEASH_SIG_FACTOR` × median (at least `KEYLEASH_SIG_MIN_ALARM`), and when a purpose appears that
was never seen before. With `KEYLEASH_SIG_DENY=1` the ticket is denied in that case. The target is the
signing oracle: an attacker who uses the legitimate signing environment.
New purposes are additionally summed over a time window (`KEYLEASH_SIG_WINDOW`, default 3600 s): if the sum
exceeds `KEYLEASH_SIG_MIN_ALARM` an alert is raised, even when the burst is spread over several renewals
(finding of 1 Nov 2026: 9 + 6 signatures each stayed under the per-renewal limit). `sigreset` also resets the
known purposes. Purposes `cert-…` are counted by the server at issuance and are exempt.
Limit: the count is reported by the process itself. An attacker controlling that process can report
lower numbers; the count becomes reliable only inside the protected signing service (level 1 against
ordinary processes, level 2 also against root).
Research item: the TPM's command audit (a signed hash chain over every `TPM2_Sign`) could make the count
tamper-evident even without the protected service – not yet investigated.

## Safety on a real TPM

- The lab stores **nothing permanently in the TPM**: no persistent handles, no NV indices, no
  `tpm2_clear`, no change to owner/endorsement passwords. Keys live as encrypted blobs in `state/`
  and are worthless after `./teardown.sh`.
- Requirement: owner and endorsement hierarchy without password (the default on Linux).
- **Dictionary-attack protection:** the demos never try wrong passwords (attack 1 fails on the
  missing policy, which does not count). A hard power-off while the TPM is in use does count as a
  suspicious event. `demos/00-pruefen.sh` shows the counter.
- PCR 16 is the debug PCR, freely resettable, used by no system component. PCR 7 (Secure Boot) is
  only read.
- `KEYLEASH_TRACE=1` in front of a command shows every tpm2-tools call.

## Hardening level 1

```bash
tools/server.sh start
sudo harden/harden.sh                  # service keyleash-signer, own identity <host>-signer
demos/90-haertung.sh
sudo harden/unharden.sh                # full removal
```

| Measure | Implementation |
|---|---|
| separate process, separate user | systemd service `keyleash-signer`, user `keyleash`, code owned by root in `/opt/keyleash` |
| isolate memory | secret in `memfd_secret` (fallback `mlock`+`MADV_DONTDUMP`), `PR_SET_DUMPABLE=0`, `LimitCORE=0` |
| bind TPM access to the process | `PolicyAuthValue`: without the secret even a valid ticket is useless; `DeviceAllow=/dev/tpmrm0` |
| block debuggers | AppArmor `deny ptrace`; optionally `--ptrace-lock` (`ptrace_scope=3`, **irreversible until reboot**) |
| signing decision inside the protected process | the service signs only purposes from `KEYLEASH_SIGN_PURPOSES` (`/etc/keyleash/signer.env`) |
| systemd isolation | `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`, empty capabilities, `MemoryDenyWriteExecute` … |

Optional `--tss-entziehen`: your user loses direct TPM access, only the service keeps it. The lab
demos then only run with `sudo`.

## Approval by a second system

For particularly valuable purposes (default: `release`) a host gets a separate key
(`agent.py enroll-purpose release`). Its tickets additionally contain **PolicySigned**: the TPM signs
only if the approval key of that purpose has approved the **cpHash of exactly this signing call**,
i.e. key and data hash. Flow:

1. `agent.py request FILE --purpose release -o REQUEST` on the signing system
2. `tools/approve.py approve REQUEST --file OWN_COPY` on the second system: checks its own copy and
   approves only if the hash matches (`tools/approve.py init release` creates the approval key)
3. `agent.py sign FILE -o SIG --purpose release --approval APPROVAL`

Because the server writes the condition into the ticket via PolicyAuthorize, new rules need no
re-enrolment. Without the approval key, even root on the signing system cannot sign.
Limit: the approver only protects if it checks independently (own copy, ideally a reproducible build
on a separate system). In the lab the approval key lives in `state/approver/` on the same machine; in
production it belongs on another system or a hardware token.

## The TPM clock as a sensor

A ticket's lifetime is tied to `clock`, not `time`. `time` restarts at every boot; `clock` is
persistent and the owner can only move it forward (which only shortens a ticket). The TPM persists
`clock` only every `TPM2_PT_CLOCK_UPDATE` milliseconds, though (`tpm2_getcap properties-fixed`).
After a hard power loss the clock restarts at the persisted value and reports `safe = NO`. Cutting
power repeatedly could stretch a ticket that way.

**Measured on gmkbox (Intel PTT, vendor INTC): `TPM2_PT_CLOCK_UPDATE = 0x400000`, i.e.
4,194,304 ms ≈ 70 minutes** (swtpm for comparison: 4096 ms). With the defaults (lifetime 600 s,
`KEYLEASH_MAX_RESETS=2`), a ticket could be stretched by up to about 140 minutes with two well-timed
power cuts if there were no countermeasure, roughly 15 times its lifetime, without the server
noticing. Consequence of the countermeasure: after a power loss the TPM may report `safe = NO` for
up to 70 minutes. During that time only tickets for the current boot are issued. With a server
connection nothing changes for the user; without one, no ticket survives a reboot in that window.
Orderly reboots are unaffected because the TPM persists the clock on `TPM2_Shutdown`.
Side effect: `tpm_clock_unsafe` in the SIEM reveals hard power losses, orderly reboots do not.

Three countermeasures are implemented:

1. **The ticket requires `safe = YES`** (`PolicyCounterTimer`, offset 24, equality). After a power
   loss the old ticket is useless immediately; the TPM checks this itself.
2. **Ticket for this boot only.** If the quote reports `safe = NO`, the server issues a ticket with
   `resetCount = current` instead of `≤ limit` and without the safe condition. Without a reboot the
   clock cannot fall back, so nothing can be stretched. SIEM: warning `tpm_clock_unsafe`.
   `KEYLEASH_UNSAFE_CLOCK=deny` refuses instead.
3. **The renewal stream as a sensor.** The server compares every quote with the last one seen:
   - `resetCount` lower, or same boot and `clock` lower: a second, older TPM state (snapshot, clone,
     replay). Alert `tpm_counter_went_backwards`, no ticket.
   - New boot, `clock` below the last value seen, but `safe = YES`: alert `tpm_clock_rollback`,
     ticket for this boot only (`KEYLEASH_CLOCK_ROLLBACK=deny` refuses). Per the specification,
     `safe = YES` means no greater value was ever reported. A cloned state rebooted several times
     looks like this. In testing, swtpm also reports this after `kill -9`, so the default is not a
     hard refusal. To be verified on gmkbox with the real TPM.
   - Same boot and same `restartCount`: the TPM clock must have advanced about as far as the server
     clock. If it deviates by more than `max(KEYLEASH_CLOCK_TOLERANCE, KEYLEASH_CLOCK_DRIFT × interval)`,
     the server reports `tpm_clock_drift` (paused VM, snapshot, migration). Warning only, because live
     migration and some sleep states trigger it as well.

Side finding from testing: a hard power loss increments the TPM's lockout (DA) counter. Many power
losses in a row lock all DA-protected keys until the lockout owner resets the counter. The demo
therefore resets it immediately. In production this belongs in the runbook.

## Prior art and differentiation

Result of a research pass in October 2026 (report "Comparable solutions to keyleash", German). In short:

- **Known:** the TPM building blocks (PolicyAuthorize, PolicyCounterTimer, PolicySigned with
  expiration, all TCG standard; *A Practical Guide to TPM 2.0*, 2015, ch. 14, already shows an
  admin-signed policy bound to one boot cycle), revocation by non-renewal (Topalovic/Boneh 2012,
  IETF STAR, noRevAvail), key release after attestation (AWS Nitro/NitroTPM, Azure SKR, Google
  Confidential Space, CoCo Trustee) and allowlisting (fapolicyd, WDAC, ThreatLocker).
- **The common market pattern:** the TPM is a join-time anchor (SPIRE `tpm_devid`, Teleport, Vault
  TPM auth, AWS IAM Roles Anywhere, Smallstep); afterwards credentials live in software, or the TPM
  key is at most password-protected. An attacker with root can then use it as a signing oracle.
  Expiry is enforced by the relying party, not by the TPM (Entra PRT, DBSC).
- **Not found:** the combination of (a) expiry enforced by the host's own TPM, i.e. revocation at key
  level even against root holding a copy of the key blob, (b) the renewal and signing stream as a
  sensor (resetCount, restartCount, clock, safe, parallel instances, signature volume and purpose)
  and (c) purpose-bound approval from a different trust domain that the TPM itself checks via
  `PolicySigned` with cpHash. Medium confidence; no patent database search.
- **Positioning:** keyleash complements SPIRE, Vault and Keylime and fits the "credential broker"
  role in `draft-bdnr-rats-trustworthy-credentials`, extended by revocation through non-renewal.
  What is new is the system design and its analytics layer, not the TPM mechanics.
- **Patents:** have Microsoft US11316693B2 (TPM policy with a usage counter) and US12452054B2
  (renewing an attestation artefact within a boot session) checked by a patent attorney before
  publishing further details. A variant "at most n signatures per ticket" via an NV counter would come
  close to the first one and is deliberately not implemented here. This is a technical prior-art
  scan, not a legal assessment.
- **Adopted from the research:** `clock` instead of `time`, `safe = YES` or a pinned resetCount,
  clock signals (see above), graded reactions instead of hard denial for ambiguous signals. Open:
  PolicySigned with expiration as an alternative for single sensitive operations, a learning phase
  for the clock tolerance, grading per Keylime enhancement 46 for the IMA gate.

## Deviations from the concept and open points

1. **resetCount instead of a separate NV counter.** The TPM counts reboots itself
   (`TPMS_CLOCK_INFO.resetCount`) and `PolicyCounterTimer` can check it directly. An NV counter
   incremented by the OS at boot could be bypassed by skipping the increment; resetCount cannot.
2. **Clock after a power loss:** the TPM clock is saved only periodically and can be behind after a
   hard power-off. Tickets therefore require `safe = YES`; after an unsafe clock a ticket is valid for
   the current boot only. Details in "The TPM clock as a sensor" (demo 72).
3. **The EK certificate is not checked** (lab: trust on first use). For a pilot:
   `tpm2_getekcertificate` and validation against the vendor CA.
4. **tpm2_certify** in tpm2-tools 5.x sets no nonce; freshness comes from the quote.
5. **Python signing path:** the secret is briefly copied into heap and pipe when calling `tpm2_sign`.
   For a pilot: signing path in C/Rust directly against tss2-esys.
6. **AppArmor profile:** if the service does not start: `journalctl -u keyleash-signer`,
   `sudo aa-complain keyleash-signer` or `sudo harden/harden.sh --ohne-apparmor`.
7. Not implemented: emergency mode, IMA measurement (needs boot parameters), level 2 (TEE),
   network segment detection across several machines (logic present, `KEYLEASH_ALLOWED_CIDRS`).

## Script and option reference

### Setup and teardown

| Command | What it does |
|---|---|
| `sudo ./setup.sh` | install packages, add your user to group `tss`, check `/dev/tpmrm0` |
| `sudo ./setup.sh --swtpm` | additionally install the software TPM; without `/dev/tpmrm0` it finishes in software TPM mode |
| `./teardown.sh` | stop server and swtpm, delete `state/`, show TPM handles and lockout counter |
| `sudo ./teardown.sh --tss` | additionally remove your user from group `tss` |

### Server and tools

| Command | What it does |
|---|---|
| `tools/server.sh start` / `stop` / `status` | run the authorisation server in the background |
| `tools/server.sh foreground` (or `vorne`) | run it in the foreground and watch decisions live |
| `tools/server.sh log` | follow `state/server.log` |
| `tools/server.sh siem` | follow the SIEM log, formatted |
| `tools/server.sh hosts` | list enrolled hosts and their state |
| `tools/server.sh revoke HOST` / `unrevoke HOST` | block / reinstate a host |
| `tools/server.sh rebaseline HOST` | accept the next boot state as the new baseline |
| `tools/server.sh sigreset HOST` | clear the learned signature volume |
| `tools/server.sh forget HOST` | remove a host completely |
| `tools/swtpm-start.sh` / `reboot` / `stop` | start, simulate a reboot of, stop the software TPM |
| `tools/siem-report.py` | summary of all decisions: per host, alerts, denials by reason |
| `tools/approve.py init PURPOSE` | second system: create an approval key |
| `tools/approve.py approve REQUEST --file COPY [-o OUT] [--yes]` | second system: check own copy and approve |
| `tools/mail-setup.sh [--file P] [--test] [--show] [--delete]` | store SMTP credentials in `keyleash.mail.env` (mode 600, never exported) |
| `tests/test_policy.sh` | Python policy calculation equals TPM trial session |
| `verify/verify.sh FILE SIG CERT CA` | relying party: certificate chain + signature only |

### Agent (`agent/agent.py`)

| Command | What it does |
|---|---|
| `enroll` | create EK/AK, create the machine key in the TPM, get a certificate |
| `renew [--ttl N]` | create a quote and fetch a ticket (shorter lifetime allowed) |
| `loop [--ttl N]` | renew every lifetime/4 (heartbeat) |
| `sign FILE -o SIG [--purpose P] [--approval FILE]` | sign with the machine key (only with a valid ticket) |
| `status` | TPM clock, reset count, signature counts, remaining ticket lifetime |
| `enroll-purpose PURPOSE` | create a purpose key that also needs an approval |
| `request FILE --purpose P -o OUT` | write an approval request for the second system |

### Hardening

| Command | What it does |
|---|---|
| `sudo harden/harden.sh` | install the protected signing service |
| `  --ptrace-lock` | set `ptrace_scope=3` now (**irreversible until reboot**) |
| `  --ptrace-lock-dauerhaft` | also persist it in `/etc/sysctl.d` |
| `  --tss-entziehen` | remove your user from `tss`; only the service keeps TPM access |
| `  --ohne-apparmor` | do not load the AppArmor profile |
| `sudo harden/unharden.sh` | remove everything again |
| `harden/signer-client.py status` / `sign PURPOSE FILE -o SIG` | talk to the signing service |

### Settings (`keyleash.env`)

| Variable | Default | Meaning |
|---|---|---|
| `KEYLEASH_TPM` | `hw` | `hw` = real TPM, `swtpm` = software TPM |
| `KEYLEASH_LANG` | `de` | language of all output: `de` or `en` |
| `KEYLEASH_SERVER` / `KEYLEASH_LISTEN` | `127.0.0.1:8740` | server address for agent / server |
| `KEYLEASH_TTL` | `600` | maximum ticket lifetime (s, TPM clock) |
| `KEYLEASH_MAX_RESETS` | `2` | reboots allowed per ticket |
| `KEYLEASH_MIN_INTERVAL` | `5` | minimum interval between requests of one host (s) |
| `KEYLEASH_GRACE` | `10` | grace period before a missed renewal raises an alert (s) |
| `KEYLEASH_UNSAFE_CLOCK` | `pin` | quote reports `safe = NO`: `pin` = ticket for this boot only, `deny` = refuse |
| `KEYLEASH_CLOCK_ROLLBACK` | `pin` | clock behind after a reboot despite `safe = YES`: `pin` = alert and ticket for this boot only, `deny` = refuse |
| `KEYLEASH_CLOCK_TOLERANCE` | `30` | allowed difference between TPM clock and server clock between two renewals (s) |
| `KEYLEASH_CLOCK_DRIFT` | `0.05` | additionally allowed relative difference |
| `KEYLEASH_PCRS` | `sha256:7,16` | PCRs bound into the ticket |
| `KEYLEASH_ALLOWED_CIDRS` | private ranges | network segments allowed to request tickets |
| `KEYLEASH_WINDOW` | `00:00-24:00` | operating window (outside: warning) |
| `KEYLEASH_ENROLL_TOKEN` | `lab-enroll` | shared enrolment token (lab only) |
| `KEYLEASH_SYSLOG` | `0` | `1` = also send decisions to syslog |
| `KEYLEASH_SIG_FACTOR` | `5` | outlier above median × factor |
| `KEYLEASH_SIG_MIN_ALARM` | `10` | never alert below this volume |
| `KEYLEASH_SIG_MIN_SAMPLES` | `3` | reports needed before the median applies |
| `KEYLEASH_SIG_CAP` | `100` | fixed limit during the learning phase |
| `KEYLEASH_SIG_DENY` | `0` | `1` = deny the ticket on an outlier |
| `KEYLEASH_APPROVAL` | `release=state/approver/release_pub.pem` | purposes requiring approval and their public approval keys |
| `KEYLEASH_TRACE` | unset | `1` = print every tpm2-tools call |
| `KEYLEASH_KEYSTORE` | `file` | `nethsm` = ticket and CA keys in a Nitrokey NetHSM |
| `KEYLEASH_NETHSM_URL` / `_USER` / `_PASS_FILE` | – | NetHSM address, Operator user, passphrase file (set by `tools/nethsm-setup.py import`) |
| `KEYLEASH_NETHSM_CA` / `_INSECURE` | – | CA file for the NetHSM's TLS certificate / `1` = no TLS check (lab only) |
| `KEYLEASH_NETHSM_AUTHZ_KEY` / `_CA_KEY` | `keyleashauthz` / `keyleashca` | key IDs in the NetHSM |
| `KEYLEASH_DATA_URL` | `http://127.0.0.1:8741` | data API for the dashboard demo |

### SIEM events

| Event | Severity | Meaning |
|---|---|---|
| `enroll_started` / `enroll_succeeded` | info | enrolment |
| `ticket_issued` | info | ticket issued, with reported signatures and purposes |
| `ticket_denied` | warn/alert | ticket refused, `reason` says why |
| `request_denied` / `request_malformed` | warn/alert | other refused or invalid requests |
| `renewal_missed` | alert | heartbeat missing |
| `new_signing_purpose` | warn | purpose never seen before |
| `signature_volume_anomaly` | alert | signature volume outlier |
| `many_reboots` | alert | more reboots than allowed since the last ticket |
| `tpm_clock_unsafe` | warn | quote reports `safe = NO` (power loss); ticket for this boot only |
| `tpm_clock_rollback` | alert | new boot, clock below the last value despite `safe = YES` (clone?) |
| `tpm_clock_drift` | warn | TPM clock and server clock diverge within one boot (paused VM, snapshot, migration) |
| `outside_operating_window` | warn | request outside `KEYLEASH_WINDOW` |
| `baseline_updated` | warn | new boot state accepted after `rebaseline` |
| `purpose_key_created` | info | purpose key with approval enrolled |
| `admin_*` | warn | administrative action |

Denial reasons include `host_revoked`, `boot_state_mismatch_tampering`, `too_frequent_parallel_instance`,
`nonce_invalid_replay`, `tpm_counter_went_backwards`, `tpm_clock_unsafe`, `tpm_clock_rollback`, `unexpected_network_segment`, `unknown_host`.

## Files

```
keyleash.env           central settings (TPM mode, language, lifetimes, PCRs, window)
setup.sh / teardown.sh setup / teardown
server/authz_server.py authorisation server + CA + SIEM log
agent/agent.py         agent: enroll | renew | loop | sign | status | enroll-purpose | request
lib/kl/                TPM structures, policy calculation, helpers, i18n.py (language)
lib/i18n.sh            language switch for shell scripts
verify/verify.sh       relying party (OpenSSL)
demos/                 scenarios 00–90
harden/                hardening level 1 (service, systemd unit, AppArmor)
tools/                 server.sh, swtpm-start.sh, siem-report.py, approve.py, mail-setup.sh
tests/test_policy.sh   Python policy == TPM trial session
state/                 runtime data (deleted by teardown.sh)
```

## Video (demos/reel.sh, tools/reel.tape)

Short version for the website: seven scenes in about a minute and a half (new: 6 split signing burst, 7 cloud VM without a TPM using the signing service/NetHSM), without TPM commands, error codes, paths
or host names. Runs separately from the lab (state in `state/reel/`, server on port 8742, host
`build-server-01`).

    demos/reel.sh all              # rehearse in the terminal
    vhs tools/reel.tape            # record -> keyleash-reel-en.mp4

Install `vhs` (Linux Mint/Ubuntu):

    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
    echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list
    sudo apt update && sudo apt install vhs ffmpeg ttyd

## License

Copyright (c) 2026 Christian Scheller.

keyleash is free software: you can redistribute and modify it under the terms of the **GNU Affero General
Public License**, version 3 or (at your option) any later version (`AGPL-3.0-or-later`, full text in
`LICENSE`). It comes without any warranty.

If you run a **modified** version as a network service, for example the keyleash server, you must offer its
users the source code of that modified version (AGPL, section 13). Exception: `webdemo/db.php` and
`webdemo/db-error.php` are WordPress drop-ins under GPL-2.0-or-later. Third-party software: `NOTICE`.
Contributions: `CONTRIBUTING.md`; please report vulnerabilities privately: `SECURITY.md`.
