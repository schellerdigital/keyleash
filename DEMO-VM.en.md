# keyleash lab on a Mac – demo VM guide

Goal: the complete lab runs offline on the Mac, for demonstrations on the road.
The Mac has no TPM; inside the Linux VM a **software TPM (swtpm)** takes its place.
Say so openly in the demo: *"This is a simulated chip; the behaviour is identical. I can show the runs on
real hardware as well."*

This guide uses the existing **Ubuntu 26.04 VM in VMware Fusion** (ARM64). A fresh VM in UTM works the
same way; see the appendix.

---

## What has been verified

| Item | Status |
|---|---|
| All required packages exist for Ubuntu 26.04 ARM64 (tpm2-tools 5.7, swtpm 0.10.1, tpm2-abrmd 3.0.0, libtss2-tcti-swtpm0t64, python3-cryptography 46) | checked in the official package index |
| All demos 00–80 incl. 65, 67, 70 (simulated reboot) run in software TPM mode, freshly unpacked, without a hardware TPM, with Python 3.14 + cryptography 46 | checked: full run of `demos/alle.sh`, ~3¼ minutes, no deviation |
| English output (`KEYLEASH_LANG=en`) for all demos, tools and SIEM events; German unchanged | checked: full run in both languages |
| On the real Mac/VM | **not tested by me**; newer tpm2-tools and swtpm than in my tests |
| Demo 90 (hardening) | **not available** in software TPM mode (needs `/dev/tpmrm0`), see option B |

---

## 1. Check the VM

```bash
lsb_release -d; uname -m
```

Expected: `Ubuntu 26.04` (or 24.04) and `aarch64` (Apple chip) or `x86_64` (Intel Mac). Both work.

## 2. Copy the lab into the VM

Put `keyleash-lab.tar.gz` into your home directory in the VM, e.g. by drag & drop (needs
`open-vm-tools-desktop`) or via a shared folder (VM settings → Sharing; it appears under `/mnt/hgfs/`).

```bash
cd ~
tar xzf keyleash-lab.tar.gz
cd keyleash-lab
```

Keep the lab **directly in your home directory** (`~/keyleash-lab`). With very long paths the software
TPM fails to start with "Socket name too long".

## 3. Set up (once)

```bash
sudo ./setup.sh --swtpm
sed -i 's/^KEYLEASH_TPM=.*/KEYLEASH_TPM=swtpm/; s/^KEYLEASH_LANG=.*/KEYLEASH_LANG=en/' keyleash.env
grep -E '^KEYLEASH_(TPM|LANG)' keyleash.env     # must show swtpm and en
```

`setup.sh` ends with "no /dev/tpmrm0 – the lab runs in software TPM mode". That is correct.

## 4. Start the software TPM and check

```bash
tools/swtpm-start.sh
demos/00-pruefen.sh
```

**After every VM reboot** run `tools/swtpm-start.sh` again. The state of the simulated chip, including
the enrolled key, stays in `state/swtpm/`.

## 5. Dress rehearsal

```bash
demos/alle.sh
```

Takes a bit over 3 minutes. Expected: no "UNEXPECTED", clean finish.

---

## Demo flow (about 10–12 minutes)

| Step | Script | Message |
|---|---|---|
| 1 | `demos/10-provisionieren.sh` | the key is born in the chip, a certificate is issued |
| 2 | `demos/20-signieren.sh` | normal operation – and three attacks the chip itself refuses |
| 3 | `demos/30-ablauf.sh` | without renewal the identity ends on its own |
| 4 | `demos/40-sperrung.sh` | revocation without revocation lists |
| 5 | `demos/50-manipulation.sh` | changed system state → ticket worthless, alert |
| 6 | `demos/65-signaturen.sh` | unusual volume / new purpose stands out |
| 7 | `demos/67-freigabe.sh` | sensitive purpose only with consent from a second system |
| 8 | `tools/server.sh siem` (second terminal) | everything lands structured in the SIEM |

Tips:

- Run `demos/10-provisionieren.sh` once beforehand; in the demo start at step 2.
- Two terminal windows side by side: demos on the left, `tools/server.sh siem` on the right.
- Large font (⌘ +), dark profile.
- Fallback: take the output of the hardware runs on gmkbox as text or screenshots.

### Reset to a clean state before the demo

```bash
tools/server.sh stop
tools/swtpm-start.sh stop
rm -rf state
tools/swtpm-start.sh
demos/00-pruefen.sh && demos/10-provisionieren.sh
```

### Keeper-specific framing

- Step 2 answers *"what if the host is compromised and the key file is copied?"* – there is no key file.
- Step 4 answers *"how fast can we cut off a machine?"* – at the latest when its last ticket expires.
- Step 6 and 7 answer *"what about an attacker using the legitimate signing environment?"* – counted, flagged,
  and for sensitive purposes blocked without a second approval.
- The authorisation server only signs short-lived policies and never sees a secret, so it fits a
  zero-knowledge architecture.

---

## Option B (optional, untested): virtual TPM from VMware Fusion

VMware Fusion can add a **Trusted Platform Module** device to a VM (VM must be encrypted; Settings →
Add Device → Trusted Platform Module). Linux then sees a device `/dev/tpmrm0`, and these work in addition:

- **Demo 90 (hardening)** with systemd service and AppArmor,
- **Demo 70 with a real VM reboot** instead of a simulated one.

What I could **not** verify:

- whether Ubuntu on ARM detects the Fusion vTPM. Check with `ls -l /dev/tpmrm0` after adding it;
- whether `memfd_secret` is active in the VM kernel; demo 90 may then report
  "mlock-fallback … secretmem disabled in the kernel?", the rest of the isolation still works.

Only when `/dev/tpmrm0` exists: set `KEYLEASH_TPM=hw` in `keyleash.env`, run `sudo ./setup.sh`
(without `--swtpm`), log out and in, then proceed as on gmkbox.

Recommendation: set up the software TPM path first – it is tested. Try option B only if time allows.

---

## Appendix: new VM with UTM instead of Fusion

1. UTM, free: <https://github.com/utmapp/UTM/releases>
2. Ubuntu Server for ARM: <https://ubuntu.com/download/server/arm>
3. UTM: + → Virtualize → Linux, 4 GB RAM, 2 cores, 20 GB disk, do **not** tick "Use Apple Virtualization".
4. During installation tick "Install OpenSSH server". If the VM hangs on a black screen after the
   installer's reboot: stop it, eject the ISO, start again (known UTM behaviour).
5. Find the VM address (`ip -4 addr`, usually `192.168.64.x`), copy the archive with
   `scp keyleash-lab.tar.gz user@192.168.64.x:` and continue with step 2 above.

## Sources

- VMware Fusion, TPM device: <https://techdocs.broadcom.com/us/en/vmware-cis/desktop-hypervisors/fusion-pro/13-0/using-vmware-fusion/configuring-your-virtual-machines/add-a-device/configuring-a-trusted-platform-module-device.html>
- UTM, installation: <https://docs.getutm.app/installation/macos/>
- UTM, Ubuntu guest: <https://docs.getutm.app/guides/ubuntu/>
- QEMU, TPM device: <https://www.qemu.org/docs/master/specs/tpm.html>
