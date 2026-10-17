# NOTES: why appman exists, what was tried, and what we know

This file is the institutional memory behind appman. It condenses roughly three weeks (Oct 2026) of
work spread over four repositories, about 160 one-off scripts and a dozen research reports into what is
still true and useful. Read it before changing how appman signs, pairs or installs.

## 1. Why consolidate

Before appman, getting an IPA from CI onto one iPhone touched:

| piece | what it was | problem |
|---|---|---|
| a patched iloader fork | GUI sideloader with a memory-entitlement patch | GUI-only; an agent cannot drive it |
| `loopdeploy` (Rust) | isideload wrapper: `sign`, later `serve` (queue) and `resign` (offline) | signing only; hard-coded Apple ID default; name inherited from an unrelated LLM project |
| `pack_ipa.py`, `install_signed.py`, `deploy.py`, `crash_latest.py`, ... | Python on pymobiledevice3 (needs Python 3.13 exactly) | each hard-coded one app (LoopLab or Nabla), a UDID, an IP |
| Sideloadly + UI Automation | `sideloadly_auto.ps1`, `_export.ps1`, IPC and database probes | GUI-only; probing found no CLI, no IPC API, no queue |
| `agent-ios-ipas` | docs and 156 tools collected from the rig | mixed research, scratch output and app-specific scripts |

**Why there were so many one-off scripts.** Agents drove everything from an iPhone shell over SSH/Tailscale
into a Windows PC, and each constraint produced another script:

* **Windows session isolation.** Credential Manager, GUI and UI Automation are unreachable from SSH
  (error 1312). Every keyring or GUI step became a `.cmd` launched with `schtasks /run` in the desktop
  session, with output written to a `.txt` file for the agent to read back.
* **No working local toolchain** (0-byte Rust stubs, Python 3.12 vs 3.13). Small programs were
  rebuilt in CI or rewritten as Python probes.
* **Apple-side incidents** (§4) arrived every few days. Each produced probes, canaries and rankers
  (`login_watch.py`, `anisette_rank.py`, `canary.cmd`) aimed at a moving target.
* **Diagnosis by experiment.** Every hypothesis became a numbered script (`sign2.cmd`, `sign3.cmd`,
  `uia3.cmd`) that was never deleted or generalised.

**What appman changes:** one binary, one config file, no app names in code. App identity is data
(`--as <slot>`); device identity is data (`appman pair`); secrets stay in the OS keychain.

## 2. Architectures tried, in order

1. **iloader GUI** (+ `iloader-memfix`): fine for a human, useless for an agent.
2. **loopdeploy `sign`** → `pack_ipa.py` → `install_signed.py` over a pymobiledevice3 RemotePairing
   tunnel on Tailscale. Worked end to end (Oct 10). Weak points: a full Apple sign-in on every build,
   three languages, hard-coded IDs.
3. **Sideloadly as signer** (Oct 12–13, during `-80045`): its *local* anisette kept working. It
   failed as an agent tool: GUI-only, localhost port 28811 exposes only `/raise`, its database ignores
   queued rows, the certificate cannot be extracted, and its refresh daemon only renews apps that it
   installed itself.
4. **loopdeploy `serve`**: one sign-in per session, then a watched queue folder, with 2FA through a file.
   Fewer sign-ins, but still remote anisette.
5. **loopdeploy `resign`**: offline signing with the cached certificate key plus a cached
   provisioning profile. This is the breakthrough: no Apple contact for 7 days per app ID.
6. **appman** (Oct 17): (5) made the default, install/apps/crash rebuilt natively in Rust on idevice
   (no Python), pairing and slots added, and a sign-in guard.

## 3. Hard-won facts (keep these)

### Signing
* **Team suffix.** A free team's app ID is `<bundle-id>.<TEAM_ID>`. An IPA still carrying the base ID
  fails to install with `0xe8008016` ("invalid entitlements"). Rewrite `CFBundleIdentifier` (and the
  extension IDs under it) **on disk before signing**: isideload's in-memory plist edit never reaches
  the repacked IPA.
* **A profile embeds its certificate.** With the cached private key, a still-valid
  `embedded.mobileprovision` is enough to re-sign offline. appman caches each profile after an online
  signing.
* **Free-account limits:**
  * 7-day profiles. The certificate lasts about 1 year.
  * 2 development certificates. A third revokes one, and every app signed with the revoked
    certificate stops launching.
  * 10 App IDs per rolling 7 days. **Each app extension needs its own App ID.**
  * **3 sideloaded apps active at once.** That is why slots (`--as`) matter.
* **Entitlements.** `com.apple.developer.kernel.increased-memory-limit` *is* granted to free teams
  (about 6 GB instead of about 3.25 GB) when the app requests it. `extended-virtual-addressing` is not.
  SideStore strips the memory entitlement on free teams; isideload and Impactor keep it.
* **IPA packaging.** Keep the `Payload/` prefix, unix permission bits and symlinks. Python's `zipfile`
  defaults entries to mode 0600, which makes the main binary non-executable.
* **Refresh does not have to mean reinstall.** AltStore and SideStore install a fresh *profile* for an
  existing app ID (misagent). The app binary and its data stay untouched.

### Apple sign-in (GrandSlam) and anisette
* **Anisette** headers prove a provisioned "machine". `X-Apple-I-MD-M` plus the persisted ADI blob are
  the identity; `X-Apple-I-MD` is a one-time password that lasts about 60 s. A remote anisette server only
  does the arithmetic. **The identity is the state you persist**, and deleting it mints a new one.
* **Error map:**
  * `-80009` "MID is invalid": no anisette.
  * `-80045` "This action cannot be completed at this time": identity or client-info rejected, at
    SRP step 1, before the password is checked.
  * `-20209`: account locked.
  * `-22406`: wrong password, or too many fresh sign-ins.
  * `-22411`: account needs verification (classic).
  * HTTP 503/429 at the edge: often random. Retry with backoff, don't loop.
* **Oct 2026 timeline** (why this layer must not be hard-coded):
  * Sep: the edge blocks the `com.apple.dt.Xcode` client-info prefix (503).
  * Oct 12: the GrandSlam check starts requiring client-info to match the identity family (Android
    ADI must say Android) → `-80045` everywhere.
  * Oct 13: isideload 0.4.5, xtool 1.22.2 and iloader 2.3.7 claim Android.
  * Oct 14: Android client-info starts returning 503. isideload 0.4.6 fetches client-info from the
    anisette server instead.
  * Oct 16: iloader 2.3.9 moves to `mac-ani.jkcoxson.com`.
  * Oct 17: Impactor 2.7.1 switches to a Windows iTunes identity. Sideloadly's *local* anisette
    (Apple's own Windows DLLs) kept working throughout.
* **Don't stack attempts.** On Oct 17, five sign-ins in 25 minutes across three anisette servers
  ended in `-20209` (account locked). appman's guard enforces this: one hour after a failure, at most
  three failures a day, and no sign-in at all after a lock until `--force-signin`.
* **Anisette identity per server.** An identity provisioned through one server is rejected through
  another (`-45025`, or the client-info mismatch). appman keeps one state folder per server.

### Device transport
* **RemotePairing (TCP 49152)** answers on every interface the phone is on, **including Tailscale**.
  Pair-verify, then a TLS-PSK tunnel with a userspace TCP stack, then RSD, then services. Services over
  RSD carry a `.shim.remote` suffix. iOS 18.2 and later dropped QUIC, so the tunnel is TCP.
* **Lockdown (62078)** works on the LAN once Wi-Fi sync is on, but **not over Tailscale**. This is
  the path Sideloadly and iTunes use (usbmuxd + Bonjour).
* **Bonjour/mDNS does not cross Tailscale.** Address the phone by its Tailscale name. On the LAN, an
  mDNS query socket must bind 5353 and join 224.0.0.251, or it never sees answers.
* **First pairing needs USB once.** iPhones don't advertise `_remotepairing-manual-pairing` (only
  Apple TV / Vision Pro do). After one USB pairing, LAN Wi-Fi and Tailscale both work. A *new*
  RemotePairing connection needs the phone unlocked.
* **Private Wi-Fi Address** randomises the MAC the phone advertises, which breaks Wi-Fi sync records
  keyed to the hardware MAC. This concerns lockdown/Sideloadly Wi-Fi, not RemotePairing.
* **Stale pairing keys.** iloader cached a RemotePairing label separately from its key pair; the phone
  then terminated pair-verify. Fix: pair again. Never mix records between tools unless the identifier
  matches (pymobiledevice3 uses `uuid3(DNS, hostname)` in upper case; appman's import accounts for that).

### Windows quirks that cost hours
* An SSH session cannot read Credential Manager (1312). Use the desktop session.
* `ssh` pipes corrupted binaries (11.1 MB arrived as 14 or 28 MB). Move files over HTTP and verify hashes.
* PowerShell 5 `Tee-Object` writes UTF-16LE, so `grep` watchers see nothing.
* `start` from Git Bash opens no visible window. Users launch interactive prompts themselves (Win+R).

### iOS 27, app side (not appman, but it will bite every new app)
* Apps that never adopt the **UIScene lifecycle** are killed at launch
  (`_UIApplicationEvaluateRuntimeIssueForNoSceneLifecycleAdoption`). winit 0.30 / Bevy need an
  Info.plist scene manifest plus a delegate class that **declares `UIWindowSceneDelegate`
  conformance**. Without the protocol, UIKit asserts in `-[UIScene initWithSession:connectionOptions:]`.
  `appman crash <exe>` shows these within seconds.

## 4. How appman compares (Oct 17, 2026)

`?` marks cells not verified from source or docs.

| | appman | Impactor / plumesign | Sideloadly | iloader | xtool | AltServer/AltStore | SideStore |
|---|---|---|---|---|---|---|---|
| UI | CLI | GUI + CLI (`plumesign`) | GUI | GUI | CLI | GUI + on-device | on-device |
| Agent-scriptable | **yes**: every step, 2FA via file | partly (sign/install CLI) | no | no | yes (build-centric) | no | no |
| Install over **Tailscale / any network** | **yes** (RemotePairing) | no (usbmuxd: USB, LAN Wi-Fi) | no (LAN only) | USB / LAN | no (usbmuxd) | Wi-Fi LAN | on-device VPN |
| First pairing | USB once (`--usb`), or import | USB | USB, then LAN Wi-Fi | USB | USB | USB | USB + pairing file |
| Offline re-sign within 7 days | **yes, automatic** | manual (`--pem --provision`) | unclear (log says `local: True`) | no | ? | n/a | n/a |
| Session reuse | **no**: full sign-in per online signing | **yes** (stored GS token) | saved credentials | no | ? | saved credentials | yes |
| Anisette | remote v3 (per-server state) | **local (omnisette) + remote** | **local (Apple DLLs)** or remote | remote | remote | local (Apple frameworks) | on-device / remote |
| Profile-only refresh (keeps data) | not yet | yes (`install_profile`) | daemon re-sign | no | no | yes | yes |
| Auto refresh | not yet | scheduler (a day before expiry) | daemon | no | no | yes | yes |
| Slots / app-ID reuse across apps | **yes** (`--as`) | custom bundle ID | manual | no | no | no | no |
| Crash reports / app list | **yes** | app list, utilities | no | no | no | no | no |
| Sign-in guard | **yes** | no | no | no | no | no | no |
| Memory entitlement on free team | yes | yes (picker) | unverified | yes | ? | yes | **stripped** |
| Tweaks / extensions handling | no | **yes** (ElleKit, appex, plugins) | yes | partial | n/a | partial | partial |
| Licence | MIT | MIT | closed | MIT | MIT | AGPL | AGPL |

**What appman fixes:**
* Cable-free install from anywhere (Tailscale), with no iTunes/usbmuxd at install time.
* One sign-in per app ID per 7 days instead of one per build.
* Agent-safe operation: no GUI, every prompt has a file/env alternative, and a guard against locking
  the account.
* App-agnostic. The old scripts assumed one app (LoopLab/Nabla) and one phone.

**Where appman is short-sighted today, honestly:**
1. **A full password sign-in for every online signing.** isideload keeps the session only in memory;
   Impactor stores Apple's GS token and rarely asks for a password.
2. **Remote anisette only.** This is the most fragile layer in the stack. Local anisette (Apple's
   Windows DLLs, or omnisette's local ADI) is what kept Sideloadly and Impactor working through the
   October incidents.
3. **No profile-only refresh and no scheduler.** Today, keeping an app alive means re-deploying it,
   which reinstalls the app.
4. **`pair --usb` is untested on a real cable** (it is idevice's reference flow, and it reaches
   usbmuxd). There is no mDNS discovery on the LAN; you type the host.
5. **Extensions and app groups** are signed by isideload's logic but not verified by appman.

## 5. Build or adopt: where the line is

The stack has three layers that change at very different speeds:

| layer | changes | owner |
|---|---|---|
| Apple sign-in + anisette | **weekly** (Apple fights it) | **adopt**: whoever ships fixes fastest |
| signing + profiles | rarely | adopt a library, keep a thin policy layer (offline cache, slots) |
| device transport + agent workflow | rarely; appman's reason to exist | **build** (appman) |

**Decision.**
* appman keeps the parts no maintained tool offers: RemotePairing over Tailscale, slots, crash/app
  queries, the guard and the agent ergonomics.
* appman must not own the Apple sign-in layer alone. Impactor and isideload both chase Apple, and
  Impactor currently ships fixes within a day.

**When to switch or fork instead of building:**
* If **Impactor gains a network (RemotePairing) device** and stored-token sessions in `plumesign`, appman
  becomes a thin wrapper over `plumesign`, or retires. The cheapest path is to **contribute the
  transport upstream**: Impactor already uses idevice, and appman's `device.rs` is the code it needs.
* If isideload lags Apple by more than a day or two again, put an optional **`plumesign` signing
  backend** behind appman's `sign`. appman keeps the offline cache, slots and install.
* Don't fork Impactor wholesale. Its value is the GUI plus the daily Apple fixes, and a fork loses the
  fixes.

## 6. Roadmap (in order of value)

1. **Session reuse.** Persist the GS token (as Impactor does) so online signing is password-free.
2. **Local anisette** on Windows/macOS, the per-machine identity the October incidents spared.
3. **`appman refresh`.** Fetch a new profile and install it via misagent: no reinstall, data kept.
   Plus a `--schedule` hint for Task Scheduler/cron.
4. **Verify `pair --usb`** on hardware, and add `appman pair --discover` (LAN mDNS).
5. **Report entitlements** after signing (memory limit, app groups), so silent loss is impossible.
6. Upstream the RemotePairing transport to Impactor (see §5).

## 7. Security lessons

The earlier tooling wrote Windows Credential Manager listings (`cmdkey /list`) and raw credential
exports (password, signing key, pairing keys) to plain files in the work folder. One listing was
committed to a public repository. It has been removed, the history rewritten, and the repository made
private. Rules for this repo:

* Secrets live only in the OS keychain. Never `cmdkey /list > file`, never export blobs to disk, never
  bundle tool output for publishing without reading it.
* Print **names, never values**, when diagnosing. Redact before committing.
* Test against a throwaway `APPMAN_HOME`. Never against the real keychain service.
