# appman-ios

Sign and install iOS apps on **your own iPhone** with a **free Apple ID**, from Windows, macOS or Linux,
**over Tailscale**: no Mac, no Xcode, and a cable only for the first pairing. One binary, `appman`.

```
appman setup                      # Apple ID (password goes to the OS keychain)
appman pair my-iphone --usb       # once, over a cable; the phone shows a code
appman deploy MyApp.ipa           # sign + install over Tailscale
```

## What you need

* An iPhone with **Developer Mode** on (Settings → Privacy & Security), and **Tailscale** running on
  both the phone and this computer, on the same tailnet.
* A free Apple ID. A paid account works too.
* An unsigned or ad-hoc-signed `.ipa`, for example from a GitHub Actions macOS runner.
* For the one-time USB pairing: iTunes on Windows (for Apple's USB driver), nothing extra on macOS,
  `usbmuxd` on Linux. iPhones cannot be paired over the network the first time; every tool needs the
  cable once.

After pairing, the phone is reachable **anywhere on your tailnet** and on the **local Wi-Fi**: use its
LAN address as the host when Tailscale is off.

Download `appman` from [Releases](../../releases) or `cargo install --git https://github.com/collinsomniac/appman-ios`.

## Commands

| command | what it does |
|---|---|
| `appman setup` | Saves your Apple ID; the password is stored in the OS keychain, never on disk. |
| `appman pair <host> --usb` | Pairs once over USB. The phone asks to Trust, then shows a code. Afterwards `<host>` (Tailscale name or LAN address) is used over the network. |
| `appman deploy <ipa> [--as SLOT] [--name NAME]` | Signs and installs. |
| `appman sign <ipa> -o out.ipa` | Signs only. |
| `appman install <ipa>` | Installs an already signed IPA. |
| `appman apps` | Lists the apps you installed. |
| `appman crash <executable>` | Saves the app's crash reports and prints the newest one's exception and backtrace. |
| `appman slot <name> <bundle-id>` | Names an app ID slot for `--as`. |
| `appman status` | Configuration, pairing, cached profiles and their expiry, sign-in guard. |
| `appman doctor` | Checks everything a deploy needs (keychain, saved session, anisette, the phone's reachability, profiles) without signing in, and says what to fix. |
| `appman refresh [--days N] [--all]` | Re-signs and reinstalls every library app whose profile expires within N days (default 2), with one Apple session for all. |
| `appman logout` | Forgets the saved Apple session. |

## How signing works (and why it rarely needs your password)

* The **first** signing of an app ID needs Apple: it registers the app ID and caches the provisioning
  profile Apple returns (free profiles last 7 days).
* **Apple sessions are reused.** The first time appman needs Apple it signs in (password from the keychain,
  and a 2FA code if Apple asks), then keeps the session Apple issued in the OS keychain. Later online
  signings resume it, using the cached Xcode token while it lasts, then a new one derived from the session:
  no password, no 2FA, one request. Only if Apple refuses the session does appman sign in again.
  The anisette machine identity is kept per server too, so Apple keeps seeing the same "device".
* **Library and refresh.** Each `deploy` keeps the unsigned IPA. `appman refresh` re-signs and
  reinstalls whatever is close to expiry, resuming one session for all of it. That's the weekly routine.
* Every later signing of that app ID is **offline**: the cached profile plus the certificate key in your
  keychain. No sign-in, no 2FA, no network. `appman status` shows how long each profile has left.
* **Sign-in guard.** Apple locks accounts that see repeated failed or unusual sign-ins. After a failed
  sign-in appman waits an hour before allowing another, stops after 3 failures in 24 hours, and refuses
  entirely once Apple reports the account locked. Use `--force-signin` to override it, for example
  after unlocking the account at iforgot.apple.com.
* **2FA.** Apple pushes a code to your trusted devices: tap Allow there and type the code when appman
  asks. Or set `APPMAN_2FA_FILE=<path>` and write the code to that file, so an agent, or you from another
  device, can supply it.
* **Certificates are never revoked silently.** appman reuses the development certificate whose key is in
  your keychain. If both of the account's certificates belong to other tools or PCs, it stops and says so;
  `--revoke-cert` replaces one, and every app that certificate signed stops launching.

## More than one app

Each app on the phone needs its own app ID (its bundle ID with your team suffix). A free Apple ID allows:

* **3 apps with live free profiles installed at once** (iOS enforces this on the device),
* **10 new app IDs per rolling 7 days** (app IDs you already have don't count again),
* **2 development certificates**, shared by every app and every tool that signs for the account.

So to add an app, give it its own slot and deploy it once; appman registers the ID. From then on, refreshing
reuses that ID and doesn't spend the weekly quota. To swap apps within the 3-app limit, reuse a slot
with `--as`.

```
appman slot cogitator io.example.cogitator
appman deploy Cogitator.ipa --as cogitator
```

## App ID slots (`--as`)

A free account can register only **10 app IDs per 7 days**, and the phone identifies an installed app
only by its bundle ID. `--as` signs any app under an app ID you already have, **replacing** whatever is
installed under it. Everything else is the new app's own: its code, home-screen name and icon. Use
`--name` to change the home-screen name.

```
appman slot morph io.example.morph
appman deploy Experiment.ipa --as morph --name "Experiment"
```

The replaced app's data is deleted.

## Notes

* **Memory:** free profiles include `com.apple.developer.kernel.increased-memory-limit` when the app
  requests it, and appman keeps it, so the app gets about 6 GB instead of about 3 GB.
* **Already using iloader?** `appman setup --keyring-service iloader --machine-name iloader` reuses its
  saved password and development certificate. A free account has only 2 certificates; making a third
  revokes one, and every app signed with the revoked certificate stops launching.
* **Already paired with pymobiledevice3?** `appman pair <host> --import-pymobiledevice3 <UDID>` reuses
  that pairing.
* **State** lives in `%APPDATA%\appman` (Windows), `~/Library/Application Support/appman` (macOS) or
  `~/.config/appman` (Linux); set `APPMAN_HOME` to move it. Set `APPMAN_LOG=debug` for verbose output.

Background, the approaches that were tried, comparisons with other tools, and the roadmap: [NOTES.md](NOTES.md).

Built on [isideload](https://github.com/nab138/isideload) (Apple sign-in and signing) and
[idevice](https://github.com/jkcoxson/idevice) (pairing, tunnel, install). Not affiliated with Apple.
