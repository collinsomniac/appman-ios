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

## How signing works (and why it rarely needs your password)

* The **first** signing of an app ID signs in to Apple, registers the app ID, and caches the
  provisioning profile Apple returns (free profiles last 7 days).
* Every later signing of that app ID is **offline**: the cached profile plus the certificate key in your
  keychain. No sign-in, no 2FA, no network. `appman status` shows how long each profile has left.
* **Sign-in guard.** Apple locks accounts that see repeated failed or unusual sign-ins. After a failed
  sign-in appman waits an hour before allowing another, stops after 3 failures in 24 hours, and refuses
  entirely once Apple reports the account locked. Use `--force-signin` to override it, for example
  after unlocking the account at iforgot.apple.com.
* **2FA.** Type the code when asked, or set `APPMAN_2FA_FILE=<path>` and write the code to that file.
  That lets an agent, or you from another device, supply it.

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
