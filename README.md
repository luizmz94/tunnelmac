# TunnelMac

Native macOS GUI for the original [openfortivpn](https://github.com/adrienverge/openfortivpn),
for [OpenVPN](https://openvpn.net/community/) 2.7+ profiles (since 0.4.0) and for
[WireGuard](https://www.wireguard.com) configurations through `wireguard-go` (since 0.5.0),
using SwiftUI/AppKit and a bundled SMAppService/XPC privileged helper. Independent
of, and not affiliated with, Fortinet or the openfortivpn project. No VPN executable
or Homebrew libraries are bundled in the distributed app.

Formerly **OpenFortiDesk**: renamed in 0.4.0 because the app is no longer
Fortinet-only.

**Development:** 0.5.0-rc.2, preparing the 1.0.0 stabilization candidate.
The commands below build the current source; the Homebrew tap may still offer an
older published candidate. Check the release page before downloading. Stability,
root lifecycle and the supported macOS matrix still require validation.

## Installation and first use

```sh
brew install --cask luizmz94/tunnelmac/tunnelmac
# Equivalent:
brew tap luizmz94/tunnelmac
brew install --cask tunnelmac
```

The tap lives at [luizmz94/homebrew-tunnelmac](https://github.com/luizmz94/homebrew-tunnelmac).
For a manual install, download `TunnelMac-<version>-arm64.zip` and `SHA256SUMS`
from [Releases](https://github.com/luizmz94/tunnelmac/releases), check the
checksum with `shasum -a 256 -c SHA256SUMS`, unzip and move the app to
`/Applications`, and install openfortivpn with `brew install openfortivpn`.

The initial candidate targets **Apple Silicon (arm64)**. The code targets macOS 13+
with standard material fallbacks before macOS 26; the new Liquid Glass APIs require
macOS 26+. Only the host OS/architecture actually checked appears in the release
report. Intel is not offered until tested; Rosetta cannot run arm64 code on Intel.

Install the signed/notarized app in `/Applications/TunnelMac.app`. Open
**Configurações… → Serviço privilegiado → Ativar serviço** (the **Gerenciar…** button
in the sidebar opens the same tab) and approve the background item in System Settings
→ General → Login Items. Return to the app, review **Aprovar openfortivpn…** and
approve with an administrator account. Each macOS user needs runtime approval.
Root is needed for openfortivpn/pppd to configure tunnels, routes and DNS; the GUI
always runs as a normal user. The runtime is copied to a protected root-owned
location, inventoried and integrity-checked before every connection.

## Usage

Use **+** → **Fortinet SSL VPN** to save a host, port, username and password or SAML authentication.
Passwords are stored in Keychain. Each profile has its own session, timer and
in-memory log. Multiple sessions may coexist; overlapping routes and DNS are not
resolved automatically. Closing the window (X/⌘W) leaves menu bar and VPNs running.
**Sair/⌘Q** asks to disconnect active sessions and waits for cleanup.

SAML opens the HTTPS gateway URL in your browser. Logins queue on callback port
8020. Cached cookies stay in Keychain for at most 30 minutes and remain valid only
as allowed by the gateway. The app does not inject a username into a signed SAML
URL. A rejected cookie permits one fresh browser login. Reconnect after a previously
established tunnel is limited to delays of 10, 20 and 40 seconds; rejected credentials,
TLS failures and initial connection failures do not loop automatically.

### OpenVPN

Install OpenVPN 2.7 or later (`brew install openvpn`), then use **Aprovar OpenVPN…**
in Configurações → Serviço privilegiado. The approval freezes the executable, its
libraries and the `dns-updown` script that configures the tunnel's DNS.
Profiles must verify the server identity: `remote-cert-tls server`,
`verify-x509-name`, `ns-cert-type server` or a server-auth `remote-cert-eku`.
Custom `tls-verify` and plugins are refused rather than removed. TLS below 1.2 and `tls-cert-profile insecure`
are refused. Ask the VPN administrator for a compatible profile; verification
policy is never silently weakened.

Use **+** (⌘N) → **OpenVPN** with a single `.ovpn`/`.conf` that carries its keys
inline, a Viscosity `.visc` folder whose profile references `ca.crt`, `cert.crt`,
`key.key` and `ta.key`, or the profile and those files selected (or dropped) together. Referenced files must sit inside the profile's
folder (no absolute paths, `..` or links leaving it); they are copied inline into a
private profile under `~/Library/Application Support/VPNGUI/OpenVPN` (0600). The
originals are not modified; a world-readable original key produces a warning.
Profiles that use `auth-user-pass` ask for a username and password (Keychain).

Only tunnel directives are kept. Scripts, plugins, `setenv`, management interfaces,
log/status files, OpenSSL providers and Windows-only options are removed with a
warning; unknown directives, proxies, PKCS#12, static `secret` keys and
password-protected private keys refuse the import. The helper repeats the check
and adds its own `script-security`, `dns-updown`, `auth-retry none` and inline
credentials. `auth RSA-SHA256` is offered as `auth SHA256` only after confirmation.
OpenVPN reconnects internally; `AUTH_FAILED` blocks retries until the credentials
are reviewed.

### WireGuard

Install `wireguard-go` (`brew install wireguard-go`; `wireguard-tools` also installs it),
then approve **WireGuard** in Configurações → Serviço privilegiado. The approval freezes
the `wireguard-go` executable; `wg`, `wg-quick` and Homebrew's bash are not used.

Use **+** (⌘N) → **WireGuard** with the `.conf` exported by the server (wg-quick
format). The normalized profile, including the private key, is stored in
`~/Library/Application Support/VPNGUI/WireGuard` (0600); the original is not modified,
a world-readable original produces a warning, and after saving the app offers to move
it to the Trash. `PreUp`/`PostUp`/`PreDown`/`PostDown`, `SaveConfig` and `FwMark` are
removed with a warning; unknown keys refuse the import. `Table` accepts `auto`, `main`
or `off`.

On Conectar the helper runs `wireguard-go -f utun` under the supervisor, sends the keys
over its root-only UAPI socket and then does what wg-quick does on macOS: addresses and
MTU with `ifconfig`, `AllowedIPs` as routes (`0.0.0.0/1` + `128.0.0.0/1`, `::/1` +
`8000::/1` for a full tunnel), a host route to each endpoint through the current
gateway, and the profile's `DNS` on the primary network service (dynamic store, not
saved network preferences). Routes and DNS are recorded first and undone on disconnect,
when wireguard-go exits, or at the next helper start after a crash. Host-name endpoints
are resolved by the helper (IPv4 preferred). WireGuard has no connection to wait for:
the session is marked connected once the tunnel is configured, and the first handshake
is logged.

No OTP/PIN form or client-certificate UI is implemented for Fortinet. Certificate failures require
explicit review and approval of the profile's trusted digest; TLS is not disabled.

## Settings

**Configurações… (⌘,)** is in the app menu and in the menu bar window. Tabs:

- **Geral:** show the menu bar icon; hide from the Dock when the window is closed
  (always kept in the Dock while the menu bar icon is off, so the app never becomes
  invisible); open at login (`SMAppService.mainApp`, only in signed builds).
- **Atualizações:** update check options and how to update (see below).
- **Serviço privilegiado:** why the service exists, its state, runtime approval and
  **Remover serviço** (formerly the Gerenciar… sheet).
- **Sobre:** version, build, repository, release notes, license and notices.

Preferences live in the app's own `UserDefaults` (`com.luiz.vpngui`); nothing
sensitive is stored there.

## Update check

The app only checks for and announces new versions; it never downloads, opens or
runs anything, and never calls `brew`. It sends one anonymous `GET` to
`https://api.github.com/repos/luizmz94/tunnelmac/releases` (no token, cookies,
machine identifiers or connection data), at launch, on **Conectar** when the last
attempt is more than 4 hours old, from an hourly timer with the same interval, and
when you choose **Verificar atualizações…**. Checking never delays a connection.
Release candidates are offered by default only when the running version is one.
Turn off **Verificar automaticamente** in Configurações → Atualizações to stop
automatic checks; manual checks stay available.

A new version shows a small card in the main window (**Atualizar**, **Depois**,
**Ver novidades**), a line in the menu bar and a dot on the Atualizações tab. You
can skip a version. To install it, quit with **Sair** (this disconnects the VPNs),
then run:

```sh
brew upgrade --cask luizmz94/tunnelmac/tunnelmac
```

## Updates, migration and removal

After publication:

```sh
brew upgrade --cask luizmz94/tunnelmac/tunnelmac
brew uninstall --cask luizmz94/tunnelmac/tunnelmac
```

Upgrade/reinstall/uninstall call the installed app's restricted normal-user
maintenance command **before** bundle removal. Homebrew runs it inside its sandbox,
where the app cannot reach the service registration or the helper. There it only
checks, without contacting anything, that TunnelMac, its supervisors and its
openfortivpn are not running, and keeps the service registered: the upgraded bundle
lands at the same path with the same identifiers and Team, so the registration stays
valid. Before `brew upgrade`, quit the app with **Sair** (this disconnects its VPNs);
otherwise brew stops and nothing is replaced.

Before `brew uninstall`, open the app and use **Configurações… → Serviço privilegiado
→ Remover serviço**, then
quit with **Sair**: the sandbox cannot remove the registration for you. Do not use
`--force` and do not reopen the app during maintenance. Outside the sandbox (for
example `./scripts/install.sh`), the same command requests normal quit, waits for
cleanup, has the authenticated helper prove global idle and unregisters the service.
This lifecycle still requires isolated VM validation before a stable release.

Moving from OpenFortiDesk (the name of this app up to 0.3.0): the bundle name changed,
so the old service registration cannot follow it. In OpenFortiDesk use **Configurações…
→ Serviço privilegiado → Remover serviço** and quit with **Sair**, then run
`brew uninstall --cask openfortidesk`, `brew untap luizmz94/openfortidesk` and
`brew install --cask luizmz94/tunnelmac/tunnelmac`, and activate the service again
from TunnelMac. Profiles, Keychain secrets and approvals of the protected runtime are
kept: the identifiers did not change.

When the cask finds `/Applications/OpenFortiDesk.app` or `/Applications/VPNGUI.app`,
it requires the old service to be removed first (checked with `launchctl print`): open
the old app, use **Remover serviço**, quit with **Sair** and run brew again. The old
bundle is moved to Application Support/VPNGUI/Backups. For manual migration, run `./scripts/install.sh`
after building/signing/notarizing. The script stages and verifies the new bundle,
backs up both possible installed names in Application Support/VPNGUI/Backups and
requires cleanup/unregister before replacing either bundle. If an old helper does
not support the maintenance contract, open the old app, use **Remover serviço…**
and quit normally, then retry. Enable the service from the new app afterward.
No installed personal app is modified by build/test commands.

Normal uninstall retains profiles, Keychain entries and the approved root runtime.
To remove the root-managed runtime, first use **Configurações… → Serviço privilegiado
→ Remover serviço… → Remover serviço e arquivos gerenciados** (administrator authorization). To delete profiles afterward,
remove the data directory listed below; delete individual Keychain entries only if
you intend to discard those credentials. There is no destructive zap stanza.

Compatibility deliberately preserves `com.luiz.vpngui`, the helper/supervisor
identifiers, Mach service, authorization right and plist name. The internal GUI
executable remains VPNGUI. Renaming these would require a separate data/service
migration.

| Data | Location |
| --- | --- |
| Profiles (0600) and backups | `~/Library/Application Support/VPNGUI/` |
| Preferences | `UserDefaults` domain `com.luiz.vpngui` |
| Passwords | Keychain service `com.luiz.vpngui.password` |
| SAML cookies | Keychain service `com.luiz.vpngui.saml-cookie` |
| Protected runtime | `/private/var/db/com.luiz.vpngui.helper` |
| Logs | Memory only; bounded to 1,500 lines per session |

## Development and release

Use Xcode with macOS 26 SDK or newer. Preparation used Swift 6.4/macOS 27 SDK.

```sh
brew install openfortivpn
./scripts/build.sh
./scripts/test.sh
TUNNELMAC_REVIEW_APP="$PWD/build/0.5.0/TunnelMac.app" \
  ./build/0.5.0/VPNGUILocalChecks-0.5.0.app/Contents/MacOS/VPNGUI --release-checks
```

Build outputs are isolated under `build/<version>`; set OUTPUT_DIR to preserve other
bundles. Use ARCH=arm64 or ARCH=x86_64 to compile explicitly. Compiling a slice is
not proof it runs. Ad hoc builds render and test but fail closed for privileged
operations; they are not functional VPN releases. The full suite needs graphical
login, Keychain and anonymous XPC. Additional `--release-checks` do not replace it.

For your own distribution, provide SIGNING_IDENTITY and optional TEAM_ID to
`build.sh`, then NOTARY_PROFILE to `notarize.sh`. These inputs reference your own
Keychain identity/profile. App, helper and supervisor must share a verified Apple
Team. `package-release.sh` accepts only Developer ID signed, timestamped, hardened,
notarized/stapled arm64 bundles and computes SHA-256 after final ZIP packaging.
`publish-release.sh` gates draft creation on a clean default branch, full test report,
audit and successful CI. `update-tap.py` generates a versioned cask only from a
published, verified release. No private key export or signing secret in CI is needed.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
[LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Behavior while preparing 1.0.0

Internet DNS defaults to **Do not change**. Existing explicit selections are
preserved. Public DNS is applied only after choosing a provider in Settings;
profile DNS takes precedence. A WireGuard profile requiring DNS fails visibly if
it cannot own/apply it. Only one WireGuard may own system DNS at a time.
Runtime approval shows the actual source and warnings before administrator consent;
disconnect all sessions before replacing a runtime.

A stop allows ten seconds for the client, then forces that child to exit and runs
helper network cleanup. Cleanup failures retain recovery journals, report failure,
and block further starts/maintenance until recovery succeeds. Quitting times out
with the app still open if cleanup cannot be confirmed. This is **not a kill switch**:
traffic may resume over the physical connection after a tunnel fails.

OpenVPN/WireGuard private keys remain in 0600 profile files inside 0700 folders,
including a pending transaction journal during interrupted edits. These are readable
by the owning user and their backups. Passwords and SAML cookies remain in Keychain.
Interrupted saves/deletes are completed on the next launch; failed cleanup keeps a
recoverable operation and a visible error rather than silently forgetting secrets.

Run `swift test` for focused regressions and `./scripts/test.sh` for the separate
GUI/Keychain/XPC integration runner. Production GUI contains no fixtures or test modes.
The runner uses a temporary bundle identifier and never registers the real service.
Publication through either script or workflow requires the same preflight: clean
commit, privacy/secret audit, full-suite attestation and successful CI for that commit.
Historical audit findings remain a release blocker until individually reviewed.
