# TunnelMac guide

Everything the [README](../README.md) leaves out: how each protocol is handled, what the
app stores and where, updates, migration and removal.

- [Installation details](#installation-details)
- [Usage](#usage) · [OpenVPN](#openvpn) · [WireGuard](#wireguard) · [GlobalProtect](#globalprotect) · [Certificates](#fortinet-client-certificates-and-gateway-certificates)
- [Settings](#settings)
- [Update check](#update-check)
- [Updates, migration and removal](#updates-migration-and-removal)
- [Behavior while preparing 1.0.0](#behavior-while-preparing-100)

## Installation details

For a manual install, download `TunnelMac-<version>-arm64.dmg` (Apple Silicon) or
`TunnelMac-<version>-x86_64.dmg` (Intel) and `SHA256SUMS`
from [Releases](https://github.com/luizmz94/tunnelmac/releases), check the
checksum with `shasum -a 256 -c SHA256SUMS --ignore-missing`, open the disk image and
drag TunnelMac to Applications. The setup guide then installs the clients you need. The
`.zip` archives hold the same signed app; in-app updates and Homebrew use them.

Releases are built for **Apple Silicon (arm64)** and **Intel (x86_64)**, as separate
archives; the Homebrew cask picks the one for your Mac. The full local suite runs in CI
on Apple Silicon before a release; the Intel app is cross-compiled from the same code. The code targets macOS 13+
with standard material fallbacks before macOS 26; the new Liquid Glass APIs require
macOS 26+.

On Intel, Homebrew installs into `/usr/local` (Apple Silicon: `/opt/homebrew`) and
TunnelMac looks for the clients there. Homebrew no longer builds Intel bottles for
every formula, so installing OpenVPN in particular may compile it and its
dependencies from source. If a source build fails, run the same `brew install` again
before reporting it. Approve the clients only after they are installed.

Install the signed/notarized app in `/Applications/TunnelMac.app`. On first launch a
setup guide opens in five steps: **Escolher as VPNs** (installed and outdated clients
are detected, with the exact `brew install`/`brew upgrade` command and a **Verificar**
button), **Ativar o serviço**, **Permitir em segundo plano** (System Settings → General →
Login Items opens from the guide's button), **Aprovar os clientes** with an
administrator account, and **Pronto**. **Agora não** postpones it until the next launch;
everything stays available in Configurações… → Serviço privilegiado (also reachable
from the shield button or **Gerenciar…**). Each macOS user needs runtime approval.
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
`key.key` and `ta.key` (or a `.zip` of that folder, e.g. `Viscosity.visc.zip`), or the profile and those files selected (or dropped) together. Referenced files must sit inside the profile's
folder (no absolute paths, `..` or links leaving it); they are copied inline into a
private profile under `~/Library/Application Support/VPNGUI/OpenVPN` (0600). The
originals are not modified; a world-readable original key produces a warning. A `.zip`
is checked first (at most 64 entries and 4 MB uncompressed, no absolute or `..`
paths, no links), extracted with the system's `ditto` into a private temporary folder
that is removed after reading; the archive is the only original.
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

### GlobalProtect

Install OpenConnect (`brew install openconnect`), then approve **GlobalProtect
(OpenConnect)** in Configurações → Serviço privilegiado. Use **+** (⌘N) →
**GlobalProtect** with the gateway (`vpn.example.com` or `vpn.example.com:4443`). Only
direct gateway logins are supported (the portal's gateway list is not read).

With **SAML**, Conectar asks the gateway's `prelogin.esp`, opens the identity provider in
the default browser and waits up to five minutes for the gateway's
`globalprotectcallback:` return. Allow the browser to open TunnelMac at the end. While a
login waits, TunnelMac is the handler of that URL scheme and gives it back to the
previous app (such as the official GlobalProtect client) afterwards. If the browser
shows the link instead, **Colar retorno…** in the connection details takes it. The user
and cookie stay in memory and reach openconnect on stdin only; each connection logs in
again. **Senha** uses the user name and password saved in Keychain. HIP reports are not
sent; the log says so when the gateway asks for one.

**Rotas:** by default only the internal networks (`10.0.0.0/8, 172.16.0.0/12`, editable)
go through the tunnel and only the gateway's domains use its DNS; the rest of the
internet stays on your network, whatever the gateway asks. **Todo o tráfego pela VPN**
follows the gateway instead (often all traffic, where the company may inspect HTTPS).
The helper configures the tunnel with its own script, not Homebrew's vpnc-script:
address, routes, a host route to the gateway through the current router and the DNS as a
TunnelMac resolver. All of it is undone on disconnect, or by the helper if openconnect
was killed.

**Certificados da rede** (in the details while connected) connects to a few sites through
the tunnel and lists the authorities a network uses to inspect HTTPS. Each one can be
installed on its own after comparing its SHA-256: a root goes to the login keychain,
trusted for SSL only (macOS asks for your password; delete it in Keychain Access to
undo), an intermediate is only added.

After a SAML login (GlobalProtect or Fortinet) the app closes the page left in the
default browser (Safari, Chrome, Brave, Edge or Vivaldi); macOS asks once whether
TunnelMac may control it.

### Fortinet client certificates and gateway certificates

A Fortinet connection can use a client certificate from your Keychain (FortiClient's
"Certificado do Cliente"); macOS may ask to let TunnelMac use the key on each
connection. No OTP/PIN form is implemented. Gateway certificate failures require
explicit review and approval of the profile's trusted digest; TLS is not disabled.

## Settings

**Configurações… (⌘,)** is in the app menu and in the menu bar window. Tabs:

- **Geral:** show the menu bar icon; hide from the Dock when the window is closed
  (always kept in the Dock while the menu bar icon is off, so the app never becomes
  invisible); open at login (`SMAppService.mainApp`, only in signed builds).
- **Atualizações:** update check options and how to update (see below).
- **Serviço privilegiado:** its state, runtime approval and **Remover serviço** on top;
  why the service exists below (formerly the Gerenciar… sheet).
- **Backup:** export every connection to one `.tunnelmacbackup` file, and import it
  on this or another Mac (see below).
- **Sobre:** version, build, repository, release notes, license and notices.

Preferences live in the app's own `UserDefaults` (`com.luiz.vpngui`); nothing
sensitive is stored there.

### Backup and moving to another Mac

**Exportar…** writes the connections, their Keychain passwords, the OpenVPN and
WireGuard profiles (private keys included) and, optionally, the app preferences
(menu bar, Dock, update check and DNS da internet) into one file, encrypted with
AES-256-GCM under a key derived from the password you choose (PBKDF2-HMAC-SHA256,
600,000 iterations, random salt and nonce; the header is authenticated too). The
password must be rated **Forte** by the strength meter (at least 12 characters; common
words, years, whole dictionary-like words, repeats and keyboard sequences count
little) and cannot be recovered.
**Gerar senha forte** fills in a random password shaped like the ones macOS suggests
(three groups of six letters and digits, about 105 bits) with a Copiar button.

**Importar…** asks for that password, validates every connection and profile with
the same rules as a manual save and shows what will change before writing anything:
connections from the backup are added, those with the same identifier (an earlier
import or a restore on the same Mac) are replaced, and all others are kept.

Not included: SAML sessions (temporary, bound to this Mac), the login item and update
bookkeeping. A Fortinet client certificate travels only as a reference: import the
identity into the other Mac's Keychain (Keychain Access → File → Import Items) and the
connection uses it as before; the import summary lists any that are missing.

## Update check

The check only looks for and announces new versions; it never calls `brew`. It sends
one anonymous `GET` to
`https://api.github.com/repos/luizmz94/tunnelmac/releases` (no token, cookies,
machine identifiers or connection data), at launch, on **Conectar** when the last
attempt is more than 4 hours old, from an hourly timer with the same interval, and
when you choose **Verificar atualizações…**. Checking never delays a connection.
Release candidates are offered by default only when the running version is one.
Turn off **Verificar automaticamente** in Configurações → Atualizações to stop
automatic checks; manual checks stay available.

When the check at launch finds a new version, the update window opens with its notes
and **Instalar atualização**, **Lembrar mais tarde** and **Pular esta versão**. The
version also shows a small card in the main window (**Atualizar**, **Depois**,
**Ver novidades**), a line in the menu bar and a dot on the Atualizações tab.

**Atualizar** (or **Atualizar agora** in Configurações → Atualizações) downloads that
release, checks its signatures, asks to disconnect active VPNs if there are any,
replaces the app and opens it again. Profiles, passwords, preferences and the
privileged service are kept. This works the same for Homebrew installations: the cask
is marked `auto_updates`, so ordinary bulk upgrades skip it. An explicit
`brew upgrade --cask luizmz94/tunnelmac/tunnelmac` still uses the version in the tap. Installing in the app needs a
version that already includes it; the first one is installed with brew.

To update with Homebrew instead, quit with **Sair** (this disconnects the VPNs),
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

## Behavior while preparing 1.0.0

Internet DNS defaults to **Do not change**. Existing explicit selections are
preserved. Public DNS is applied only after choosing a provider in Settings;
profile DNS takes precedence. A WireGuard profile requiring DNS fails visibly if
it cannot own/apply it. Only one WireGuard may own system DNS at a time.

Whatever the choice, the helper saves the primary service's DNS when the first VPN
starts (`dns-baseline.json`, root-only) and checks it when the last one has ended and
each client undid its own change. A VPN's servers left behind (a client that died,
a failed `dns-updown`) are replaced by the saved value and the log says so; a DNS
the user changed in System Settings meanwhile is kept. Connections that start while
others run share that first snapshot, so a VPN's DNS is never taken for the user's.
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
