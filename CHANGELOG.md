# Changelog

## 1.0.0 — 2026-10-29

- First stable release.
- Each release also ships a notarized disk image per architecture
  (`TunnelMac-<version>-arm64.dmg`, `-x86_64.dmg`): open it and drag TunnelMac to
  Applications. The zip archives stay for in-app updates and Homebrew.
- The app speaks English, German, Spanish, French, Hindi and Portuguese. Configurações ›
  Geral › Idioma picks one (or follows the system, English when the system language is
  not one of these); the new language applies when the app reopens (**Reabrir agora**),
  and the choice is kept in backups. The privileged service answers in the app's
  language (helper protocol 8: update the service together with the app).
- Liquid Glass layout for macOS 26:
  - Main window: connection actions on the toolbar (the main action plus a menu), chain
    symbols for connect/disconnect, sidebar rows with the protocol on a tinted tile and
    a state dot, connection details in a titled card, compact log actions.
  - Menu bar window: glass background, switches like Control Center and protocol
    tiles; the menu bar icon keeps its arc shape, takes the brand color when connected,
    shows a count badge and spins while connecting.
  - Configurações: tab name only in the title bar, colored tab tiles drawn as pictures
    (black tiles for the dark icon style, filled accent tiles for tinted), mini
    switches, and an Aparência picker (Claro, Escuro, Automático) with the system's
    thumbnails, kept in backups.
  - Sheets: fit the window, glass footer buttons, brand/protocol headers, an eye button
    on password fields (a password typed before the user is kept), shorter copy.
- A failed connection shows a quiet **Ver logs** link next to its status in the menu bar
  window, opening the main window at that connection. **Limpar logs** also dismisses the
  failure (back to Desconectada); a refused authentication still waits for the
  credentials to be reviewed.
- Homebrew: the cask no longer installs openfortivpn with the app; the setup guide
  installs only the clients of the VPN types chosen (openfortivpn, OpenVPN, wireguard-go).
- The menu bar icon's count badge shows from the first connection, not only from two.
- The app icon is built by `iconutil`: the 16 and 32 px sizes were PNG in icp4/icp5, which
  the Dock's window previews and Mission Control drew as noise.
- Deleting a connection no longer blocks the app when the Keychain refuses to delete its
  password or SAML session (errSecInvalidOwnerEdit, items created by an earlier build):
  the secret is overwritten with nothing and the deletion finishes.
- README: the setup guide replaces the manual first-run steps, new screenshots of the
  guide and of Backup, and a Built on section crediting openfortivpn, OpenVPN and
  wireguard-go. docs/GUIDE.md describes the setup guide.
- `scripts/showcase.sh --capture` also captures the setup guide (fictitious Homebrew
  state) and Configurações › Backup.
- Updates install from the app (Sparkle 2): the update window opens at launch when a
  new version exists, and **Atualizar** / **Atualizar agora** download it, verify its
  EdDSA signatures, disconnect the VPNs through the normal Sair path (cancelling keeps
  them connected and installs on the next quit), replace the app and reopen it. Each release carries signed appcasts (one per
  architecture) for exactly that version; Sparkle never checks on its own. The Homebrew
  cask is marked `auto_updates`; `brew upgrade` keeps working.

## 0.5.0-rc.5 — 2026-10-25

- First launch: a setup guide in steps. Choose the VPN types you use (installed and
  outdated clients are detected, with the exact `brew install`/`brew upgrade` command
  and a Verificar button), activate the service, allow it in Login Items (System
  Settings opens only from the guide's button, next to a picture of the switch), approve
  each chosen client, done. The first registration's "Operation not permitted" (waiting
  for that approval) is no longer shown as a failure, and a never-registered service no
  longer reads as "não encontrado".
- The administrator prompt says TunnelMac and names the client being approved; a right
  created by older builds ("VPN GUI …") is rewritten.
- A connection whose approved client copy is older than Homebrew's latest shows how to
  update it; a Homebrew installation older than the approved copy no longer asks for an
  upgrade or a (downgrading) approval.
- Serviço privilegiado: state and approvals on top, the explanation below.
- The main window's sidebar keeps its minimum width (260 pt) on macOS 13–15, which
  restored a narrower saved width and hid the settings, service and + buttons.
- OpenVPN import accepts a `.zip` of a Viscosity `.visc` folder (or of a profile).
- The user's DNS is saved when the first VPN starts and checked after the last one
  ends; a VPN's servers left behind are replaced by it, a change made in System
  Settings meanwhile is kept.
- Shorter OpenVPN password note in the editor.
- Configurações → Backup: export every connection with its password and OpenVPN or
  WireGuard profile, plus the app preferences, into one `.tunnelmacbackup` file
  encrypted with a password (AES-256-GCM, PBKDF2-SHA256 600k), and import it on this or
  another Mac. Import validates everything first, shows what will be added or replaced,
  and keeps connections that are not in the backup. SAML sessions are not exported;
  client certificates must already be in the other Mac's Keychain.
- The backup password must be strong: a strength meter (length, variety, common words,
  repeats and sequences) gates Exportar, and Gerar senha forte suggests a random
  macOS-style password (xxxxxx-xxxxxx-xxxxxx) with show/hide and Copiar.

## 0.5.0-rc.4 — 2026-10-25

- Intel Macs (x86_64) are supported: each release ships `TunnelMac-<version>-arm64.zip`
  and `TunnelMac-<version>-x86_64.zip`, and the Homebrew cask picks the right one. The
  Apple Silicon archive, its name and its contents are unchanged.
- Intel: the protected OpenVPN copy fits library names into the shorter `/usr/local`
  load commands (it uses the install name, e.g. `liblz4.1.dylib`, when the Cellar file
  name does not fit), and the default client paths use the Intel Homebrew prefix.
- CI runs the full suite on an Intel runner too; a release needs both to pass.
- Shorter README with screenshots and a connect GIF; protocol details moved to docs/GUIDE.md.
- `scripts/showcase.sh` opens the interface with fictitious connections (local checks
  runner only) and regenerates the README images with `--capture`.
- CONTRIBUTING.md: local setup, project map and contribution workflow.

## 0.5.0-rc.3 — 2026-10-25

- WireGuard: a re-resolved endpoint moves only after its route outside the tunnel exists.
- Automatic releases: a push to main that passes the checks is released (version picked
  or bumped by `scripts/next-version.py`) and the Homebrew tap is updated.

## 0.5.0-rc.2 — 2026-10-25

- Address parser, authentication, runtime consent, timeout and network recovery findings.
- Runtime approval shows the source path and inspection warnings before asking for the
  administrator password; approving is refused while VPNs are connected.
- OpenVPN profiles must verify the server (`remote-cert-tls server`, `verify-x509-name`,
  `ns-cert-type server` or a server-auth `remote-cert-eku`); `tls-verify`, plugins,
  TLS below 1.2 and `tls-cert-profile insecure` are refused.
- WireGuard: profile DNS and the endpoint route are required before reporting connected;
  the endpoint route follows the current gateway, roaming and re-resolution, and the
  tunnel survives a temporary loss of the default route (sleep, Wi-Fi roaming).
- A client that ignores SIGTERM is killed after 10 s; Sair gives up after 30 s.
- Homebrew version queries follow the automatic update preference.
- Helper protocol 7.
- Recover interrupted connection mutations; run imports and persistence in background.
- Separate production GUI, integration runner and focused regression tests.
- Share publication preflight and classify stable/prerelease from the version.
- Preserve explicit DNS selections; new installations leave system DNS unchanged.

## 0.5.0-rc.1 — 2026-10-24

- **DNS da internet** (Configurações › Geral › Rede): 1.1.1.1 - Cloudflare (default),
  8.8.8.8 - Google, 94.140.14.14 - AdGuard, entries of your own (**Adicionar mais…**, a
  name and up to 4 addresses) or **Não alterar o DNS**. While a Fortinet VPN, or a
  WireGuard profile without its own DNS, is connected, the service puts those servers on
  the primary network service (no password: the service already runs as root), applies
  them again after network changes and restores the previous DNS when the last such VPN
  disconnects (or at the next helper start after a crash). Internal names keep resolving
  through each Fortinet VPN's per-domain DNS; OpenVPN and WireGuard profiles with DNS keep
  their own. Helper protocol 6.
- Fortinet client certificates. The editor lists the certificates with a private key in
  the Keychain (TLS client use only) and imports a `.p12`/`.pfx` into the login keychain
  (its password is used only for the import). On each connection the app exports the
  key as encrypted PKCS#8 under a random passphrase; the helper writes the certificate
  and the key into a root-only directory (0600), passes `user-cert`/`user-key`/
  `pem-passphrase` to openfortivpn and removes the files when the session ends (or on
  the next helper start). macOS may ask once to let TunnelMac use the key.
- The Fortinet **Servidor** field takes the gateway like FortiClient does —
  `vpn.exemplo.com`, `vpn.exemplo.com:10443` or `vpn.exemplo.com:443/realm` — and the
  separate Porta field is gone. Port 443 is used when omitted; a `/realm` becomes
  openfortivpn's `realm`. Lists show the port only when it is not 443.
- Fortinet DNS now works in apps, not only in `nslookup`. On macOS openfortivpn only
  edits `/etc/resolv.conf`, which the system resolver ignores. The helper reads the
  gateway's DNS servers and domains (`Got addresses: … ns […] ns_suffix […]`) and, while
  the tunnel is up, publishes a per-domain resolver (`SupplementalMatchDomains`): names
  under those domains use the VPN's DNS, everything else keeps the current DNS, and
  several Fortinet VPNs can be connected at once. Removed when openfortivpn exits, or by
  the next helper start. **Atualizar serviço** is also offered when the registered helper
  speaks another protocol.
- Helper protocol 5 (client certificate and realm in the request): use **Atualizar
  serviço** after installing.
- WireGuard support next to Fortinet and OpenVPN. **+** (⌘N) → **WireGuard** imports
  the `.conf` exported by a WireGuard server (the wg-quick format: one `[Interface]`
  with `PrivateKey`/`Address`/`DNS`/`MTU`, one or more `[Peer]`). The normalized profile,
  with the private key, is kept in a private 0600 file under
  `~/Library/Application Support/VPNGUI/WireGuard`; the original is never modified and
  can be moved to the Trash after saving. The app shows the profile's public key.
- `PreUp`/`PostUp`/`PreDown`/`PostDown`, `SaveConfig` and `FwMark` are removed with a
  warning (wg-quick runs those hooks as root); unknown keys refuse the import. The
  helper checks the same rules again and refuses any profile that still has them.
- The privileged service approves and freezes `wireguard-go` (Homebrew) like the other
  clients. wg-quick and bash are not used: the supervisor runs `wireguard-go -f utun`
  (`--wireguard` mode), the helper sends the keys over wireguard-go's root-only UAPI
  socket (checking that the socket belongs to that process), then configures addresses,
  MTU, `AllowedIPs` routes (`0/1` + `128/1` for a full tunnel), a host route to each
  endpoint through the physical gateway and the profile's DNS on the primary network
  service — the same steps wg-quick takes on macOS, each shown in the log.
- Routes and DNS outside the interface are recorded before they change and undone when
  wireguard-go exits, and by the next helper start if the helper died first. Gateway
  changes move the endpoint routes; network changes re-apply the DNS.
- The connection is marked connected once the tunnel is configured; the first
  handshake is logged, and a warning appears if none happens within 30 seconds.
  wireguard-go runs with `LOG_LEVEL=error`: the log shows its errors and the service's
  own steps, not its debug output.
- Helper protocol 4: update the service after upgrading.

## 0.4.0-rc.1 — 2026-10-24

- Rename the product from OpenFortiDesk to **TunnelMac** (bundle `TunnelMac.app`,
  cask `tunnelmac`, repositories `luizmz94/tunnelmac` and
  `luizmz94/homebrew-tunnelmac`). Bundle/helper identifiers, profiles, Keychain
  services and runtime approvals are unchanged. The cask and `install.sh` treat
  `OpenFortiDesk.app` as a legacy bundle: its service must be removed first, and the
  old bundle is backed up.
- OpenVPN support next to Fortinet. **Importar perfil OpenVPN…** (⌘I) reads a single
  `.ovpn`/`.conf` with inline keys or a Viscosity `.visc` folder with external
  `ca`/`cert`/`key`/`ta` files. Referenced files are read only from inside the
  profile's folder and copied inline into a private 0600 profile; originals are never
  modified. Passwords stay in Keychain.
- Profiles are reduced to an allowlist of tunnel directives. Scripts (`up`, `down`,
  `plugin`, `script-security`…), `setenv`, management, logs/status files, OpenSSL
  providers and identity changes are removed with a warning; unknown directives,
  proxies, PKCS#12, `secret` and encrypted keys refuse the import. The helper checks
  the same allowlist again before root runs anything.
- `auth RSA-SHA256` (refused by OpenVPN 2.7: "Message hash algorithm not found") is
  detected at import and from the connection log; switching the app's copy to
  `auth SHA256` requires explicit confirmation.
- The privileged service approves and freezes an OpenVPN 2.7+ installation like
  openfortivpn, including its `dns-updown` script, passed explicitly so nothing runs
  from the writable Homebrew prefix. Credentials travel inline in the protected,
  unlinked config descriptor (`--config /dev/fd/3`), never in arguments or files.
- Helper protocol 3: update the service after upgrading.
- Nova conexão (+ at the top of the sidebar, ⌘N) first asks for the VPN type
  (Fortinet or OpenVPN). OpenVPN accepts a file, a .visc folder, or the profile and
  its certificates selected together (or dropped on the sheet).
- Editing an imported OpenVPN profile shows the auth RSA-SHA256 → SHA256
  compatibility option and can turn it off again.
- After saving an imported OpenVPN profile the app offers to move the original
  files (or the whole .visc folder) to the Trash; the private copy is already saved.
- Connection details show the name and state in the toolbar, and a footer credits
  the client that makes the tunnel (openfortivpn or OpenVPN, with version and link).
  The privileged service is a status icon next to + at the top of the sidebar.

## 0.3.0-rc.5 — 2026-10-24

- Fix a crash at launch in rc.4: SwiftUI writes the menu bar icon state back while
  building the scenes, and that unchanged value was published as a preference
  change, re-evaluating the scenes until the stack overflowed. Only real changes
  are now published.

## 0.3.0-rc.4 — 2026-10-23

- New Configurações window (⌘,) with Geral, Atualizações, Serviço privilegiado and
  Sobre tabs: menu bar icon, hide from the Dock on close (never both hidden), open
  at login, and the app version in the sidebar.
- Update check: an anonymous request to the public GitHub releases API at launch, on
  Conectar (at most every 4 hours), hourly and on demand (Verificar atualizações…).
  A new version shows a discreet card, a menu bar line and a dot; it can be postponed
  or skipped. Nothing is downloaded or run; updating stays `brew upgrade` with the
  app closed. Release candidates are offered when running one; both are switchable.
- The privileged service management moved from a sheet to the Serviço privilegiado
  tab, with a short explanation of why the service exists. Gerenciar… opens it.

## 0.3.0-rc.3 — 2026-10-23

- Fix `brew upgrade`, `reinstall` and `uninstall`, which always failed because
  Homebrew 7 runs cask steps inside a sandbox that blocks the service registration
  and the helper connection. Inside the sandbox the maintenance command now only
  verifies, through libproc, that the app, its supervisors and the managed
  openfortivpn are not running, and keeps the service registered for the upgraded
  bundle.
- The cask's VPNGUI.app migration requires the old service to be removed first, and
  the caveats explain that Remover serviço must be used before `brew uninstall`.
- The local checks run the maintenance command under Homebrew's sandbox profile.
- rc.1 and rc.2 cannot upgrade by themselves; see the release notes for the manual
  steps.

## 0.3.0-rc.2 — 2026-10-23

- Fix the SAML fallback after a refused saved session: the helper no longer rejects
  the browser login as a duplicate while the previous attempt's final events are
  still being acknowledged.
- A refused saved session that the Keychain will not delete (for example one written
  by VPNGUI.app) is no longer retried on every connection, and the failure is logged.

## 0.3.0-rc.1 — 2026-10-23

- Rename the distributed bundle and visible product to OpenFortiDesk.
- Preserve legacy app/helper identifiers, profiles and Keychain services.
- Add normal-user maintenance with normal quit, global helper idle verification,
  a start gate and successful unregister required before replacing a bundle.
- Preserve backups when migrating VPNGUI.app to OpenFortiDesk.app.
- Package only Developer ID signed, notarized, stapled arm64 releases; generate
  final ZIP checksums and prepare a Homebrew tap from verified release assets.
- Keep the existing Liquid Glass UI, close-window behavior, V/node icon and
  authorization hardening developed before this release preparation.
