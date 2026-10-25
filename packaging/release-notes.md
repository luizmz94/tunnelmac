TunnelMac release candidate: macOS 13+, Apple Silicon arm64 only.

TunnelMac is the new name of OpenFortiDesk: the app now handles Fortinet SSL VPN
(openfortivpn), OpenVPN profiles and WireGuard configurations.

Changes in 0.5.0-rc.2 (stabilization review):
- Helper protocol 7: after upgrading, use Atualizar serviço, then approve
  openfortivpn/OpenVPN/wireguard-go again with every VPN disconnected. The approval
  now shows where the program comes from and any inspection warning.
- OpenVPN profiles must verify the server identity (remote-cert-tls server or
  verify-x509-name, for example). Profiles relying on tls-verify or plugins, TLS below
  1.2 or tls-cert-profile insecure are refused with an explanation.
- WireGuard: profile DNS and the route that keeps the server outside the tunnel are
  required before showing Conectada; that route follows network changes and endpoint
  roaming, and the tunnel survives sleep and Wi-Fi roaming.
- Network recovery keeps its records until routes and DNS are really restored;
  pending cleanup blocks new connections instead of being forgotten.
- A client that ignores the stop request is ended after 10 s; Sair gives up after
  30 s instead of hanging.
- DNS da internet: without an explicit choice the system DNS is left unchanged
  (choices already saved are kept).
- Saving and deleting connections recover after an interruption; imports and
  Keychain work no longer block the window. Changing the Fortinet client certificate
  discards the saved SAML session; intermediate certificates are sent too.
- Homebrew version checks follow the automatic update setting.

Changes in 0.5.0-rc.1:
- WireGuard support: import the server's `.conf` (wg-quick format). PreUp/PostUp/
  PreDown/PostDown hooks are removed; the private key stays in a private profile.
- The privileged service approves and freezes `wireguard-go` and sets up the tunnel
  itself (keys over UAPI, addresses, routes, endpoint route and DNS), without wg-quick
  or bash; routes and DNS are undone on disconnect and after a crash.
- Fortinet client certificates: pick a certificate from the Keychain or import a
  `.p12`/`.pfx`. Each connection exports the key encrypted, only for that session.
- The Fortinet Servidor field takes the gateway like FortiClient: `vpn.example.com`,
  `vpn.example.com:10443` or `vpn.example.com:443/realm` (no separate port field).
- Fortinet DNS now works in apps (not only in nslookup): the gateway's DNS servers and
  domains become a per-domain resolver while the tunnel is up.
- DNS da internet (Configurações › Geral): Cloudflare (default), Google, AdGuard, your
  own entries or Não alterar. Applied while a VPN is connected, restored afterwards.
- Helper protocol 6: use Atualizar serviço after upgrading.

Changes in 0.4.0-rc.1:
- OpenVPN 2.7+ support next to Fortinet: import a single `.ovpn`/`.conf` or a
  Viscosity `.visc` folder (Importar perfil OpenVPN…, ⌘I). Profiles are reduced to an
  allowlist of tunnel directives; passwords stay in Keychain.
- The privileged service approves and freezes an OpenVPN installation the same way it
  does openfortivpn.
- New-connection chooser and a reorganized connection detail.
See CHANGELOG.md.

Coming from OpenFortiDesk (the bundle name changed, so the service registration
cannot be kept):
1. In OpenFortiDesk, use Configurações… > Serviço privilegiado > Remover serviço,
   then quit with Sair (this disconnects its VPNs).
2. brew uninstall --cask openfortidesk
3. brew untap luizmz94/openfortidesk
4. brew install --cask luizmz94/tunnelmac/tunnelmac
5. Open TunnelMac and activate the service again. Profiles and Keychain secrets are kept.

Developer ID signed, hardened, timestamped, notarized and stapled.
First launch requires macOS background-service approval and administrator approval
of the protected openfortivpn/OpenVPN/wireguard-go runtime. openfortivpn, OpenVPN and
wireguard-go are external Homebrew dependencies. Overlapping routes/DNS are not resolved; SAML logins queue on
port 8020 and cookie validity depends on the gateway. SIGKILL of a supervisor can
leave an orphaned client. Root registration and Homebrew lifecycle integration
require isolated VM validation; this candidate is not declared stable. Uninstall
preserves profiles and Keychain.
