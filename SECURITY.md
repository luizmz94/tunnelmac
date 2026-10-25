# Security

## Reporting

Do not post exploits, secrets or real VPN details in public issues. Report
vulnerabilities privately through GitHub:
[Security → Report a vulnerability](https://github.com/luizmz94/tunnelmac/security/advisories/new).
No response-time commitment is made. There has been no independent security audit.

Include version/build, macOS, architecture and a reproduction with fictitious
profiles. Remove users, gateways, cookies, passwords, tokens and SAML URLs from
attachments. Never send a private key or Keychain export.

## Trust boundaries

The GUI runs as the logged-in user. A bundled LaunchDaemon runs as root, registered
through SMAppService and approved by macOS. Both XPC peers require an Apple-issued
signature with the expected legacy identifier and the same certificate Team ID.
Ad hoc builds cannot enable privileged operations. No sudo or deprecated privilege
fallback is provided.

The helper accepts typed, bounded operations, not shell commands, writable output
paths, arbitrary PIDs or argument vectors. The protected runtime is copied from the
user's inspected openfortivpn installation after administrator authorization.
The helper verifies its integrity before every start. Initial approval trusts the
inspected local files; hashes alone do not establish upstream provenance.

Besides VPN/gateway/IdP traffic, automatic update checks use an
anonymous HTTPS `GET` to the public GitHub releases API of luizmz94/tunnelmac
(ephemeral session, no cookies, cache or token, no redirects, 1 MiB response limit).
The service panel also queries the public Homebrew formula JSON endpoints for the
three client versions (512 KiB limit). Both automatic checks can be turned off in
Configurações → Atualizações. Only release pages of this repository are linked;
release notes are shown as plain text. The check itself downloads nothing.

Installing an offered version happens only when the user clicks **Atualizar agora** (or
the install button of the update window shown at launch), through Sparkle 2
(sparkle-project.org). Sparkle reads the appcast attached to that exact GitHub release
(`releases/download/v<version>/appcast-<arch>.xml`), which must carry a valid EdDSA
signature (`SURequireSignedFeed`, with failure expiration disabled), downloads the archive listed there, verifies its
EdDSA signature before extracting it (`SUVerifyUpdateBeforeExtraction`) and validates the
new bundle’s code signature. Sparkle permits Apple signing identity rotation when the
archive is authenticated by the trusted EdDSA key; these are not two independent
same-identity requirements. Release builds separately enforce the configured Apple Team ID.
The app also rejects feeds pointing to an archive outside the offered release/architecture. The public
key ships in Info.plist (`SUPublicEDKey`); the private key lives only in the
maintainer's Keychain and in the release environment's secrets. Sparkle never checks on
its own schedule, never installs silently and sends no system profile. Quitting for the
installation goes through the normal Sair path (VPNs disconnected and cleaned up first);
the service registration is kept, as with `brew upgrade`.

Passwords and SAML cookies use Keychain and authenticated XPC, then anonymous
file descriptors. They are excluded from argv, environment, JSON and logs. TLS is
not disabled; trusting a certificate digest requires explicit profile approval.
Closing the window preserves sessions; Sair requests normal disconnect and waits
for cleanup. Lost GUI/XPC connections stop their sessions; lost helper channels
ask supervisors to stop normally.

Backups (Configurações → Backup) are the only export of passwords and private keys.
The file is AES-256-GCM with a key from PBKDF2-HMAC-SHA256 (600,000 iterations,
16-byte random salt, header authenticated) under a password the app rates strong
(or generates from SecRandomCopyBytes); it is written 0600 where the user
chooses. Import accepts only bounded parameters, decrypts in memory and revalidates
every connection and profile before the normal per-connection transaction. SAML
cookies are never exported.

Maintenance runs as a normal user through the same authenticated helper channel.
A global idle check rejects active sessions and surviving supervisors; a helper
start gate remains held during unregister. Refusal, missing proof, protocol mismatch,
timeout or unregister error aborts bundle replacement. No root app scripts are run.
An old helper without this operation must be removed through the old app first.

Homebrew runs cask steps under sandbox-exec, which denies mach-lookup, Apple events
and LaunchServices. Detected there (sandboxed, daemon plist present, registration
unreadable), the command is read-only: it lists processes through libproc and refuses
while the app, a supervisor or the managed openfortivpn runs. It never signals a
process, contacts the helper or changes the registration, which is kept for the
upgraded bundle at the same path. Uninstall therefore requires Remover serviço in the
app first. The VPNGUI.app migration step requires the old service to be absent
(`launchctl print`) before it moves the old bundle.

## Known limitations

A direct SIGKILL of a supervisor can leave an orphaned openfortivpn. Do not use
killall, forced termination or launchctl bootout as a cleanup substitute. Overlapping
routes/DNS are not resolved automatically. Gateway, IdP, openfortivpn and macOS
behavior still affect authentication, TLS and network cleanup. A globally unregistered
service cannot be made transactional with an arbitrary external file manager:
do not reopen the app during package maintenance.

Normal uninstall preserves profiles, Keychain secrets and the root-managed runtime.
Use Configurações → Serviço privilegiado → Remover serviço e arquivos gerenciados
before uninstall to request
administrator-authorized runtime removal. Do not manually delete root state while
it is in use. No broad zap stanza deletes credentials. Forks need their own identity
and notarization. Do not run fork PR workflows with signing/notarization secrets.

Recovery records are persisted before DNS and external endpoint-route mutations.
Failed restoration keeps its record; recovery retries after restart. The interface
reports pending cleanup, and maintenance refuses to discard unresolved records.
This does not guarantee traffic blocking: TunnelMac does not implement a kill switch.

The GUI, privileged core, integration runner and focused test target are separate
modules. Distribution builds exclude integration fixtures and their command modes.
Runtime replacements are refused while any session is active or ending. Approval
shows the actual source path and mutable-file warnings; it does not authenticate
upstream provenance. The full approved source inventory is compared in the background
for drift, including libraries and the DNS script.
