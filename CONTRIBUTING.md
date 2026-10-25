# Contributing

Thanks for helping. Bug reports, ideas and focused pull requests are all welcome. You can
build, run and test TunnelMac without an Apple developer account and without touching a
real VPN.

## Set up in five minutes

**You need:** a Mac with Apple Silicon, [Homebrew](https://brew.sh) and Xcode with the
macOS 26 SDK or newer (the project was prepared with Swift 6.4 and the macOS 27 SDK).
The deployment target is macOS 13, so newer APIs need fallbacks.

```sh
git clone https://github.com/luizmz94/tunnelmac.git
cd tunnelmac
brew install openfortivpn          # the GUI checks look for it, like CI
```

**See the app with demo data.** This opens the real interface with fictitious connections.
Conectar and Desconectar replay client output in-process: no VPN, no admin password,
no network.

```sh
./scripts/showcase.sh
```

**Run the tests.**

```sh
./scripts/test-regressions.sh   # fast unit regressions (swift test), no GUI needed
./scripts/test.sh               # full suite: regressions + GUI, Keychain and XPC checks
```

`test.sh` builds an ad hoc `TunnelMac.app` and a separate checks runner under
`build/<version>/`, opens the runner as a normal app and writes `TestResults.txt` next to it.
It needs a logged-in graphical session; from a restricted shell it may be blocked. Report
that as blocked, not as passing. Release-oriented checks of a finished bundle run with
`TUNNELMAC_REVIEW_APP="$PWD/build/<version>/TunnelMac.app" ./build/<version>/VPNGUILocalChecks-<version>.app/Contents/MacOS/VPNGUI --release-checks`;
they complement the full suite, never replace it.

**Build the app.**

```sh
./scripts/build.sh   # ad hoc signature → build/<version>/TunnelMac.app
```

An ad hoc build opens and renders, but the privileged service stays disabled (it fails
closed without a verified Apple Team), so it cannot connect. To try real connections,
sign with your own identity, see [Signing your own build](#signing-your-own-build).
Use `OUTPUT_DIR` to keep another build untouched and `ARCH=arm64` or `ARCH=x86_64` to
choose the slice (compiling a slice does not prove it runs).

## Project map

| Path | What lives there |
| --- | --- |
| `Sources/VPNGUI` | SwiftUI/AppKit app: windows, menu bar, editor, settings, imports, persistence |
| `Sources/VPNHelperShared` | Contracts shared by app and helper: XPC messages, profile validation, trust policy |
| `Sources/VPNHelperCore` | Privileged helper logic: sessions, runtime approval, routes and DNS, WireGuard |
| `Sources/VPNHelper` | LaunchDaemon entry point registered with `SMAppService` |
| `Sources/VPNSupervisor` | Small C supervisor that runs one VPN client per connection |
| `Sources/ProcessBridge` | `posix_spawn` and process-identity primitives |
| `Tests/ReviewTests` | `swift test` regressions |
| `IntegrationRunner` | Debug-only runner: GUI, Keychain, XPC and release checks, plus the showcase |
| `scripts` | Build, test, showcase, sign, notarize, package and publish |

## Making a change

1. Branch from `main` and keep the PR focused on one problem.
2. Run `./scripts/test.sh` (or at least `./scripts/test-regressions.sh`) and say in the PR
   what you ran and what you could not run.
3. UI change? Add before/after screenshots taken with `./scripts/showcase.sh`, never with
   real connections. `./scripts/showcase.sh --capture` regenerates the README images in
   `docs/assets`.
4. Describe the trigger, the resulting behavior and the checks performed (the PR template
   asks for this).

PRs run `./scripts/test.sh` on GitHub-hosted macOS with read-only permissions and no
secrets. Graphical-session failures there are still failures.

## Ground rules

- **No VPN protocol code and no bundled clients.** openfortivpn, OpenVPN and wireguard-go
  stay external dependencies that the user installs and approves.
- **Security boundaries need maintainer review.** Changes to helper operations, XPC trust,
  runtime integrity, maintenance or persistence require explicit review. Read
  [SECURITY.md](SECURITY.md) first.
- **Never commit secrets or real data:** passwords, tokens, cookies, real VPN profiles,
  private certificates, Keychain exports, signing profiles or client screenshots.
- **Tests stay harmless.** The runner uses separate data, disposable Keychain services,
  anonymous XPC listeners and stand-in processes. It never registers a daemon, connects a
  VPN, asks for root or changes routes/DNS. Update checks use a fake transport; settings use
  a disposable `UserDefaults` suite. Keep it that way, and don't use personal VPNs or the
  installed service for automated tests.
- **No test modes in the shipped app.** Fixtures and demo data live only in
  `IntegrationRunner`, which is not part of the distributed bundle.
- Preserve the original work when updating specifications or brand assets.

## Signing your own build

Forks and distributors use their own Apple identity and notarization profile. These are
your inputs, not project credentials:

```sh
SIGNING_IDENTITY='Developer ID Application: Your Name (YOURTEAMID)' \
  TEAM_ID=YOURTEAMID ./scripts/build.sh
NOTARY_PROFILE=your-keychain-profile ./scripts/notarize.sh
./scripts/package-release.sh
```

App, helper and supervisor must share one verified Team. Install the signed app in
`/Applications` before enabling the service. `package-release.sh` accepts only Developer ID
signed, timestamped, hardened, notarized arm64 bundles. `publish-release.sh` requires a
clean default branch, a full test report, the publication audit and successful CI.

## How releases happen

Releases of this repository are automatic. Every push to `main` runs the macOS checks;
when they pass, `.github/workflows/release.yml` runs the full suite and the shared
publication preflight, then picks the version with `scripts/next-version.py`: a
`releaseVersion` set by hand in `Constants.swift` (for example `1.0.0`) is used as is;
if it is already released, the next one (`-rc.N+1`, or the next patch) and the next
build number are committed back to `main`. Pushes that change nothing under `Sources`,
`Package.swift` or `Resources` are not released, so docs-only PRs never ship a build.
The app is signed, notarized and published (prerelease when the version has a suffix),
and the cask in `luizmz94/homebrew-tunnelmac` is updated with a deploy key limited to that
repository. Signing and notarization credentials live only in the `release` environment,
which accepts `main` only. A manual run with `dry_run` builds, signs and notarizes without
publishing.

## Install, upgrade and uninstall testing

Full lifecycle validation belongs in an isolated macOS VM with distinct service identifiers
and root state: cancellation, cleanup timeout, unregister failure, data retention and
reinstall, before promoting a candidate to stable. Homebrew runs cask steps inside its
sandbox; the local checks run the maintenance command under the installed Homebrew's
profile with a harmless stand-in process, never against the installed app or service.

A submission to homebrew/cask must satisfy the official acceptance, platform, security,
verifiable-download and livecheck policies; a private tap does not imply eligibility.
