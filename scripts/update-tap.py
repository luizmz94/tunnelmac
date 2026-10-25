#!/usr/bin/env python3
"""Generate the tap only from a published, signed, stapled arm64 release."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

REPO = 'luizmz94/tunnelmac'

def command(*args):
    return subprocess.check_output(args, text=True).strip()

def cask(version, digest):
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-rc\.\d+)?', version):
        raise ValueError('Invalid version')
    if not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ValueError('Invalid SHA-256')
    return r'''cask "tunnelmac" do
  version "%s"
  sha256 "%s"

  url "https://github.com/luizmz94/tunnelmac/releases/download/v#{version}/TunnelMac-#{version}-arm64.zip"
  name "TunnelMac"
  desc "Native GUI for openfortivpn, OpenVPN and WireGuard"
  homepage "https://github.com/luizmz94/tunnelmac"

  livecheck do
    url :url
    strategy :github_releases do |json|
      json.filter_map do |release|
        next if release["draft"]

        release["tag_name"][/\Av?(\d+\.\d+\.\d+(?:-rc\.\d+)?)\z/i, 1]
      end
    end
  end

  depends_on arch: :arm64
  depends_on formula: "openfortivpn"
  depends_on macos: :ventura

  app "TunnelMac.app"

  preflight_steps do
    if_path_exists "OpenFortiDesk.app", base: :appdir do
      # Homebrew runs this in its sandbox: read-only, requires the old service removed.
      run "TunnelMac.app/Contents/MacOS/VPNGUI",
          args:         ["--prepare-for-legacy-migration"],
          base:         :staged_path,
          sudo:         false,
          must_succeed: true
      move "OpenFortiDesk.app", "~/Library/Application Support/VPNGUI/Backups/OpenFortiDesk-before-TunnelMac.app",
           source_base: :appdir,
           overwrite:   false
    end
    if_path_exists "VPNGUI.app", base: :appdir do
      # Homebrew runs this in its sandbox: read-only, requires the old service removed.
      run "TunnelMac.app/Contents/MacOS/VPNGUI",
          args:         ["--prepare-for-legacy-migration"],
          base:         :staged_path,
          sudo:         false,
          must_succeed: true
      move "VPNGUI.app", "~/Library/Application Support/VPNGUI/Backups/VPNGUI-before-TunnelMac.app",
           source_base: :appdir,
           overwrite:   false
    end
  end

  # In Homebrew's sandbox: refuses while the app runs, keeps the registration.
  uninstall_preflight_steps do
    run "TunnelMac.app/Contents/MacOS/VPNGUI",
        args:         ["--prepare-for-maintenance"],
        base:         :appdir,
        sudo:         false,
        must_succeed: true
  end

  caveats <<~EOS
    First use: open TunnelMac, activate its service, approve it in System
    Settings and approve the protected openfortivpn, OpenVPN and/or
    wireguard-go runtime.

    Before brew upgrade: quit TunnelMac with Sair (this disconnects its
    VPNs). The service registration is kept for the upgraded app.

    Before brew uninstall: open the app, use Configurações… > Serviço
    privilegiado > Remover serviço, then quit with Sair. Homebrew's sandbox does
    not allow removing the registration.

    Migrating from OpenFortiDesk.app or VPNGUI.app (same product, earlier
    name): remove its service first the same way, quit it, then
    brew uninstall --cask openfortidesk (if installed) before installing.

    %s
    Profiles, Keychain secrets and the protected runtime survive uninstall. Do not
    reopen the app during an upgrade. See SECURITY.md before removing managed root
    files.
  EOS
end
''' % (version, digest, 'Release candidate: isolated root lifecycle integration is not yet validated.' if '-' in version else 'Stable release: see the release validation report for supported platforms.')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tag')
    parser.add_argument('--tap', type=Path, default=Path(__file__).resolve().parent.parent.parent / 'homebrew-tunnelmac',
                        help='checkout of luizmz94/homebrew-tunnelmac (default: next to this repository)')
    args = parser.parse_args()
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-rc\.\d+)?', args.tag):
        parser.error('Invalid release tag')
    release = json.loads(command('gh', 'release', 'view', args.tag, '--repo', REPO,
                                 '--json', 'isDraft,isPrerelease,assets,tagName'))
    if release['isDraft'] or release['tagName'] != args.tag:
        raise SystemExit('Only an existing published release can populate the tap')
    version = args.tag[1:]
    asset = f'TunnelMac-{version}-arm64.zip'
    if asset not in [a['name'] for a in release['assets']]:
        raise SystemExit('The required release asset is absent')
    with tempfile.TemporaryDirectory(prefix='tunnelmac-tap-') as tmp:
        command('gh', 'release', 'download', args.tag, '--repo', REPO, '--pattern', asset,
                '--pattern', 'SHA256SUMS', '--dir', tmp)
        root = Path(tmp)
        digest = hashlib.sha256((root / asset).read_bytes()).hexdigest()
        if f'{digest}  {asset}' not in (root / 'SHA256SUMS').read_text().splitlines():
            raise SystemExit('Published checksum mismatch')
        command('ditto', '-x', '-k', str(root / asset), str(root / 'unpacked'))
        app = root / 'unpacked/TunnelMac.app'
        command(str(Path(__file__).resolve().parent / 'verify-bundle.sh'), str(app))
        if command('/usr/libexec/PlistBuddy', '-c', 'Print :CFBundleShortVersionString', str(app / 'Contents/Info.plist')) != version.split('-')[0]:
            raise SystemExit('Bundle version differs from the release tag')
        command('xcrun', 'stapler', 'validate', str(app))
        command('spctl', '--assess', '--type', 'execute', str(app))
        for binary in ('VPNGUI', 'VPNHelper', 'VPNSupervisor'):
            if command('lipo', '-archs', str(app / 'Contents/MacOS' / binary)) != 'arm64':
                raise SystemExit('Release architectures do not match the cask')
        target = args.tap / 'Casks/tunnelmac.rb'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(cask(version, digest))
        print(target)

if __name__ == '__main__':
    main()
