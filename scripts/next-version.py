#!/usr/bin/env python3
"""Choose the version of an automatic release from main.

Prints `skip`, `keep <release>` or `bump <release>`:
- skip: nothing that ships in the app changed since the last release tag;
- keep: Constants.swift already names a version without a tag (set by hand, e.g. 1.0.0);
- bump: that version is already released, so the next one is written into
  Constants.swift (rc.N -> rc.N+1, X.Y.Z -> X.Y.Z+1) with the build number + 1.
"""
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
CONSTANTS = ROOT / 'Sources/VPNHelperShared/Constants.swift'
APP_PATHS = ['Sources', 'Package.swift', 'Resources']

def git(*args):
    return subprocess.run(['git', *args], cwd=ROOT, text=True, capture_output=True)

def field(text, name):
    match = re.search(r'static let %s = "([^"]*)"' % name, text)
    if not match:
        raise SystemExit(f'{name} not found in {CONSTANTS}')
    return match.group(1)

def main():
    text = CONSTANTS.read_text()
    release, build = field(text, 'releaseVersion'), field(text, 'build')
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-rc\.\d+)?', release) or not build.isdigit():
        raise SystemExit(f'Unexpected releaseVersion/build: {release} ({build})')
    last = git('describe', '--tags', '--abbrev=0', '--match', 'v*', 'HEAD').stdout.strip()
    if last and git('diff', '--quiet', last, 'HEAD', '--', *APP_PATHS).returncode == 0:
        print('skip')
        return
    if not git('rev-parse', '-q', '--verify', f'refs/tags/v{release}').stdout.strip():
        print(f'keep {release}')
        return
    base, _, rc = release.partition('-rc.')
    if rc:
        version, release = base, f'{base}-rc.{int(rc) + 1}'
    else:
        major, minor, patch = map(int, base.split('.'))
        version = release = f'{major}.{minor}.{patch + 1}'
    if git('rev-parse', '-q', '--verify', f'refs/tags/v{release}').stdout.strip():
        raise SystemExit(f'v{release} already exists; set releaseVersion by hand')
    text = re.sub(r'(static let version = ")[^"]*(")', rf'\g<1>{version}\g<2>', text, count=1)
    text = re.sub(r'(static let releaseVersion = ")[^"]*(")', rf'\g<1>{release}\g<2>', text, count=1)
    text = re.sub(r'(static let build = ")[^"]*(")', rf'\g<1>{int(build) + 1}\g<2>', text, count=1)
    CONSTANTS.write_text(text)
    print(f'bump {release}')

if __name__ == '__main__':
    sys.exit(main())
