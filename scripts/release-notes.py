#!/usr/bin/env python3
"""Notes of one release from packaging/release-notes.md.

The file keeps every release's section ("Changes in <version>:") for reference; a release
gets the introduction (everything before the first section) plus its own section only.
Prints nothing and exits 1 when the version has no section.

    scripts/release-notes.py 1.1.0 [packaging/release-notes.md]
"""
from pathlib import Path
import re
import sys

def extract(text, release):
    sections = re.split(r'(?m)^(?=Changes in [^\n]+:\s*$)', text)
    intro, rest = sections[0], sections[1:]
    own = [s for s in rest if s.startswith(f'Changes in {release}:')]
    if not own:
        return None
    return intro.rstrip() + '\n\n' + own[0].rstrip() + '\n'

def main():
    if len(sys.argv) not in (2, 3):
        raise SystemExit(__doc__)
    path = Path(sys.argv[2] if len(sys.argv) == 3 else Path(__file__).resolve().parent.parent / 'packaging/release-notes.md')
    notes = extract(path.read_text(), sys.argv[1])
    if notes is None:
        return 1
    sys.stdout.write(notes)
    return 0

if __name__ == '__main__':
    sys.exit(main())
