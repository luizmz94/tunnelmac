#!/usr/bin/env python3
"""Sparkle appcasts of one release: appcast-<arch>.xml next to each packaged archive.

    scripts/appcast.py 0.5.0-rc.6 --dir build/releases/0.5.0-rc.6 --notes notes.md --tools <Sparkle>/bin

Each appcast lists only that release, so the app installs exactly the version its update
check offered (AppUpdater reads releases/download/v<version>/appcast-<arch>.xml). The
archive and the feed are signed with the EdDSA key: SPARKLE_ED_PRIVATE_KEY (CI), else the
"tunnelmac" account of the login Keychain. The key is never written to disk or printed.
"""
import argparse
import html
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

REPO = 'luizmz94/tunnelmac'
ARCHES = ('arm64', 'x86_64')
SPARKLE = '{http://www.andymatuschak.org/xml-namespaces/sparkle}'


def inline(text):
    """Escaped Markdown line: links, bare URLs, bold and code; nothing else survives."""
    parts = re.split(r'(\[[^\]]*\]\(https://[^)\s]+\)|https://\S+)', text)
    out = []
    for part in parts:
        link = re.fullmatch(r'\[([^\]]*)\]\((https://[^)\s]+)\)', part)
        if link:
            out.append(f'<a href="{html.escape(link[2])}">{html.escape(link[1])}</a>')
        elif part.startswith('https://'):
            out.append(f'<a href="{html.escape(part)}">{html.escape(part)}</a>')
        else:
            escaped = html.escape(part)
            escaped = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', escaped)
            out.append(re.sub(r'`([^`]+)`', r'<code>\1</code>', escaped))
    return ''.join(out)


# Sparkle shows the notes in a web view under its own title and version line: system
# font, light and dark mode, compact list. Only CSS, no script.
NOTES_STYLE = """<style>
:root { color-scheme: light dark; }
body { font: 13px/1.45 -apple-system, system-ui, sans-serif; margin: 10px 14px; }
h3 { font-size: 13px; font-weight: 600; margin: 0 0 6px; }
p { margin: 0 0 8px; }
ul { margin: 0 0 8px; padding-left: 18px; }
li { margin: 0 0 7px; }
li::marker { color: #8e8e93; }
code { font: 12px ui-monospace, Menlo, monospace; padding: 1px 4px; border-radius: 4px;
       background: rgba(127, 127, 127, .16); }
a { color: LinkText; text-decoration: none; }
</style>"""


def notes_html(markdown):
    """Release notes as an HTML fragment (embedded in the appcast, shown by Sparkle).

    Only the "Changes in <version>:" section: the introduction (what TunnelMac is, how to
    install it) means nothing to someone already updating. Wrapped lines continue their
    paragraph or list item instead of starting a new one.
    """
    text = re.sub(r'(?s)<!--.*?-->', '', markdown)
    changes = re.search(r'(?m)^Changes in [^\n]+:\s*$', text)
    if changes:
        text = text[changes.end():]
    blocks = []   # ('ul', [items]) | ('p', [lines]) | ('h3', [line])
    for raw in text.splitlines():
        line = raw.strip()
        bullet = re.match(r'^[-*+]\s+(.*)', line)
        heading = re.match(r'^#{1,6}\s+(.*)', line)
        if not line or re.fullmatch(r'[-*_]{3,}', line):
            blocks.append(None)
        elif bullet:
            if blocks and blocks[-1] and blocks[-1][0] == 'ul':
                blocks[-1][1].append([bullet[1]])
            else:
                blocks.append(('ul', [[bullet[1]]]))
        elif heading:
            blocks.append(('h3', [heading[1]]))
        elif blocks and blocks[-1] and blocks[-1][0] == 'ul':
            blocks[-1][1][-1].append(line)   # wrapped list item
        elif blocks and blocks[-1] and blocks[-1][0] == 'p':
            blocks[-1][1].append(line)       # wrapped paragraph
        else:
            blocks.append(('p', [line]))
    out = []
    for block in filter(None, blocks):
        kind, body = block
        if kind == 'ul':
            out.append('<ul>' + ''.join(f'<li>{inline(" ".join(item))}</li>' for item in body) + '</ul>')
        else:
            out.append(f'<{kind}>{inline(" ".join(body))}</{kind}>')
    if not out:
        out = ['<p>Veja as novidades na página da versão no GitHub.</p>']
    return NOTES_STYLE + '\n' + '\n'.join(out)


def bundle_versions(archive):
    with zipfile.ZipFile(archive) as z:
        plist = z.read('TunnelMac.app/Contents/Info.plist').decode()
    def value(key):
        found = re.search(rf'<key>{key}</key>\s*<string>([^<]+)</string>', plist)
        if not found:
            raise SystemExit(f'{key} missing in {archive.name}')
        return found[1]
    return value('CFBundleVersion'), value('CFBundleShortVersionString')


def generate(release, arch, folder, notes, tools):
    archive = folder / f'TunnelMac-{release}-{arch}.zip'
    if not archive.is_file():
        raise SystemExit(f'Missing {archive}')
    prefix = f'https://github.com/{REPO}/releases/download/v{release}/'
    build, short = bundle_versions(archive)
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        shutil.copy2(archive, work / archive.name)
        (work / archive.with_suffix('.html').name).write_text(notes)
        key = os.environ.get('SPARKLE_ED_PRIVATE_KEY')
        command = [str(tools / 'generate_appcast'), '--download-url-prefix', prefix,
                   '--link', f'https://github.com/{REPO}/releases/tag/v{release}',
                   '--embed-release-notes', '--maximum-deltas', '0', '--disable-signing-warning',
                   '-o', str(work / 'appcast.xml')]
        command += ['--ed-key-file', '-'] if key else ['--account', 'tunnelmac']
        subprocess.run(command + [str(work)], input=(key or '').encode(), check=True, stdout=subprocess.DEVNULL)
        feed = (work / 'appcast.xml').read_text()
    check(feed, archive, prefix, build, short)
    target = folder / f'appcast-{arch}.xml'
    target.write_text(feed)
    return target


def check(feed, archive, prefix, build, short):
    """One item, this archive, signed; the feed carries Sparkle's signature comment."""
    items = ET.fromstring(feed).findall('./channel/item')
    if len(items) != 1:
        raise SystemExit(f'Expected one appcast item, found {len(items)}')
    item = items[0]
    enclosure = item.find('enclosure')
    if (enclosure is None or enclosure.get('url') != prefix + archive.name
            or enclosure.get('length') != str(archive.stat().st_size) or not enclosure.get(SPARKLE + 'edSignature')):
        raise SystemExit('Appcast enclosure does not match the signed archive')
    if item.findtext(SPARKLE + 'version') != build or item.findtext(SPARKLE + 'shortVersionString') != short:
        raise SystemExit('Appcast version does not match the archive')
    if 'sparkle-signatures:' not in feed:
        raise SystemExit('Appcast feed is not signed (SURequireSignedFeed)')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('release')
    parser.add_argument('--dir', type=Path, required=True, help='folder with TunnelMac-<release>-<arch>.zip')
    parser.add_argument('--notes', type=Path, required=True, help='release notes in Markdown')
    parser.add_argument('--tools', type=Path, required=True, help='bin folder of the Sparkle distribution')
    args = parser.parse_args()
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-rc\.\d+)?', args.release):
        parser.error('Invalid release version')
    notes = notes_html(args.notes.read_text())
    for arch in ARCHES:
        print(generate(args.release, arch, args.dir, notes, args.tools))


if __name__ == '__main__':
    main()
