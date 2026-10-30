# Third-party notices

The Swift and C sources in this repository were developed for this project;
Git records no imported source files or vendored packages. They use Apple system
SDKs and POSIX APIs. The project's MIT license does not relicense those SDKs.
This is a source/history review, not an independent provenance or security audit.

**openfortivpn** is an external dependency, maintained by its own contributors:
https://github.com/adrienverge/openfortivpn (GPL-3.0 with the upstream OpenSSL
exception; consult upstream LICENSE and source headers for its exact scope). Neither its executable
nor Homebrew libraries are included in release archives. The locally approved
runtime is copied from the user's installation by the privileged helper.

**OpenVPN** is an external dependency, maintained by OpenVPN Inc. and its
contributors: https://github.com/OpenVPN/openvpn (GPL-2.0; its `dns-updown`
script is BSD-2-Clause). It is not included in release archives either; when the
user approves it, the helper copies the local installation, its libraries, its
`dns-updown` script and license files into the protected runtime. OpenVPN is a
registered trademark of OpenVPN Inc.; this project is independent of it.

**wireguard-go** is an external dependency, maintained by Jason A. Donenfeld and the
WireGuard contributors: https://git.zx2c4.com/wireguard-go (MIT). It is not included
in release archives; when the user approves it, the helper copies the local Homebrew
executable and its license files into the protected runtime. wg-quick and the other
wireguard-tools programs are not used: the helper implements the macOS tunnel setup
itself, following wg-quick's documented behavior. "WireGuard" and the WireGuard logo
are registered trademarks of Jason A. Donenfeld; this project is independent of it.

**OpenConnect** is an external dependency, maintained by David Woodhouse and its
contributors: https://www.infradead.org/openconnect/ (LGPL-2.1). It is not included in
release archives; when the user approves it, the helper copies the local Homebrew
executable, its libraries (GnuTLS and others, each under its own license) and their
license files into the protected runtime. Its vpnc-script is not used: the helper ships
its own script for addresses, routes and DNS, written for this project. GlobalProtect is
a trademark of Palo Alto Networks; this project is independent of it.

**Sparkle** 2.9.6 (https://sparkle-project.org) is included in the app bundle
(`Contents/Frameworks/Sparkle.framework`) for in-app updates, under the MIT License.
Its complete LICENSE file, with the notices of the code it bundles (bsdiff 4.3 by Colin
Percival, BSD; sais-lite by Yuta Mori, MIT; ed25519 by Orson Peters, zlib; code by Mark
Hamlin, BSD), ships in the app as `Contents/Resources/Sparkle-LICENSE.txt` and is at
https://github.com/sparkle-project/Sparkle/blob/2.9.6/LICENSE.

    Copyright (c) 2006-2013 Andy Matuschak.
    Copyright (c) 2009-2013 Elgato Systems GmbH.
    Copyright (c) 2011-2014 Kornel Lesiński.
    Copyright (c) 2015-2017 Mayur Pawashe.
    Copyright (c) 2014 C.W. Betts.
    Copyright (c) 2014 Petroules Corporation.
    Copyright (c) 2014 Big Nerd Ranch.
    All rights reserved.

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
    FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
    COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
    IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

**Protocol marks:** the Fortinet, OpenVPN and WireGuard marks in the Nova conexão
chooser use path data from Simple Icons 13.21.0 (https://simpleicons.org, CC0-1.0).
The marks are trademarks of Fortinet, Inc., OpenVPN Inc. and Jason A. Donenfeld; they
only identify which kind of server a connection talks to and imply no affiliation or
endorsement.

**Brand assets:** the original V/node symbol and icon were supplied by the project
owner as the VPN GUI brand pack. SVG content credentials identify Claude as a
creating/modifying tool, not an exclusive human author. They are retained as
project assets. The editable TunnelMac wordmark uses generic sans-serif text;
no font files or copied Manrope glyph outlines are included in that wordmark.
The original Manrope wordmark exports have been excluded from the public asset
set; no font license is inferred from the font name alone.

AppKit/SwiftUI use system fonts and SF Symbols through Apple's APIs. No system
font or SF Symbols font file is redistributed. Fortinet and openfortivpn names
belong to their respective owners. This project is independent of both.
