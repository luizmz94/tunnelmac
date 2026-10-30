import Foundation
import Darwin
import VPNHelperShared

/// Network setup of openconnect (GlobalProtect) sessions. With "Só redes internas"
/// (TUNNELMAC_INTERNAL_NETWORKS) only those networks use the tunnel and only the gateway's
/// domains its DNS: the rest of the internet keeps the physical network and its trust.
/// openconnect runs a vpnc-script
/// synchronously as root for each phase; the helper uses its own script, embedded here and
/// written root-owned into the state directory, never Homebrew's (user-writable) vpnc-script.
///
/// The script sets the utun address, routes (the gateway's split includes, or 0/1 + 128/1
/// for a full tunnel, so the default route stays untouched), excludes and a host route to
/// the gateway through the physical router, and publishes the VPN's DNS as a TunnelMac
/// resolver in the dynamic store. Routes through the physical router are recorded in
/// `work/oc.<token>.routes`; if openconnect never ran "disconnect" (killed), the helper
/// removes them when the client ends or at its next start.
enum GlobalProtectNetwork {
    static let scriptName = "tunnelmac-vpnc-script"

    static func routesFile(work: String, token: String) -> String { work + "/oc.\(token).routes" }

    /// Lines "host|net <destination> <gateway>" written by the script; anything else is ignored.
    static func recordedRoutes(_ text: String) -> [(kind: String, destination: String, gateway: String)] {
        text.split(separator: "\n").compactMap { line in
            let fields = line.split(separator: " ").map(String.init)
            guard fields.count == 3, ["host", "net"].contains(fields[0]),
                  fields[1].range(of: #"^[0-9.]{7,15}(/[0-9]{1,2})?$"#, options: .regularExpression) != nil,
                  fields[2].range(of: #"^[0-9.]{7,15}$"#, options: .regularExpression) != nil else { return nil }
            return (fields[0], fields[1], fields[2])
        }
    }

    /// Removes the routes a session left through the physical router, then its record.
    static func removeLeftovers(_ path: String, host: WireGuardHost) {
        guard let (data, _) = try? SecureFile.read(path, limit: 256 * 1024) else { unlink(path); return }
        for route in recordedRoutes(String(decoding: data, as: UTF8.self)) {
            _ = host.run(WireGuardTools.route, ["-q", "-n", "delete", "-inet", "-\(route.kind)", route.destination, route.gateway])
        }
        unlink(path)
    }

    /// Records of sessions that are gone (helper crash or restart).
    static func recover(work: String, live: Set<String>, host: WireGuardHost) {
        for entry in (try? FileManager.default.contentsOfDirectory(atPath: work)) ?? []
        where entry.hasPrefix("oc.") && entry.hasSuffix(".routes") {
            let token = String(entry.dropFirst(3).dropLast(7))
            if !live.contains(token) { removeLeftovers(work + "/" + entry, host: host) }
        }
    }

    static let script = #"""
#!/bin/sh
# TunnelMac vpnc-script for openconnect (GlobalProtect) on macOS, written by the helper.
# Every value comes from the gateway: each one is checked before use, nothing is evaluated.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077
set -f

is_ipv4() {
	case "$1" in ''|*[!0-9.]*|.*|*.|*..*) return 1 ;; esac
	_old=$IFS; IFS=.; set -- $1; IFS=$_old
	[ $# -eq 4 ] || return 1
	for _octet in "$@"; do
		case "$_octet" in ????*) return 1 ;; esac
		[ "$_octet" -le 255 ] || return 1
	done
	return 0
}
is_masklen() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ "$1" -le 32 ]; }
is_domain() {
	case "$1" in ''|*[!A-Za-z0-9._-]*|.*|-*) return 1 ;; esac
	[ ${#1} -le 253 ]
}
is_count() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ "$1" -le 512 ]; }

case "$TUNNELMAC_TOKEN" in ''|*[!A-Fa-f0-9-]*) echo "[!] TunnelMac: sessão inválida no script de rede."; exit 1 ;; esac
case "$TUNNELMAC_ROUTES" in /*) ;; *) exit 1 ;; esac
case "$TUNNELMAC_ROUTES" in *[!A-Za-z0-9/._-]*) exit 1 ;; esac
DNS_KEY="State:/Network/Service/TunnelMac-$TUNNELMAC_TOKEN/DNS"

# First non-scoped default route with a real gateway: the physical router.
physical_gateway() {
	netstat -nr -f inet | awk '$1 == "default" && $2 !~ /^link#/ && $3 !~ /I/ { print $2; exit }'
}

# Route through the physical router, recorded so the helper can undo it.
add_external() {
	if route -q -n add -inet "-$1" "$2" "$GATEWAY" >/dev/null 2>&1; then
		echo "$1 $2 $GATEWAY" >> "$TUNNELMAC_ROUTES"
		echo "[#] route add -$1 $2 $GATEWAY"
	else
		echo "[!] Rota $2 pelo roteador $GATEWAY não adicionada (já existe ou falhou)."
	fi
}

remove_external() {
	[ -f "$TUNNELMAC_ROUTES" ] || return 0
	while read -r kind destination router; do
		case "$kind" in host|net) route -q -n delete -inet "-$kind" "$destination" "$router" >/dev/null 2>&1 ;; esac
	done < "$TUNNELMAC_ROUTES"
	: > "$TUNNELMAC_ROUTES"
}

setup_external() {
	GATEWAY=$(physical_gateway)
	if ! is_ipv4 "$GATEWAY"; then
		echo "[!] Roteador físico não encontrado; rotas de exceção não configuradas."
		return 0
	fi
	is_ipv4 "$VPNGATEWAY" && add_external host "$VPNGATEWAY"
	# Only internal networks use the tunnel: the gateway's excludes are not needed.
	[ -n "$TUNNELMAC_INTERNAL_NETWORKS" ] && return 0
	count=${CISCO_SPLIT_EXC:-0}
	is_count "$count" || count=0
	i=0
	while [ "$i" -lt "$count" ]; do
		eval "address=\${CISCO_SPLIT_EXC_${i}_ADDR:-} length=\${CISCO_SPLIT_EXC_${i}_MASKLEN:-}"
		i=$((i + 1))
		is_ipv4 "$address" && is_masklen "$length" && [ "$length" -gt 0 ] || continue
		add_external net "$address/$length"
	done
}

# Route through the tunnel that the session needs; a failure is remembered in $missing.
add_tunnel() {
	if route -q -n add -inet -net "$1" -interface "$TUNDEV" >/dev/null 2>&1; then
		echo "[#] route add -net $1 -interface $TUNDEV"
	else
		echo "[!] Rota $1 não adicionada."
		missing="$missing $1"
	fi
}

# Without these routes or the DNS the session would look connected while traffic or names
# miss the tunnel: the helper stops openconnect when it sees this line.
incomplete() {
	[ -z "$missing" ] && return 0
	echo "[!] TunnelMac: rede da VPN incompleta:$missing."
	exit 1
}

flush_dns() {
	dscacheutil -flushcache >/dev/null 2>&1
	killall -HUP mDNSResponder >/dev/null 2>&1
}

do_connect() {
	case "$TUNDEV" in utun[0-9]|utun[0-9][0-9]|utun[0-9][0-9][0-9]) ;; *) echo "[!] Interface inesperada: $TUNDEV"; exit 1 ;; esac
	if ! is_ipv4 "$INTERNAL_IP4_ADDRESS"; then echo "[!] O gateway não informou um endereço IPv4 válido."; exit 1; fi
	mtu=${INTERNAL_IP4_MTU:-1300}
	case "$mtu" in ''|*[!0-9]*) mtu=1300 ;; esac
	{ [ "$mtu" -ge 576 ] && [ "$mtu" -le 9000 ]; } || mtu=1300
	ifconfig "$TUNDEV" inet "$INTERNAL_IP4_ADDRESS" "$INTERNAL_IP4_ADDRESS" netmask 255.255.255.255 mtu "$mtu" up || exit 1
	echo "[#] ifconfig $TUNDEV inet $INTERNAL_IP4_ADDRESS mtu $mtu up"
	: > "$TUNNELMAC_ROUTES"
	missing=""
	setup_external

	# Full tunnel when the gateway sends no include, or includes 0.0.0.0/0 among them
	# (PAN-OS sends the default network next to host routes such as its DNS servers).
	default=0
	count=${CISCO_SPLIT_INC:-0}
	is_count "$count" || count=0
	i=0
	while [ "$i" -lt "$count" ]; do
		eval "address=\${CISCO_SPLIT_INC_${i}_ADDR:-} length=\${CISCO_SPLIT_INC_${i}_MASKLEN:-}"
		i=$((i + 1))
		is_ipv4 "$address" && is_masklen "$length" && [ "$length" -eq 0 ] && default=1
	done
	full=0
	{ [ "$count" -eq 0 ] || [ "$default" -eq 1 ]; } && full=1
	if [ -n "$TUNNELMAC_INTERNAL_NETWORKS" ]; then
		[ "$full" -eq 1 ] && echo "[i] O gateway pede todo o tráfego pela VPN; só as redes internas escolhidas usarão o túnel."
		full=0
		count=0
		for network in $TUNNELMAC_INTERNAL_NETWORKS; do
			address=${network%/*}; length=${network#*/}
			is_ipv4 "$address" && is_masklen "$length" && [ "$length" -gt 0 ] || continue
			add_tunnel "$address/$length"
		done
	fi
	i=0
	while [ "$i" -lt "$count" ]; do
		eval "address=\${CISCO_SPLIT_INC_${i}_ADDR:-} length=\${CISCO_SPLIT_INC_${i}_MASKLEN:-}"
		i=$((i + 1))
		is_ipv4 "$address" && is_masklen "$length" || continue
		[ "$length" -eq 0 ] && continue
		[ "$address" = "$INTERNAL_IP4_ADDRESS" ] && continue
		add_tunnel "$address/$length"
	done
	if [ "$full" -eq 1 ]; then
		# Two halves are more specific than the default route, which stays untouched.
		for half in 0.0.0.0/1 128.0.0.0/1; do add_tunnel "$half"; done
		# The tunnel's own packets must keep the physical network.
		if is_ipv4 "$VPNGATEWAY"; then
			via=$(route -n get -inet "$VPNGATEWAY" 2>/dev/null | awk '/interface:/ { print $2; exit }')
			[ "$via" = "$TUNDEV" ] && missing="$missing $VPNGATEWAY"
		fi
	fi

	servers=""
	n=0
	for server in $INTERNAL_IP4_DNS; do
		is_ipv4 "$server" || continue
		[ "$n" -lt 4 ] || break
		servers="$servers $server"; n=$((n + 1))
		# The VPN's DNS must be reached through the tunnel, never the local network.
		[ "$full" -eq 1 ] || route -q -n add -inet -host "$server" -interface "$TUNDEV" >/dev/null 2>&1
		via=$(route -n get -inet "$server" 2>/dev/null | awk '/interface:/ { print $2; exit }')
		[ "$via" = "$TUNDEV" ] || missing="$missing $server"
	done
	incomplete
	domains=""
	for domain in $CISCO_DEF_DOMAIN $(echo "$CISCO_SPLIT_DNS" | tr ',;' '  '); do
		is_domain "$domain" || continue
		case " $domains " in *" $domain "*) continue ;; esac
		domains="$domains $domain"
	done
	if [ -z "$servers" ]; then
		echo "[!] O gateway não informou DNS; nomes internos podem não resolver."
		return 0
	fi
	if [ "$full" -eq 1 ]; then
		# Full tunnel: the VPN's DNS answers every name (match domain "").
		match='""'; order='d.add SupplementalMatchOrders * # 100000'
	elif [ -n "$domains" ]; then
		match=$domains; order=''
	else
		echo "[!] O gateway não informou domínios de DNS; nomes internos podem não resolver nos apps (só pelo IP)."
		return 0
	fi
	search=''
	[ -n "$domains" ] && search="d.add SearchDomains *$domains"
	printf 'open\nd.init\nd.add ServerAddresses *%s\nd.add SupplementalMatchDomains * %s\n%s\n%s\nset %s\nclose\n' \
		"$servers" "$match" "$order" "$search" "$DNS_KEY" | scutil >/dev/null 2>&1
	# The resolver must really be published: read it back.
	printf 'open\nshow %s\nclose\n' "$DNS_KEY" | scutil 2>/dev/null | grep -q ServerAddresses || missing="$missing DNS"
	incomplete
	flush_dns
	if [ "$full" -eq 1 ]; then
		echo "[#] DNS da VPN ($servers ) para todos os nomes."
	else
		echo "[#] DNS da VPN ($servers ) para$domains; os demais nomes seguem no DNS atual."
	fi
}

do_disconnect() {
	printf 'open\nremove %s\nclose\n' "$DNS_KEY" | scutil >/dev/null 2>&1
	flush_dns
	remove_external
	rm -f "$TUNNELMAC_ROUTES"
	echo "[#] Rotas e DNS da VPN removidos."
}

case "$reason" in
	pre-init) ;;
	connect) do_connect && echo "[+] TunnelMac: rede do túnel configurada em $TUNDEV." ;;
	disconnect) do_disconnect ;;
	attempt-reconnect)
		# The physical network may have changed: move the routes to the current router.
		remove_external; setup_external ;;
	reconnect) ;;
	*) ;;
esac
exit 0
"""#
}

/// Cleanup of one GlobalProtect session once openconnect has exited: the DNS resolver and
/// any route left through the physical router (normally already removed by the script).
final class GlobalProtectCleanup: SessionObserver {
    private let token: String
    private let routes: String
    private let dns: SupplementalDNS
    private let host: WireGuardHost
    /// Stops the session (set by the helper once the runner exists).
    var fail: () -> Void = {}
    init(token: String, routes: String, dns: SupplementalDNS, host: WireGuardHost) {
        self.token = token; self.routes = routes; self.dns = dns; self.host = host
    }
    func clientStarted(pid: pid_t) {}
    func clientOutput(_ line: String) {
        if line.hasPrefix(GlobalProtectRules.networkFailure) { fail() }
    }
    func clientEnded() {
        if dns.tokens().contains(token) {
            dns.remove(token: token)
            dns.flush()
        }
        var info = stat()
        if lstat(routes, &info) == 0 { GlobalProtectNetwork.removeLeftovers(routes, host: host) }
    }
}
