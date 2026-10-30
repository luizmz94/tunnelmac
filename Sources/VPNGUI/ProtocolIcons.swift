import SwiftUI
import AppKit

/// Protocol marks used only to tell the connection types apart. Path data from
/// Simple Icons 13.21.0 (CC0-1.0); the marks themselves belong to Fortinet, Inc.,
/// OpenVPN Inc. and Jason A. Donenfeld (WireGuard). This project is independent of all
/// of them (see THIRD_PARTY_NOTICES.md).
enum ProtocolIcons {
    private static let paths: [VPNProtocol: String] = [
        .fortinet: "M0 9.785h6.788v4.454H0zm8.666-6.33h6.668v4.453H8.666zm0 12.637h6.668v4.454H8.666zm8.522-6.307H24v4.454h-6.812zM2.792 3.455C1.372 3.814.265 5.404 0 7.425v.506h6.788V3.454zM0 16.091v.554c.24 1.926 1.276 3.466 2.624 3.9h4.188v-4.454zm24-8.184v-.506c-.265-1.998-1.372-3.587-2.792-3.972h-4.02v4.454H24zM21.376 20.57c1.324-.458 2.36-1.974 2.624-3.9v-.554h-6.812v4.454Z",
        .openvpn: "M12 .357C5.385.357 0 5.69 0 12.254c0 4.36 2.358 8.153 5.896 10.204l.77-5.076a7.046 7.046 0 01-1.846-4.719c0-3.897 3.18-7.076 7.13-7.076 3.948 0 7.126 3.18 7.126 7.076 0 1.847-.717 3.488-1.846 4.77L18 22.51c3.59-2.05 6-5.899 6-10.258C24 5.69 18.615.357 12 .357zm-.05 8.157a3.786 3.786 0 00-3.796 3.795 3.738 3.738 0 002.461 3.54L9.13 23.643h5.64l-1.435-7.795c1.385-.564 2.41-1.898 2.41-3.54a3.786 3.786 0 00-3.795-3.794z",
        .wireguard: "M23.98 11.645S24.533 0 11.735 0C.418 0 .064 11.17.064 11.17S-1.6 24 11.997 24C25.04 24 23.98 11.645 23.98 11.645zM8.155 7.576c2.4-1.47 5.469-.571 6.618 1.638.218.419.246 1.063.108 1.503-.477 1.516-1.601 2.366-3.145 2.728.455-.39.817-.832.933-1.442a2.112 2.112 0 0 0-.364-1.677 2.14 2.14 0 0 0-2.465-.75c-.95.36-1.47 1.228-1.377 2.294.087.99.839 1.632 2.245 1.876-.21.111-.372.193-.53.281a5.113 5.113 0 0 0-1.644 1.43c-.143.192-.24.208-.458.075-2.827-1.729-3.009-6.067.078-7.956zM6.04 18.258c-.455.116-.895.286-1.359.438.227-1.532 2.021-2.943 3.539-2.782a3.91 3.91 0 0 0-.74 2.072c-.504.093-.98.155-1.44.272zM15.703 3.3c.448.017.898.01 1.347.02a2.324 2.324 0 0 1 .334.047 3.249 3.249 0 0 1-.34.434c-.16.15-.341.296-.573.069-.055-.055-.187-.042-.283-.044-.447-.005-.894-.02-1.34-.003a8.323 8.323 0 0 0-1.154.118c-.072.013-.178.25-.146.338.078.207.191.435.359.567.619.49 1.277.928 1.9 1.413.604.472 1.167.99 1.51 1.7.446.928.46 1.9.267 2.877-.322 1.63-1.147 2.98-2.483 3.962-.538.395-1.205.62-1.821.903-.543.25-1.1.465-1.644.712-.98.446-1.53 1.51-1.369 2.615.149 1.015 1.04 1.862 2.059 2.037 1.223.21 2.486-.586 2.785-1.83.336-1.397-.423-2.646-1.845-3.024l-.256-.066c.38-.17.708-.291 1.012-.458q.793-.437 1.558-.925c.15-.096.231-.096.36.014.977.846 1.56 1.898 1.724 3.187.27 2.135-.74 4.096-2.646 5.101-2.948 1.555-6.557-.215-7.208-3.484-.558-2.8 1.418-5.34 3.797-5.83 1.023-.211 1.958-.637 2.685-1.425.47-.508.697-.944.775-1.141a3.165 3.165 0 0 0 .217-1.158 2.71 2.71 0 0 0-.237-.992c-.248-.566-1.2-1.466-1.435-1.656l-2.24-1.754c-.079-.065-.168-.06-.36-.047-.23.016-.815.048-1.067-.018.204-.155.76-.38 1-.56-.726-.49-1.554-.314-2.315-.46.176-.328 1.046-.831 1.541-.888a7.323 7.323 0 0 0-.135-.822c-.03-.111-.154-.22-.263-.283-.262-.154-.541-.281-.843-.434a1.755 1.755 0 0 1 .906-.28 3.385 3.385 0 0 1 .908.088c.54.123.97.042 1.399-.324-.338-.136-.676-.26-1.003-.407a9.843 9.843 0 0 1-.942-.493c.85.118 1.671.437 2.54.32l.022-.118-2.018-.47c1.203-.11 2.323-.128 3.384.388.299.146.61.266.897.432.14.08.233.24.348.365.09.098.164.23.276.29.424.225.89.234 1.366.223l.01-.16c.479.15 1.017.702 1.017 1.105-.776 0-1.55-.003-2.325.004-.083 0-.165.061-.247.094.078.046.155.128.235.131z M14.703 2.153a.118.118 0 0 0-.016.19.179.179 0 0 0 .246.065c.075-.038.148-.078.238-.125-.072-.062-.13-.114-.19-.163-.106-.087-.193-.032-.278.033z",
    ]

    static func image(_ kind: VPNProtocol) -> NSImage? {
        guard let path = paths[kind] else { return nil }
        let svg = "<svg viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\"><path d=\"\(path)\"/></svg>"
        guard let image = NSImage(data: Data(svg.utf8)) else { return nil }
        image.isTemplate = true
        return image
    }
}

extension VPNProtocol {
    /// Brand colors published with the marks.
    var brandColor: Color {
        switch self {
        case .fortinet: return Color(red: 0xEE / 255, green: 0x31 / 255, blue: 0x24 / 255)
        case .openvpn: return Color(red: 0xEA / 255, green: 0x7E / 255, blue: 0x20 / 255)
        // Simple Icons lists #88171A; lifted slightly so the mark stays legible in dark mode.
        case .wireguard: return Color(red: 0xA8 / 255, green: 0x1D / 255, blue: 0x21 / 255)
        // No vendor mark is shipped for GlobalProtect: a system symbol in a neutral blue.
        case .globalProtect: return Color(red: 0x1F / 255, green: 0x6F / 255, blue: 0xC5 / 255)
        }
    }
    var fallbackSymbol: String {
        switch self {
        case .fortinet: return "shield.lefthalf.filled"
        case .openvpn: return "lock.shield"
        case .wireguard: return "point.3.connected.trianglepath.dotted"
        case .globalProtect: return "globe.badge.chevron.backward"
        }
    }
}

struct ProtocolIcon: View {
    let kind: VPNProtocol
    var size: CGFloat = 28
    @Environment(\.colorScheme) private var scheme
    /// WireGuard's dark red disappears on dark surfaces; there it takes the brighter red
    /// the TunnelMac brand uses on dark backgrounds.
    private var color: Color {
        kind == .wireguard && scheme == .dark ? Color(red: 0xE0 / 255, green: 0x52 / 255, blue: 0x4F / 255) : kind.brandColor
    }
    var body: some View {
        Group {
            if let image = ProtocolIcons.image(kind) {
                Image(nsImage: image).resizable().renderingMode(.template).interpolation(.high)
            } else {
                Image(systemName: kind.fallbackSymbol).resizable()
            }
        }
        .aspectRatio(contentMode: .fit)
        .foregroundStyle(color)
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// Protocol mark on a soft brand-tinted tile, with the connection state as a dot in the
/// corner (none while disconnected). The row's text still names the state, so color is
/// never the only signal.
struct ProtocolTile: View {
    let kind: VPNProtocol
    let state: ConnectionState
    var size: CGFloat = 30
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ProtocolIcon(kind: kind, size: size * 0.6)
            .frame(width: size, height: size)
            .background(RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
                .fill(kind.brandColor.opacity(0.14)))
            .overlay(alignment: .bottomTrailing) {
                if state != .disconnected { dot.offset(x: 3, y: 3) }
            }
            .accessibilityHidden(true)
    }

    private var dot: some View {
        let diameter = size * 0.36
        let image = Image(systemName: "circle.fill")
            .font(.system(size: diameter))
            .foregroundStyle(state.tone.color)
            .background(Circle().fill(.background).padding(-2))
        return Group {
            if #available(macOS 14, *) {
                image.symbolEffect(.pulse, options: .repeating, isActive: state.inProgress && !reduceMotion)
            } else {
                image
            }
        }
        .transition(.scale.combined(with: .opacity))
    }
}
