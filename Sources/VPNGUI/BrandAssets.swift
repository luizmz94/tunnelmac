import SwiftUI
import AppKit

@MainActor
enum BrandAssets {
    static let menuIcon: NSImage? = {
        guard let image = Bundle.main.image(forResource: "MenuBarIconTemplate") else { return nil }
        image.isTemplate = true
        image.size = NSSize(width: 18, height: 18)
        return image
    }()
    /// Menu bar icon. Idle: the monochrome template. Connected: the same shape in the logo's
    /// colors. `angle` turns it (only while a connection is starting, since every frame costs
    /// CPU), and the active connection count is knocked out of a corner badge.
    static func menuIcon(connected: Bool, angle: CGFloat = 0, badge: Int) -> NSImage? {
        let key = "\(connected)-\(angle)-\(min(badge, 10))"
        if let cached = menuIconVariants[key] { return cached }
        let image = renderMenuIcon(connected: connected, angle: angle, badge: badge)
        menuIconVariants[key] = image
        return image
    }
    private static var menuIconVariants: [String: NSImage] = [:]
    private static func renderMenuIcon(connected: Bool, angle: CGFloat, badge: Int) -> NSImage? {
        guard let base = menuIcon else { return nil }
        let image = NSImage(size: base.size, flipped: false) { rect in
            guard let context = NSGraphicsContext.current?.cgContext else { return false }
            // Drawn per appearance: colors follow the menu bar (light or dark), as in the brand README.
            let dark = NSAppearance.currentDrawing().bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            let ink = connected ? NSColor(hex: dark ? 0xE9F0F2 : 0x0E1720) : NSColor.black
            context.saveGState()
            context.translateBy(x: rect.midX, y: rect.midY)
            context.rotate(by: -angle * .pi / 180)
            context.translateBy(x: -rect.midX, y: -rect.midY)
            if connected {
                // MenuBarTemplate.svg arcs (18 pt grid, angles with y up): FortiClient top right,
                // OpenVPN at the bottom, WireGuard top left, gaps kept.
                let scale = rect.width / 18, center = NSPoint(x: rect.midX, y: rect.midY)
                let arcs: [(UInt32, UInt32, CGFloat, CGFloat)] = [(0x2E95D6, 0x1F7EC2, -14.0, 74.2),
                                                                  (0xEE8A34, 0xDE7420, -133.7, -46.3),
                                                                  (0xD0423F, 0xBF3532, 105.8, 194.0)]
                for (onDark, onLight, start, end) in arcs {
                    let arc = NSBezierPath()
                    arc.appendArc(withCenter: center, radius: 6.2 * scale, startAngle: start, endAngle: end)
                    arc.lineWidth = 2.2 * scale
                    NSColor(hex: dark ? onDark : onLight).setStroke()
                    arc.stroke()
                }
                ink.setFill()
                NSBezierPath(ovalIn: NSRect(x: center.x - 2.2 * scale, y: center.y - 2.2 * scale,
                                            width: 4.4 * scale, height: 4.4 * scale)).fill()
            } else {
                base.draw(in: rect)
            }
            context.restoreGState()
            guard badge > 0 else { return true }
            let text = NSAttributedString(string: badge > 9 ? "9+" : "\(badge)",
                                          attributes: [.font: NSFont.systemFont(ofSize: 7.5, weight: .heavy),
                                                       .foregroundColor: NSColor.black])
            let textSize = text.size()
            let height: CGFloat = 9
            let pill = NSRect(x: rect.maxX - max(height, textSize.width + 3), y: rect.minY,
                              width: max(height, textSize.width + 3), height: height)
            // Clear a gap around the badge so it reads apart from the icon, then knock the digits out of it.
            context.setBlendMode(.clear)
            NSBezierPath(roundedRect: pill.insetBy(dx: -1.5, dy: -1.5), xRadius: height / 2 + 1.5, yRadius: height / 2 + 1.5).fill()
            context.setBlendMode(.normal)
            ink.setFill()
            NSBezierPath(roundedRect: pill, xRadius: height / 2, yRadius: height / 2).fill()
            context.setBlendMode(.destinationOut)
            text.draw(at: NSPoint(x: pill.midX - textSize.width / 2, y: pill.midY - textSize.height / 2))
            return true
        }
        image.isTemplate = !connected
        return image
    }
    static let lightSymbol = Bundle.main.image(forResource: "BrandSymbol")
    static let darkSymbol = Bundle.main.image(forResource: "BrandSymbolDark")
}

struct BrandSymbol: View {
    var size: CGFloat = 32
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        Group {
            if let image = scheme == .dark ? BrandAssets.darkSymbol : BrandAssets.lightSymbol {
                Image(nsImage: image).resizable().scaledToFit()
            } else {
                Image(systemName: "network.badge.shield.half.filled").resizable().scaledToFit()
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

private extension NSColor {
    convenience init(hex: UInt32) {
        self.init(srgbRed: CGFloat(hex >> 16 & 0xFF) / 255, green: CGFloat(hex >> 8 & 0xFF) / 255,
                  blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
    }
}
