// Draws the DMG window background (660×420 pt) at 1x and 2x in the TunnelMac palette.
//   swift packaging/dmg/render-background.swift
// Writes packaging/dmg/background.png and background@2x.png; make-dmg.sh merges them
// into one HiDPI TIFF. Icon positions must match scripts/make-dmg.sh.
import AppKit

let size = CGSize(width: 660, height: 420)
let appCenter = CGPoint(x: 180, y: 210), applicationsCenter = CGPoint(x: 480, y: 210) // from the top
let labelCenterY: CGFloat = 287 // Finder's name line under a 112 pt icon (14 pt text)
let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let logo = NSImage(contentsOf: root.appendingPathComponent("../../TunnelMac-Brand/01-Logo/PNG/TunnelMac-logo-horizontal-color-dark.png"))!

func color(_ hex: UInt32, _ alpha: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: CGFloat(hex >> 16 & 0xFF) / 255, green: CGFloat(hex >> 8 & 0xFF) / 255, blue: CGFloat(hex & 0xFF) / 255, alpha: alpha)
}
let blue = color(0x2E95D6), orange = color(0xEE8A34), red = color(0xD0423F), mist = color(0xE9F0F2)

func draw(in context: CGContext) {
    // Flip to top-left origin, like Finder's icon coordinates.
    context.translateBy(x: 0, y: size.height); context.scaleBy(x: 1, y: -1)
    let rect = CGRect(origin: .zero, size: size)
    // Plate gradient of the app icon.
    let plate = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB), colors: [color(0x1E2C38).cgColor, color(0x0E1720).cgColor] as CFArray, locations: [0, 1])!
    context.drawLinearGradient(plate, start: .zero, end: CGPoint(x: 0, y: size.height), options: [])
    // Soft glows on the two icons only, so the names below them stay on dark ground.
    for (center, tint) in [(appCenter, blue), (applicationsCenter, orange)] {
        let glow = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB), colors: [tint.withAlphaComponent(0.14).cgColor, tint.withAlphaComponent(0).cgColor] as CFArray, locations: [0, 1])!
        let middle = CGPoint(x: center.x, y: center.y - 8)
        context.drawRadialGradient(glow, startCenter: middle, startRadius: 0, endCenter: middle, endRadius: 92, options: [])
    }
    // Finder draws icon names in black over a background picture, in Light and Dark Mode
    // alike: each name sits on a light pill so it reads on this dark window.
    for center in [appCenter, applicationsCenter] {
        let pill = CGRect(x: center.x - 62, y: labelCenterY - 11, width: 124, height: 22)
        context.addPath(CGPath(roundedRect: pill, cornerWidth: 11, cornerHeight: 11, transform: nil))
        context.setFillColor(mist.withAlphaComponent(0.92).cgColor)
        context.fillPath()
    }
    // The logo's three arcs, large and faint, running off the bottom right corner.
    context.saveGState()
    context.setLineCap(.round); context.setLineWidth(34)
    let ring = CGPoint(x: 640, y: 460), radius: CGFloat = 130
    for (start, end, tint) in [(-75.0, 15.0, blue), (45.0, 135.0, orange), (165.0, 255.0, red)] {
        context.setStrokeColor(tint.withAlphaComponent(0.10).cgColor)
        context.addArc(center: ring, radius: radius, startAngle: start * .pi / 180, endAngle: end * .pi / 180, clockwise: false)
        context.strokePath()
    }
    context.restoreGState()
    // Hairline border, like the icon plate.
    context.setStrokeColor(NSColor.white.withAlphaComponent(0.06).cgColor); context.setLineWidth(1)
    context.stroke(rect.insetBy(dx: 0.5, dy: 0.5))

    // Arrow from the app to Applications: the three brand colors, dashed lead-in, chevron.
    let y = appCenter.y, from = appCenter.x + 78, to = applicationsCenter.x - 78
    let arrow = CGMutablePath()
    arrow.move(to: CGPoint(x: from, y: y)); arrow.addLine(to: CGPoint(x: to, y: y))
    arrow.move(to: CGPoint(x: to - 13, y: y - 13)); arrow.addLine(to: CGPoint(x: to, y: y)); arrow.addLine(to: CGPoint(x: to - 13, y: y + 13))
    context.saveGState()
    context.addPath(arrow.copy(strokingWithWidth: 5, lineCap: .round, lineJoin: .round, miterLimit: 1))
    context.clip()
    let stroke = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB), colors: [blue.cgColor, orange.cgColor, red.cgColor] as CFArray, locations: [0, 0.5, 1])!
    context.drawLinearGradient(stroke, start: CGPoint(x: from, y: y), end: CGPoint(x: to, y: y), options: [])
    context.restoreGState()

    // Header: horizontal logo; footer: one line of copy.
    NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: true)
    let logoHeight: CGFloat = 30, logoWidth = logo.size.width / logo.size.height * logoHeight
    logo.draw(in: CGRect(x: (size.width - logoWidth) / 2, y: 34, width: logoWidth, height: logoHeight),
              from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: true, hints: nil)
    let style = NSMutableParagraphStyle(); style.alignment = .center
    func text(_ string: String, _ font: NSFont, _ alpha: CGFloat, y: CGFloat, kern: CGFloat = 0) {
        NSAttributedString(string: string, attributes: [.font: font, .foregroundColor: mist.withAlphaComponent(alpha), .paragraphStyle: style, .kern: kern])
            .draw(in: CGRect(x: 0, y: y, width: size.width, height: 24))
    }
    text("Drag TunnelMac to Applications to install", .systemFont(ofSize: 13, weight: .medium), 0.72, y: 76)
    text("FORTINET  ·  OPENVPN  ·  WIREGUARD", .systemFont(ofSize: 10, weight: .semibold), 0.32, y: 372, kern: 1.6)
}

for scale in [1, 2] {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width) * scale, pixelsHigh: Int(size.height) * scale,
                               bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = size
    // rep.size in points: the context already maps points to pixels.
    let context = NSGraphicsContext(bitmapImageRep: rep)!.cgContext
    draw(in: context)
    let name = scale == 1 ? "background.png" : "background@2x.png"
    try! rep.representation(using: .png, properties: [:])!.write(to: root.appendingPathComponent(name))
}
print("ok")
