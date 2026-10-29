// Frames of the drag-to-install animation over the DMG window, for docs/assets/install.gif.
//   swift packaging/dmg/render-install-gif.swift <frames dir>
// Uses background@2x.png (render-background.swift) and the same icon positions.
import AppKit

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try? FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
let background = NSImage(contentsOf: root.appendingPathComponent("background@2x.png"))!
let appIcon = NSImage(contentsOf: root.appendingPathComponent("../../TunnelMac-Brand/02-AppIcon/AppIcon-1024.png"))!
// The Applications link as Finder shows it: folder icon with the alias badge.
let link = FileManager.default.temporaryDirectory.appendingPathComponent("Applications-\(getpid())")
try? FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: "/Applications")
let folderIcon = NSWorkspace.shared.icon(forFile: link.path)
try? FileManager.default.removeItem(at: link)

let content = CGSize(width: 660, height: 420), titleBar: CGFloat = 28, margin: CGFloat = 36
let canvas = CGSize(width: content.width + margin * 2, height: content.height + titleBar + margin * 2)
let window = CGRect(x: margin, y: margin, width: content.width, height: content.height + titleBar)
let origin = CGPoint(x: margin, y: margin + titleBar) // content origin, top-left
let appCenter = CGPoint(x: 180, y: 210), applicationsCenter = CGPoint(x: 480, y: 210), labelY: CGFloat = 287, icon: CGFloat = 112

func color(_ hex: UInt32, _ alpha: CGFloat = 1) -> NSColor {
    NSColor(srgbRed: CGFloat(hex >> 16 & 0xFF) / 255, green: CGFloat(hex >> 8 & 0xFF) / 255, blue: CGFloat(hex & 0xFF) / 255, alpha: alpha)
}
func ease(_ t: CGFloat) -> CGFloat { let t = min(max(t, 0), 1); return t < 0.5 ? 4 * t * t * t : 1 - pow(-2 * t + 2, 3) / 2 }
func mix(_ a: CGPoint, _ b: CGPoint, _ t: CGFloat) -> CGPoint { CGPoint(x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t) }
func progress(_ time: CGFloat, _ start: CGFloat, _ end: CGFloat) -> CGFloat { min(max((time - start) / (end - start), 0), 1) }
func at(_ point: CGPoint) -> CGPoint { CGPoint(x: origin.x + point.x, y: origin.y + point.y) }

func label(_ text: String, center: CGPoint, selected: Bool) {
    let font = NSFont.systemFont(ofSize: 14)
    let attributes: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: selected ? NSColor.white : NSColor.black]
    let size = (text as NSString).size(withAttributes: attributes)
    let rect = CGRect(x: center.x - size.width / 2, y: center.y - size.height / 2, width: size.width, height: size.height)
    if selected {
        NSColor.controlAccentColor.usingColorSpace(.sRGB)!.setFill()
        NSBezierPath(roundedRect: rect.insetBy(dx: -6, dy: -1), xRadius: 5, yRadius: 5).fill()
    }
    (text as NSString).draw(in: rect, withAttributes: attributes)
}

func frame(_ time: CGFloat) {
    // Backdrop and window shadow.
    let backdrop = NSGradient(colors: [color(0x2A3947), color(0x111A22)])!
    backdrop.draw(in: CGRect(origin: .zero, size: canvas), angle: -90)
    let shadow = NSShadow(); shadow.shadowColor = NSColor.black.withAlphaComponent(0.5); shadow.shadowBlurRadius = 24; shadow.shadowOffset = NSSize(width: 0, height: -10)
    NSGraphicsContext.saveGraphicsState(); shadow.set()
    let frame = NSBezierPath(roundedRect: window, xRadius: 12, yRadius: 12)
    color(0x1B2630).setFill(); frame.fill()
    NSGraphicsContext.restoreGraphicsState()
    NSGraphicsContext.saveGraphicsState(); frame.addClip()
    color(0x232F39).setFill(); CGRect(x: window.minX, y: window.minY, width: window.width, height: titleBar).fill()
    for (index, hex) in [0xFF5F57, 0xFEBC2E, 0x28C840].enumerated() {
        color(UInt32(hex)).setFill()
        NSBezierPath(ovalIn: CGRect(x: window.minX + 14 + CGFloat(index) * 20, y: window.minY + 8, width: 12, height: 12)).fill()
    }
    let style = NSMutableParagraphStyle(); style.alignment = .center
    ("TunnelMac" as NSString).draw(in: CGRect(x: window.minX, y: window.minY + 6, width: window.width, height: 18),
                                   withAttributes: [.font: NSFont.systemFont(ofSize: 13, weight: .semibold), .foregroundColor: NSColor.white.withAlphaComponent(0.85), .paragraphStyle: style])
    background.draw(in: CGRect(origin: origin, size: content), from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: true, hints: nil)

    // Timeline (seconds): reach the app, press, drag, hover the folder, drop, rest.
    let reach = ease(progress(time, 0.3, 1.1)), press = time >= 1.25, drag = ease(progress(time, 1.4, 2.6))
    let dropped = time >= 2.75, sink = progress(time, 2.75, 3.0), leave = ease(progress(time, 3.3, 4.0))
    let selected = press && time < 3.3
    let start = CGPoint(x: 600, y: 400), grab = CGPoint(x: appCenter.x + 8, y: appCenter.y + 10)
    var pointer = mix(start, grab, reach)
    if press { pointer = mix(grab, CGPoint(x: applicationsCenter.x + 8, y: applicationsCenter.y + 10), drag) }
    if time >= 3.3 { pointer = mix(CGPoint(x: applicationsCenter.x + 8, y: applicationsCenter.y + 10), CGPoint(x: 560, y: 380), leave) }
    let overFolder = press && !dropped && drag > 0.82

    func box(_ center: CGPoint) -> CGRect { CGRect(x: at(center).x - icon / 2, y: at(center).y - icon / 2, width: icon, height: icon) }
    // Finder's selection and drop-target highlight behind an icon.
    for (center, on) in [(appCenter, selected), (applicationsCenter, overFolder)] where on {
        NSColor.white.withAlphaComponent(0.12).setFill()
        NSBezierPath(roundedRect: box(center).insetBy(dx: -2, dy: -2), xRadius: 12, yRadius: 12).fill()
    }
    appIcon.draw(in: box(appCenter))
    folderIcon.draw(in: box(applicationsCenter), from: .zero, operation: .sourceOver, fraction: overFolder ? 0.75 : 1, respectFlipped: true, hints: nil)
    label("TunnelMac", center: at(CGPoint(x: appCenter.x, y: labelY)), selected: selected)
    label("Applications", center: at(CGPoint(x: applicationsCenter.x, y: labelY)), selected: overFolder)

    // The dragged copy follows the pointer, then sinks into the folder.
    if press && (!dropped || sink < 1) {
        let offset = CGPoint(x: pointer.x - grab.x + appCenter.x, y: pointer.y - grab.y + appCenter.y)
        let scale = 1 - 0.6 * sink
        let size = icon * scale
        let rect = CGRect(x: at(offset).x - size / 2, y: at(offset).y - size / 2, width: size, height: size)
        if drag > 0 || dropped { appIcon.draw(in: rect, from: .zero, operation: .sourceOver, fraction: 0.65 * (1 - sink), respectFlipped: true, hints: nil) }
    }
    // Done: a quiet confirmation under the header.
    let done = progress(time, 3.0, 3.3) * (1 - progress(time, 4.6, 4.9))
    if done > 0 {
        let text = "✓  Installed in Applications" as NSString
        let attributes: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 13, weight: .semibold), .foregroundColor: color(0x0E1720)]
        let size = text.size(withAttributes: attributes)
        let pill = CGRect(x: at(CGPoint(x: 330, y: 0)).x - size.width / 2 - 14, y: at(CGPoint(x: 0, y: 322)).y, width: size.width + 28, height: 26)
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current?.cgContext.setAlpha(done)
        color(0x5FC27E).setFill(); NSBezierPath(roundedRect: pill, xRadius: 13, yRadius: 13).fill()
        text.draw(at: CGPoint(x: pill.minX + 14, y: pill.minY + (26 - size.height) / 2), withAttributes: attributes)
        NSGraphicsContext.restoreGraphicsState()
    }
    NSGraphicsContext.restoreGraphicsState()
    // macOS arrow pointer: black with a white outline, tip at the pointer.
    let hot = at(pointer), arrow = NSBezierPath()
    for (index, point) in [(0, 0), (0, 17), (4.2, 13.2), (7, 19.6), (9.6, 18.5), (6.9, 12.3), (12.2, 12.3)].enumerated() {
        let p = CGPoint(x: hot.x + point.0 * 1.15, y: hot.y + point.1 * 1.15)
        if index == 0 { arrow.move(to: p) } else { arrow.line(to: p) }
    }
    arrow.close(); arrow.lineJoinStyle = .round; arrow.lineWidth = 1.6
    NSGraphicsContext.saveGraphicsState()
    let pointerShadow = NSShadow(); pointerShadow.shadowColor = NSColor.black.withAlphaComponent(0.35); pointerShadow.shadowBlurRadius = 3; pointerShadow.shadowOffset = NSSize(width: 0, height: -1.5)
    pointerShadow.set()
    NSColor.white.setStroke(); arrow.stroke()
    NSGraphicsContext.restoreGraphicsState()
    NSColor.black.setFill(); arrow.fill()
}

let fps = 24.0, duration = 5.4
for index in 0..<Int(duration * fps) {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(canvas.width) * 2, pixelsHigh: Int(canvas.height) * 2, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = canvas
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(cgContext: NSGraphicsContext(bitmapImageRep: rep)!.cgContext, flipped: true)
    let context = NSGraphicsContext.current!.cgContext
    context.translateBy(x: 0, y: canvas.height); context.scaleBy(x: 1, y: -1)
    frame(CGFloat(Double(index) / fps))
    NSGraphicsContext.restoreGraphicsState()
    try! rep.representation(using: .png, properties: [:])!.write(to: output.appendingPathComponent(String(format: "%04d.png", index)))
}
print("ok")
