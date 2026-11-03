import AppKit
import CoreGraphics

// Double tap of a modifier (⌘ ⌥ ⌃ ⇧) as the global shortcut. Opt-in: it needs Input
// Monitoring, and the event tap exists only while that form is chosen. The tap is listen-only
// (it neither changes nor consumes events) and its mask has modifier changes only: it never
// sees what is typed. Nothing it receives is stored, logged or sent.

/// One modifier change, as the tap delivers it.
struct ModifierChange: Equatable {
    var keyCode: UInt16
    var flags: CGEventFlags
    /// Seconds (event timestamp).
    var time: TimeInterval
    /// System-wide count of key presses so far (a number, never the keys): a key pressed while
    /// the modifier is held (⌘C) breaks the tap.
    var keyDowns: UInt32
}

/// Two taps of exactly one modifier, each pressed and released alone within 300 ms, the
/// second starting at most 0.4 s (or the double-click interval, if shorter) after the first.
struct DoubleTapDetector {
    static let eventMask = CGEventMask(1 << CGEventType.flagsChanged.rawValue)
    static let maxHold: TimeInterval = 0.3
    static var maxGap: TimeInterval { min(NSEvent.doubleClickInterval, 0.4) }
    private static let modifierFlags: [CGEventFlags] = [.maskCommand, .maskAlternate, .maskControl, .maskShift,
                                                        .maskAlphaShift, .maskSecondaryFn]

    let modifier: ModifierKey
    let side: ModifierSide
    var maxGap = DoubleTapDetector.maxGap
    private var pressedAt: TimeInterval?
    private var pressedKeyDowns: UInt32 = 0
    private var lastTapAt: TimeInterval?

    init(modifier: ModifierKey, side: ModifierSide) {
        self.modifier = modifier
        self.side = side
    }

    private func held(_ flags: CGEventFlags) -> [CGEventFlags] { Self.modifierFlags.filter { flags.contains($0) } }

    private mutating func reset() { pressedAt = nil; lastTapAt = nil }

    /// True exactly when the second tap completes.
    mutating func handle(_ change: ModifierChange) -> Bool {
        guard let (key, keySide) = ModifierKey.of(keyCode: change.keyCode), key == modifier,
              side == .any || side == keySide else { reset(); return false }
        let held = held(change.flags)
        if held == [modifier.cgFlag] {
            // Pressed alone. A second press too long after the first tap starts over.
            if let last = lastTapAt, change.time - last > maxGap { lastTapAt = nil }
            pressedAt = change.time
            pressedKeyDowns = change.keyDowns
            return false
        }
        guard held.isEmpty, let pressed = pressedAt else { reset(); return false }
        pressedAt = nil
        guard change.time - pressed <= Self.maxHold, change.keyDowns == pressedKeyDowns else { reset(); return false }
        if lastTapAt != nil {
            // Fired: a third tap starts a new pair.
            lastTapAt = nil
            return true
        }
        lastTapAt = change.time
        return false
    }
}

/// Source of modifier changes (a fake in the local checks, which never create an event tap).
@MainActor protocol ModifierTapSource: AnyObject {
    /// Input Monitoring is allowed (CGPreflightListenEventAccess).
    var hasAccess: Bool { get }
    /// Asks macOS (CGRequestListenEventAccess); System Settings opens.
    func requestAccess()
    /// Starts a listen-only tap with `mask`; false when it could not be created.
    func start(mask: CGEventMask, handler: @escaping (ModifierChange) -> Void) -> Bool
    func stop()
}

/// The real listen-only tap of modifier changes.
@MainActor
final class EventTapModifierSource: ModifierTapSource {
    private var tap: CFMachPort?
    private var source: CFRunLoopSource?
    private var handler: ((ModifierChange) -> Void)?
    private var reenabled = false
    /// The tap was disabled twice by macOS (timeout or user input).
    var onFailure: (() -> Void)?

    var hasAccess: Bool { CGPreflightListenEventAccess() }
    func requestAccess() { _ = CGRequestListenEventAccess() }

    func start(mask: CGEventMask, handler: @escaping (ModifierChange) -> Void) -> Bool {
        stop()
        self.handler = handler
        reenabled = false
        guard let tap = CGEvent.tapCreate(tap: .cgSessionEventTap, place: .headInsertEventTap, options: .listenOnly,
                                          eventsOfInterest: mask, callback: { _, type, event, userInfo in
            guard let userInfo else { return nil }
            let source = Unmanaged<EventTapModifierSource>.fromOpaque(userInfo).takeUnretainedValue()
            let keyCode = UInt16(truncatingIfNeeded: event.getIntegerValueField(.keyboardEventKeycode))
            let change = ModifierChange(keyCode: keyCode, flags: event.flags, time: TimeInterval(event.timestamp) / 1_000_000_000,
                                        keyDowns: CGEventSource.counterForEventType(.combinedSessionState, eventType: .keyDown))
            let rawType = type.rawValue
            MainActor.assumeIsolated { source.receive(rawType, change) }
            // Listen-only: the event goes on untouched.
            return nil
        }, userInfo: Unmanaged.passUnretained(self).toOpaque()) else {
            self.handler = nil
            return false
        }
        let source = CFMachPortCreateRunLoopSource(nil, tap, 0)
        CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes)
        CGEvent.tapEnable(tap: tap, enable: true)
        self.tap = tap
        self.source = source
        return true
    }

    private func receive(_ type: UInt32, _ change: ModifierChange) {
        if type == CGEventType.tapDisabledByTimeout.rawValue || type == CGEventType.tapDisabledByUserInput.rawValue {
            // Once back on; a second time is reported.
            if !reenabled, let tap { reenabled = true; CGEvent.tapEnable(tap: tap, enable: true) } else { stop(); onFailure?() }
            return
        }
        guard type == CGEventType.flagsChanged.rawValue else { return }
        handler?(change)
    }

    func stop() {
        if let tap {
            CGEvent.tapEnable(tap: tap, enable: false)
            CFMachPortInvalidate(tap)
        }
        if let source { CFRunLoopRemoveSource(CFRunLoopGetMain(), source, .commonModes) }
        tap = nil
        source = nil
        handler = nil
    }
}
