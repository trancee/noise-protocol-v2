import Foundation

/// Which key slot to reference in a DH operation.
enum KeyRef: Sendable {
    case s, e, rs, re
}

/// A DH operation descriptor: local key pair + remote public key.
struct DhOp: Equatable, Sendable {
    let local: KeyRef
    let remote: KeyRef
}

/// Complete DH dispatch table — maps (token, role) to key references.
let DH_DISPATCH: [String: [Role: DhOp]] = [
    "ee": [.initiator: DhOp(local: .e, remote: .re),
           .responder: DhOp(local: .e, remote: .re)],
    "es": [.initiator: DhOp(local: .e, remote: .rs),
           .responder: DhOp(local: .s, remote: .re)],
    "se": [.initiator: DhOp(local: .s, remote: .re),
           .responder: DhOp(local: .e, remote: .rs)],
    "ss": [.initiator: DhOp(local: .s, remote: .rs),
           .responder: DhOp(local: .s, remote: .rs)],
]
