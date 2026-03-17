import Foundation

/// Represents the role a party plays in a Noise Protocol handshake.
///
/// Each Noise handshake has exactly two participants: an initiator who sends the
/// first message and a responder who receives it.
public enum Role: Sendable {
    /// The party that initiates the handshake by sending the first message.
    case initiator
    /// The party that responds to the initiator's first message.
    case responder
}
