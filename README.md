# Noise Protocol

A complete [Noise Protocol Framework](https://noiseprotocol.org/noise.html) implementation for Android (Kotlin) and iOS (Swift) with **zero external dependencies**.

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](LICENSE)

## About

This library implements the full Noise Protocol Framework specification (revision 34) for mobile platforms. It uses platform cryptographic APIs where available (Android JCA, Apple CryptoKit) and includes pure implementations for primitives without platform support (X448, BLAKE2b, BLAKE2s).

Both platforms share test vectors but are otherwise fully independent codebases — no shared code, no code generation, no bridging layers. Each implementation is idiomatic to its platform.

## Features

- **All 12 fundamental handshake patterns**: NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX
- **One-way patterns**: N, K, X
- **23 deferred patterns**: NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1, K1X, KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1
- **PSK modifier**: 0–9 positions on any pattern
- **Fallback modifier**: IK → XXfallback pattern switching
- **DH functions**: Curve25519, X448
- **Ciphers**: ChaChaPoly, AESGCM
- **Hash functions**: SHA256, SHA512, BLAKE2b, BLAKE2s
- **Security hardening**: MAC-failure invalidation, nonce exhaustion protection, auto-rekey, thread-safe `CipherState`
- **Secure memory**: Automatic secret zeroing with `SecureMemory` (Kotlin) / `SecureBuffer` (Swift)
- **Benchmarking**: Built-in benchmark harness for all primitives, handshakes, and transport throughput

## Installation

### Android (Gradle)

Add the dependency to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("noise.protocol:noise-protocol:0.1.0")
}
```

**Maven Central** (when published):

```kotlin
repositories {
    mavenCentral()
}
```

**GitHub Packages** (pre-release):

```kotlin
repositories {
    maven {
        url = uri("https://maven.pkg.github.com/trancee/noise-protocol-v2")
        credentials {
            username = project.findProperty("gpr.user") as String? ?: System.getenv("GITHUB_ACTOR")
            password = project.findProperty("gpr.key") as String? ?: System.getenv("GITHUB_TOKEN")
        }
    }
}
```

### iOS (Swift Package Manager)

Add the package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/trancee/noise-protocol-v2.git", from: "0.1.0")
]
```

Then add `"NoiseProtocol"` to your target's dependencies:

```swift
.target(name: "MyApp", dependencies: ["NoiseProtocol"])
```

**Requirements:** iOS 16+ / macOS 13+, Swift 6.0+

## Quick Start

### Kotlin — NN Handshake

```kotlin
import noise.protocol.*

// NN pattern: no static keys needed
val initiator = NoiseSession(
    protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
    role = Role.INITIATOR
)
val responder = NoiseSession(
    protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
    role = Role.RESPONDER
)

// Two-message handshake
val msg1 = initiator.writeMessage()
responder.readMessage(msg1)
val msg2 = responder.writeMessage()
initiator.readMessage(msg2)

// Split into transport
val iTransport = initiator.split()
val rTransport = responder.split()

// Encrypted communication
val ciphertext = iTransport.sender.encryptWithAd(byteArrayOf(), "hello".toByteArray())
val plaintext = rTransport.receiver.decryptWithAd(byteArrayOf(), ciphertext)
```

### Swift — XX Handshake

```swift
import NoiseProtocol

// XX pattern: mutual authentication with static keys
let iKeys = Curve25519DH.generateKeyPair()
let rKeys = Curve25519DH.generateKeyPair()

let initiator = try NoiseSession(
    protocolName: "Noise_XX_25519_ChaChaPoly_SHA256",
    role: .initiator,
    staticKeyPair: iKeys
)
let responder = try NoiseSession(
    protocolName: "Noise_XX_25519_ChaChaPoly_SHA256",
    role: .responder,
    staticKeyPair: rKeys
)

// Three-message handshake
let msg1 = try initiator.writeMessage()
let _ = try responder.readMessage(msg1)
let msg2 = try responder.writeMessage()
let _ = try initiator.readMessage(msg2)
let msg3 = try initiator.writeMessage()
let _ = try responder.readMessage(msg3)

// Split and communicate
let iTransport = try initiator.split()
let rTransport = try responder.split()

let ciphertext = try iTransport.sender.encryptWithAd(Data(), plaintext: message)
let plaintext = try rTransport.receiver.decryptWithAd(Data(), ciphertext: ciphertext)
```

### Pre-Shared Keys (PSK)

```kotlin
val psk = ByteArray(32) // your 32-byte pre-shared key

val session = NoiseSession(
    protocolName = "Noise_NNpsk0_25519_ChaChaPoly_SHA256",
    role = Role.INITIATOR,
    preSharedKeys = listOf(psk)
)
```

### Custom CryptoResolver

Override algorithm wiring for testing or to provide alternative implementations:

```kotlin
val customCrypto = DefaultCryptoResolver.Builder()
    .dh("25519") { Curve25519DH }
    .cipher("ChaChaPoly") { ChaChaPoly }
    .hash("SHA256") { SHA256Hash }
    .build()

val session = NoiseSession(
    protocolName = "Noise_NN_25519_ChaChaPoly_SHA256",
    role = Role.INITIATOR,
    crypto = customCrypto
)
```

## Protocol Name Format

Protocol names follow the Noise specification format:

```
Noise_{pattern}[modifier]_{dh}_{cipher}_{hash}
```

| Component | Options |
|-----------|---------|
| **Pattern** | NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX, N, K, X |
| **Deferred** | NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1, K1X, KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1 |
| **Modifier** | `psk0`–`psk9`, `fallback` |
| **DH** | `25519` (Curve25519), `448` (X448) |
| **Cipher** | `ChaChaPoly`, `AESGCM` |
| **Hash** | `SHA256`, `SHA512`, `BLAKE2b`, `BLAKE2s` |

Examples:
- `Noise_XX_25519_ChaChaPoly_SHA256` — mutual auth, Curve25519, ChaCha20-Poly1305, SHA-256
- `Noise_IKpsk2_448_AESGCM_BLAKE2b` — immediate key transmission with PSK at position 2, X448, AES-GCM, BLAKE2b
- `Noise_XXfallback_25519_ChaChaPoly_SHA256` — fallback from failed IK to XX

## Architecture

The library follows a layered architecture where each module has a single responsibility.
Upper layers depend only on the layer directly below.

```mermaid
graph TD
    NS["<b>NoiseSession</b><br/>Public API — parses protocol name,<br/>orchestrates handshake + transport"]
    HS["<b>HandshakeState</b><br/>Drives message patterns & DH tokens"]
    HC["<b>HandshakeConfig</b><br/>Immutable config (keys, PSKs, role)"]
    KS["<b>KeyStore</b> + <b>DhDispatch</b><br/>Key state management & DH routing"]
    SS["<b>SymmetricState</b><br/>Chaining key, handshake hash, mix ops"]
    PP["<b>PatternParser</b><br/>Protocol name → tokens (thin orchestrator)"]
    PR["<b>PatternRegistry</b><br/>38 patterns: 12 fundamental, 3 one-way, 23 deferred"]
    MOD["<b>Modifiers</b><br/>fallback + PSK token insertion"]
    CS["<b>CipherState</b><br/>AEAD encrypt/decrypt, nonce, rekey"]
    CR["<b>CryptoResolver</b><br/>Algorithm name → implementation"]
    CP["<b>CryptoProvider</b><br/>DH · Cipher · Hash implementations"]

    NS --> HS
    NS --> PP
    NS --> CR
    HS --> HC
    HS --> KS
    HS --> SS
    PP --> PR
    PP --> MOD
    SS --> CS
    CR --> CP
    CS --> CP
```

### Session Lifecycle

A `NoiseSession` progresses through three phases:

```mermaid
stateDiagram-v2
    [*] --> Handshake : NoiseSession(protocolName, role, ...)
    Handshake --> Handshake : writeMessage() / readMessage()
    Handshake --> Ready : All pattern messages exchanged
    Ready --> Transport : split() → (sender, receiver)
    Transport --> Transport : sender.encryptWithAd() / receiver.decryptWithAd()
    Transport --> [*] : Session complete
```

### Handshake Message Flow (XX Pattern)

The XX pattern authenticates both parties over three messages:

```mermaid
sequenceDiagram
    participant I as Initiator
    participant R as Responder

    Note over I,R: Handshake Phase
    I->>R: msg1 → e
    R->>I: msg2 → e, ee, s, es
    I->>R: msg3 → s, se

    Note over I,R: split() → Transport Phase
    I->>R: encryptWithAd(plaintext)
    R->>I: encryptWithAd(plaintext)
```

### Protocol Name Parsing Pipeline

`PatternParser.parse()` decomposes a protocol name into a fully resolved handshake descriptor:

```mermaid
flowchart LR
    Input["Noise_IKpsk2_25519_ChaChaPoly_SHA256"]
    Split["Split on _<br/>prefix · pattern · dh · cipher · hash"]
    Lookup["PatternRegistry<br/>look up base pattern IK"]
    Fallback{"fallback<br/>modifier?"}
    PSK{"psk<br/>modifier?"}
    Apply["Modifiers.applyFallback()"]
    Insert["Modifiers.insertPskTokens()"]
    Output["HandshakeDescriptor<br/>pre-messages + token sequences"]

    Input --> Split --> Lookup --> Fallback
    Fallback -- Yes --> Apply --> PSK
    Fallback -- No --> PSK
    PSK -- Yes --> Insert --> Output
    PSK -- No --> Output
```

### Algorithm Resolution

`CryptoResolver` maps algorithm names to implementations. The default resolver wires all eight standard algorithms; custom resolvers can override or extend:

```mermaid
flowchart LR
    subgraph CryptoResolver
        direction TB
        DH["DH Registry<br/>25519 → Curve25519DH<br/>448 → X448DH"]
        C["Cipher Registry<br/>ChaChaPoly → ChaCha20-Poly1305<br/>AESGCM → AES-256-GCM"]
        H["Hash Registry<br/>SHA256 · SHA512<br/>BLAKE2b · BLAKE2s"]
    end

    Name["resolve(dh, cipher, hash)"] --> DH
    Name --> C
    Name --> H
    DH --> Suite["CryptoSuite<br/>(dh, cipher, hash)"]
    C --> Suite
    H --> Suite
```

## Security Considerations

### What this library does

- **MAC-failure invalidation**: A failed `decryptWithAd` permanently invalidates the `CipherState`. All subsequent operations throw an error.
- **Nonce exhaustion**: Hard error when the nonce counter reaches its maximum value.
- **Auto-rekey**: `Rekey()` follows the Noise spec: `ENCRYPT(k, maxnonce, zerolen, zeros)`, truncated to 32 bytes.
- **Thread safety**: `CipherState` is thread-safe on both platforms (Kotlin `@Synchronized`, Swift `NSLock`).
- **Secret zeroing**: `SecureMemory` (Kotlin) and `SecureBuffer` (Swift) zero sensitive key material when no longer needed.

### What this library does NOT guarantee

- **Constant-time operations**: Platform crypto APIs (JCA, CryptoKit) are best-effort constant-time. The pure X448 and BLAKE2 implementations use constant-time patterns (no secret-dependent branches) but run on general-purpose hardware without timing guarantees.
- **Side-channel resistance**: No protection against power analysis, cache-timing attacks, or other physical side channels.
- **Memory pinning**: Secrets may be copied by the garbage collector (JVM) or ARC (Swift) before zeroing occurs.

### Recommendations

- Use Curve25519 over X448 for performance-sensitive applications (platform-native DH vs. pure implementation).
- Use ChaChaPoly over AESGCM on devices without AES hardware acceleration.
- Call `Rekey()` periodically for long-lived sessions to limit exposure from a compromised key.

## Development

### Building

```bash
# Kotlin
cd android && gradle build

# Swift
cd ios && swift build
```

### Running Tests

```bash
# Kotlin (127 tests)
cd android && gradle test

# Swift (69 tests)
cd ios && swift test
```

### Generating Documentation

```bash
# Kotlin (Dokka)
cd android && gradle dokkaHtml
# Output: build/dokka/html/

# Swift (DocC)
cd ios && swift package generate-documentation
```

### Benchmarks

Both platforms include a benchmark harness. Run benchmarks as part of the test suite:

```bash
# Kotlin
cd android && gradle test --tests "noise.protocol.BenchmarkTest"

# Swift (use release mode for meaningful numbers)
cd ios && swift test -c release --filter BenchmarkTests
```

## Project Structure

```
├── android/                  # Kotlin implementation
│   ├── build.gradle.kts      # Gradle build + Maven publishing
│   └── src/
│       ├── main/kotlin/noise/protocol/
│       │   ├── NoiseSession.kt       # Public API entry point
│       │   ├── HandshakeState.kt     # Handshake driver
│       │   ├── HandshakeConfig.kt    # Immutable handshake configuration
│       │   ├── SymmetricState.kt     # Symmetric key management
│       │   ├── CipherState.kt        # AEAD encryption/decryption
│       │   ├── CryptoProvider.kt     # DH, Cipher, Hash implementations
│       │   ├── CryptoResolver.kt     # Algorithm name → implementation
│       │   ├── CryptoSuite.kt        # (DH, Cipher, Hash) tuple
│       │   ├── PatternParser.kt      # Protocol name → tokens (orchestrator)
│       │   ├── PatternRegistry.kt    # 38 standard pattern definitions
│       │   ├── PatternDef.kt         # Pattern data structure
│       │   ├── Modifiers.kt          # Fallback + PSK modifiers
│       │   ├── NoiseException.kt     # Error hierarchy
│       │   ├── KeyStore.kt           # Key state with domain errors
│       │   ├── DhDispatch.kt         # Role-conditional DH routing
│       │   ├── KeyPair.kt            # DH key pair
│       │   ├── Role.kt               # INITIATOR / RESPONDER
│       │   ├── SecureMemory.kt       # Secret zeroing
│       │   ├── X448.kt               # Pure X448 DH
│       │   └── Benchmark.kt          # Benchmark harness
│       └── test/kotlin/noise/protocol/
│           └── *.kt                  # 127 tests
├── ios/                      # Swift implementation
│   ├── Package.swift         # SPM manifest
│   └── Sources/NoiseProtocol/
│       │   ├── NoiseProtocol.swift       # Public API entry point
│       │   ├── HandshakeState.swift      # Handshake driver
│       │   ├── HandshakeConfig.swift     # Immutable handshake configuration
│       │   ├── SymmetricState.swift      # Symmetric key management
│       │   ├── CipherState.swift         # AEAD encryption/decryption
│       │   ├── CryptoProvider.swift      # Platform crypto + BLAKE2
│       │   ├── CryptoResolver.swift      # Algorithm name → implementation
│       │   ├── CryptoSuite.swift         # (DH, Cipher, Hash) tuple
│       │   ├── PatternParser.swift       # Protocol name → tokens (orchestrator)
│       │   ├── PatternRegistry.swift     # 38 standard pattern definitions
│       │   ├── PatternDef.swift          # Pattern data structure
│       │   ├── Modifiers.swift           # Fallback + PSK modifiers
│       │   ├── NoiseError.swift          # Error types
│       │   ├── KeyStore.swift            # Key state with domain errors
│       │   ├── DhDispatch.swift          # Role-conditional DH routing
│       │   ├── KeyPair.swift             # DH key pair
│       │   ├── Role.swift                # initiator / responder
│       │   ├── SecureBuffer.swift        # Secret zeroing
│       │   ├── X448.swift                # Pure X448 DH
│       │   └── Benchmark.swift           # Benchmark harness
│       └── Tests/NoiseProtocolTests/
│           └── *.swift               # 69 tests
├── test-vectors/             # Shared JSON test vectors (cacophony format)
└── LICENSE                   # Unlicense (public domain)
```

## License

This project is released into the public domain under the [Unlicense](LICENSE). You are free to use, modify, and distribute it without restriction.
