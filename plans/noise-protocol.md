# Plan: Noise Protocol Framework for Android & iOS

> Source PRD: [GitHub Issue #1 — trancee/noise-protocol-v2](https://github.com/trancee/noise-protocol-v2/issues/1)

## Architectural decisions

Durable decisions that apply across all phases:

- **Repository layout**: Monorepo with `android/` (Kotlin/Gradle) and `ios/` (Swift/SPM) top-level directories, plus `test-vectors/` (shared JSON files consumed by both platforms).
- **Package names**: Kotlin → `noise.protocol`, Swift → `NoiseProtocol`.
- **Module layering** (bottom-up): `CryptoProvider` → `CipherState` → `SymmetricState` → `HandshakeState` → `NoiseSession`. Both platforms follow the identical layering.
- **CryptoProvider interface**: Abstract `DH`, `Cipher`, and `Hash` interfaces. Platform crypto APIs are wrapped behind these interfaces; pure implementations (BLAKE2, X448) register as additional providers. Selection is driven by the protocol name string parsed by `PatternParser`.
- **Public API shape**: `NoiseSession(protocolName: String, role: Role, ...)` — high-level entry point. Synchronous state machine: `writeMessage(payload) → bytes`, `readMessage(bytes) → payload`, `split() → (CipherState, CipherState)`.
- **Error model**: Sealed class (Kotlin) / enum with associated values (Swift). Types: `DecryptionFailed`, `InvalidState`, `NonceExhausted`, `InvalidKey`, `InvalidPattern`, `HandshakeIncomplete`, `SessionInvalidated`.
- **Noise protocol name format**: `Noise_<pattern>[modifiers]_<DH>_<cipher>_<hash>` per the spec. Parsed by `PatternParser` into a `HandshakeDescriptor`.
- **Test vector format**: JSON files in `test-vectors/` following the noise-c/cacophony schema. Both platforms deserialize the same files.
- **Minimum Android API**: 33 (ensures platform support for X25519, ChaCha20-Poly1305, AES-GCM, SHA-2).
- **Thread safety boundary**: `CipherState` is thread-safe (atomic nonce + synchronized encrypt/decrypt). `HandshakeState` is single-threaded.
- **Constant-time posture**: Best-effort branchless code. Documented platform limitations (JVM JIT, Swift optimizer).

---

## Phase 1: Kotlin — First complete handshake

**User stories**: 1, 3, 5

### What to build

A working end-to-end `Noise_NN_25519_ChaChaPoly_SHA256` handshake on Android. NN is the simplest interactive pattern (no static keys), making it the ideal tracer bullet — it touches every layer without requiring key management logic.

This phase delivers: Gradle project scaffolding with the `noise.protocol` package, `CryptoProvider` interface with platform-backed Curve25519 (X25519 via `java.security`), ChaChaPoly (`javax.crypto`), and SHA256 (`MessageDigest`) implementations, the three core state machines (`CipherState`, `SymmetricState`, `HandshakeState`) wired for the NN pattern, and a `NoiseSession` high-level wrapper that accepts the protocol name string `"Noise_NN_25519_ChaChaPoly_SHA256"` (hardcoded pattern resolution is fine at this stage).

Two `NoiseSession` instances (initiator + responder) should be able to complete the NN handshake in-memory, `split()`, and then encrypt/decrypt payloads in both directions.

### Acceptance criteria

- [ ] Gradle project builds cleanly targeting API 33+
- [ ] `CryptoProvider` interface defined with `DH`, `Cipher`, `Hash` abstractions
- [ ] Platform implementations: X25519 key generation + DH, ChaChaPoly encrypt/decrypt, SHA256 hash + HMAC + HKDF
- [ ] `CipherState` encrypts/decrypts with nonce tracking
- [ ] `SymmetricState` implements `mixKey`, `mixHash`, `encryptAndHash`, `decryptAndHash`, `split`
- [ ] `HandshakeState` processes NN token sequence (→ e, ← e, ee)
- [ ] `NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", role)` creates a working session
- [ ] Integration test: initiator + responder complete NN handshake + transport encrypt/decrypt
- [ ] At least one noise-c/cacophony test vector for `Noise_NN_25519_ChaChaPoly_SHA256` passes

---

## Phase 2: Swift — First complete handshake

**User stories**: 2, 3, 5, 20

### What to build

Port the identical vertical slice to iOS. A working `Noise_NN_25519_ChaChaPoly_SHA256` handshake in pure Swift, using CryptoKit for all primitives.

This phase delivers: SPM package scaffolding for `NoiseProtocol`, the same `CryptoProvider` interface with CryptoKit-backed Curve25519, ChaChaPoly, and SHA256, the three core state machines, and the `NoiseSession` high-level wrapper.

Crucially, this phase also establishes the shared `test-vectors/` directory in the monorepo root. Both Kotlin and Swift test suites consume the same JSON test vector files and must produce byte-identical outputs for identical inputs.

### Acceptance criteria

- [ ] SPM package builds cleanly
- [ ] `CryptoProvider` interface mirrors Kotlin's design using Swift idioms
- [ ] CryptoKit implementations: X25519, ChaChaPoly, SHA256
- [ ] Core state machines (`CipherState`, `SymmetricState`, `HandshakeState`) implemented
- [ ] `NoiseSession("Noise_NN_25519_ChaChaPoly_SHA256", role:)` creates a working session
- [ ] Integration test: initiator + responder complete NN handshake + transport encrypt/decrypt
- [ ] Shared `test-vectors/` JSON files consumed by both Kotlin and Swift test suites
- [ ] Cross-platform validation: identical inputs produce identical outputs on both platforms

---

## Phase 3: PatternParser + all fundamental patterns

**User stories**: 4, 10, 22

### What to build

Replace hardcoded NN pattern resolution with a general-purpose `PatternParser` that takes any valid Noise protocol name string and produces a `HandshakeDescriptor` (token sequences per message, DH/cipher/hash selection). Then implement all fundamental interactive patterns (NK, NX, KN, KK, KX, XN, XK, XX) and one-way patterns (N, K, X) on both platforms.

This requires `HandshakeState` to handle static key tokens (`s`, `es`, `se`, `ss`) in addition to the ephemeral tokens it already supports. Patterns that require pre-known static keys (NK, KK, KN, K, etc.) need the caller to supply them via `NoiseSession`.

Introduce sealed error types for invalid pattern names, missing keys, and invalid state transitions.

### Acceptance criteria

- [ ] `PatternParser` parses all fundamental + one-way pattern names correctly
- [ ] `PatternParser` rejects malformed protocol name strings with `InvalidPattern` error
- [ ] `HandshakeState` processes `s`, `es`, `se`, `ss` tokens (static key encrypt/decrypt + DH)
- [ ] All 12 patterns (NN, NK, NX, KN, KK, KX, XN, XK, XX, N, K, X) work end-to-end on both platforms
- [ ] `NoiseSession` accepts optional `staticKey`, `remoteStaticKey` parameters
- [ ] Sealed error types implemented: `InvalidPattern`, `InvalidKey`, `InvalidState`, `HandshakeIncomplete`
- [ ] noise-c/cacophony test vectors pass for all 12 patterns × `25519_ChaChaPoly_SHA256`
- [ ] Both platforms pass the same shared test vector files

---

## Phase 4: Full cipher/hash matrix via platform APIs

**User stories**: 15

### What to build

Expand the `CryptoProvider` to include AESGCM (AES-256-GCM) and SHA512, both backed by platform crypto APIs. This multiplies the supported protocol name combinations: 1 DH × 2 ciphers × 2 hashes = 4 combos per pattern, across all 12 patterns = 48 working protocol strings.

The `PatternParser` already handles DH/cipher/hash selection from the protocol name string; this phase adds the concrete provider implementations and their test vectors.

### Acceptance criteria

- [ ] AESGCM provider implemented on both platforms (Android: `javax.crypto`, iOS: CryptoKit `AES.GCM`)
- [ ] SHA512 provider implemented on both platforms (Android: `MessageDigest`, iOS: CryptoKit)
- [ ] All 12 patterns work with all 4 cipher/hash combos (ChaChaPoly+SHA256, ChaChaPoly+SHA512, AESGCM+SHA256, AESGCM+SHA512)
- [ ] Primitive-level test vectors: RFC 7539 (ChaCha20-Poly1305), NIST SP 800-38D (AES-GCM), NIST CSRC (SHA-256, SHA-512)
- [ ] noise-c/cacophony test vectors pass for all 48 protocol name combinations
- [ ] Cross-platform byte-identical output for all combos

---

## Phase 5: Pure BLAKE2s + BLAKE2b

**User stories**: 15, 18, 25

### What to build

Implement BLAKE2s (256-bit) and BLAKE2b (512-bit) from scratch on both platforms, following RFC 7693. Support the full BLAKE2 parameter block (key, salt, personalization, tree hashing parameters).

Integrate as `Hash` providers in `CryptoProvider`. Use HMAC-BLAKE2 (not BLAKE2 keyed mode) for key derivation, strictly following the Noise spec's HMAC-HASH construction.

This expands the hash options from 2 to 4, giving 1 DH × 2 ciphers × 4 hashes = 8 combos per pattern.

### Acceptance criteria

- [ ] Pure BLAKE2s implementation on both platforms, RFC 7693 compliant
- [ ] Pure BLAKE2b implementation on both platforms, RFC 7693 compliant
- [ ] Full parameter block support (key, salt, personalization, fanout, depth, leaf length, node offset, node depth, inner length)
- [ ] HMAC-BLAKE2s and HMAC-BLAKE2b produce correct HKDF output
- [ ] RFC 7693 appendix A (BLAKE2b) and appendix B (BLAKE2s) test vectors pass
- [ ] All 12 patterns work with BLAKE2s and BLAKE2b hash options
- [ ] noise-c/cacophony test vectors pass for BLAKE2-based protocol name combinations
- [ ] Cross-platform byte-identical output for all BLAKE2 combos

---

## Phase 6: Pure X448

**User stories**: 15, 18

### What to build

Implement X448 Diffie-Hellman from scratch on both platforms, following RFC 7748. This involves:

- Goldilocks prime field arithmetic (p = 2⁴⁴⁸ − 2²²⁴ − 1): addition, subtraction, multiplication, inversion, reduction
- Montgomery ladder scalar multiplication (constant-time, best-effort)
- Key pair generation (clamp + scalar mult with base point)

Integrate as a `DH` provider in `CryptoProvider`. This doubles the DH options, giving 2 DH × 2 ciphers × 4 hashes = 16 combos per pattern.

### Acceptance criteria

- [ ] Goldilocks field arithmetic implemented and correct on both platforms
- [ ] Montgomery ladder scalar multiplication (best-effort constant-time)
- [ ] X448 key generation, DH agreement produce correct results
- [ ] RFC 7748 Section 6.2 test vectors pass (including the iterated 1,000,000× scalar multiplication vector)
- [ ] All 12 fundamental + one-way patterns work with X448
- [ ] noise-c/cacophony test vectors pass for all 448-based protocol name combinations
- [ ] Full 16-combo matrix (2 DH × 2 cipher × 4 hash) verified across all patterns
- [ ] Cross-platform byte-identical output for X448-based combos

---

## Phase 7: PSK + deferred + fallback patterns

**User stories**: 11, 12, 13, 23

### What to build

Extend `PatternParser` and `HandshakeState` to support the three Noise pattern modifiers:

- **PSK modifier**: `psk0`, `psk1`, `psk2`, etc. at any valid position. Multiple PSK modifiers in a single pattern (e.g., `psk0+psk2`). The `psk` token is processed by `HandshakeState` using `mixKeyAndHash`.
- **Deferred patterns**: All 24 deferred patterns (NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1, K1X, KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1). These rearrange when DH operations occur in the handshake.
- **Fallback modifier**: Allows a failed handshake (e.g., IK) to transition into a fallback pattern (e.g., XXfallback), preserving the handshake hash from the failed attempt.

`NoiseSession` is extended to accept an optional `psks` parameter (list of PSK bytes indexed by modifier position) and support fallback transition.

### Acceptance criteria

- [ ] `PatternParser` correctly parses PSK modifier positions from protocol name strings
- [ ] `PatternParser` handles multiple PSK modifiers (e.g., `Noise_XXpsk0+psk2_25519_ChaChaPoly_SHA256`)
- [ ] `HandshakeState` processes `psk` token via `mixKeyAndHash` at correct positions
- [ ] All 24 deferred patterns implemented and working end-to-end on both platforms
- [ ] Fallback modifier: `HandshakeState` can transition from a failed pattern to a fallback pattern
- [ ] `NoiseSession` accepts `psks` parameter and `fallbackFrom` for fallback transitions
- [ ] noise-c/cacophony test vectors pass for PSK, deferred, and fallback patterns
- [ ] Cross-platform validation for all modifier-based patterns

---

## Phase 8: Security hardening

**User stories**: 6, 7, 8, 9, 14, 16, 19

### What to build

Harden the library for production use with security-critical features that span all existing modules:

- **SecureMemory module**: Android — direct `ByteBuffer` (off-heap) with explicit zeroing; iOS — `withUnsafeMutableBytes` + `memset_s`. Scoped `use { }` pattern for automatic cleanup. Retrofit into `HandshakeState` and `CipherState` for ephemeral keys and intermediate key material.
- **Thread-safe CipherState**: Atomic nonce increment + synchronized encryption. The two `CipherState` objects from `split()` can safely be used from different threads.
- **Nonce exhaustion protection**: Auto-rekey when nonce approaches 2⁶⁴ − 1, hard `NonceExhausted` error at the absolute limit.
- **MAC failure invalidation**: `CipherState.decryptWithAd()` failure permanently marks the session as `SessionInvalidated`. All subsequent operations throw `SessionInvalidated`.
- **Prologue support**: `NoiseSession` accepts an optional `prologue` byte array that is mixed into the handshake hash before any messages are exchanged.

### Acceptance criteria

- [ ] `SecureMemory` allocates off-heap (Android) / unsafe (iOS) buffers with explicit zeroing
- [ ] Ephemeral keys and intermediate key material use `SecureMemory` throughout handshake
- [ ] `CipherState` encrypt/decrypt is thread-safe (concurrent stress test with multiple threads)
- [ ] Nonce auto-rekey triggers before 2⁶⁴ − 1, verified by test
- [ ] Nonce hard-stop throws `NonceExhausted` at absolute limit, verified by test
- [ ] MAC failure on `decryptWithAd` permanently invalidates session, verified by test
- [ ] Subsequent operations after invalidation throw `SessionInvalidated`
- [ ] `NoiseSession` accepts `prologue` parameter, mixed into handshake hash
- [ ] Prologue-mismatch between initiator and responder causes handshake failure (verified by test)
- [ ] Best-effort constant-time documented in public API documentation

---

## Phase 9: Benchmarks + optimization + publishing

**User stories**: 21, 24

### What to build

A benchmark harness on both platforms that measures performance across four dimensions, plus optimization passes tracked by benchmark results, and package publishing.

**Benchmarking**:
- Primitive throughput: operations/second for each DH, cipher, and hash function
- Handshake latency: microseconds per complete handshake for representative patterns
- Transport throughput: MB/s encrypt/decrypt at various payload sizes (64B, 1KB, 64KB, 1MB)
- Memory allocation: heap allocations per operation (Android — critical for GC pressure)
- Results stored per run for self-comparison over time

**Optimization**: Identify bottlenecks from benchmark results (likely X448 field arithmetic and BLAKE2 compression), apply targeted optimizations, verify improvement via benchmarks.

**Publishing**:
- Android: Maven artifact (`noise.protocol`) published to Maven Central or GitHub Packages
- iOS: Swift Package with proper `Package.swift` manifest
- API documentation for both platforms

### Acceptance criteria

- [ ] Benchmark harness runs on Android (JMH or `androidx.benchmark`) and iOS (`XCTest.measure` or equivalent)
- [ ] All four metric dimensions measured and reported: primitive throughput, handshake latency, transport throughput, memory allocation
- [ ] Benchmark results stored per run with comparison against previous baselines
- [ ] At least one optimization pass with measurable improvement documented
- [ ] Maven artifact builds and publishes (manual or CI trigger)
- [ ] SPM package resolves and builds from its repository URL
- [ ] Public API documentation generated for both platforms
- [ ] README with usage examples, supported protocol names, and security considerations
