import Foundation

/// A secure memory buffer that guarantees zeroing of sensitive data on deallocation.
///
/// `SecureBuffer` allocates raw memory and uses individual byte stores (rather than `memset`)
/// to prevent the compiler from optimizing away the zeroing operation. This is critical for
/// protecting secret key material in memory.
final class SecureBuffer {
    private let pointer: UnsafeMutableRawBufferPointer

    /// The number of bytes in this buffer.
    let size: Int

    private init(size: Int) {
        self.size = size
        self.pointer = UnsafeMutableRawBufferPointer.allocate(byteCount: size, alignment: 1)
    }

    /// Allocates a new zero-initialized secure buffer of the given size.
    ///
    /// - Parameter size: The number of bytes to allocate.
    /// - Returns: A new `SecureBuffer` with all bytes set to zero.
    static func allocate(size: Int) -> SecureBuffer {
        let buf = SecureBuffer(size: size)
        buf.pointer.initializeMemory(as: UInt8.self, repeating: 0)
        return buf
    }

    /// Creates a secure buffer by copying the contents of existing data.
    ///
    /// - Parameter data: The data to copy into the secure buffer.
    /// - Returns: A new `SecureBuffer` containing a copy of the data.
    static func wrap(_ data: Data) -> SecureBuffer {
        let buf = SecureBuffer(size: data.count)
        data.withUnsafeBytes { src in
            buf.pointer.copyMemory(from: src)
        }
        return buf
    }

    /// Returns a copy of the buffer contents as `Data`.
    ///
    /// - Returns: A `Data` instance containing a copy of the buffer bytes.
    func copyBytes() -> Data {
        guard size > 0, let ptr = pointer.baseAddress else { return Data() }
        return Data(bytes: ptr, count: size)
    }

    /// Securely zeroes all bytes in the buffer.
    ///
    /// Uses individual byte stores and a compiler barrier (`_fixLifetime`) to prevent
    /// the optimizer from eliding the zeroing operation.
    func zero() {
        guard size > 0, let ptr = pointer.baseAddress else { return }
        // Use individual byte stores to prevent compiler optimization of the zeroing
        for i in 0..<size {
            ptr.advanced(by: i).storeBytes(of: 0 as UInt8, as: UInt8.self)
        }
        // Compiler barrier
        _fixLifetime(self)
    }

    /// Executes a closure with access to this buffer, then securely zeroes it.
    ///
    /// - Parameter block: A closure that receives this `SecureBuffer`.
    /// - Returns: The value returned by the closure.
    /// - Throws: Rethrows any error thrown by the closure.
    func use<R>(_ block: (SecureBuffer) throws -> R) rethrows -> R {
        defer { zero() }
        return try block(self)
    }

    deinit {
        zero()
        pointer.deallocate()
    }
}
