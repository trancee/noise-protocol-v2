import Foundation

final class SecureBuffer {
    private let pointer: UnsafeMutableRawBufferPointer
    let size: Int

    private init(size: Int) {
        self.size = size
        self.pointer = UnsafeMutableRawBufferPointer.allocate(byteCount: size, alignment: 1)
    }

    static func allocate(size: Int) -> SecureBuffer {
        let buf = SecureBuffer(size: size)
        buf.pointer.initializeMemory(as: UInt8.self, repeating: 0)
        return buf
    }

    static func wrap(_ data: Data) -> SecureBuffer {
        let buf = SecureBuffer(size: data.count)
        data.withUnsafeBytes { src in
            buf.pointer.copyMemory(from: src)
        }
        return buf
    }

    func copyBytes() -> Data {
        guard size > 0, let ptr = pointer.baseAddress else { return Data() }
        return Data(bytes: ptr, count: size)
    }

    func zero() {
        guard size > 0, let ptr = pointer.baseAddress else { return }
        // Use individual byte stores to prevent compiler optimization of the zeroing
        for i in 0..<size {
            ptr.advanced(by: i).storeBytes(of: 0 as UInt8, as: UInt8.self)
        }
        // Compiler barrier
        _fixLifetime(self)
    }

    func use<R>(_ block: (SecureBuffer) throws -> R) rethrows -> R {
        defer { zero() }
        return try block(self)
    }

    deinit {
        zero()
        pointer.deallocate()
    }
}
