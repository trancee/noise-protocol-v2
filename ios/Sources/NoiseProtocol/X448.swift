import Foundation

/// Pure X448 Diffie-Hellman per RFC 7748.
/// Uses a minimal big-integer implementation for field arithmetic.
public enum X448_: Sendable {

    public static func scalarMult(k: Data, u: Data) -> Data {
        let scalar = decodeScalar448(k)
        let uCoord = decodeUCoordinate(u)

        var x2 = BigNum.one
        var z2 = BigNum.zero
        var x3 = uCoord
        var z3 = BigNum.one
        let x1 = uCoord

        var swap = 0
        for t in stride(from: 447, through: 0, by: -1) {
            let kt = Int(scalar[t / 8] >> (t % 8)) & 1
            swap ^= kt
            if swap != 0 { Swift.swap(&x2, &x3); Swift.swap(&z2, &z3) }
            swap = kt

            let a  = modP(x2 + z2)
            let aa = modP(a * a)
            let b  = subMod(x2, z2)
            let bb = modP(b * b)
            let e  = subMod(aa, bb)
            let c  = modP(x3 + z3)
            let d  = subMod(x3, z3)
            let da = modP(d * a)
            let cb = modP(c * b)

            let daPcb = modP(da + cb)
            x3 = modP(daPcb * daPcb)
            let daMcb = subMod(da, cb)
            z3 = modP(x1 * modP(daMcb * daMcb))
            x2 = modP(aa * bb)
            z2 = modP(e * modP(aa + modP(a24 * e)))
        }

        if swap != 0 { Swift.swap(&x2, &x3); Swift.swap(&z2, &z3) }

        let result = modP(x2 * modInverse(z2))
        return encodeUCoordinate(result)
    }

    // MARK: - Constants

    // P = 2^448 - 2^224 - 1
    private static let p = BigNum([
        0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFE_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_FFFF_FFFF
    ])

    private static let a24 = BigNum(39081)

    // MARK: - Modular arithmetic

    /// Fast reduction using 2^448 ≡ 2^224 + 1 (mod P)
    private static func modP(_ x: BigNum) -> BigNum {
        var r = x
        while r.bitLength > 449 {
            let lo = r.lo448
            let hi = r.shiftRight(448)
            r = lo + hi.shiftLeft(224) + hi
        }
        while r >= p { r = r - p }
        return r
    }

    private static func subMod(_ a: BigNum, _ b: BigNum) -> BigNum {
        a >= b ? a - b : p - (b - a)
    }

    /// a^(p-2) mod p  (Fermat's little theorem)
    private static func modInverse(_ a: BigNum) -> BigNum {
        var result = BigNum.one
        var base = modP(a)
        let exp = p - BigNum(2)
        for i in 0..<exp.bitLength {
            if exp.bit(i) == 1 { result = modP(result * base) }
            base = modP(base * base)
        }
        return result
    }

    // MARK: - Encoding / decoding

    private static func decodeScalar448(_ k: Data) -> [UInt8] {
        var s = [UInt8](repeating: 0, count: 56)
        for i in 0..<min(k.count, 56) { s[i] = k[k.startIndex + i] }
        s[0] &= 252
        s[55] |= 128
        return s
    }

    private static func decodeUCoordinate(_ u: Data) -> BigNum {
        var w = [UInt64](repeating: 0, count: 7)
        for i in 0..<7 {
            for j in 0..<8 {
                let idx = i * 8 + j
                if idx < u.count { w[i] |= UInt64(u[u.startIndex + idx]) << (j * 8) }
            }
        }
        return modP(BigNum(w))
    }

    private static func encodeUCoordinate(_ fe: BigNum) -> Data {
        let v = modP(fe)
        var bytes = Data(count: 56)
        for i in 0..<min(v.count, 7) {
            for j in 0..<8 {
                bytes[i * 8 + j] = UInt8(truncatingIfNeeded: v[i] >> (j * 8))
            }
        }
        return bytes
    }

    // MARK: - BigNum (fixed-size inline storage, zero heap allocation)
    //
    // Stores up to 15 UInt64 words in a tuple (120 bytes, stack-allocated).
    // Field elements need 7 words; multiplication intermediates need up to 14.
    // The `count` field tracks significant words (replaces dynamic array trim).

    private struct BigNum: Equatable, Comparable, Sendable {
        private var s: (UInt64,UInt64,UInt64,UInt64,UInt64,UInt64,UInt64,UInt64,
                        UInt64,UInt64,UInt64,UInt64,UInt64,UInt64,UInt64)
        private(set) var count: Int

        static let zero = BigNum(0)
        static let one  = BigNum(1)

        @inline(__always)
        subscript(i: Int) -> UInt64 {
            get {
                withUnsafePointer(to: s) { ptr in
                    ptr.withMemoryRebound(to: UInt64.self, capacity: 15) { $0[i] }
                }
            }
            set {
                withUnsafeMutablePointer(to: &s) { ptr in
                    ptr.withMemoryRebound(to: UInt64.self, capacity: 15) { $0[i] = newValue }
                }
            }
        }

        init(_ value: UInt64) {
            s = (value,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
            count = 1
        }

        init(_ words: [UInt64]) {
            s = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
            count = min(words.count, 15)
            withUnsafeMutablePointer(to: &s) { ptr in
                ptr.withMemoryRebound(to: UInt64.self, capacity: 15) { buf in
                    for i in 0..<count { buf[i] = words[i] }
                }
            }
            trim()
        }

        private init(count: Int, fill: (UnsafeMutablePointer<UInt64>) -> Void) {
            s = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
            self.count = min(count, 15)
            withUnsafeMutablePointer(to: &s) { ptr in
                ptr.withMemoryRebound(to: UInt64.self, capacity: 15) { fill($0) }
            }
            trim()
        }

        @inline(__always)
        private mutating func trim() {
            while count > 1 && self[count - 1] == 0 { count -= 1 }
        }

        var isZero: Bool { count == 1 && self[0] == 0 }

        var bitLength: Int {
            let top = self[count - 1]
            if top == 0 { return 0 }
            return (count - 1) * 64 + (64 - top.leadingZeroBitCount)
        }

        @inline(__always)
        func bit(_ i: Int) -> Int {
            let w = i / 64
            guard w < count else { return 0 }
            return Int((self[w] >> (i % 64)) & 1)
        }

        var lo448: BigNum {
            if count <= 7 { return self }
            var r = BigNum(0)
            r.count = 7
            for i in 0..<7 { r[i] = self[i] }
            r.trim()
            return r
        }

        // MARK: Comparison

        static func < (lhs: BigNum, rhs: BigNum) -> Bool {
            if lhs.count != rhs.count { return lhs.count < rhs.count }
            for i in stride(from: lhs.count - 1, through: 0, by: -1) {
                if lhs[i] != rhs[i] { return lhs[i] < rhs[i] }
            }
            return false
        }

        static func == (lhs: BigNum, rhs: BigNum) -> Bool {
            if lhs.count != rhs.count { return false }
            for i in 0..<lhs.count {
                if lhs[i] != rhs[i] { return false }
            }
            return true
        }

        // MARK: Arithmetic

        static func + (lhs: BigNum, rhs: BigNum) -> BigNum {
            let n = max(lhs.count, rhs.count)
            return BigNum(count: n + 1) { r in
                var carry: UInt64 = 0
                for i in 0..<n {
                    let a: UInt64 = i < lhs.count ? lhs[i] : 0
                    let b: UInt64 = i < rhs.count ? rhs[i] : 0
                    let (s1, o1) = a.addingReportingOverflow(b)
                    let (s2, o2) = s1.addingReportingOverflow(carry)
                    r[i] = s2
                    carry = (o1 ? 1 : 0) + (o2 ? 1 : 0)
                }
                r[n] = carry
            }
        }

        static func - (lhs: BigNum, rhs: BigNum) -> BigNum {
            return BigNum(count: lhs.count) { r in
                var borrow: UInt64 = 0
                for i in 0..<lhs.count {
                    let a = lhs[i]
                    let b: UInt64 = i < rhs.count ? rhs[i] : 0
                    let (d1, o1) = a.subtractingReportingOverflow(b)
                    let (d2, o2) = d1.subtractingReportingOverflow(borrow)
                    r[i] = d2
                    borrow = (o1 ? 1 : 0) + (o2 ? 1 : 0)
                }
            }
        }

        static func * (lhs: BigNum, rhs: BigNum) -> BigNum {
            let m = lhs.count, n = rhs.count
            return BigNum(count: min(m + n, 15)) { r in
                let total = min(m + n, 15)
                for x in 0..<total { r[x] = 0 }
                for i in 0..<m {
                    var carry: UInt64 = 0
                    for j in 0..<n {
                        guard i + j < 15 else { break }
                        let (hi, lo) = lhs[i].multipliedFullWidth(by: rhs[j])
                        let (s1, o1) = lo.addingReportingOverflow(r[i + j])
                        let (s2, o2) = s1.addingReportingOverflow(carry)
                        r[i + j] = s2
                        carry = hi + (o1 ? 1 : 0) + (o2 ? 1 : 0)
                    }
                    if i + n < 15 { r[i + n] = carry }
                }
            }
        }

        // MARK: Shifts

        func shiftLeft(_ n: Int) -> BigNum {
            if n == 0 { return self }
            let ws = n / 64, bs = n % 64
            let cnt = min(count + ws + (bs > 0 ? 1 : 0), 15)
            return BigNum(count: cnt) { r in
                for x in 0..<cnt { r[x] = 0 }
                if bs == 0 {
                    for i in 0..<self.count where i + ws < 15 { r[i + ws] = self[i] }
                } else {
                    for i in 0..<self.count where i + ws < 15 {
                        r[i + ws] |= self[i] << bs
                        if i + ws + 1 < 15 { r[i + ws + 1] |= self[i] >> (64 - bs) }
                    }
                }
            }
        }

        func shiftRight(_ n: Int) -> BigNum {
            let ws = n / 64, bs = n % 64
            if ws >= count { return .zero }
            let cnt = count - ws
            return BigNum(count: cnt) { r in
                if bs == 0 {
                    for i in 0..<cnt { r[i] = self[i + ws] }
                } else {
                    for i in 0..<cnt {
                        r[i] = self[i + ws] >> bs
                        if i + ws + 1 < self.count { r[i] |= self[i + ws + 1] << (64 - bs) }
                    }
                }
            }
        }
    }
}
