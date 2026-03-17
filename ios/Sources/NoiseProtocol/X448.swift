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
        for i in 0..<min(v.words.count, 7) {
            for j in 0..<8 {
                bytes[i * 8 + j] = UInt8(truncatingIfNeeded: v.words[i] >> (j * 8))
            }
        }
        return bytes
    }

    // MARK: - BigNum (private unsigned big integer, little-endian UInt64 words)

    private struct BigNum: Equatable, Comparable, Sendable {
        var words: [UInt64]

        static let zero = BigNum([0])
        static let one  = BigNum([1])

        init(_ words: [UInt64]) {
            self.words = words
            self.trim()
        }

        init(_ value: UInt64) {
            self.words = [value]
        }

        private mutating func trim() {
            while words.count > 1, words.last! == 0 { words.removeLast() }
        }

        var isZero: Bool { words.count == 1 && words[0] == 0 }

        var bitLength: Int {
            guard let top = words.last, top != 0 else { return 0 }
            return (words.count - 1) * 64 + (64 - top.leadingZeroBitCount)
        }

        func bit(_ i: Int) -> Int {
            let w = i / 64
            guard w < words.count else { return 0 }
            return Int((words[w] >> (i % 64)) & 1)
        }

        /// Lower 448 bits (7 full words since 448 = 7×64)
        var lo448: BigNum {
            if words.count <= 7 { return self }
            return BigNum(Array(words.prefix(7)))
        }

        // MARK: Comparison

        static func < (lhs: BigNum, rhs: BigNum) -> Bool {
            if lhs.words.count != rhs.words.count {
                return lhs.words.count < rhs.words.count
            }
            for i in stride(from: lhs.words.count - 1, through: 0, by: -1) {
                if lhs.words[i] != rhs.words[i] { return lhs.words[i] < rhs.words[i] }
            }
            return false
        }

        // MARK: Arithmetic

        static func + (lhs: BigNum, rhs: BigNum) -> BigNum {
            let n = max(lhs.words.count, rhs.words.count)
            var r = [UInt64](repeating: 0, count: n + 1)
            var carry: UInt64 = 0
            for i in 0..<n {
                let a: UInt64 = i < lhs.words.count ? lhs.words[i] : 0
                let b: UInt64 = i < rhs.words.count ? rhs.words[i] : 0
                let (s1, o1) = a.addingReportingOverflow(b)
                let (s2, o2) = s1.addingReportingOverflow(carry)
                r[i] = s2
                carry = (o1 ? 1 : 0) + (o2 ? 1 : 0)
            }
            r[n] = carry
            return BigNum(r)
        }

        static func - (lhs: BigNum, rhs: BigNum) -> BigNum {
            var r = [UInt64](repeating: 0, count: lhs.words.count)
            var borrow: UInt64 = 0
            for i in 0..<lhs.words.count {
                let a = lhs.words[i]
                let b: UInt64 = i < rhs.words.count ? rhs.words[i] : 0
                let (d1, o1) = a.subtractingReportingOverflow(b)
                let (d2, o2) = d1.subtractingReportingOverflow(borrow)
                r[i] = d2
                borrow = (o1 ? 1 : 0) + (o2 ? 1 : 0)
            }
            return BigNum(r)
        }

        static func * (lhs: BigNum, rhs: BigNum) -> BigNum {
            let m = lhs.words.count, n = rhs.words.count
            var r = [UInt64](repeating: 0, count: m + n)
            for i in 0..<m {
                var carry: UInt64 = 0
                for j in 0..<n {
                    let (hi, lo) = lhs.words[i].multipliedFullWidth(by: rhs.words[j])
                    let (s1, o1) = lo.addingReportingOverflow(r[i + j])
                    let (s2, o2) = s1.addingReportingOverflow(carry)
                    r[i + j] = s2
                    carry = hi + (o1 ? 1 : 0) + (o2 ? 1 : 0)
                }
                r[i + n] = carry
            }
            return BigNum(r)
        }

        // MARK: Shifts

        func shiftLeft(_ n: Int) -> BigNum {
            if n == 0 { return self }
            let ws = n / 64, bs = n % 64
            let cnt = words.count + ws + (bs > 0 ? 1 : 0)
            var r = [UInt64](repeating: 0, count: cnt)
            if bs == 0 {
                for i in 0..<words.count { r[i + ws] = words[i] }
            } else {
                for i in 0..<words.count {
                    r[i + ws] |= words[i] << bs
                    r[i + ws + 1] |= words[i] >> (64 - bs)
                }
            }
            return BigNum(r)
        }

        func shiftRight(_ n: Int) -> BigNum {
            let ws = n / 64, bs = n % 64
            if ws >= words.count { return .zero }
            let cnt = words.count - ws
            var r = [UInt64](repeating: 0, count: cnt)
            if bs == 0 {
                for i in 0..<cnt { r[i] = words[i + ws] }
            } else {
                for i in 0..<cnt {
                    r[i] = words[i + ws] >> bs
                    if i + ws + 1 < words.count { r[i] |= words[i + ws + 1] << (64 - bs) }
                }
            }
            return BigNum(r)
        }
    }
}
