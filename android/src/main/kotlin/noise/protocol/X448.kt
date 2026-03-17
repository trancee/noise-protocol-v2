package noise.protocol

import java.math.BigInteger

/**
 * Pure X448 Diffie-Hellman implementation per RFC 7748.
 * Field: GF(p) where p = 2^448 - 2^224 - 1 (Goldilocks prime).
 * Uses BigInteger for field arithmetic to ensure correctness.
 */
object X448 {

    private val P: BigInteger = BigInteger.TWO.pow(448) -
            BigInteger.TWO.pow(224) - BigInteger.ONE

    private val A24: BigInteger = BigInteger.valueOf(39081) // (156326 - 2) / 4

    fun scalarMult(k: ByteArray, u: ByteArray): ByteArray {
        val scalar = decodeScalar448(k)
        val uCoord = decodeUCoordinate(u)

        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = uCoord
        var z3 = BigInteger.ONE
        val x1 = uCoord

        var swap = 0
        for (t in 447 downTo 0) {
            val kt = (scalar[t / 8].toInt() and 0xFF shr (t % 8)) and 1
            swap = swap xor kt
            if (swap != 0) {
                val tx = x2; x2 = x3; x3 = tx
                val tz = z2; z2 = z3; z3 = tz
            }
            swap = kt

            val a = (x2 + z2).mod(P)
            val aa = (a * a).mod(P)
            val b = (x2 - z2).mod(P)
            val bb = (b * b).mod(P)
            val e = (aa - bb).mod(P)
            val c = (x3 + z3).mod(P)
            val d = (x3 - z3).mod(P)
            val da = (d * a).mod(P)
            val cb = (c * b).mod(P)

            x3 = ((da + cb) * (da + cb)).mod(P)
            z3 = (x1 * ((da - cb) * (da - cb)).mod(P)).mod(P)
            x2 = (aa * bb).mod(P)
            z2 = (e * (aa + A24 * e)).mod(P)
        }

        if (swap != 0) {
            val tx = x2; x2 = x3; x3 = tx
            val tz = z2; z2 = z3; z3 = tz
        }

        val result = (x2 * z2.modInverse(P)).mod(P)
        return encodeUCoordinate(result)
    }

    private fun decodeScalar448(k: ByteArray): ByteArray {
        val scalar = k.copyOf(56)
        scalar[0] = (scalar[0].toInt() and 252).toByte()
        scalar[55] = (scalar[55].toInt() or 128).toByte()
        return scalar
    }

    private fun decodeUCoordinate(u: ByteArray): BigInteger {
        // Little-endian 56 bytes, reduced mod p
        val le = u.copyOf(56)
        // Convert to big-endian for BigInteger
        val be = ByteArray(57) // extra zero byte to ensure positive
        for (i in 0 until 56) be[56 - i] = le[i]
        return BigInteger(be).mod(P)
    }

    private fun encodeUCoordinate(fe: BigInteger): ByteArray {
        val bytes = ByteArray(56)
        val value = fe.mod(P)
        val be = value.toByteArray()
        // BigInteger's toByteArray is big-endian, may have leading zeros
        // Convert to little-endian 56 bytes
        val start = if (be.size > 56) be.size - 56 else 0
        for (i in start until be.size) {
            bytes[be.size - 1 - i] = be[i]
        }
        return bytes
    }
}
