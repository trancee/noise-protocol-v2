package noise.protocol

import java.nio.ByteBuffer

/**
 * A secure wrapper around a direct [ByteBuffer][java.nio.ByteBuffer] for holding
 * sensitive cryptographic key material.
 *
 * Uses direct (off-heap) memory allocation so that the JVM garbage collector is less
 * likely to copy the data around in memory. Provides an explicit [zero] method to
 * overwrite the buffer contents when the key material is no longer needed.
 *
 * Typical usage with the [use] pattern:
 * ```kotlin
 * SecureBuffer.wrap(secretBytes).use { buf ->
 *     // work with buf.copyBytes()
 * } // buffer is automatically zeroed on exit
 * ```
 *
 * @see KeyPair
 */
class SecureBuffer private constructor(private val buffer: ByteBuffer) {
    /** The capacity of this buffer in bytes. */
    val size: Int get() = buffer.capacity()

    /**
     * Copies the buffer contents into a new [ByteArray].
     *
     * @return A new byte array containing a snapshot of the buffer data.
     */
    fun copyBytes(): ByteArray {
        val dst = ByteArray(size)
        buffer.clear()
        buffer.get(dst)
        return dst
    }

    /**
     * Overwrites all bytes in the buffer with zeros, securely erasing the contents.
     *
     * Should be called as soon as the key material is no longer needed.
     */
    fun zero() {
        buffer.clear()
        for (i in 0 until size) {
            buffer.put(i, 0)
        }
    }

    /**
     * Executes the given [block] with this buffer and then automatically zeroes
     * the buffer contents, even if [block] throws an exception.
     *
     * @param R The return type of the block.
     * @param block The function to execute with this [SecureBuffer].
     * @return The result of [block].
     */
    inline fun <R> use(block: (SecureBuffer) -> R): R {
        try {
            return block(this)
        } finally {
            zero()
        }
    }

    companion object {
        /**
         * Allocates a new [SecureBuffer] of the given [size] backed by direct memory.
         *
         * @param size The number of bytes to allocate.
         * @return A new zeroed [SecureBuffer].
         */
        fun allocate(size: Int): SecureBuffer {
            return SecureBuffer(ByteBuffer.allocateDirect(size))
        }

        /**
         * Creates a new [SecureBuffer] and copies the contents of [data] into direct memory.
         *
         * @param data The byte array to wrap.
         * @return A new [SecureBuffer] containing a copy of [data].
         */
        fun wrap(data: ByteArray): SecureBuffer {
            val buf = ByteBuffer.allocateDirect(data.size)
            buf.put(data)
            return SecureBuffer(buf)
        }
    }
}
