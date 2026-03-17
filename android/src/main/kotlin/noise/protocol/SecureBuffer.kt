package noise.protocol

import java.nio.ByteBuffer

class SecureBuffer private constructor(private val buffer: ByteBuffer) {
    val size: Int get() = buffer.capacity()

    fun copyBytes(): ByteArray {
        val dst = ByteArray(size)
        buffer.clear()
        buffer.get(dst)
        return dst
    }

    fun zero() {
        buffer.clear()
        for (i in 0 until size) {
            buffer.put(i, 0)
        }
    }

    inline fun <R> use(block: (SecureBuffer) -> R): R {
        try {
            return block(this)
        } finally {
            zero()
        }
    }

    companion object {
        fun allocate(size: Int): SecureBuffer {
            return SecureBuffer(ByteBuffer.allocateDirect(size))
        }

        fun wrap(data: ByteArray): SecureBuffer {
            val buf = ByteBuffer.allocateDirect(data.size)
            buf.put(data)
            return SecureBuffer(buf)
        }
    }
}
