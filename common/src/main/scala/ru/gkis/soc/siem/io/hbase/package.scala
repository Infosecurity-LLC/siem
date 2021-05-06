package ru.gkis.soc.siem.io

package object hbase {

    type HBaseColumn = (Array[Byte], Array[Byte])

    def longToBytes(value: Long): Array[Byte] = {
        Array(
            (value      ).toByte,
            (value >>  8).toByte,
            (value >> 16).toByte,
            (value >> 24).toByte,
            (value >> 32).toByte,
            (value >> 40).toByte,
            (value >> 48).toByte,
            (value >> 56).toByte
        )
    }

    def bytesToLong(value: Array[Byte]): Long = {
         value(7).toLong         << 56 |
        (value(6).toLong & 0xff) << 48 |
        (value(5).toLong & 0xff) << 40 |
        (value(4).toLong & 0xff) << 32 |
        (value(3).toLong & 0xff) << 24 |
        (value(2).toLong & 0xff) << 16 |
        (value(1).toLong & 0xff) <<  8 |
        (value(0).toLong & 0xff)
    }

}
