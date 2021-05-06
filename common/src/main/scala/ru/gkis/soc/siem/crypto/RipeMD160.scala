package ru.gkis.soc.siem.crypto

import java.nio.charset.StandardCharsets

import gnu.crypto.util.Util

object RipeMD160 {

    def apply(args: String*): String = {
        val ripeMd = new gnu.crypto.hash.RipeMD160
        args
            .map(_.getBytes(StandardCharsets.UTF_8))
            .foreach(bytes => ripeMd.update(bytes, 0, bytes.length))
        Util.toString(ripeMd.digest()).toLowerCase
    }

}
