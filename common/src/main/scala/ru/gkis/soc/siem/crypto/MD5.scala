package ru.gkis.soc.siem.crypto

import java.nio.charset.StandardCharsets

import gnu.crypto.util.Util

object MD5 {

    def apply(args: String*): String = {
        val md5 = new gnu.crypto.hash.MD5()
        args
            .map(_.getBytes(StandardCharsets.UTF_8))
            .foreach(bytes => md5.update(bytes, 0, bytes.length))
        Util.toString(md5.digest()).toLowerCase
    }

}
