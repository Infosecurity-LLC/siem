package ru.gkis.soc.siem.enricher.cache.radixtree

import java.net.InetAddress

object RichRadixTree {

    implicit class RichRadixTree[KV](tree: AbstractRadixTree[KV]) {
        def find(key: KV): Option[Long] = {
            val result = tree.selectValue(key)

            if (result == AbstractRadixTree.NO_VALUE) {
                None
            } else {
                Some(result)
            }
        }

        def find(ip: String): Option[Long] = {
            val result = tree.selectValue(ip)

            if (result == AbstractRadixTree.NO_VALUE) {
                None
            } else {
                Some(result)
            }
        }

        def find(ip: InetAddress): Option[Long] = {
            val result = tree.selectValue(ip)

            if (result == AbstractRadixTree.NO_VALUE) {
                None
            } else {
                Some(result)
            }
        }
    }

}
