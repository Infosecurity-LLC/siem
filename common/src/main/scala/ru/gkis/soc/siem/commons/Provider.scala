package ru.gkis.soc.siem.commons

import java.util.concurrent.ConcurrentHashMap
import scala.language.postfixOps

abstract class Provider[K, V] {

    import scala.compat.java8.FunctionConverters._

    private val cache = new ConcurrentHashMap[K, V]()

    protected def get(key: K, spawner: K => V): V = {
        cache.computeIfAbsent(key, (spawner(_)) asJava)
    }

}
