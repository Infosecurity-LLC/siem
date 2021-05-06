package ru.gkis.soc.siem.router

import com.typesafe.config.Config

trait RouterConfig {
    import scala.collection.JavaConversions._

    protected val appConf: Config
    private val basic = appConf.getConfig("app.router")

    val garbagePercentage: Int = basic.getInt("garbage.percentage")
    val dropDevTypes: Set[String] = basic.getStringList("garbage.drop").toSet
}