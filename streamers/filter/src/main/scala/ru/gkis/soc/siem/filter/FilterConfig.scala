package ru.gkis.soc.siem.filter

import com.typesafe.config.Config

import scala.concurrent.duration.FiniteDuration

trait FilterConfig {

    import scala.compat.java8.DurationConverters._

    protected val appConf: Config

    private val basic = appConf.getConfig("app.filter")

    val scriptsUpdateInterval: FiniteDuration = basic.getDuration("cache.scripts.updateInterval").toScala

}

