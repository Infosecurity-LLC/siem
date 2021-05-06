package ru.gkis.soc.siem.enricher

import com.typesafe.config.Config

import scala.concurrent.duration.FiniteDuration

trait EnricherConfig {

    import scala.compat.java8.DurationConverters._

    protected val appConf: Config
    private val basic = appConf.getConfig("app.enricher")

    val geoIpCacheUpdateInterval: FiniteDuration = basic.getDuration("cache.geoIp.updateInterval").toScala
    val scheduleCacheUpdateInterval: FiniteDuration = basic.getDuration("cache.schedule.updateInterval").toScala
    val loginsCacheUpdateInterval: FiniteDuration = basic.getDuration("cache.logins.updateInterval").toScala
    val destinationHostRulesCacheUpdateInterval: FiniteDuration = basic.getDuration("cache.destinationHostRules.updateInterval").toScala
    val windowsObjectAccessRulesUpdateInterval: FiniteDuration = basic.getDuration("cache.windowsObjectAccessRules.updateInterval").toScala
    val vpnLogonRulesUpdateInterval: FiniteDuration = basic.getDuration("cache.vpnLogonRules.updateInterval").toScala
    val firewallConnectionRulesUpdateInterval: FiniteDuration = basic.getDuration("cache.firewallConnectionRules.updateInterval").toScala
    val proizvodstvennyyKalendarUpdateInterval: FiniteDuration = basic.getDuration("cache.proizvodstvennyyKalendar.updateInterval").toScala
}
