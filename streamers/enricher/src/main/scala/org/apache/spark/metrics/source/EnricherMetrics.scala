package org.apache.spark.metrics.source

import com.codahale.metrics.MetricRegistry
import ru.gkis.soc.siem.enricher.InternalStatistics
import ru.gkis.soc.siem.enricher.cache.CacheStatus


class EnricherMetrics(registry: MetricRegistry, metricSystemNamespace: String) extends Metrics {
    override val sourceName: String = "EnrichmentMetrics"

    override val metricRegistry: MetricRegistry = registry

    def updateClientStats(stats: Array[InternalStatistics],
                          ipGeoCache: CacheStatus,
                          loginCache: CacheStatus): Unit = {
        stats.foreach { stat =>
            add(s"${key(stat)}.enricher.events.processed.count", stat.eventCount)
            set(s"${key(stat)}.enricher.cache.geoip.size", ipGeoCache.size)
            set(s"${key(stat)}.enricher.cache.geoip.lastupdate", ipGeoCache.lastUpdated)
            add(s"${key(stat)}.enricher.cache.geoip.hit", stat.geoIpCache.hit)
            add(s"${key(stat)}.enricher.cache.geoip.miss", stat.geoIpCache.miss)
            set(s"${key(stat)}.enricher.cache.login.size", loginCache.size)
            set(s"${key(stat)}.enricher.cache.login.lastupdate", loginCache.lastUpdated)
            add(s"${key(stat)}.enricher.cache.login.hit", stat.loginCache.hit)
            add(s"${key(stat)}.enricher.cache.login.miss", stat.geoIpCache.miss)
        }
    }

    private def key(sc: InternalStatistics): String = {
        s"$metricSystemNamespace" +
            s".$sourceName" +
            s".${sc.organization}" +
            s".${replaceInvalidCharacters(sc.product)}"
    }
}