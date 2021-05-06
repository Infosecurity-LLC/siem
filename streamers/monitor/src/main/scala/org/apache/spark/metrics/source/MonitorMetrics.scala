package org.apache.spark.metrics.source

import com.codahale.metrics.MetricRegistry
import ru.gkis.soc.siem.monitor.stats.Stats

class MonitorMetrics(registry: MetricRegistry, metricSystemNamespace: String) extends Metrics {

    override val sourceName: String = "MessageProcessingDelay"

    override val metricRegistry: MetricRegistry = registry

    def updateClientStats(stats: Array[Iterable[Stats]]): Unit = {
        stats.foreach(_.foreach(fs => set(s"${buildStats(fs)}.mean", fs.delay)))
    }

    private def buildStats(sc: Stats): String = {
        s"$metricSystemNamespace" +
            s".$sourceName" +
            s".${replaceInvalidCharacters(sc.org)}" +
            s".${replaceInvalidCharacters(sc.collectorIn)}" +
            s".${replaceInvalidCharacters(sc.collectorOut)}"
    }
}

