package org.apache.spark.metrics.source

import com.codahale.metrics.MetricRegistry
import ru.gkis.soc.siem.router.dsl.model.Statistics

class RouterMetrics(registry: MetricRegistry, metricSystemNamespace: String) extends Metrics {
    override val sourceName: String = "RouterMetrics"

    override val metricRegistry: MetricRegistry = registry

    def updateClientStats(stats: Array[Statistics]): Unit = {
        val result = stats.reduce(_ + _)

        add(s"${key(result)}.total", result.total)
        add(s"${key(result)}.garbage", result.garbage)

        result.sent.foreach { case (topic, count) =>
            add(s"${key(result)}.$topic", count)
        }
    }

    private def key(sc: Statistics): String = {
        s"$metricSystemNamespace.$sourceName"
    }
}