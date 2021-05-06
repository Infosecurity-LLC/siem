package ru.gkis.soc.siem.enricher.dsl

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.enricher.InternalStatistics

trait StatisticsCollector {

    implicit class Sender(rdd: RDD[InternalStatistics]) extends Serializable {
        private def agg(combined: InternalStatistics, stats: InternalStatistics): InternalStatistics = {
            combined.copy(
                geoIpCache = combined.geoIpCache + stats.geoIpCache,
                loginCache = combined.loginCache + stats.loginCache,
                eventCount = combined.eventCount + stats.eventCount
            )
        }

        def summarize: Array[InternalStatistics] = {
            rdd
                .map(stats => stats.key -> stats)
                .reduceByKey(agg)
                .map(_._2)
                .collect()
        }
    }

}
