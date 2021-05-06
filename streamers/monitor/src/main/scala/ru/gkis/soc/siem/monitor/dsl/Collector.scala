package ru.gkis.soc.siem.monitor.dsl

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.monitor.alias.Value
import ru.gkis.soc.siem.monitor.stats.{CollectorNames, Stats}


trait Collector {

    implicit class Collector(rdd: RDD[(String, Iterable[Value])]) {
        def stats: RDD[Iterable[Stats]] =
            rdd.mapPartitions(_.map { case (org, chains) =>
                chains
                    .zip(chains.tail)
                    .groupBy { case (to, from) => CollectorNames(from._1, to._1) }
                    .map { case (names, stats) =>
                        val averageDelay = stats.foldLeft(0L) {
                            case (acc, ((_, to), (_, from))) => acc + (to - from) } / Math.max(stats.size, 1)
                        Stats(org, names.nameIn, names.nameOut, averageDelay)
                    }
            })
    }

}
