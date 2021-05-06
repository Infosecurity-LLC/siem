package ru.gkis.soc.siem.enricher.dsl

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.enricher.{InternalSocEvent, InternalStatistics, Split}
import ru.gkis.soc.siem.model.SocEvent

trait Splitter {

    implicit class Splitter(rdd: RDD[SocEvent]) extends Serializable {
        def split: RDD[Split] = {
            rdd.mapPartitions(it => {
                it.flatMap { event =>
                    Iterator(
                        InternalSocEvent(event),
                        InternalStatistics(event)
                    )
                }
            })
        }
    }

}
