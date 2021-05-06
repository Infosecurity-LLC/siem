package ru.gkis.soc.siem.monitor.dsl

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.model.ChainEvent

trait ChainReader {

    implicit class ChainReader(rdd: RDD[Array[Byte]]) {
        def deserialize: RDD[ChainEvent] =
            rdd.mapPartitions(_.map(bytes => ChainEvent.parseFrom(bytes)), preservesPartitioning = true)
    }

}
