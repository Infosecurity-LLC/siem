package ru.gkis.soc.siem.enricher.dsl

import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.model.SocEvent

trait EventReader {

    implicit class EventReader(rdd: RDD[ConsumerRecord[String, Array[Byte]]]) {
        def deserialize(): RDD[SocEvent] =
            rdd.mapPartitions(it =>
                it.map(evt => SocEvent.parseFrom(evt.value())),
                preservesPartitioning = true
            )

    }

}