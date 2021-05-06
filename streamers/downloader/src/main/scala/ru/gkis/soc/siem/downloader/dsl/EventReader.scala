package ru.gkis.soc.siem.downloader.dsl

import org.apache.spark.broadcast.Broadcast
import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.io.hbase.EventTypeConfig
import scalapb.GeneratedMessage

trait EventReader {

    implicit class EventReader(rdd: RDD[(String, Array[Byte])]) {

        def deserialize(eventTypeConfigs: Broadcast[Map[String, EventTypeConfig]] ): RDD[GeneratedMessage] =
            rdd.mapPartitions(it => it.map(evt => eventTypeConfigs.value(evt._1).spawner.parseFrom(evt._2)), preservesPartitioning = true)

    }

}
