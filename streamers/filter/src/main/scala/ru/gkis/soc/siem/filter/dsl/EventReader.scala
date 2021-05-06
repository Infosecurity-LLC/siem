package ru.gkis.soc.siem.filter.dsl

import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.spark.rdd.RDD
import org.json4s._
import org.json4s.jackson.JsonMethods

trait EventReader {

    implicit class EventReader(rdd: RDD[ConsumerRecord[String, String]]) extends Serializable {

        def deserialize(): RDD[Map[String, Any]] = {
            rdd.mapPartitions(
                _.map(evt => {
                        implicit val formats: DefaultFormats = org.json4s.DefaultFormats
                        JsonMethods.parse(evt.value()).extract[Map[String, Any]]
                    }
                ), preservesPartitioning = true)
        }

    }

}
