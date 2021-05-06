package ru.gkis.soc.siem.filter.dsl

import java.util

import org.apache.spark.rdd.RDD
import org.json4s.DefaultFormats
import org.json4s.jackson.Serialization
import ru.gkis.soc.siem.filter.{Event, Split, Statistic}

import scala.collection.JavaConverters._


trait Serializer {

    implicit class Serializer(rdd: RDD[util.List[Any]]) extends Serializable {
        def serialize: RDD[Split] = rdd.mapPartitions { iter =>

            implicit val formats: DefaultFormats = org.json4s.DefaultFormats

            def toSMap(jmap: util.HashMap[String, Any]): Map[String, Any] = {
                jmap.asScala.map {
                    case (k, v: util.HashMap[_, _]) => k -> toSMap(v.asInstanceOf[util.HashMap[String, Any]])
                    case (k, v) => k -> v
                }.toMap
            }

            val (required, filtered) = iter.partition(_.get(1).asInstanceOf[Boolean])
            required.map(elements =>
                Event(Serialization.write(toSMap(elements.get(0).asInstanceOf[util.HashMap[String, Any]])))) ++
                Iterator(Statistic(filtered.size, required.size))
        }
    }

}
