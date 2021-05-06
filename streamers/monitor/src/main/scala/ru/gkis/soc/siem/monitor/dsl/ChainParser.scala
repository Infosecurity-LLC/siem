package ru.gkis.soc.siem.monitor.dsl

import org.apache.spark.rdd.RDD
import org.json4s._
import org.json4s.jackson.JsonMethods
import ru.gkis.soc.siem.model.{Chain, ChainEvent}
import ru.gkis.soc.siem.monitor.alias.Value

import scala.concurrent.duration._

trait ChainParser {

    implicit class ChainParser(rdd: RDD[ChainEvent]) {
        def parse: RDD[(String, Iterable[Value])] =
            rdd.mapPartitions(_.map { event =>
                implicit val formats: DefaultFormats = org.json4s.DefaultFormats
                val parsed = JsonMethods.parse(event.chain)
                val keys = parsed.extract[Map[String, Any]].keys.filterNot(_ == "number")
                    .map(key => key -> (parsed \ key).extract[Chain])
                    .toList
                    .sortBy { case (_, chain) => -chain.number }
                    .map { case (key, chain) => key -> chain.rt }
                event.getCollector.organization ->
                    (keys ++ Iterable(event.getCollector.organization -> event.eventTime.seconds.toMicros))
            }, preservesPartitioning = true)
    }

}
