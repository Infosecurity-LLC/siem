package ru.gkis.soc.siem.ingester.dsl

import java.time.format.DateTimeFormatter
import java.time.{Instant, LocalDateTime, ZoneId, ZoneOffset, ZonedDateTime}

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.model.{DataPayload, SocEvent}

object Transformer {

    implicit class Transformer(rdd: RDD[SocEvent]) extends Serializable {

        import ru.gkis.soc.siem.io.elastic._

        private val fieldName = "@timestamp"

        private def failOnDataAbsent: DataPayload = throw new RuntimeException("Data field cannot be null")

        private def generateTimestamp(evt: SocEvent): (String, Any) = {
            val evtTimestamp = Instant.ofEpochSecond(evt.data.getOrElse(failOnDataAbsent).time)
            fieldName -> ZonedDateTime.ofInstant(evtTimestamp, ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
        }

        def eventsToMap: RDD[Map[String, Any]] = {
            rdd.map(evt => evt.toMap + generateTimestamp(evt))
        }

    }

}
