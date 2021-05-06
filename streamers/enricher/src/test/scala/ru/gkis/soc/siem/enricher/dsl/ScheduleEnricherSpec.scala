package ru.gkis.soc.siem.enricher.dsl

import java.sql.Timestamp
import java.time.{LocalDate, LocalDateTime, LocalTime}

import org.apache.spark.rdd.RDD
import org.apache.spark.streaming.{Seconds, StreamingContext}
import org.junit.runner.RunWith
import org.scalatest.{Matchers, WordSpec}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.enricher.cache.{LoginsCache, ScheduleCache}
import ru.gkis.soc.siem.io.spark.EditableBroadcast
import ru.gkis.soc.siem.model.access.Schedule
import ru.gkis.soc.siem.model.{Counterpart, DomainLogin, SocEvent}
import ru.gkis.soc.siem.spark.SharedSparkContext
import scala.concurrent.duration._

import scala.concurrent.duration._

@RunWith(classOf[JUnitRunner])
class ScheduleEnricherSpec extends WordSpec with Matchers with SharedSparkContext with Serializable {
    "ScheduleEnricher" should {
        "correct work" in new setup {

            import ScheduleEnricher._

            val event: SocEvent = defaultEvent.update(
                _.eventTime := Timestamp.valueOf(LocalDateTime.now()).getTime.millis.toSeconds
            )
            val enriched: Array[SocEvent] =
                rdd.enrichWorkSchedule(scheduleCache, loginsCache).collect()

            enriched.headOption should not be empty
            val resultEvent = enriched.head
            resultEvent.getSubject.getEnrichment.isTimeAllowed should be(Some(true))
            resultEvent.getSubject.getEnrichment.isWorkingDay should be(Some(true))
        }

    }

    @transient
    trait setup {
        val name = "name"
        val domain = "domain"
        val organization = "organization"
        val eventSource = "windows"
        val groupId = 1

        def event: SocEvent

        lazy val events: Seq[SocEvent] = Seq(event)
        lazy val rdd: RDD[SocEvent] = sc.parallelize(events, 1)
        lazy val ctx = new StreamingContext(sc, Seconds(15))

        lazy val loginsCache: EditableBroadcast[LoginsCache] = new EditableBroadcast(ctx,
            LoginsCache(Map(LoginsCache.makeKey(organization, domain, name) ->
                DomainLogin(groupId, Some(name), None, None, monitored = true, LocalDateTime.now().minusMonths(1)))),
            period = 60.seconds)
        lazy val scheduleCache: EditableBroadcast[ScheduleCache] = new EditableBroadcast(ctx,
            ScheduleCache(List(Schedule(groupId, groupId, LocalTime.of(0, 0), LocalTime.of(0, 0), 7, 0, isCalendar = true))),
            period = 60.seconds)

        val defaultEvent: SocEvent = SocEvent().update(
            _.subject.category := Counterpart.account,
            _.subject.name := name,
            _.subject.domain := domain,
            _.collector.organization := organization,
            _.eventSource.title := eventSource
        )
    }

}
