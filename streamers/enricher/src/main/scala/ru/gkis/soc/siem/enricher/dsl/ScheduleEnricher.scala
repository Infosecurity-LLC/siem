package ru.gkis.soc.siem.enricher.dsl

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.enricher.cache.{LoginsCache, ScheduleCache}
import ru.gkis.soc.siem.enricher.time.TimeChecker
import ru.gkis.soc.siem.io.spark.EditableBroadcast
import ru.gkis.soc.siem.model.SocEvent

trait ScheduleEnricher {

    implicit class ScheduleEnricher(rdd: RDD[SocEvent]) extends Serializable {

        def enrichWorkSchedule(scheduleCache: EditableBroadcast[ScheduleCache], logins: EditableBroadcast[LoginsCache]): RDD[SocEvent] = {
            rdd.mapPartitions(_.map {
                case event if isScheduleEnrichmentPossible(event) =>
                    val subject = event.getSubject
                    (for {
                        login <- subject.name
                        domain <- subject.domain
                        org = event.getCollector.organization
                        login <- logins.value.find(org.toLowerCase, domain.toLowerCase, login.toLowerCase)
                    } yield {
                        val schedule = scheduleCache.value.find(login.groupId)
                        //TODO: We create that object on every message. Use ProizvodstvennyyKalendar here!
                        val timeChecker = TimeChecker(event.eventTime, Nil) //TODO: Add holidays calendar
                        val isWorkingDay = timeChecker.isWorkingDay(login, schedule)
                        val isTimeAllowed = timeChecker.isTimeAllowed(schedule)

                        event.update(
                            _.subject.enrichment.isTimeAllowed := isTimeAllowed,
                            _.subject.enrichment.isWorkingDay := isWorkingDay
                        )
                    }) match {
                        case None =>
                            event
                        case Some(result) =>
                            result
                    }
                case event =>
                    event
            }, preservesPartitioning = true)
        }
    }

    def isScheduleEnrichmentPossible(event: SocEvent): Boolean =
        event.getSubject.category.isaccount && event.getEventSource.title.toLowerCase.contains("windows")

}

object ScheduleEnricher extends ScheduleEnricher with Serializable

