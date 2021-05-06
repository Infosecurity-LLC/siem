package ru.gkis.soc.siem.enricher.cache

import java.time.{Instant, LocalDate, LocalDateTime, ZoneOffset}

import ru.gkis.soc.siem.model.access.{DomainSchedule, Schedule}
import ru.gkis.soc.siem.model.{Period, access}

import scala.collection.immutable.IntMap
import scala.concurrent.duration._

object ScheduleCache {

    def apply(items: List[Schedule]): ScheduleCache = {
        val schedule: IntMap[List[DomainSchedule]] = items.groupBy(_.groupId).flatMap {
            case (idx, schedule) => IntMap((idx, schedule.flatMap(breakPeriod)))
        }(collection.breakOut)

        new ScheduleCache(schedule)
    }

    private[this] def breakPeriod(schedule: Schedule): List[DomainSchedule] = {
        val start = schedule.timeFrom
        val end = schedule.timeTo
        val periods = if (start.isAfter(end))
            List(Period(
                (start.getHour.hours.toMinutes + start.getMinute).toShort,
                24.hour.toMinutes.toShort),
                Period(0, (end.getHour.hours.toMinutes + end.getMinute).toShort))
        else if (start == end)
            List(Period(0, 24.hour.toMinutes.toShort))
        else List(Period(
            (start.getHour.hours.toMinutes + start.getMinute).toShort,
            (end.getHour.hours.toMinutes + end.getMinute).toShort))
        periods.map(access.DomainSchedule(_, schedule.daysWork, schedule.daysWeekend, schedule.isCalendar))
    }
}

case class ScheduleCache(schedule: IntMap[List[DomainSchedule]],
                         lastUpdated: Long = Instant.now().getEpochSecond) extends CacheStatus {

    def find(scheduleGroupId: Int): List[DomainSchedule] = schedule.get(scheduleGroupId).toList.flatten

    override def size: Long = schedule.size
}

