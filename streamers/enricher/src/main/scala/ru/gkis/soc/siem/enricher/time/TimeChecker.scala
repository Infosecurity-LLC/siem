package ru.gkis.soc.siem.enricher.time

import java.time._

import ru.gkis.soc.siem.model.DomainLogin
import ru.gkis.soc.siem.model.access.DomainSchedule

import scala.concurrent.duration._

case class TimeChecker(origin: Long, holidays: List[LocalDate]) extends Serializable {

    private lazy val ldt = LocalDateTime.ofInstant(Instant.ofEpochSecond(origin), ZoneOffset.UTC)

    def isTimeAllowed(schedule: List[DomainSchedule]): Boolean = {
        val eventTime = ldt.getHour.hours.toMinutes + ldt.getMinute
        schedule.exists(_.period.isBetween(eventTime.toShort))
    }

    def isWorkingDay(login: DomainLogin, schedule: List[DomainSchedule]): Boolean =
        schedule.exists(isWorkingDay(login.startWork, _))

    private def isStandard(daysWork: Byte, daysWeekend: Byte): Boolean = daysWork == 5 && daysWeekend == 2

    private def isFullWeek(daysWork: Byte): Boolean = daysWork == 7

    private def isPlainWeekend: Boolean = {
        ldt.getDayOfWeek match {
            case DayOfWeek.SATURDAY | DayOfWeek.SUNDAY => true
            case _ => false
        }
    }

    private def isWorkingDay(startWork: LocalDateTime, schedule: DomainSchedule) = {
        isFullWeek(schedule.daysWork) || (if (isStandard(schedule.daysWork, schedule.daysWeekend))
            !isPlainWeekend && !holidays.exists(_.isEqual(ldt.toLocalDate))
        else {
            val totalDays = ldt.toLocalDate.toEpochDay - startWork.toLocalDate.toEpochDay
            val daysWithoutHolidays = if (schedule.isCalendar) totalDays - holidays.count(_.isBefore(ldt.toLocalDate))
            else totalDays
            val result = Math.floorMod(daysWithoutHolidays, schedule.daysWeekend + schedule.daysWork)
            result >= 0 && result < schedule.daysWork
        })

    }

}
