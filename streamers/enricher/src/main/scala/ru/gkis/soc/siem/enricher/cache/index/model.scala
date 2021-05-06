package ru.gkis.soc.siem.enricher.cache.index

import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.model._

import java.time.{Instant, ZoneId, ZonedDateTime}
import java.time.temporal.ChronoField

sealed trait ObjectType

case object TFile extends ObjectType

case object TProcess extends ObjectType

case object TProtocol extends ObjectType

case class Aux[T](values: Set[T])

/**
 *
 * @param from
 * @param to
 * @param daysWork
 * @param daysWeekend
 * @param isCalendar - is working hours is "proizvodstvennyy kalendar'" or not
 */
case class Schedule(from: Int, to: Int, daysWork: Int, daysWeekend: Int, isCalendar: Boolean) {
    private[this] def checkTime(secondsOfDay: Int): Boolean = {
        // No access time limitations
        if (from == 0 && to == 0) {
            true
        } else {
            secondsOfDay >= from && secondsOfDay <= to
        }
    }

    private[this] def checkAgainstCalendar(eventTime: ZonedDateTime, pk: ProductionCalendar): Boolean = {
        pk.isWorkingDay(eventTime)
    }

    //TODO: Add support correct calculation for 2/2 and like that
    private[this] def checkIsDayWorking(eventTime: ZonedDateTime): Boolean = {
        if (daysWork + daysWeekend == 7) {
            val dayOfWeek = eventTime.get(ChronoField.DAY_OF_WEEK)
            dayOfWeek <= daysWork
        } else {
            false
        }
    }

    def check(eventTime: Long, pk: ProductionCalendar): Boolean = {
        val time: ZonedDateTime = Instant.ofEpochSecond(eventTime).atZone(ZoneId.of("UTC"))

        val secondsOfDay = time.get(ChronoField.SECOND_OF_DAY)

        if (isCalendar) {
            checkAgainstCalendar(time, pk) && checkTime(secondsOfDay)
        } else {
            checkIsDayWorking(time) && checkTime(secondsOfDay)
        }
    }
}

case class ScheduleGroup(intervals: Set[Schedule])

case class Subject(org: String, login: Option[String], startWork: Long, schedule: ScheduleGroup, domain: Option[String])

case class Object(tp: ObjectType, name: Option[String], path: Option[String], port: Option[Int])

case class Location(hostname: Option[String], ip: Option[String])

case class Rule[K, V](id: Long,
                      tp: access.RuleType,
                      subj: Subject,
                      obj: Option[Object],
                      source: Option[Location],
                      destination: Option[Location],
                      schedule: ScheduleGroup,
                      aux1: Option[Aux[K]],
                      aux2: Option[Aux[V]],
                      result: access.RuleResult)

trait Spec {
    type Node
    type RuleKey
    type RuleValue
    def path: DecisionPath[Node]
    def rule: Rule[RuleKey, RuleValue]
}
case class RuleSpec[T, K, V](path: DecisionPath[T], rule: Rule[K, V]) extends Spec {
    override type Node = T
    override type RuleKey = K
    override type RuleValue = V
}

trait Node {
    type Inner
}
case class PathNode[T](key: Option[T], selector: Option[AnyRef] = None) extends Node {
    override type Inner = T
}
