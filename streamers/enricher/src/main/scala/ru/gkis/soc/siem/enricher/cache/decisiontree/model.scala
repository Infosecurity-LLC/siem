package ru.gkis.soc.siem.enricher.cache.decisiontree

import org.json4s.DefaultFormats
import org.json4s.jackson.Serialization.write
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.model.access.{RuleResult, RuleType}

import java.time.{Instant, ZoneId, ZonedDateTime}
import java.time.temporal.ChronoField

sealed trait ObjectType

case object TFile extends ObjectType

case object TProcess extends ObjectType

case object TPort extends ObjectType

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

case class Rule[T, K](id: Long,
                      tp: RuleType,
                      subj: Subject,
                      obj: Option[Object],
                      source: Option[Location],
                      destination: Option[Location],
                      schedule: ScheduleGroup,
                      aux1: Option[Aux[T]],
                      aux2: Option[Aux[K]],
                      result: RuleResult)

case class RuleSpec[T, K](path: List[Option[String]], selector: String, rule: Rule[T, K]) {
    override def toString: String = {
        val (level, pathTree) = path.foldLeft((0, "")) { case ((level, acc), next) =>
            (level + 1, s"$acc" + "  " * level + s"${next.getOrElse("*")} ->\n")
        }

        s"$pathTree" + "  " * (level + 1) + s"$selector -> ${rule.id}"
    }
}

case class RuleSpec2[T](path: List[T], ruleId: Long)

case class PathNode(key: String, selector: Option[String])

object PathNode {
    def apply(key: String): PathNode = {
        new PathNode(key, None)
    }

    def some(key: String): Option[PathNode] = {
        Some(PathNode(key, None))
    }
}

private[decisiontree] class DecisionTreeNode(var next: Option[DMap], var rules: Map[String, Long]) extends Serializable {
    override def toString: String = {
        implicit val formats: DefaultFormats = DefaultFormats
        write(this)
    }
}

private[decisiontree] class DecisionTreeNode2[T](var next: Option[DMap2[T]], var rules: Set[Long]) extends Serializable {
    override def toString: String = {
        implicit val formats: DefaultFormats = DefaultFormats
        write(this)
    }
}

private[decisiontree] case class Decision(selector: Option[String], node: Option[DecisionTreeNode]) {
    override def toString: String = {
        implicit val formats: DefaultFormats = DefaultFormats
        write(this)
    }
}