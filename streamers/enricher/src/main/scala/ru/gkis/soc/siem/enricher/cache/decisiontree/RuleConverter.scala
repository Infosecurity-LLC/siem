package ru.gkis.soc.siem.enricher.cache.decisiontree

import ru.gkis.soc.siem.model.access.{Host, Organization, RuleObject, RuleType, WindowsLogon, Rule => AccessRule, Schedule => AccessSchedule, ScheduleGroup => AccessScheduleGroup, Subject => AccessSubject}

import java.time.ZoneOffset

trait RuleConverter[T] {
    def convert(src: AccessRule): T
}

object RuleConverter {

    def apply[A](implicit mapper: RuleConverter[A]): RuleConverter[A] = mapper

    object ops {

        def convert[A: RuleConverter](a: AccessRule): A = RuleConverter[A].convert(a)

        def convertAll[A: RuleConverter](a: List[AccessRule]): List[A] = a.map(RuleConverter[A].convert)

        implicit class MapOps[A: RuleConverter](a: AccessRule) {
            def convert = RuleConverter[A].convert(a)
        }

        implicit class MapAllOps[A: RuleConverter](a: List[AccessRule]) {
            def convertAll = a.map(RuleConverter[A].convert)
        }

    }

     def canConvertToIntStringRule(rt: RuleType): RuleConverter[Rule[Int, String]] = /*rt match {
        case WindowsLogon => {*/
        new RuleConverter[Rule[Int, String]] {
            def convert(src: AccessRule) = src match {
                case AccessRule(id, subject, source, destination, obj, result, _, tpe, scheduleGroup, aux1, aux2) =>
                    Rule(
                        id = id,
                        tp = tpe,
                        subj = convertSubject(subject, scheduleGroup),
                        obj = obj.map(convertType),
                        source = source.map(convertHost),
                        destination = destination.map(convertHost),
                        schedule = convertSchedule(scheduleGroup.schedule),
                        aux1 = aux1.map(a => Aux(a.split(';').map(_.toInt).toSet)),
                        aux2 = aux2.map(a => Aux(Set(a))),
                        result = result
                    )
            }
    }

    private[this] def convertHost(host: Host): Location = {
        Location(host.hostName, host.hostIp)
    }

    private[this] def convertType(obj: RuleObject): Object = {
        val tpe = obj.objType match {
            case "file" =>
                TFile
            case "process" =>
                TProcess
            case "port" =>
                TPort
            case other =>
                throw new RuntimeException(s"Unknown $other rule type")
        }

        Object(tpe, obj.objName, obj.objPath, obj.port)
    }

    private[this] def convertSchedule(schedule: List[AccessSchedule]): ScheduleGroup = ScheduleGroup(
        schedule.map {
            case AccessSchedule(_, _, timeFrom, timeTo, daysWork, daysWeekend, isCalendar) =>
                Schedule(timeFrom.toSecondOfDay, timeTo.toSecondOfDay, daysWork, daysWeekend, isCalendar)
        }.toSet
    )

    private[this] def convertSubject(subject: AccessSubject, sg: AccessScheduleGroup): Subject = {
        Subject(
            org = subject.organization.shortName,
            login = subject.login,
            startWork = subject.startWork.toInstant(ZoneOffset.UTC).toEpochMilli,
            schedule = convertSchedule(sg.schedule),
            domain = subject.userDomain
        )
    }
}
