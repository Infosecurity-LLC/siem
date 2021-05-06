package ru.gkis.soc.siem.enricher.cache.index

import ru.gkis.soc.siem.model.access.{Host, Organization, RuleObject, Rule => AccessRule, Schedule => AccessSchedule, ScheduleGroup => AccessScheduleGroup, Subject => AccessSubject}

import java.time.ZoneOffset

object RuleConverter {

    def convert[K, V](ar: AccessRule, aux1: Option[Aux[K]] = None, aux2: Option[Aux[V]] = None): Rule[K, V] = ar match {
        case AccessRule(id, subject, source, destination, obj, result, _, tpe, scheduleGroup, _, _) =>
            Rule[K, V](
                id = id,
                tp = tpe,
                subj = convert(subject.organization, subject, scheduleGroup),
                obj = obj.map(convert),
                source = source.map(convert),
                destination = destination.map(convert),
                schedule = convert(scheduleGroup.schedule),
                aux1 = aux1,
                aux2 = aux2,
                result = result
            )
    }

    private[this] def convert(host: Host): Location = {
        Location(host.hostName, host.hostIp)
    }

    private[this] def convert(obj: RuleObject): Object = {
        val tpe = obj.objType match {
            case "file" =>
                TFile
            case "process" =>
                TProcess
            case "protocol" =>
                TProtocol
            case other =>
                throw new RuntimeException(s"Unknown $other rule type")
        }

        Object(tpe, obj.objName, obj.objPath, obj.port)
    }

    private[this] def convert(schedule: List[AccessSchedule]): ScheduleGroup = ScheduleGroup(
        schedule.map {
            case AccessSchedule(_, _, timeFrom, timeTo, daysWork, daysWeekend, isCalendar) =>
                Schedule(timeFrom.toSecondOfDay, timeTo.toSecondOfDay, daysWork, daysWeekend, isCalendar)
        }.toSet
    )

    private[this] def convert(organization: Organization, subject: AccessSubject, sg: AccessScheduleGroup): Subject = {
        Subject(
            org = organization.shortName,
            login = subject.login,
            startWork = subject.startWork.toInstant(ZoneOffset.UTC).toEpochMilli,
            schedule = convert(sg.schedule),
            domain = subject.userDomain
        )
    }
}
