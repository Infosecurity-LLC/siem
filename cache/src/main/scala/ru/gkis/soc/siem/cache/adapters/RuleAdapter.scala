package ru.gkis.soc.siem.cache.adapters

import ru.gkis.soc.siem.model.access.{Host, Rule, RuleObject, RuleResult, RuleType, ScheduleGroup, Subject}


private[cache] case class RuleAdapter(id: Int,
                                      subject: Int,
                                      source: Option[Int],
                                      destination: Option[Int],
                                      `object`: Option[Int],
                                      result: RuleResult,
                                      usecaseId: String,
                                      `type`: RuleType,
                                      schedule: Int,
                                      aux1: Option[String],
                                      aux2: Option[String]
                                ) {
    def rule(subject: Subject, source: Option[Host], destination: Option[Host], schedule: ScheduleGroup, `object`: Option[RuleObject]): Rule = {
        Rule(id = id,
            subject = subject,
            source = source,
            destination = destination,
            `object` = `object`,
            result = result,
            usecaseId = usecaseId,
            `type` = `type`,
            scheduleGroup = schedule,
            aux1 = aux1,
            aux2 = aux2)
    }
}
