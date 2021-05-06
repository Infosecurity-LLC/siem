package ru.gkis.soc.siem.model.access

case class Rule(id: Int,
                subject: Subject,
                source: Option[Host],
                destination: Option[Host],
                `object`: Option[RuleObject],
                result: RuleResult,
                usecaseId: String,
                `type`: RuleType,
                scheduleGroup: ScheduleGroup,
                aux1: Option[String],
                aux2: Option[String]
               )
