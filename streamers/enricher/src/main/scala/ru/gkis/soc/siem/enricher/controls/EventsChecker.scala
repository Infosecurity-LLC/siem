package ru.gkis.soc.siem.enricher.controls

import ru.gkis.soc.siem.enricher.cache.index.{DecisionPath, LayeredIndex, Rule}
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.model.SocEvent
import ru.gkis.soc.siem.model.access.{Allowed, Restricted, RuleResult}
import com.google.common.collect.{Range => NumericRange}

import java.time.{Instant, ZoneOffset}
import java.time.temporal.ChronoField

trait EventsChecker[K, V] {

    def decisionPath(evt: SocEvent): DecisionPath[AnyRef]
    def enrichmentPossible(event: SocEvent): Boolean
    def check(index: LayeredIndex[K, V], evt: SocEvent, pk: ProductionCalendar): RuleResult

    protected def negate(rr: RuleResult): RuleResult = if (rr == Allowed) Restricted else Allowed

    protected def applySchedule(activeRule: Rule[K, V], originTime: Long, pk: ProductionCalendar): Boolean =
        activeRule.schedule.intervals.exists { schedule =>
            schedule.check(originTime, pk)
        }

    protected def checkInternal(activeRule: Rule[K, V], aux1: Boolean, aux2: Boolean, originTime: Long, pk: ProductionCalendar): RuleResult =
        if (applySchedule(activeRule, originTime, pk) && aux1 && aux2) activeRule.result else negate(activeRule.result)

    protected def timeToSinglePoint(time: Long): NumericRange[Integer] =
        NumericRange.singleton[Integer](Instant.ofEpochSecond(time).atZone(ZoneOffset.UTC).get(ChronoField.SECOND_OF_DAY))

}
