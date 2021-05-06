package ru.gkis.soc.siem.enricher.controls

import com.typesafe.scalalogging.LazyLogging
import ru.gkis.soc.siem.enricher.cache.index
import ru.gkis.soc.siem.enricher.cache.index.{DecisionPath, LayeredIndex, Node, PathNode, Rule, RuleConverter, Spec}
import com.google.common.collect.{Range => NumericRange}
import ru.gkis.soc.siem.model.access.{RuleResult, Undefined, VpnLogon, Rule => AccessRule}
import ru.gkis.soc.siem.enricher.cache.index.layers.{ExactMatchLayer, Layer, RangeLayer}
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.model.SocEvent
import scalapb.lenses.Lens

object VpnLogonControl2 extends IndexBuilder[Nothing, Nothing]
                           with EventsChecker[Nothing, Nothing]
                           with RuleTypeConverter[Nothing, Nothing]
                           with LazyLogging {

    // create index ====================================================================================================
    override protected def rulesToPathSpec(rules: List[index.Rule[Nothing, Nothing]]): List[Spec] =
        rules
            .map(r => {
                val path = List(
                    List(PathNode(Some(r.subj.org), None)),
                    List(PathNode(r.subj.domain, None)),
                    List(PathNode(r.subj.login, None)),
                    r.schedule.intervals.toList.map(int => PathNode(Some(NumericRange.closed[Integer](int.from, int.to)), None))
                )
                index.RuleSpec[Node, Nothing, Nothing](path.asInstanceOf[DecisionPath[Node]], r)
            })


    override protected def createLayers: List[Layer] =
        List(
            new ExactMatchLayer[String](1, anyString),
            new ExactMatchLayer[String](1, anyString),
            new ExactMatchLayer[String](1, anyString),
            new RangeLayer[Integer](anyRange)
        )

    override def apply(rules: List[index.Rule[Nothing, Nothing]]): LayeredIndex[Nothing, Nothing] = {
        val specs = rulesToPathSpec(rules)
        val index = new LayeredIndex[Nothing, Nothing](createLayers)
        index.addAll(specs)
        index
    }

    // check event =====================================================================================================
    private val org = Lens.unit[SocEvent].collector.organization
    private val domain = Lens.unit[SocEvent].subject.optionalDomain
    private val subject = Lens.unit[SocEvent].subject.optionalName
    private val originTime = Lens.unit[SocEvent].data.originTime

    override def decisionPath(evt: SocEvent): DecisionPath[AnyRef] =
        List(
            List(PathNode(Some(org.get(evt)))),
            List(PathNode(domain.get(evt))),
            List(PathNode(subject.get(evt))),
            List(PathNode(Some(timeToSinglePoint(originTime.get(evt)))))
        )

    override def enrichmentPossible(event: SocEvent): Boolean =
        event.subject.fold(false)(_.category.isaccount) &&
        event.interaction.fold(false)(_.action.isup) &&
        Lens.unit[SocEvent].data.optionalAux9.get(event).fold(false)(_.equalsIgnoreCase("VPN")) &&
        event.data.isDefined

    override def check(index: LayeredIndex[Nothing, Nothing], evt: SocEvent, pk: ProductionCalendar): RuleResult =
        index.search(decisionPath(evt)).fold[RuleResult](Undefined)(activeRules => {
            val activeRule = activeRules.head

            if (activeRules.size > 1)
                logger.warn(s"More than a single rule was found for event: $evt. Random rule id ${activeRule.id} was selected to continue processing")

            checkInternal(
                activeRule,
                aux1 = true,
                aux2 = true,
                originTime.get(evt),
                pk
            )
        })

    // converter =======================================================================================================
    override def convertAccessRule(src: List[AccessRule]): List[Rule[Nothing, Nothing]] =
        src
            .filter(_.`type` == VpnLogon)
            .map(ar => RuleConverter.convert[Nothing, Nothing](ar))
}
