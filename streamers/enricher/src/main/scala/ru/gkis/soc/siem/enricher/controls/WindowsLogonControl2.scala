package ru.gkis.soc.siem.enricher.controls

import ru.gkis.soc.siem.enricher.cache.index
import ru.gkis.soc.siem.enricher.cache.index.{DecisionPath, LayeredIndex, Location, Node, PathNode, Rule, RuleConverter, Spec, Aux}
import com.google.common.collect.{Range => NumericRange}
import com.typesafe.scalalogging.LazyLogging
import ru.gkis.soc.siem.enricher.cache.index.layers.{ExactMatchLayer, Layer, RangeLayer}
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.model.access._
import ru.gkis.soc.siem.model.{InteractionCategory, SocEvent}
import scalapb.lenses.Lens
import ru.gkis.soc.siem.model.access.{Rule => AccessRule}

object WindowsLogonControl2 extends IndexBuilder[Int, Nothing]
                               with EventsChecker[Int, Nothing]
                               with RuleTypeConverter[Int, Nothing]
                               with LazyLogging {

    sealed trait CheckBy
    case object Hostname extends CheckBy
    case object IpAddress extends CheckBy

    // create index ====================================================================================================
    private def emptyOrLocationPath(location: Option[Location]) =
        location.fold(List.empty[PathNode[String]])(l => List(PathNode(l.hostname, Some(Hostname)), PathNode(l.ip, Some(IpAddress))))

    override protected def rulesToPathSpec(rules: List[Rule[Int, Nothing]]): List[Spec] =
        rules
        .map(r => {
            val path = List(
                List(PathNode(Some(r.subj.org))),
                List(PathNode(r.subj.domain)),
                List(PathNode(r.subj.login)),
                emptyOrLocationPath(r.source),
                emptyOrLocationPath(r.destination),
                r.schedule.intervals.toList.map(int => PathNode(Some(NumericRange.closed[Integer](int.from, int.to))))
            )
            index.RuleSpec[Node, Int, Nothing](path.asInstanceOf[DecisionPath[Node]], r)
        })

    override protected def createLayers: List[Layer] =
        List(
            new ExactMatchLayer[String](1, anyString),
            new ExactMatchLayer[String](1, anyString),
            new ExactMatchLayer[String](1, anyString),
            new ExactMatchLayer[String](2, anyString),
            new ExactMatchLayer[String](2, anyString),
            new RangeLayer[Integer](anyRange)
        )

    override def apply(rules: List[Rule[Int, Nothing]]): LayeredIndex[Int, Nothing] = {
        val specs = rulesToPathSpec(rules)
        val index = new LayeredIndex[Int, Nothing](createLayers)
        index.addAll(specs)
        index
    }

    // check event =====================================================================================================
    private val lower = Lens[String, String](_.toLowerCase)((_, _) => ???)
    private val optionalLower = Lens[Option[String], Option[String]](_.map(_.toLowerCase))((_, _) => ???)
    private val org = Lens.unit[SocEvent].collector.organization compose lower
    private val domain = Lens.unit[SocEvent].subject.optionalDomain compose optionalLower
    private val subject = Lens.unit[SocEvent].subject.optionalName compose optionalLower
    private val sourceHost = Lens.unit[SocEvent].source.optionalHostname compose optionalLower
    private val sourceIp = Lens.unit[SocEvent].source.optionalIp compose optionalLower
    private val destinationHost = Lens.unit[SocEvent].destination.optionalHostname compose optionalLower
    private val destinationIp = Lens.unit[SocEvent].destination.optionalIp compose optionalLower
    private val originTime = Lens.unit[SocEvent].data.originTime
    private val aux1 = Lens.unit[SocEvent].interaction.logonType

    override def decisionPath(evt: SocEvent): DecisionPath[AnyRef] =
        List(
            List(PathNode(Some(org.get(evt)), None)),
            List(PathNode(domain.get(evt), None)),
            List(PathNode(subject.get(evt), None)),
            List(PathNode(sourceHost.get(evt), Some(Hostname)), PathNode(sourceIp.get(evt), Some(IpAddress))),
            List(PathNode(destinationHost.get(evt), Some(Hostname)), PathNode(destinationIp.get(evt), Some(IpAddress))),
            List(PathNode(Some(timeToSinglePoint(originTime.get(evt))), None))
        )

    override def enrichmentPossible(event: SocEvent): Boolean = {
        Lens.unit[SocEvent].interaction.optionalLogonType.get(event).isDefined &&
            event.eventSource.fold(false)(_.title.toLowerCase.contains("windows")) &&
            event.subject.fold(false)(_.category.isaccount) &&
            event.`object`.fold(false)(_.category.ishost) &&
            event.interaction.fold(false)(_.action == InteractionCategory.login) &&
            event.data.isDefined
    }

    override def check(index: LayeredIndex[Int, Nothing], evt: SocEvent, pk: ProductionCalendar): RuleResult =
        index.search(decisionPath(evt)).fold[RuleResult](Undefined)(activeRules => {
            val activeRule = activeRules.head

            if (activeRules.size > 1)
                logger.warn(s"More than a single rule was found for event: $evt. Random rule id ${activeRule.id} was selected to continue processing")

            checkInternal(
                activeRule,
                activeRule.aux1.fold(true)(_.values.contains(aux1.get(evt))),
                aux2 = true,
                originTime.get(evt),
                pk
            )
        })

    // converter =======================================================================================================
    override def convertAccessRule(src: List[AccessRule]): List[Rule[Int, Nothing]] =
        src
            .filter(_.`type` == WindowsLogon)
            .map(ar => RuleConverter.convert[Int, Nothing](ar, ar.aux1.map(a => Aux(a.split(';').map(_.toInt).toSet))))

}
