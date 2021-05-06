package ru.gkis.soc.siem.enricher.controls

import com.typesafe.scalalogging.LazyLogging
import ru.gkis.soc.siem.enricher.cache.index.{Aux, DecisionPath, LayeredIndex, Location, Node, PathNode, Rule, RuleConverter, RuleSpec, Spec}
import ru.gkis.soc.siem.enricher.cache.index.layers.{ExactMatchLayer, Layer, RangeLayer}
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.model.access.{FirewallConnection, RuleResult, Undefined, Rule => AccessRule}
import ru.gkis.soc.siem.model.{EventSourceCategory, SocEvent}
import com.google.common.collect.{Range => NumericRange}
import scalapb.lenses.Lens

object FirewallConnectionControl extends IndexBuilder[NumericRange[Integer], NumericRange[Integer]]
                                    with EventsChecker[NumericRange[Integer], NumericRange[Integer]]
                                    with RuleTypeConverter[NumericRange[Integer], NumericRange[Integer]]
                                    with LazyLogging {

    sealed trait CheckBy
    case object Hostname extends CheckBy
    case object IpAddress extends CheckBy

    // create index ====================================================================================================
    private def emptyOrLocationPath(location: Option[Location]) =
        location.fold(List.empty[PathNode[String]])(l => List(PathNode(l.hostname, Some(Hostname)), PathNode(l.ip, Some(IpAddress))))

    override protected def rulesToPathSpec(rules: List[Rule[NumericRange[Integer], NumericRange[Integer]]]): List[Spec] =
        rules
            .map(r => {
                val path = List(
                    List(PathNode(Some(r.subj.org))),
                    emptyOrLocationPath(r.source),
                    emptyOrLocationPath(r.destination),
                    r.obj.fold(List.empty[PathNode[String]])(o => List(PathNode(o.name, None))),
                    r.aux1.fold(List.empty[PathNode[NumericRange[Integer]]])(aux => aux.values.map(i => PathNode(Some(i), None)).toList),
                    r.aux2.fold(List.empty[PathNode[NumericRange[Integer]]])(aux => aux.values.map(i => PathNode(Some(i), None)).toList)
                )
                RuleSpec[Node, NumericRange[Integer], NumericRange[Integer]](path.asInstanceOf[DecisionPath[Node]], r)
            })

    override protected def createLayers: List[Layer] =
        List(
            new ExactMatchLayer[String](1, anyString),
            new ExactMatchLayer[String](2, anyString),
            new ExactMatchLayer[String](2, anyString),
            new ExactMatchLayer[String](1, anyString),
            new RangeLayer[Integer](anyRange),
            new RangeLayer[Integer](anyRange)
        )

    override def apply(rules: List[Rule[NumericRange[Integer], NumericRange[Integer]]]): LayeredIndex[NumericRange[Integer], NumericRange[Integer]] = {
        val specs = rulesToPathSpec(rules)
        val index = new LayeredIndex[NumericRange[Integer], NumericRange[Integer]](createLayers)
        index.addAll(specs)
        index
    }

    // check event =====================================================================================================
    private val optionalLower = Lens[Option[String], Option[String]](_.map(_.toLowerCase))((_, _) => ???)
    private val org = Lens.unit[SocEvent].collector.organization
    private val sourceHost = Lens.unit[SocEvent].source.optionalHostname compose optionalLower
    private val sourceIp = Lens.unit[SocEvent].source.optionalIp compose optionalLower
    private val sourcePort = Lens.unit[SocEvent].source.port
    private val destinationHost = Lens.unit[SocEvent].destination.optionalHostname compose optionalLower
    private val destinationIp = Lens.unit[SocEvent].destination.optionalIp compose optionalLower
    private val destinationPort = Lens.unit[SocEvent].destination.port
    private val protocol = Lens.unit[SocEvent].interaction.optionalProtocol compose optionalLower

    override def decisionPath(evt: SocEvent): DecisionPath[AnyRef] =
        List(
            List(PathNode(Some(org.get(evt)), None)),
            List(PathNode(sourceHost.get(evt), Some(Hostname)), PathNode(sourceIp.get(evt), Some(IpAddress))),
            List(PathNode(destinationHost.get(evt), Some(Hostname)), PathNode(destinationIp.get(evt), Some(IpAddress))),
            List(PathNode(protocol.get(evt), None)),
            List(PathNode(Some(NumericRange.singleton[Integer](sourcePort.get(evt))), None)),
            List(PathNode(Some(NumericRange.singleton[Integer](destinationPort.get(evt))), None))
        )

    override def enrichmentPossible(event: SocEvent): Boolean =
        event.eventSource.fold(false)(_.category == EventSourceCategory.Firewall) &&
        event.source.fold(false)(_.port.isDefined) &&
        event.destination.fold(false)(_.port.isDefined)

    /**
     * This control works as a permissive exclusion for connection control rules,
     * thus having only two results: Allowed or Undefined. Restricted is never used here
     */
    override def check(index: LayeredIndex[NumericRange[Integer], NumericRange[Integer]], evt: SocEvent, pk: ProductionCalendar): RuleResult =
        index.search(decisionPath(evt)).fold[RuleResult](Undefined)(activeRules => {
            val activeRule = activeRules.head

            if (activeRules.size > 1)
                logger.warn(s"More than a single rule was found for event: $evt. Random rule id ${activeRule.id} was selected to continue processing")

            activeRule.result
        })

    // converter =======================================================================================================
    private def portRangeParser(aux: Option[String]) =
        aux.map(a => Aux(a.split(',').map {
            case portRange if portRange.contains("-") =>
                val bounds = portRange.split("-")
                NumericRange.closed[Integer](bounds(0).toInt, bounds(1).toInt)
            case port =>
                NumericRange.singleton[Integer](port.toInt)
        }.toSet))

    override def convertAccessRule(src: List[AccessRule]): List[Rule[NumericRange[Integer], NumericRange[Integer]]] =
        src
            .filter(_.`type` == FirewallConnection)
            .map(ar => RuleConverter.convert[NumericRange[Integer], NumericRange[Integer]](ar, aux1 = portRangeParser(ar.aux1), aux2 = portRangeParser(ar.aux2)))

}
