package ru.gkis.soc.siem.enricher.controls

import com.typesafe.scalalogging.LazyLogging
import ru.gkis.soc.siem.enricher.cache.index
import ru.gkis.soc.siem.enricher.cache.index.{DecisionPath, LayeredIndex, Node, PathNode, Rule, RuleConverter, Spec}
import ru.gkis.soc.siem.enricher.cache.index.layers.{DecisionTreeLayer, ExactMatchLayer, Layer, RangeLayer}
import com.google.common.collect.{Range => NumericRange}
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.model.{InteractionCategory, SocEvent}
import ru.gkis.soc.siem.model.access.{RuleResult, Undefined, WindowsObject, Rule => AccessRule}
import scalapb.lenses.Lens

import java.util.regex.Pattern

object WindowsObjectControl2 extends IndexBuilder[Nothing, Nothing]
                                with EventsChecker[Nothing, Nothing]
                                with RuleTypeConverter[Nothing, Nothing]
                                with LazyLogging {

    sealed trait CheckBy
    case object Hostname extends CheckBy
    case object IpAddress extends CheckBy

    private val pathPattern = Pattern.compile("""(:\\)|(\\+)""")
    private[this] val allowedInteractions = Set(InteractionCategory.access, InteractionCategory.remove)

    private def pathToSegments(path: Option[String]): List[Option[String]] = {
        val result: List[String] = path match {
            case Some(p) if p.startsWith("""\\*\""") || p.startsWith("""\??\""") =>
                pathPattern.split(p.substring(4)).map(_.toLowerCase).toList
            case Some(p) =>
                pathPattern.split(p).map(_.toLowerCase).toList
            case None =>
                List.empty
        }

        result.map(el => Some(el))
    }

    // create index ====================================================================================================
    override protected def rulesToPathSpec(rules: List[Rule[Nothing, Nothing]]): List[Spec] =
        rules
            .map(r => {
                val path = List(
                    List(PathNode(Some(r.subj.org))),
                    List(PathNode(r.subj.domain)),
                    List(PathNode(r.subj.login)),
                    r.source.fold(List.empty[PathNode[String]])(l => List(PathNode(l.hostname, Some(Hostname)), PathNode(l.ip, Some(IpAddress)))),
                    r.obj.map(o => pathToSegments(o.path.orElse(o.name))).getOrElse(List.empty).map(elem => PathNode(elem)),
                    r.schedule.intervals.toList.map(int => PathNode(Some(NumericRange.closed[Integer](int.from, int.to))))
                )
                index.RuleSpec[Node, Nothing, Nothing](path.asInstanceOf[DecisionPath[Node]], r)
            })

    override protected def createLayers: List[Layer] =
        List(
            new ExactMatchLayer[String](1, anyString),
            new ExactMatchLayer[String](1, anyString),
            new ExactMatchLayer[String](1, anyString),
            new ExactMatchLayer[String](2, anyString),
            new DecisionTreeLayer[String](anyString),
            new RangeLayer[Integer](anyRange)
        )

    override def apply(rules: List[Rule[Nothing, Nothing]]): LayeredIndex[Nothing, Nothing] = {
        val specs = rulesToPathSpec(rules)
        val index = new LayeredIndex[Nothing, Nothing](createLayers)
        index.addAll(specs)
        index
    }

    // check event =====================================================================================================
    private val lower = Lens[String, String](_.toLowerCase)((_, _) => ???)
    private val optionalLower = Lens[Option[String], Option[String]](_.map(_.toLowerCase))((_, _) => ???)
    private val org = Lens.unit[SocEvent].collector.organization compose lower
    private val domain = Lens.unit[SocEvent].subject.optionalDomain compose optionalLower
    private val subject = Lens.unit[SocEvent].subject.optionalName compose optionalLower
    private val destHost = Lens.unit[SocEvent].destination.optionalHostname compose optionalLower
    private val destIp = Lens.unit[SocEvent].destination.optionalIp compose optionalLower
    private val objectCategory = Lens.unit[SocEvent].`object`.category
    private val path = Lens.unit[SocEvent].`object`.optionalPath compose optionalLower
    private val name = Lens.unit[SocEvent].`object`.optionalName compose optionalLower
    private val originTime = Lens.unit[SocEvent].data.originTime

    override def decisionPath(evt: SocEvent): DecisionPath[AnyRef] = {
        val pathOrName = if (objectCategory.get(evt).isfile) path.get(evt) else name.get(evt)
        List(
            List(PathNode(Some(org.get(evt)))),
            List(PathNode(domain.get(evt))),
            List(PathNode(subject.get(evt))),
            List(PathNode(destHost.get(evt), Some(Hostname)), PathNode(destIp.get(evt), Some(IpAddress))),
            pathToSegments(pathOrName).map(p => PathNode[AnyRef](p)),
            List(PathNode(Some(timeToSinglePoint(originTime.get(evt)))))
        )
    }

    override def enrichmentPossible(event: SocEvent): Boolean =
        event.eventSource.fold(false)(_.title.toLowerCase.contains("windows")) &&
        event.subject.fold(false)(_.category.isaccount) &&
        ((event.`object`.fold(false)(obj => obj.category.isfile) && event.`object`.fold(false)(obj => obj.path.isDefined)) ||
            (event.`object`.fold(false)(obj => obj.category.isurl) && event.`object`.fold(false)(obj => obj.name.isDefined))) &&
        event.interaction.fold(false)(inter => allowedInteractions.contains(inter.action)) &&
        event.data.isDefined

    override def check(index: LayeredIndex[Nothing, Nothing], evt: SocEvent, pk: ProductionCalendar): RuleResult =
        index.search(decisionPath(evt)).fold[RuleResult](Undefined)(activeRules => {
            val activeRule = activeRules.head

            if (activeRules.size > 1)
                logger.warn(s"More than a single rule was found for event: $evt. Random rule id ${activeRule.id} was selected to continue processing")

            activeRule.result
        })

    // converter =======================================================================================================
    override def convertAccessRule(src: List[AccessRule]): List[Rule[Nothing, Nothing]] =
        src
            .filter(_.`type` == WindowsObject)
            .map(ar => RuleConverter.convert[Nothing, Nothing](ar))
}
