package ru.gkis.soc.siem.enricher.dsl

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.enricher.cache.decisiontree.{DecisionTree, Rule}
import ru.gkis.soc.siem.enricher.cache.index.LayeredIndex
import ru.gkis.soc.siem.enricher.controls.{WindowsLogonControl, WindowsLogonControl2}
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.io.spark.EditableBroadcast
import ru.gkis.soc.siem.model.access.{Allowed, Restricted, Undefined, WindowsLogon}
import ru.gkis.soc.siem.model.{InteractionCategory, SocEvent}
import scalapb.lenses.Lens

trait WindowsLogonEnricher {

    implicit class WindowsLogonEnricher(rdd: RDD[SocEvent]) extends Serializable {
        def enrichWindowsLogon(decisionTree: EditableBroadcast[DecisionTree[Int, String]], pk: EditableBroadcast[ProductionCalendar]): RDD[SocEvent] = {
            rdd.mapPartitions(_.map {
                case event if isWindowsLogonEnrichmentPossible(event) =>
                    WindowsLogonControl.decisionPath(event) match {
                        case Some(path) =>
                            val result = decisionTree.value.newControl(
                                decisionPath = path,
                                eventTime = Some(Lens.unit[SocEvent].eventTime),
                                aux1 = Some(Lens.unit[SocEvent].interaction.logonType)
                            ).check(event, pk.value)

                            result match {
                                case Allowed =>
                                    event.update(_.subject.enrichment.isHostAccessTimeAllowed := true)
                                case Restricted =>
                                    event.update(_.subject.enrichment.isHostAccessTimeAllowed := false)
                                case Undefined =>
                                    event
                            }
                        case None =>
                            event
                    }
                case event =>
                    event
            }, preservesPartitioning = true)
        }

        def enrichWindowsLogon2(index: EditableBroadcast[LayeredIndex[Int, Nothing]], pk: EditableBroadcast[ProductionCalendar]): RDD[SocEvent] = {
            rdd.mapPartitions(_.map {
                case event if WindowsLogonControl2.enrichmentPossible(event) =>
                    WindowsLogonControl2.check(index.value, event, pk.value) match {
                        case Allowed =>
                            event.update(_.subject.enrichment.isHostAccessTimeAllowed := true)
                        case Restricted =>
                            event.update(_.subject.enrichment.isHostAccessTimeAllowed := false)
                        case Undefined =>
                            event
                    }
                case event =>
                    event
            }, preservesPartitioning = true)
        }
    }

    def generateWindowsLogonDecisionTree(rules: => List[Rule[Int, String]]): DecisionTree[Int, String] = {
        val result = new DecisionTree[Int, String]
        result.addAll(WindowsLogonControl[Int, String](rules.filter(_.tp == WindowsLogon)))
        result
    }

    private[this] def isWindowsLogonEnrichmentPossible(event: SocEvent) = {
        Lens.unit[SocEvent].interaction.optionalLogonType.get(event).isDefined &&
        event.eventSource.fold(false)(_.title.toLowerCase.contains("windows")) &&
        event.subject.fold(false)(_.category.isaccount) &&
        event.`object`.fold(false)(_.category.ishost) &&
        event.interaction.fold(false)(_.action == InteractionCategory.login)
    }

}

object WindowsLogonEnricher extends WindowsLogonEnricher with Serializable