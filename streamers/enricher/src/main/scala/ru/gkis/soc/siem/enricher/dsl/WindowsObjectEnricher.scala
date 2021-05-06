package ru.gkis.soc.siem.enricher.dsl

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.enricher.cache.decisiontree._
import ru.gkis.soc.siem.enricher.cache.index.LayeredIndex
import ru.gkis.soc.siem.enricher.controls.{WindowsObjectControl, WindowsObjectControl2}
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.io.spark.EditableBroadcast
import ru.gkis.soc.siem.model.access.{Allowed, Restricted, Undefined, WindowsObject}
import ru.gkis.soc.siem.model.{InteractionCategory, SocEvent}

trait WindowsObjectEnricher {

    implicit class WindowsObjectEnricher(rdd: RDD[SocEvent]) extends Serializable {
        def enrichWindowsObjectAccess(decisionTree: EditableBroadcast[DecisionTree[Int, String]], pk: EditableBroadcast[ProductionCalendar]): RDD[SocEvent] = {
            rdd.mapPartitions(_.map {
                case event if isWindowsObjectAccessEnrichmentPossible(event) =>
                    WindowsObjectControl.decisionPath(event) match {
                        case Some(path) =>
                            decisionTree.value.newControl(path).check(event, pk.value) match {
                                case Allowed =>
                                    event.update(_.subject.enrichment.isObjectAccessAllowed := true)
                                case Restricted =>
                                    event.update(_.subject.enrichment.isObjectAccessAllowed := false)
                                case Undefined =>
                                    event
                            }
                        case None =>
                            event
                    }
                case event =>
                    event
            })
        }

        def enrichWindowsObjectAccess2(index: EditableBroadcast[LayeredIndex[Nothing, Nothing]], pk: EditableBroadcast[ProductionCalendar]): RDD[SocEvent] = {
            rdd.mapPartitions(_.map {
                case event if WindowsObjectControl2.enrichmentPossible(event) =>
                    WindowsObjectControl2.check(index.value, event, pk.value) match {
                        case Allowed =>
                            event.update(_.subject.enrichment.isObjectAccessAllowed := true)
                        case Restricted =>
                            event.update(_.subject.enrichment.isObjectAccessAllowed := false)
                        case Undefined =>
                            event
                    }
                case event =>
                    event
            })
        }
    }

    def generateWindowsObjectAccessDecisionTree(rules: => List[Rule[Int, String]]): DecisionTree[Int, String] = {
        val result = new DecisionTree[Int, String]
        result.addAll(WindowsObjectControl[Int, String](rules.filter(_.tp == WindowsObject)))
        result
    }

    private[this] val allowedInteractions = Set(InteractionCategory.access, InteractionCategory.remove)

    private[this] def isWindowsObjectAccessEnrichmentPossible(event: SocEvent) = {
        event.eventSource.fold(false)(_.title.toLowerCase.contains("windows")) &&
        event.subject.fold(false)(_.category.isaccount) &&
        event.`object`.fold(false)(_.category.isfile) &&
        event.`object`.fold(false)(obj => obj.path.isDefined || obj.name.isDefined) &&
        event.interaction.fold(false)(inter => allowedInteractions.contains(inter.action))
    }
}
