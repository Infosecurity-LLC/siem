package ru.gkis.soc.siem.enricher.dsl

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.enricher.cache.decisiontree._
import ru.gkis.soc.siem.enricher.cache.index.LayeredIndex
import ru.gkis.soc.siem.enricher.controls.{VpnLogonControl, VpnLogonControl2}
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.io.spark.EditableBroadcast
import ru.gkis.soc.siem.model.access.{Allowed, Restricted, Undefined, VpnLogon}
import ru.gkis.soc.siem.model.SocEvent
import scalapb.lenses.Lens

trait VpnLogonEnricher {

    implicit class VpnLogonEnricher(rdd: RDD[SocEvent]) extends Serializable {
        def enrichVpnLogon(decisionTree: EditableBroadcast[DecisionTree[Int, String]], pk: EditableBroadcast[ProductionCalendar]): RDD[SocEvent] = {
            rdd.mapPartitions(_.map {
                case event if isVpnLogonEnrichmentPossible(event) =>
                    VpnLogonControl.decisionPath(event) match {
                        case Some(path) =>
                            decisionTree.value.newControl(
                                decisionPath = path,
                                eventTime = Some(Lens.unit[SocEvent].eventTime)
                            ).check(event, pk.value) match {
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

        def enrichVpnLogon2(index: EditableBroadcast[LayeredIndex[Nothing, Nothing]], pk: EditableBroadcast[ProductionCalendar]): RDD[SocEvent] = {
            rdd.mapPartitions(_.map {
                case event if VpnLogonControl2.enrichmentPossible(event) =>
                    VpnLogonControl2.check(index.value, event, pk.value) match {
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

    def generateVpnLogonDecisionTree(rules: => List[Rule[Int, String]]): DecisionTree[Int, String] = {
        val result = new DecisionTree[Int, String]
        result.addAll(VpnLogonControl[Int, String](rules.filter(_.tp == VpnLogon)))
        result
    }

    private[this] val vpn: String = "VPN"

    def isVpnLogonEnrichmentPossible(event: SocEvent): Boolean = {
        event.subject.fold(false)(_.category.isaccount) &&
        event.interaction.fold(false)(_.action.isup) &&
        Lens.unit[SocEvent].data.optionalAux9.get(event).fold(false)(_.equalsIgnoreCase(vpn))
    }
}