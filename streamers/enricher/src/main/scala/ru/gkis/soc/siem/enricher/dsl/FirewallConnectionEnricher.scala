package ru.gkis.soc.siem.enricher.dsl

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.enricher.cache.index.LayeredIndex
import ru.gkis.soc.siem.enricher.controls.FirewallConnectionControl
import ru.gkis.soc.siem.enricher.time.ProductionCalendar
import ru.gkis.soc.siem.io.spark.EditableBroadcast
import ru.gkis.soc.siem.model.SocEvent
import ru.gkis.soc.siem.model.access.{Allowed, Restricted, Undefined}
import com.google.common.collect.{Range => NumericRange}

trait FirewallConnectionEnricher {

    implicit class FirewallConnectionEnricher(rdd: RDD[SocEvent]) extends Serializable {

        def enrichFirewallConnection(index: EditableBroadcast[LayeredIndex[NumericRange[Integer], NumericRange[Integer]]], pk: EditableBroadcast[ProductionCalendar]): RDD[SocEvent] = {
            rdd.mapPartitions(_.map {
                case event if FirewallConnectionControl.enrichmentPossible(event) =>
                    FirewallConnectionControl.check(index.value, event, pk.value) match {
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

}

object FirewallConnectionEnricher extends FirewallConnectionEnricher with Serializable
