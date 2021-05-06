package ru.gkis.soc.siem.enricher.dsl

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.enricher.cache.IpGeoInfoCache
import ru.gkis.soc.siem.io.spark.EditableBroadcast
import ru.gkis.soc.siem.model.{NetworkEnrichment, GeoInfo, IpInfo, SocEvent}
import scalapb.lenses.{Lens, Mutation}

import scala.language.implicitConversions

trait GeoIpEnricher {

    implicit class GeoIpEnricher(rdd: RDD[SocEvent]) extends Serializable {

        import ru.gkis.soc.siem.model.SocEvent._

        def enrichGeo(cache: EditableBroadcast[IpGeoInfoCache]): RDD[SocEvent] = {
            rdd.mapPartitions(it =>
                it.map { event =>
                    val sourceGeoInfo: Option[IpInfo] = event.source.flatMap(_.ip).flatMap(cache.value.find)
                    val destinationGeoInfo: Option[IpInfo] = event.destination.flatMap(_.ip).flatMap(cache.value.find)

                    event.update(
                        e => geoInfo(e.source.enrichment, sourceGeoInfo),
                        e => network(e.source.enrichment, sourceGeoInfo.map(_.network)),
                        e => isLocal(e.source.enrichment, event.source.flatMap(_.ip).map(cache.value.isLocalIp)),
                        e => geoInfo(e.destination.enrichment, destinationGeoInfo),
                        e => network(e.destination.enrichment, destinationGeoInfo.map(_.network)),
                        e => isLocal(e.destination.enrichment, event.destination.flatMap(_.ip).map(cache.value.isLocalIp))
                    )
                },
                preservesPartitioning = true
            )
        }

        private[this] def geoInfo(enrichment: Lens[SocEvent, NetworkEnrichment],
                                  ipGeoInfo: Option[IpInfo]): Mutation[SocEvent] = {
            enrichment.geo.setIfDefined(ipGeoInfo.map(info => GeoInfo(info.city, info.country, info.org)))
        }

        private[this] def network(enrichment: Lens[SocEvent, NetworkEnrichment],
                                  value: Option[String]): Mutation[SocEvent] = {
            enrichment.network.setIfDefined(value)
        }

        private[this] def isLocal(enrichment: Lens[SocEvent, NetworkEnrichment],
                                  value: Option[Boolean]): Mutation[SocEvent] = {
            enrichment.isNetworkLocal.setIfDefined(value)
        }
    }

}
