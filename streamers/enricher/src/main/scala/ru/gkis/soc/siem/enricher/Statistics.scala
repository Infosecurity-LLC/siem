package ru.gkis.soc.siem.enricher

import ru.gkis.soc.siem.model.{NetworkEnrichment, SocEvent}

sealed trait Split

case class CacheStatistic(hit: Int, miss: Int) {
    def +(other: CacheStatistic): CacheStatistic = {
        CacheStatistic(hit + other.hit, miss + other.miss)
    }

    override def toString: String = {
        val total = hit + miss
        f"(hit=$hit%s, miss=$miss%s, ratio=${miss.toDouble / (if (total > 0) total.toDouble else 1.toDouble)}%.2f)"
    }
}

case class InternalSocEvent(event: SocEvent) extends Split

case class InternalStatistics(product: String,
                              organization: String,
                              geoIpCache: CacheStatistic,
                              loginCache: CacheStatistic,
                              eventCount: Int = 1) extends Split {
    val key = s"$product.$organization"

    override def toString: String = {
        s"""(product=$product, org=$organization, processed=$eventCount, geoIpCache=$geoIpCache, loginCache=$loginCache)"""
    }
}

object InternalStatistics {
    def apply(event: SocEvent): InternalStatistics = {
        val (geoIpHits, geoIpMiss) = Seq(
            geoIpCache(event.source.flatMap(_.ip), event.getSource.getEnrichment),
            geoIpCache(event.destination.flatMap(_.ip), event.getDestination.getEnrichment)
        ).unzip

        val (loginHits, loginMiss) = loginCache(event)

        InternalStatistics(
            event.getEventSource.title,
            event.getCollector.organization,
            CacheStatistic(
                geoIpHits.sum,
                geoIpMiss.sum
            ),
            CacheStatistic(
                loginHits,
                loginMiss
            )
        )
    }

    private[this] def loginCache(event: SocEvent): (Int, Int) = {
        if (event.getSubject.name.isDefined && event.getSubject.domain.isDefined) {
            if (event.getSubject.getEnrichment.isTimeAllowed.isDefined && event.getSubject.getEnrichment.isWorkingDay.isDefined) {
                cacheHit
            } else {
                cacheMiss
            }
        } else {
            noData
        }
    }

    // Return Hit/Miss
    private[this] def geoIpCache(ip: Option[String], enrichment: NetworkEnrichment): (Int, Int) = {
        ip match {
            case None =>
                noData
            case Some(_) if enrichment.getIsNetworkLocal =>
                noData
            case Some(_) =>
                if (enrichment.geo.isDefined || enrichment.network.isDefined) {
                    cacheHit
                } else {
                    cacheMiss
                }
        }
    }

    private[this] val noData: (Int, Int) = (0, 0)
    private[this] val cacheHit: (Int, Int) = (1, 0)
    private[this] val cacheMiss: (Int, Int) = (0, 1)
}

