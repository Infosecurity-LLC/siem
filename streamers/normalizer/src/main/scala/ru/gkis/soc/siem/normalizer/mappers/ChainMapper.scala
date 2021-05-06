package ru.gkis.soc.siem.normalizer.mappers

import ru.gkis.soc.siem.model.{AssetLocation, ChainEvent, CollectorInfo}
import ru.gkis.soc.siem.normalizer.InternalChainEvent
import ru.gkis.soc.siem.normalizer.mappers.helpers.HostnameVsFqdn
import ru.gkis.soc.siem.normalizer.mappers.helpers.Coalesce._

class ChainMapper extends Mapper[InternalChainEvent] {

    override def map(src: InternalChainEvent): ChainEvent = {
        val (eventSourceFqdn, eventSourceHostname) = HostnameVsFqdn(None, Some(src.message.collectorHostname))
        val collectorLocation = AssetLocation(
            ip = Some(src.message.collectorHostIP),
            fqdn = eventSourceFqdn,
            hostname = eventSourceHostname,
            host = src.message.collectorHostIP
        )

        val collectorInfo = CollectorInfo(
            location = Some(collectorLocation),
            organization = src.message.organization,
            inputId = src.message.inputId
        )

        ChainEvent(
            rawId = src.rawId,
            normalizedId = src.normId,
            chain = src.message.chain,
            collector = Some(collectorInfo),
            eventTime = src.message.eventReceivedTime.toEpochSecond
        )
    }

}

object ChainMapper {
    val name: String = "chain"
    val version: Int = 1
}