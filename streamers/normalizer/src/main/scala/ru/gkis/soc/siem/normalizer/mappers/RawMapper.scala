package ru.gkis.soc.siem.normalizer.mappers

import ru.gkis.soc.siem.model.{AssetLocation, CollectorInfo, RawEvent}
import ru.gkis.soc.siem.normalizer.InternalRawEvent
import ru.gkis.soc.siem.normalizer.mappers.helpers.HostnameVsFqdn

class RawMapper extends Mapper[InternalRawEvent] {

    override def map(src: InternalRawEvent): RawEvent = {
        val (eventSourceFqdn, eventSourceHostname) = HostnameVsFqdn(None, src.message.eventHostname)
        val eventSourceLocation = AssetLocation(
            ip = Some(src.message.eventHostIP),
            fqdn = eventSourceFqdn,
            hostname = eventSourceHostname,
            host = src.message.eventHostIP
        )

        val collectorLocation = AssetLocation(
            host = src.message.collectorHostIP,
            hostname = Some(src.message.collectorHostname),
            ip = Some(src.message.collectorHostIP)
        )

        val collectorInfo = CollectorInfo(
            location = Some(collectorLocation),
            organization = src.message.organization,
            inputId = src.message.inputId
        )

        RawEvent(
            id = src.rawId,
            raw = src.message.rawMessage,
            preparsedMessage = src.message.preparsedMessage,
            collector = Some(collectorInfo),
            eventTime = src.message.eventReceivedTime.toEpochSecond,
            devType = src.message.eventDevType,
            eventSource = Some(eventSourceLocation),
            severityId = src.message.severityId,
            severity = src.message.severity,
            normalizedId = src.normId
        )
    }

}

object RawMapper {
    val name: String = "nx_log"
    val version: Int = 1
}
