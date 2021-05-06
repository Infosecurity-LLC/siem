package ru.gkis.soc.siem.normalizer.mappers

import ru.gkis.soc.siem.commons.Constants
import ru.gkis.soc.siem.model.{DevTypeToVendorMapping, SocEvent, _}
import ru.gkis.soc.siem.normalizer.InternalSocEvent
import ru.gkis.soc.siem.normalizer.mappers.helpers.HostnameVsFqdn
import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._

import java.time.format.DateTimeFormatter
import java.time.{LocalDateTime, ZoneOffset}

class Fail2BanMapper extends  Mapper[(DevTypeToVendorMapping, InternalSocEvent)] {
    private[this] def formatter: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss,SSS")

    override def map(src: (DevTypeToVendorMapping, InternalSocEvent)): SocEvent = {
        val (devTypeMappings, isoc) = src

        val (eventSourceFqdn, eventSourceHostname) = HostnameVsFqdn(None, isoc.message.eventHostname)

        val eventSourceLocation = AssetLocation(
            fqdn = eventSourceFqdn,
            hostname = eventSourceHostname,
            ip = Some(isoc.message.eventHostIP),
            host = isoc.message.eventHostIP
        )

        val vendor = devTypeMappings(isoc.message.eventDevType)
        val eventSourceInfo = EventSourceInfo(
            id = isoc.message.inputId,
            category = EventSourceCategory.HostSecurity,
            title = vendor.product,
            vendor = vendor.vendorName,
            location = Some(eventSourceLocation)
        )

        val collectorLocation = AssetLocation(
            hostname = Some(isoc.message.collectorHostname),
            host = isoc.message.collectorHostIP,
            ip = Some(isoc.message.collectorHostIP)
        )

        val collectorInfo = CollectorInfo(
            organization = isoc.message.organization,
            inputId = isoc.message.inputId,
            location = Some(collectorLocation)
        )

        val sourceLocation = InteractingAssetLocation()
            .update(_.ip.setIfDefined(isoc.event.extractOpt("sourceIp")))

        val destinationLocation = InteractingAssetLocation(
            ip = eventSourceLocation.ip,
            fqdn = eventSourceLocation.fqdn,
            hostname = eventSourceLocation.hostname
        )

        val objectInfo = ObjectInfo(category = Counterpart.application, name = Some("fail2ban"))

        val interactionDescription = InteractionDescription(
            status = InteractionStatus.success,
            action = isoc.event.extract("aux2").toInteractionCategory,
            importance = isoc.event.extract("importance").toImportanceLevel
        )

        val originTime = LocalDateTime.parse(isoc.event.extract("originTime"), formatter).atZone(ZoneOffset.UTC)
        val payload = DataPayload(
            msgId = isoc.event.extractOpt("msgId"),
            originTime = originTime.toEpochSecond,
            time = isoc.message.eventReceivedTime.toEpochSecond,
            aux1 = isoc.event.extractOpt("aux1"),
            aux2 = isoc.event.extractOpt("aux2")
        )

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = CiscoAsaMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(eventSourceInfo),
            source = Some(sourceLocation),
            destination = Some(destinationLocation),
            interaction = Some(interactionDescription),
            `object` = Some(objectInfo),
            collector = Some(collectorInfo),
            data = Some(payload)
        )
    }
}

object Fail2BanMapper {
    val name: String = "fail2ban02901"
    val version: Int = 1
}