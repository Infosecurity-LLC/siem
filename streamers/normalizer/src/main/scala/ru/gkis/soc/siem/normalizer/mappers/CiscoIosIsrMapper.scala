package ru.gkis.soc.siem.normalizer.mappers

import ru.gkis.soc.siem.commons.Constants
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.normalizer.InternalSocEvent
import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._
import ru.gkis.soc.siem.normalizer.mappers.helpers.{CiscoDateMapper, CiscoImportanceLevel, HostnameVsFqdn}

class CiscoIosIsrMapper extends Mapper[(DevTypeToVendorMapping, InternalSocEvent)] {
    override def map(src: (DevTypeToVendorMapping, InternalSocEvent)): SocEvent = {
        val (devTypeMappings, isoc) = src

        val (eventSourceFqdn, eventSourceHostname) = HostnameVsFqdn(None, isoc.message.eventHostname)
        val eventSourceLocation = AssetLocation(
            ip = Some(isoc.message.eventHostIP),
            fqdn = eventSourceFqdn,
            hostname = eventSourceHostname,
            host = isoc.message.eventHostIP
        )

        val eventType = isoc.event.extract("eventType")

        val vendor = devTypeMappings(isoc.message.eventDevType)
        val eventSourceInfo = EventSourceInfo(
            location = Some(eventSourceLocation),
            id = isoc.message.inputId,
            category = EventSourceCategory.NetworkDevice,
            title = vendor.product,
            vendor = vendor.vendorName
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

        val interactionDescription = InteractionDescription(
            importance = CiscoImportanceLevel(isoc.event.extract("importance")),
            reason = isoc.event.extractOpt("interactionReason"),
            action = eventType match {
                case "login_failed" | "login_success" | "ssh2_userauth" =>
                    InteractionCategory.login
                case "logout" =>
                    InteractionCategory.logout
                case "config_i" =>
                    InteractionCategory.modify
            },
            status = eventType match {
                case "login_failed" =>
                    InteractionStatus.failure
                case "login_success" | "logout" | "config_i" =>
                    InteractionStatus.success
                case "ssh2_userauth" =>
                    isoc.event.extract("status").toInteractionStatus
            }
        )

        val subjectInfo = SubjectInfo(
            category = eventType match {
                case "login_failed" | "login_success" | "ssh2_userauth" | "logout" | "config_i" =>
                    Counterpart.account
            }
        ).update(_.name.setIfDefined(isoc.event.extractOpt("subjectName")))

        val sourceLocation = InteractingAssetLocation(
            ip = isoc.event.extractOpt("sourceIp")
        )

        val destinationLocation = InteractingAssetLocation(
            ip = Some(isoc.message.eventHostIP),
            fqdn = eventSourceFqdn,
            hostname = eventSourceHostname,
            host = isoc.message.eventHostIP,
            port = isoc.event.extractOpt(int"destinationPort")
        )

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            msgId = isoc.event.extractOpt("msgId"),
            originTime = CiscoDateMapper(isoc),
            aux1 = isoc.event.extractOpt("aux1"),
            aux2 = isoc.event.extractOpt("aux2")
        )

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = CiscoIosIsrMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(eventSourceInfo),
            source = Some(sourceLocation),
            destination = Some(destinationLocation),
            interaction = Some(interactionDescription),
            subject = Some(subjectInfo),
            collector = Some(collectorInfo),
            data = Some(payload)
        )
    }
}

object CiscoIosIsrMapper {
    val name: String = "ios/isr00401"
    val version: Int = 1
}