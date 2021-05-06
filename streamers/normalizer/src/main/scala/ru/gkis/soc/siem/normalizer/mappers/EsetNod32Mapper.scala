package ru.gkis.soc.siem.normalizer.mappers

import ru.gkis.soc.siem.commons.Constants
import ru.gkis.soc.siem.model.{AssetLocation, CollectorInfo, DataPayload, DevTypeToVendorMapping, EventSourceCategory, EventSourceInfo, SocEvent, _}
import ru.gkis.soc.siem.normalizer.InternalSocEvent
import ru.gkis.soc.siem.normalizer.mappers.helpers.Coalesce._
import ru.gkis.soc.siem.normalizer.mappers.helpers.HostnameVsFqdn
import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._

import java.time.format.{DateTimeFormatter, DateTimeFormatterBuilder}
import java.time.{LocalDateTime, ZoneOffset}
import java.util.Locale

class EsetNod32Mapper extends Mapper[(DevTypeToVendorMapping, InternalSocEvent)] {
    private[this] val formatter: DateTimeFormatter = new DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .appendPattern("dd-MMM-yyyy HH:mm:ss")
        .toFormatter(Locale.ENGLISH)

    override def map(src: (DevTypeToVendorMapping, InternalSocEvent)): SocEvent = {
        val (devTypeMappings, isoc) = src

        //Fill information about events source

        val (eventSourceFqdn, eventSourceHostname) = HostnameVsFqdn(None, isoc.message.eventHostname)
        val eventSourceLocation = AssetLocation(
            ip = Some(isoc.message.eventHostIP),
            fqdn = eventSourceFqdn,
            hostname = eventSourceHostname,
            host = isoc.message.eventHostIP
        )

        val vendor = devTypeMappings(isoc.message.eventDevType)

        val eventSourceInfo = EventSourceInfo(
            location = Some(eventSourceLocation),
            id = isoc.message.inputId,
            category = EventSourceCategory.AntiVirus,
            title = vendor.product,
            vendor = vendor.vendorName
        )

        //Fill information about collector
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

        val eventType: String = isoc.event.extract("event_type").toLowerCase

        val originTime = LocalDateTime.parse(isoc.event.extract("occured"), formatter).atZone(ZoneOffset.UTC)

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = originTime.toEpochSecond,
            time = isoc.message.eventReceivedTime.toEpochSecond,
            msgId = Some(eventType),
            aux1 = isoc.event.extractOpt("hash").map(_.toLowerCase),
            aux2 = isoc.event.extractOpt("source_uuid"),
            aux3 = isoc.event.extractOpt("threat_name") ~> isoc.event.extractOpt("rule_id"),
            aux4 = isoc.event.extractOpt(boolean"inbound").map(_.toString) ~> isoc.event.extractOpt("processname"),
            aux5 = eventType match {
                case "threat_event" =>
                    isoc.event.extractOpt("threat_type")
                case _ =>
                    isoc.event.extractOpt(int"aggregate_count").map(_.toString) ~> isoc.event.extractOpt("scanner_id")
            },
            aux6 = isoc.event.extractOpt(boolean"threat_handled").map(_.toString),
            aux7 = isoc.event.extractOpt(boolean"need_restart").map(_.toString),
            aux8 = isoc.event.extractOpt("firstseen"),
            aux9 = eventType match {
                case "threat_event" =>
                    isoc.event.extractOpt("scanner_id")
                case _ =>
                    None
            },
            aux10 = isoc.event.extractOpt("scan_id")
        )

        val action: Option[String] = isoc.event.extractOpt("action") ~> isoc.event.extractOpt("action_taken")

        val (fqdn, hostname) = HostnameVsFqdn(None, isoc.event.extractOpt("hostname"))

        val sourceLocation = InteractingAssetLocation(
            ip = eventType match {
                case "filteredwebsites_event" =>
                    isoc.event.extractOpt("ipv4") ~> isoc.event.extractOpt("ipv6")
                case "firewallaggregated_event" =>
                    isoc.event.extractOpt("source_address")
                case _ =>
                    None
            },
            port = isoc.event.extractOpt(int"source_port"),
            hostname = hostname,
            fqdn = fqdn
        )

        val destinationLocation = InteractingAssetLocation(
            ip = eventType match {
                case "filteredwebsites_event" =>
                    isoc.event.extractOpt("target_address")
                case _ =>
                    isoc.event.extractOpt("ipv4") ~> isoc.event.extractOpt("ipv6") ~> isoc.event.extractOpt("target_address")
            },
            hostname = hostname,
            fqdn = fqdn,
            port = isoc.event.extractOpt(int"target_port")
        )

        val interactionDescription = InteractionDescription(
            importance = isoc.event.extract("severity").toImportanceLevel
        )
            .update(_.action.setIfDefined(eventType match {
                case "audit_event" =>
                    action.collect {
                        case "login attempt" =>
                            InteractionCategory.login
                        case "logout" =>
                            InteractionCategory.logout
                    }
                case "firewallaggregated_event" =>
                    Some(InteractionCategory.connect)
                case "filteredwebsites_event" =>
                    Some(InteractionCategory.lock)
                case "threat_event" =>
                    action.collect {
                        case "cleaned by deleting" =>
                            InteractionCategory.remove
                        case "connection terminated" =>
                            InteractionCategory.terminate
                    }

            }))
            .update(_.status.setIfDefined(isoc.event.extractOpt("result").map(_.toInteractionStatus)))
            .update(_.reason.setIfDefined(isoc.event.extractOpt("detail") ~> isoc.event.extractOpt("event") ~> isoc.event.extractOpt("circumstances")))
            .update(_.protocol.setIfDefined(isoc.event.extractOpt("protocol")))

        val user: Option[String] = (isoc.event.extractOpt("user") match {
            case Some(empty) if empty.isEmpty =>
                None
            case Some(name) =>
                Some(name)
            case _ =>
                None
        }) ~> isoc.event.extractOpt("parsed_username")

        val subjectInfo = SubjectInfo(category = Counterpart.account)
            .update(_.domain.setIfDefined(isoc.event.extractOpt("domain") ~> isoc.event.extractOpt("parsed_domain")))
            .update(_.name.setIfDefined(user))

        val objectInfo = ObjectInfo()
            .update(_.category.setIfDefined(eventType match {
                case "firewallaggregated_event" | "filteredwebsites_event" =>
                    Some(Counterpart.process)
                case "threat_event" =>
                    Some(Counterpart.malwareObject)
                case _ =>
                    None
            }))
            .update(_.name.setIfDefined(isoc.event.extractOpt("process_name")))
            .update(_.path.setIfDefined(isoc.event.extractOpt("object_uri")))

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = EsetNod32Mapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(eventSourceInfo),
            source = Some(sourceLocation),
            destination = Some(destinationLocation),
            interaction = Some(interactionDescription),
            subject = Some(subjectInfo),
            `object` = Some(objectInfo),
            collector = Some(collectorInfo),
            data = Some(payload)
        )
    }
}


object EsetNod32Mapper {
    val name: String = "esetnode02701"
    val version: Int = 1
}
