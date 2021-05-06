package ru.gkis.soc.siem.normalizer.mappers

import ru.gkis.soc.siem.commons.Constants
import ru.gkis.soc.siem.normalizer.mappers.helpers.Coalesce._
import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.normalizer.InternalSocEvent
import ru.gkis.soc.siem.normalizer.mappers.helpers.HostnameVsFqdn
import ru.gkis.soc.siem.normalizer.mappers.helpers.ProtocolResolver

class FortigateMapper extends Mapper[(DevTypeToVendorMapping, InternalSocEvent)] {

    import FortigateMapper.domainDelimiter

    override def map(src: (DevTypeToVendorMapping, InternalSocEvent)): SocEvent = {
        val isoc = src._2
        val vendor = src._1(isoc.message.eventDevType)

        val category = Constants.normalized

        val (eventSourceFqdn, eventSourceHostname) = HostnameVsFqdn(None, isoc.event.extractOpt("devname"))
        val eventSourceLocation = AssetLocation(
            ip = Some(isoc.message.eventHostIP),
            fqdn = eventSourceFqdn,
            hostname = eventSourceHostname,
            host = isoc.message.eventHostIP
        )

        val eventSourceInfo = EventSourceInfo(
            location = Some(eventSourceLocation),
            id = isoc.message.inputId,
            category = EventSourceCategory.Firewall,
            subsys = isoc.event.extractOpt("type"),
            title = vendor.product,
            vendor = vendor.vendorName
        )

        val sourceNat = NatInfo(
            ip = isoc.event.extractOpt("transip"),
            port = isoc.event.extractOpt(int"transport")
        )

        val sourceInfo = InteractingAssetLocation(
            nat = Some(sourceNat),
            ip = isoc.event.extractOpt("srcip") ~> isoc.event.extractOpt("remip") ~> isoc.event.extractOpt("ip"),
            hostname = isoc.event.extractOpt("srcname") ~> isoc.event.extractOpt("name"),
            port = isoc.event.extractOpt(int"srcport") ~> isoc.event.extractOpt(int"remport") ~> isoc.event.extractOpt(int"src_port"),
            mac = isoc.event.extractOpt("srcmac"),
            host = (isoc.event.extractOpt("srcip") ~> isoc.event.extractOpt("srcname")).getOrElse(Constants.unknown)
        )

        val destinationNat = NatInfo(
            ip = isoc.event.extractOpt("trandip"),
            port = isoc.event.extractOpt(int"trandport")
        )

        val destinationLocation = InteractingAssetLocation(
            nat = Some(destinationNat),
            ip = isoc.event.extractOpt("dstip") ~> isoc.event.extractOpt("locip") ~> isoc.event.extractOpt("tunnelip"),
            hostname = isoc.event.extractOpt("dstname") ~> isoc.event.extractOpt("hostname"),
            port = isoc.event.extractOpt(int"dstport") ~> isoc.event.extractOpt(int"locport") ~> isoc.event.extractOpt(int"dst_port"),
            mac = isoc.event.extractOpt("dstmac"),
            host = (isoc.event.extractOpt("dstip") ~> isoc.event.extractOpt("dstname")).getOrElse(Constants.unknown)
        )

        val subjectUserInfo = isoc.event.extractOpt("user").map(info => info -> info.indexOf(domainDelimiter))
        val subjectInfo = subjectUserInfo.map {
                                case (info, idx) =>
                                    SubjectInfo(
                                        category = Counterpart.account,
                                        name = if (idx > 0) Some(info.substring(0, idx)) else Some(info),
                                        domain = if (idx > 0) Some(info.substring(idx + 1, info.length)) else None,
                                        group = isoc.event.extractOpt("group") ~> isoc.event.extractOpt("profile")
                                    )
                            }

        val objType = if (isoc.event.contains("filename") || isoc.event.contains("qname")) Counterpart.file
                      else if (isoc.event.contains("url")) Counterpart.url
                      else Counterpart.UnknownCounterpart
        val objectInfo = ObjectInfo(
            category = objType,
            name = isoc.event.extractOpt("filename") ~> isoc.event.extractOpt("qname"),
            path = isoc.event.extractOpt("url")
        )

        val interactionDescription = InteractionDescription(
            importance = isoc.event.extractOpt("level").toImportanceLevel,
            direction = isoc.event.extractOpt("direction") ~> isoc.event.extractOpt("dir"),
            action = isoc.event.extractOpt("action").toInteractionCategory,
            reason = isoc.event.extractOpt("reason"),
            status = isoc.event.extractOpt("status").toInteractionStatus,
            duration = isoc.event.extractOpt(int"duration"),
            protocol = isoc.event.extractOpt("proto").map(ProtocolResolver(_))
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

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = isoc.event.extract("eventtime").toEpochTimeSeconds,
            time = isoc.message.eventReceivedTime.toEpochSecond,
            msgId = isoc.event.extractOpt("logid"),
            bytesIn = isoc.event.extractOpt(long"rcvdbyte"),
            bytesOut = isoc.event.extractOpt(long"sentbyte"),
            packetsIn = isoc.event.extractOpt(long"rcvdpkt"),
            packetsOut = isoc.event.extractOpt(long"sentpkt"),
            aux1 = isoc.event.extractOpt("msg"),
            aux2 = isoc.event.extractOpt("logdesc") ~> isoc.event.extractOpt("ref"),
            aux3 = isoc.event.extractOpt("sessionid") ~> isoc.event.extractOpt("session_id") ~> isoc.event.extractOpt("incidentserialno"),
            aux4 = isoc.event.extractOpt("server") ~> isoc.event.extractOpt("authserver") ~> isoc.event.extractOpt("call_id"),
            aux5 = isoc.event.extractOpt("service") ~> isoc.event.extractOpt("method") ~> isoc.event.extractOpt("app") ~> isoc.event.extractOpt("kind"),
            aux6 = isoc.event.extractOpt("profile") ~> isoc.event.extractOpt("applist") ~> isoc.event.extractOpt("voip_proto"),
            aux7 = isoc.event.extractOpt("catid") ~> isoc.event.extractOpt("appid") ~> isoc.event.extractOpt("attackid") ~> isoc.event.extractOpt("virusid") ~> isoc.event.extractOpt("from"),
            aux8 = isoc.event.extractOpt("catdesc") ~> isoc.event.extractOpt("appcat") ~> isoc.event.extractOpt("attack") ~> isoc.event.extractOpt("virus") ~> isoc.event.extractOpt("to"),
            aux9 = isoc.event.extractOpt("subtype")
        )

        SocEvent(
            id = isoc.normId,
            category = category,
            normalizerVersion = FortigateMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(eventSourceInfo),
            source = Some(sourceInfo),
            destination = Some(destinationLocation),
            interaction = Some(interactionDescription),
            subject = subjectInfo,
            `object` = Some(objectInfo),
            collector = Some(collectorInfo),
            data = Some(payload)
        )
    }
}

object FortigateMapper {
    val name: String = "fortigate"
    val version: Int = 1
    val domainDelimiter = "@"
}
