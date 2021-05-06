package ru.gkis.soc.siem.normalizer.mappers

import java.time.ZonedDateTime
import ru.gkis.soc.siem.commons.Constants
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.normalizer.InternalSocEvent
import scalapb.GeneratedMessage
import ru.gkis.soc.siem.normalizer.mappers.helpers.Coalesce._
import ru.gkis.soc.siem.normalizer.mappers.helpers.HostnameVsFqdn
import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._

class SymantecMapper extends Mapper[(DevTypeToVendorMapping, InternalSocEvent)] {

    override def map(src: (DevTypeToVendorMapping, InternalSocEvent)): GeneratedMessage = {
        val (devTypeMappings, isoc) = src

        // eventSource =================================================================================================
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
            subsys = isoc.event.extractOpt("ModuleName"),
            title = vendor.product,
            vendor = vendor.vendorName
        )

        // collector ===================================================================================================
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

        // subject =====================================================================================================
        val subjectName = isoc.event.extractOpt("UserName")
        val subjectDomain = isoc.event.extractOpt("UserDomainName")
        val subjectInfo = if (subjectName.isDefined || subjectDomain.isDefined)
                                Some(SubjectInfo(
                                    name = subjectName,
                                    domain = subjectDomain,
                                    category = Counterpart.account
                                ))
                            else
                                None

        // object ======================================================================================================
        val objectName = isoc.event.extractOpt("ObjectName") ~> isoc.event.extractOpt("ProcessName")
        val objectPath = isoc.event.extractOpt("ObjectPath") ~> isoc.event.extractOpt("URL")
        val objectType = isoc.event.extractOpt("ObjectType").map(_.toCounterpart) ~>
                         isoc.event.extractOpt("ProcessName").map(_ => Counterpart.process) ~>
                         isoc.event.extractOpt("URL").map(_ => Counterpart.url) ~>
                         isoc.event.extractOpt("ObjectPath").map(_ => Counterpart.file)
        val objectInfo = if (objectName.isDefined || objectPath.isDefined)
                                Some(ObjectInfo(
                                    name = objectName,
                                    path = objectPath,
                                    category = objectType.getOrElse(Counterpart.UnknownCounterpart)
                                ))
                            else
                                None

        // interaction description =====================================================================================
        val severity = isoc.event.extract("Severity")
        val block = isoc.event.extract(int"Block")
        val delete = isoc.event.extract(int"Deleted")
        val typeActivity = isoc.event.extract("TypeActivity")

        val interactionDescription = InteractionDescription(
            importance = severity.toImportanceLevel,
            protocol = isoc.event.extractOpt("Proto"),
            action = if (delete == 1)                   InteractionCategory.remove
                     else if (block == 1 & delete == 0) InteractionCategory.lock
                     else if (block == 0 & delete == 0) InteractionCategory.detect
                     else                               InteractionCategory.UnknownInteractionCategory,
            reason = Some(typeActivity),
            status = InteractionStatus.success
        )

        // source and destination ======================================================================================
        val (sourceLocation, destinationLocation) = typeActivity match {
            case "NetworkAttack" =>
                val source = InteractingAssetLocation(
                    ip = isoc.event.extractOpt("SourceIP"),
                    host = isoc.event.extractOpt("SourceIP").getOrElse(Constants.unknown)
                )
                val hostname = isoc.event.extractOpt("HostName")
                val destination = InteractingAssetLocation(
                    ip = isoc.event.extractOpt("IP"),
                    hostname = hostname,
                    host = (isoc.event.extractOpt("IP") ~> hostname).getOrElse(Constants.unknown),
                    fqdn = isoc.event.extractOpt("FQDN"),
                    port = isoc.event.extractOpt(int"Port")
                )
                (Some(source), Some(destination))
            case _ =>
                val hostname = isoc.event.extractOpt("HostName")
                val source = InteractingAssetLocation(
                    ip = isoc.event.extractOpt("IP"),
                    hostname = hostname,
                    host = (isoc.event.extractOpt("IP") ~> hostname).getOrElse(Constants.unknown),
                    fqdn = isoc.event.extractOpt("FQDN")
                )
                (Some(source), None)
        }

        // data ========================================================================================================
        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = ZonedDateTime.parse(isoc.event.extract("DetectionTime")).toEpochSecond,
            time  = isoc.message.eventReceivedTime.toEpochSecond,
            aux1  = isoc.event.extractOpt("Sha256").map(_.toLowerCase),
            aux2  = isoc.event.extractOpt("Block"),
            aux3  = isoc.event.extractOpt("EventName"),
            aux4  = isoc.event.extractOpt("SignatureDescription"),
            aux5  = isoc.event.extractOpt("Signature"),
            aux6  = isoc.event.extractOpt("Action"),
            aux7  = isoc.event.extractOpt("TypeActivity"),
            aux8  = isoc.event.extractOpt("Delete"),
            aux9  = isoc.event.extractOpt("MailSubject"),
            aux10 = isoc.event.extractOpt("Signatureid")
        )

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = SymantecMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(eventSourceInfo),
            source = sourceLocation,
            destination = destinationLocation,
            interaction = Some(interactionDescription),
            subject = subjectInfo,
            `object` = objectInfo,
            collector = Some(collectorInfo),
            data = Some(payload)
        )
    }

}

object SymantecMapper {
    val name: String = "symantec"
    val version: Int = 1
}
