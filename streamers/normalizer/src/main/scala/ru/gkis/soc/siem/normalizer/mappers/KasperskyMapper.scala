package ru.gkis.soc.siem.normalizer.mappers

import java.time.ZonedDateTime
import ru.gkis.soc.siem.commons.Constants
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.normalizer.InternalSocEvent
import ru.gkis.soc.siem.normalizer.mappers.helpers.Coalesce._
import ru.gkis.soc.siem.normalizer.mappers.helpers.HostnameVsFqdn
import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._

class KasperskyMapper extends Mapper[(DevTypeToVendorMapping, InternalSocEvent)] {

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
            subsys = isoc.event.extractOpt("ModuleName"),
            title = vendor.product,
            vendor = vendor.vendorName
        )


        //Fill information about subject

        val subjectName = isoc.event.extractOpt("UserName")
        val subjectDomain = isoc.event.extractOpt("UserDomainName")

        //Fill information about object

        val objectName = isoc.event.extractOpt("ObjectName") ~> isoc.event.extractOpt("ProcessName")
        val objectPath = isoc.event.extractOpt("ObjectPath") ~> isoc.event.extractOpt("URL")

        val typeActivity = isoc.event.extract("TypeActivity")

        val (subjectInfo, objectInfo) = typeActivity match {
            case "NetworkAttack" =>
                val obj = if (subjectName.isDefined || subjectDomain.isDefined)
                    Some(ObjectInfo(
                        name = subjectName,
                        domain = subjectDomain,
                        category = Counterpart.account
                    ))
                else
                    None
                (None, obj)
            case _ =>
                val subj = if (subjectName.isDefined || subjectDomain.isDefined)
                               Some(SubjectInfo(
                                   name = subjectName,
                                   domain = subjectDomain,
                                   category = Counterpart.account
                               ))
                           else
                               None
                val obj = if (objectName.isDefined || objectPath.isDefined)
                              Some(ObjectInfo(
                                  name = objectName,
                                  path = objectPath,
                                  category = isoc.event.extractOpt("ObjectType").toCounterpart
                              ))
                          else
                              None
                (subj, obj)
        }

        val (sourceLocation, destinationLocation) = typeActivity match {
            case "NetworkAttack" =>
                val source = InteractingAssetLocation(
                    ip = isoc.event.extractOpt("SourceIP"),
                    host = isoc.event.extractOpt("SourceIP").getOrElse(Constants.unknown)
                )
                val hostname = isoc.event.extractOpt("HostName").map(cleanTilda)
                val destination = InteractingAssetLocation(
                    ip = isoc.event.extractOpt("IP"),
                    hostname = hostname,
                    host = (isoc.event.extractOpt("IP") ~> hostname).getOrElse(Constants.unknown),
                    fqdn = isoc.event.extractOpt("FQDN").map(cleanTilda),
                    port = isoc.event.extractOpt(int"Port")
                )
                (Some(source), Some(destination))
            case _ =>
                val hostname = isoc.event.extractOpt("HostName").map(cleanTilda)
                val source = InteractingAssetLocation(
                    ip = isoc.event.extractOpt("IP"),
                    hostname = hostname,
                    host = (isoc.event.extractOpt("IP") ~> hostname).getOrElse(Constants.unknown),
                    fqdn = isoc.event.extractOpt("FQDN").map(cleanTilda)
                )
                (Some(source), None)
        }

        //Fill information about interaction

        val severity = isoc.event.extract("Severity")
        val nameblock = isoc.event.extract(int"Block")
        val namedelete = isoc.event.extract(int"Deleted")

        val interactionDescription = InteractionDescription(
            importance = severity.toImportanceLevel,
            protocol = isoc.event.extractOpt("Proto"),
            action = if (namedelete == 1)                       InteractionCategory.remove
                     else if (nameblock == 1 & namedelete == 0) InteractionCategory.lock
                     else if (nameblock == 0 & namedelete == 0) InteractionCategory.detect
                     else                                       InteractionCategory.UnknownInteractionCategory,
            reason = Some(typeActivity),
            status = InteractionStatus.success
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

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = ZonedDateTime.parse(isoc.event.extract("DetectionTime")).toEpochSecond,
            time = isoc.message.eventReceivedTime.toEpochSecond,
            aux1 = isoc.event.extractOpt("Sha256").map(_.toLowerCase),
            aux2 = isoc.event.extractOpt("Sha1"),
            aux3 = isoc.event.extractOpt("EventType"),
            aux4 = isoc.event.extractOpt("SignatureDescription"),
            aux5 = isoc.event.extractOpt("Signature"),
            aux6 = isoc.event.extractOpt("ID"),
            aux7 = isoc.event.extractOpt("SensorName"),
            aux8 = isoc.event.extractOpt("HostDomain"),
            aux9 = isoc.event.extractOpt("MailSubject")
        )

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = KasperskyMapper.version,
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

    private def cleanTilda(value: String): String = {
        value.indexOf('~') match {
            case -1 =>
                value
            case i =>
                value.substring(0, i)
        }
    }
}


object KasperskyMapper {
    val name: String = "kaspersky"
    val version: Int = 2
}
