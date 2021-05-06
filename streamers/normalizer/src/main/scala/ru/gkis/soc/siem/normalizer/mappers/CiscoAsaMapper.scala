package ru.gkis.soc.siem.normalizer.mappers

import ru.gkis.soc.siem.commons.Constants
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.normalizer.InternalSocEvent
import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._
import ru.gkis.soc.siem.normalizer.mappers.helpers.{CiscoDateMapper, CiscoImportanceLevel, HostnameVsFqdn, ProtocolResolver}


class CiscoAsaMapper extends Mapper[(DevTypeToVendorMapping, InternalSocEvent)] {
    override def map(src: (DevTypeToVendorMapping, InternalSocEvent)): SocEvent = {
        val (devTypeMappings, isoc) = src

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
            category = EventSourceCategory.Firewall,
            subsys = isoc.event.extractOpt("eventSourceSubsys"),
            title = vendor.product,
            vendor = vendor.vendorName
        )

        val sourceLocation = InteractingAssetLocation()
            .update(_.ip.setIfDefined(isoc.event.extractOpt("sourceLocationIp")))
            .update(_.port.setIfDefined(isoc.event.extractOpt(int"sourceLocationPort")))

        val destinationLocation = InteractingAssetLocation()
            .update(_.ip.setIfDefined(isoc.event.extractOpt("destinationLocationIp")))
            .update(_.port.setIfDefined(isoc.event.extractOpt(int"destinationLocationPort")))

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


        val interactionDescription = InteractionDescription()
            .update(_.importance.setIfDefined(isoc.event.extractOpt("datapayloadMsgId").collect {
                case _ => CiscoImportanceLevel(isoc.event.extract("interactionImportance"))
            }))
            .update(_.action.setIfDefined(isoc.event.extractOpt("datapayloadMsgId").collect {
                case "113004" | "113012" | "113015" | "605005" | "611101" =>
                    InteractionCategory.login
                case "111008" | "111010" =>
                    InteractionCategory.execute
                case "106023" | "710003" | "106001" | "106006" | "106007" | "106011" | "106014" =>
                    InteractionCategory.deny
                case "104001" | "104002" =>
                    InteractionCategory.info
                case "105005" =>
                    InteractionCategory.alert
                case "105008" | "105009" =>
                    InteractionCategory.check
            }))
            .update(_.reason.setIfDefined(isoc.event.extractOpt("datapayloadMsgId").collect {
                case "113004" =>
                    "successfully authenticated"
                case "113012" =>
                    "successfully authenticated to the local user database"
                case "113015" | "104001" | "104002" | "105005" =>
                    isoc.event.extract("interactionReason")
                case "605005" =>
                    "successfully authenticated"
                case "611101" =>
                    "User authentication succeeded"
                case "111008" =>
                    "User executed the command"
                case "111010" =>
                    "User made a configuration change."
                case "710003" =>
                    "access denied by ACL"
                case "105008" | "105009" =>
                    "Interface_checked"
                case "106001" =>
                    "Inbound TCP connection denied by the security policy"
                case "106006" | "106007" =>
                    "Deny inbound UDP"
                case "106011" =>
                    "Deny_inbound_no_xlate"
                case "106014" =>
                    "Deny inbound icmp"
            }))
            .update(_.status.setIfDefined(isoc.event.extractOpt("datapayloadMsgId").collect {
                case "113004" | "113012" | "605005" | "611101" | "111008" | "111010" | "111010" | "106023" | "710003" | "105005" | "105008" | "106001" | "106006" | "106007" | "106011" | "106014" =>
                    InteractionStatus.success
                case "113015" =>
                    InteractionStatus.failure
                case "105009" =>
                    isoc.event.extract("interactionStatus") match {
                        case "Passed" =>
                            InteractionStatus.success
                        case "Failed" | "Undetermined" =>
                            InteractionStatus.failure
                    }
            }))
            .update(_.protocol.setIfDefined(isoc.event.extractOpt("interactionProtocol").map(ProtocolResolver(_))))
            .update(_.protocol.setIfDefined(isoc.event.extractOpt("datapayloadMsgId").collect {
                case "106001" =>
                    ProtocolResolver("tcp")
                case "106006" | "106007" =>
                    ProtocolResolver("udp")
            }))
            .update(_.importance.setIfDefined(isoc.event.extractOpt("datapayloadMsgId").collect {
                case "105009" =>
                    isoc.event.extract("interactionStatus") match {
                        case "Passed" =>
                            ImportanceLevel.INFO
                        case "Failed" | "Undetermined" =>
                            ImportanceLevel.MEDIUM
                    }
                case "104001" | "104002" =>
                    ImportanceLevel.HIGH
                case "105005" =>
                    ImportanceLevel.MEDIUM
                case "105008" | "106001" | "106006" | "106007" | "106011" | "106014" =>
                    ImportanceLevel.INFO
            }))

        val subjectInfo = SubjectInfo(
            name = isoc.event.extractOpt("subjectName")
        ).update(_.category.setIfDefined(isoc.event.extractOpt("datapayloadMsgId").collect {
            case "113004" | "113012" | "113015" | "605005" | "611101" | "111008" | "111010" =>
                Counterpart.account
            case "106011" =>
                Counterpart.interface
        }))

        val objectInfo = ObjectInfo()
            .update(_.category.setIfDefined(isoc.event.extractOpt("datapayloadMsgId").collect {
                case "113004" | "113012" | "113015" | "611101" =>
                    Counterpart.system
                case "111008" | "111010" =>
                    Counterpart.command
                case "106023" =>
                    Counterpart.connection
                case "105008" | "105009" | "106001" | "106006" | "106007" | "106011" | "106014" =>
                    Counterpart.interface
            }))
            .update(_.value.setIfDefined(isoc.event.extractOpt("command")))
            .update(_.value.setIfDefined(isoc.event.extractOpt("datapayloadMsgId").collect {
                case "105009" =>
                    isoc.event.extract("objectValue")
            }))
            .update(_.name.setIfDefined(isoc.event.extractOpt("datapayloadMsgId").collect {
                case "106001" | "106006" | "106011" | "106014" =>
                    isoc.event.extract("objectName")
            }))


        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            time = isoc.message.eventReceivedTime.toEpochSecond,
            interface = isoc.event.extractOpt("dataPayloadInterface"),
            msgId = isoc.event.extractOpt("datapayloadMsgId"),
            aux1 = isoc.event.extractOpt("aux1"),
            aux4 = isoc.event.extractOpt("aux4"),
            aux5 = isoc.event.extractOpt("aux5"),
            aux10 = isoc.event.extractOpt("aux10")
        ).update(_.originTime.setIfDefined(isoc.event.extractOpt("datapayloadMsgId").collect {
            case _ =>
                CiscoDateMapper(isoc)
        }))

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = CiscoAsaMapper.version,
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

object CiscoAsaMapper {
    val name: String = "asa00401"
    val version: Int = 1
}