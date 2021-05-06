package ru.gkis.soc.siem.normalizer.mappers

import ru.gkis.soc.siem.commons.Constants
import ru.gkis.soc.siem.model.{DevTypeToVendorMapping, SocEvent, _}
import ru.gkis.soc.siem.normalizer.mappers.helpers.Coalesce._
import ru.gkis.soc.siem.normalizer.mappers.helpers.HostnameVsFqdn
import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._
import ru.gkis.soc.siem.normalizer.{InternalSocEvent, ParsedMessage}


class AuditdMapper extends Mapper[(DevTypeToVendorMapping, InternalSocEvent)] {
    override def map(src: (DevTypeToVendorMapping, InternalSocEvent)): SocEvent = {
        val (devTypeMappings, isoc) = src

        val (eventSourceFqdn, eventSourceHostname) = HostnameVsFqdn(None, isoc.message.eventHostname)
        val eventLocation = AssetLocation(
            ip = Some(isoc.message.eventHostIP),
            fqdn = eventSourceFqdn,
            hostname = eventSourceHostname,
            host = isoc.message.eventHostIP
        )
        val vendor = devTypeMappings(isoc.message.eventDevType)
        val eventSource = EventSourceInfo(
            id = isoc.message.inputId,
            location = Some(eventLocation),
            title = vendor.product,
            vendor = vendor.vendorName,
            category = EventSourceCategory.OperatingSystem
        )

        isoc.event.get("type") match {
            case Some(value: String) =>
                singleLineMapper(isoc.normId, isoc.message, value.toUpperCase, isoc.event, eventSource, isoc.rawId)
            case Some(types: Seq[_]) =>
                multiLineMapper(isoc.normId, isoc.message, types.mkString(";"), isoc.event, eventSource, isoc.rawId)
            case _ =>
                throw new RuntimeException("Must not happened")
        }
    }

    private def multiLineMapper(normId: String,
                                message: ParsedMessage,
                                auditType: String,
                                event: ParsedLog,
                                eventSource: EventSourceInfo,
                                rawId: String): SocEvent = {
        val collectorLocation = AssetLocation(
            hostname = Some(message.collectorHostname),
            host = message.collectorHostIP,
            ip = Some(message.collectorHostIP)
        )

        val collectorInfo = CollectorInfo(
            organization = message.organization,
            inputId = message.inputId,
            location = Some(collectorLocation)
        )

        val (fqdn, hostname) = HostnameVsFqdn(None, event.extractOpt("hostname"))

        val sourceLocation = InteractingAssetLocation()
            .update(_.fqdn.setIfDefined(fqdn))
            .update(_.hostname.setIfDefined(hostname))
            .update(_.ip.setIfDefined(event.extractOpt("addr") ~> event.extractOpt("saddr")))
            .update(_.port.setIfDefined(event.extractOpt(int"rport") ~> event.extractOpt(int"sport") ~> event.extractOpt(int"src")))

        val destinationLocation = InteractingAssetLocation()
            .update(_.ip.setIfDefined(event.extractOpt("daddr") ~> event.extractOpt("laddr")))
            .update(_.port.setIfDefined(event.extractOpt(int"dest") ~> event.extractOpt(int"dport") ~> event.extractOpt(int"lport")))

        val subjectInfo = SubjectInfo(category = Counterpart.account)
            .update(_.id.setIfDefined(event.extractOpt("euid")))
            .update(_.category.setIfDefined {
                auditType match {
                    case "USER_AUTH" =>
                        Some(Counterpart.account)
                    case _ =>
                        None
                }
            })

        val interactionDescription = InteractionDescription(
            action = event.extract("syscall").toInteractionCategory
        )
            .update(_.status.setIfDefined(event.extractOpt("success").map(_.toInteractionStatus)))
            .update(_.reason.setIfDefined(event.extractOpt("exit")))

        val objectInfo = ObjectInfo()
            .update(_.name.setIfDefined(event.extractOpt("comm")))
            .update(_.category := event.extractOpt("syscall").toCounterpart)


        val originTime: Option[Long] = event.get("msg_timestamp").flatMap {
            case value: String =>
                Some(value)
            case values: Seq[_] =>
                values.headOption.map(_.toString)
        }.map(_.toLong)

        val paths: Option[Map[Int, String]] = event
            .get("name")
            .map {
                case value: String =>
                    Set(value)
                case values: Seq[_] =>
                    values
                        .map(_.toString)
                        .toSet
            }
            .map(_.zipWithIndex.map { case (v, i) =>
                (i -> v)
            }.toMap)

        val payload = DataPayload(
            msgId = Some("SYSCALL"),
            rawIds = Seq(rawId)
        )
            .update(_.originTime.setIfDefined(originTime))
            .update(_.aux1.setIfDefined(event.extractOpt("auid")))
            .update(_.aux2.setIfDefined(event.extractOpt("pid")))
            .update(_.aux3.setIfDefined(paths.flatMap(_.get(0))))
            .update(_.aux4.setIfDefined(paths.flatMap(_.get(1))))
            .update(_.aux5.setIfDefined(paths.flatMap(_.get(2))))
            .update(_.aux6.setIfDefined(paths.flatMap(_.get(3))))
            .update(_.aux7.setIfDefined(paths.flatMap(_.get(4))))
            .update(_.aux8.setIfDefined(paths.flatMap(_.get(5))))
            .update(_.aux9.setIfDefined(paths.flatMap(_.get(6))))
            .update(_.aux10.setIfDefined(paths.flatMap(_.get(7))))

        SocEvent(
            id = normId,
            category = Constants.normalized,
            normalizerVersion = AuditdMapper.version,
            eventTime = message.eventReceivedTime.toEpochSecond,
            interaction = Some(interactionDescription),
            subject = Some(subjectInfo),
            `object` = Some(objectInfo),
            collector = Some(collectorInfo),
            data = Some(payload),
            eventSource = Some(eventSource),
            source = Some(sourceLocation),
            destination = Some(destinationLocation)
        )
    }

    private def singleLineMapper(normId: String,
                                 message: ParsedMessage,
                                 auditType: String,
                                 event: ParsedLog,
                                 eventSource: EventSourceInfo,
                                 rawId: String): SocEvent = {
        val collectorLocation = AssetLocation(
            hostname = Some(message.collectorHostname),
            host = message.collectorHostIP,
            ip = Some(message.collectorHostIP)
        )

        val collectorInfo = CollectorInfo(
            organization = message.organization,
            inputId = message.inputId,
            location = Some(collectorLocation)
        )

        val (fqdn, hostname) = HostnameVsFqdn(None, event.extractOpt("hostname"))

        val sourceLocation = InteractingAssetLocation()
            .update(_.fqdn.setIfDefined(fqdn))
            .update(_.hostname.setIfDefined(hostname))
            .update(_.ip.setIfDefined(event.extractOpt("addr") ~> event.extractOpt("saddr")))
            .update(_.port.setIfDefined(event.extractOpt(int"rport") ~> event.extractOpt(int"sport") ~> event.extractOpt(int"src")))

        val destinationLocation = InteractingAssetLocation()
            .update(_.ip.setIfDefined(event.extractOpt("daddr") ~> event.extractOpt("laddr")))
            .update(_.port.setIfDefined(event.extractOpt(int"dest") ~> event.extractOpt(int"dport") ~> event.extractOpt(int"lport")))

        val interactionDescription = InteractionDescription(
            action = auditType.toInteractionCategory
        )
            .update(_.status := {
                auditType match {
                    case "EXECVE" =>
                        InteractionStatus.success
                    case _ =>
                        (event.extractOpt("interaction_status") ~> event.extractOpt("res")).toInteractionStatus
                }
            })

        val subjectInfo = SubjectInfo()
            .update(_.name.setIfDefined(event.extractOpt("acct")))
            .update(_.id.setIfDefined(
                auditType match {
                    case "USER_AUTH" | "USER_END" | "USER_LOGIN"=>
                        event.extractOpt("id")
                    case _ =>
                        event.extractOpt("euid") ~> event.extractOpt("uid")
                }))
            .update(_.category.setIfDefined {
                auditType match {
                    case "AVC" =>
                        Some(Counterpart.system)
                    case "USER_AUTH" =>
                        Some(Counterpart.account)
                    case _ =>
                        None
                }
            })

        val objectInfo = ObjectInfo()
            .update(_.id.setIfDefined(event.extractOpt("id")))
            .update(_.category := {
                auditType match {
                    case "AVC" =>
                        event.extractOpt("tclass") match {
                            case Some("file") =>
                                Counterpart.file
                            case Some("process") =>
                                Counterpart.process
                            case _ =>
                                Counterpart.UnknownCounterpart
                        }
                    case other =>
                        other.toCounterpart
                }
            })
            .update(_.name.setIfDefined(event.extractOpt("a0")))
            .update(_.property.setIfDefined(event.extractOpt("argc")))
            .update(_.value.setIfDefined(auditType match {
                case "EXECVE" =>
                    val argumentCount: Option[String] = event.extractOpt("argc")

                    argumentCount.map { case count =>
                        val command = (0 until count.toInt)
                            .map(i => s"a$i")
                            // Don't change to flatMap, because some implicit magic broke code
                            .map(key => event.extractOpt(key))
                            .collect {
                                case Some(value) =>
                                    value
                            }
                            .mkString(" ")

                        command
                    }
                case _ =>
                    None
            }))

        val payload = DataPayload(
            rawIds = Seq(rawId),
            msgId = Some(auditType)
        )
            .update(_.originTime.setIfDefined(event.extractOpt("msg_timestamp").map(_.toLong)))
            .update(_.aux1.setIfDefined(event.extractOpt("auid")))
            .update(_.aux2.setIfDefined(event.extractOpt("pid")))
            .update(_.aux4.setIfDefined {
                auditType match {
                    case "AVC" =>
                        event.extractOpt("dev")
                    case _ =>
                        event.extractOpt("ses")
                }
            })
            .update(_.aux5.setIfDefined {
                auditType match {
                    case "USER_AUTH" | "USER_END" =>
                        event.extractOpt("terminal")
                    case "USER_CMD" =>
                        event.extractOpt("cmd")
                    case _ =>
                        event.extractOpt("subj")
                }
            })
            .update(_.aux6.setIfDefined {
                auditType match {
                    case "USER_CMD" =>
                        event.extractOpt("subj")
                    case "AVC" =>
                        event.extractOpt("comm")
                    case _ =>
                        event.extractOpt("exe")
                }
            })
            .update(_.aux7.setIfDefined {
                auditType match {
                    case "USER_AUTH" =>
                        event.extractOpt("op")
                    case "USER_CMD" =>
                        None
                    case _ =>
                        event.extractOpt("terminal")
                }
            })
            .update(_.aux8.setIfDefined {
                auditType match {
                    case "USER_AUTH" =>
                        event.extractOpt("subj")
                    case "USER_CHAUTHTOK" =>
                        event.extractOpt("op")
                    case _ =>
                        event.extractOpt("aux8")
                }

            })
            .update(_.aux9.setIfDefined {
                auditType match {
                    case "USER_CMD" =>
                        event.extractOpt("terminal")
                    case "USER_LOGIN" =>
                        event.extractOpt("subj")
                    case _ =>
                        None
                }

            })
            .update(_.aux10.setIfDefined {
                auditType match {
                    case "USER_CMD" =>
                        event.extractOpt("cwd")
                    case "USER_END" =>
                        event.extractOpt("op")
                    case _ =>
                        None
                }

            })

        SocEvent(
            id = normId,
            category = Constants.normalized,
            normalizerVersion = AuditdMapper.version,
            eventTime = message.eventReceivedTime.toEpochSecond,
            interaction = Some(interactionDescription),
            subject = Some(subjectInfo),
            `object` = Some(objectInfo),
            collector = Some(collectorInfo),
            data = Some(payload),
            eventSource = Some(eventSource),
            source = Some(sourceLocation),
            destination = Some(destinationLocation)
        )
    }
}

object AuditdMapper {
    val name: String = "reassembledAuditD01"
    val version: Int = 1
}
