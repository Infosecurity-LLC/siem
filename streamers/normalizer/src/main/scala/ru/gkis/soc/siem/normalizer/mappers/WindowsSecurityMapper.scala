package ru.gkis.soc.siem.normalizer.mappers

import java.time.ZonedDateTime
import ru.gkis.soc.siem.commons.Constants
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.normalizer.InternalSocEvent
import ru.gkis.soc.siem.normalizer.mappers.helpers.Coalesce.canCoalesceString
import ru.gkis.soc.siem.normalizer.mappers.helpers.HostnameVsFqdn
import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._
import ru.gkis.soc.siem.normalizer.mappers.helpers.WindowsAccessMask._
import scalapb.lenses.Lens

class WindowsSecurityMapper extends Mapper[(DevTypeToVendorMapping, InternalSocEvent)] {

    private val windowsEventIdLogon = Set("4624", "4801", "4625")
    private val windowsEventIdGroupAd = Set("4729", "4733", "4747", "4752", "4757", "4762",
                                            "4728", "4732", "4746", "4751", "4756", "4761",
                                            "4764", "4785", "4786", "4787", "4788")
    private val windowsEventIdModifyUser = Set("4722", "4725", "4720", "4726", "4723", "4724")
    private val windowsEventIdKerberos = Set("4771", "4768")
    private val windowsEventIdNTLM = Set("4776")
    private val windowsEventIdSetPass = Set("4794")
    private val windowsEventIdAddSid = Set("4766", "4765")
    private val windowsEventIdKerberService = Set("4769")
    private val windowsEventIdChangeUser = Set("4738")
    private val windowsEventIdChangeAudit = Set("4719")

    private val eventSourceHostnameGetter = Lens.unit[EventSourceInfo].location.optionalHostname
    private val eventSourceFqdnGetter = Lens.unit[EventSourceInfo].location.optionalFqdn
    private val eventSourceIpGetter = Lens.unit[EventSourceInfo].location.optionalIp


    override def map(src: (DevTypeToVendorMapping, InternalSocEvent)): SocEvent = {
        val (devTypeMappings, isoc) = src
        val vendor = devTypeMappings(isoc.message.eventDevType)
        val windowsEventId = isoc.event.extract("EventID")

        if      (windowsEventIdLogon.contains(windowsEventId))        mapWindowsEventLogon(isoc, vendor, windowsEventId)
        else if (windowsEventIdGroupAd.contains(windowsEventId))      mapWindowsEventGroupAd(isoc, vendor, windowsEventId)
        else if (windowsEventIdModifyUser.contains(windowsEventId))   mapWindowsEventModifyUser(isoc, vendor, windowsEventId)
        else if (windowsEventIdKerberos.contains(windowsEventId))     mapWindowsEventKerberos(isoc, vendor, windowsEventId)
        else if (windowsEventIdNTLM.contains(windowsEventId))         mapWindowsEventNTML(isoc, vendor, windowsEventId)
        else if (windowsEventIdSetPass.contains(windowsEventId))      mapWindowsEventSetPass(isoc, vendor, windowsEventId)
        else if (windowsEventIdAddSid.contains(windowsEventId))       mapWindowsEventAddSidHistory(isoc, vendor, windowsEventId)
        else if (windowsEventIdKerberService.contains(windowsEventId))mapWindowsEventKerberService(isoc, vendor, windowsEventId)
        else if (windowsEventIdChangeUser.contains(windowsEventId))   mapWindowsEventChangeUser(isoc, vendor, windowsEventId)
        else if (windowsEventIdChangeAudit.contains(windowsEventId))  mapWindowsEventChangeAudit(isoc, vendor, windowsEventId)
        else                                                          mapWindowsEventAudit(isoc, vendor, windowsEventId)
    }

    private def mapEventSource(isoc: InternalSocEvent, vendor: DeviceVendor) = {
        val (eventFqdn, eventHostname) = HostnameVsFqdn(None, isoc.message.eventHostname)
        val eventSourceLocation = AssetLocation(
            fqdn = eventFqdn,
            hostname = eventHostname,
            ip = Some(isoc.message.eventHostIP),
            host = isoc.message.eventHostIP
        )

        EventSourceInfo(
            location = Some(eventSourceLocation),
            id = isoc.message.inputId,
            category = EventSourceCategory.OperatingSystem,
            subsys = isoc.event.extractOpt("Channel"),
            title = vendor.product,
            vendor = vendor.vendorName
        )
    }

    private def mapCollectorInfo(isoc: InternalSocEvent) = {
        val (collectorFqdn, collectorHostname) = HostnameVsFqdn(None, Some(isoc.message.collectorHostname))
        val collectorLocation = AssetLocation(
            fqdn = collectorFqdn,
            hostname = collectorHostname,
            host = isoc.message.collectorHostIP,
            ip = Some(isoc.message.collectorHostIP)
        )

        CollectorInfo(
            organization = isoc.message.organization,
            inputId = isoc.message.inputId,
            location = Some(collectorLocation)
        )
    }

    private def mapSubjectInfo(isoc: InternalSocEvent, cat: Counterpart) =
        SubjectInfo(
            name = isoc.event.extractOpt("SubjectUserName"),
            domain = isoc.event.extractOpt("SubjectDomainName"),
            id = isoc.event.extractOpt("SubjectUserSid"),
            category = cat
        )

    private def mapInteractionDescription(isoc: InternalSocEvent, category: InteractionCategory, lgnType: Option[Int] = None, status: InteractionStatus = InteractionStatus.success) =
        InteractionDescription(
            action = category,
            importance = isoc.event.extractOpt("SeverityValue").toImportanceLevel,
            logonType = lgnType,
            status = status,
            reason = isoc.event.extractOpt("SubStatus").orElse(isoc.event.extractOpt("Status"))
        )

    /**
     * maps destination
     * @param isoc parsed audit data
     * @param eventSource for all events except windows filtering platform destination equals eventSource. So we try to merge
     *                    this two sources to make destination data better
     * @return
     */
    private def mapDestination(isoc: InternalSocEvent, eventSource: Option[EventSourceInfo] = None): InteractingAssetLocation = {
        val dstAddress = isoc.event.extractOpt("Hostname")   // try to get legit Hostname field
        val (dstFqdn, dstHostname) = dstAddress.fold((eventSource.flatMap(eventSourceFqdnGetter.get), eventSource.flatMap(eventSourceHostnameGetter.get)))(str => HostnameVsFqdn(None, Some(str)))
        val dstIp = eventSource.flatMap(eventSourceIpGetter.get)
        InteractingAssetLocation(
            hostname = dstHostname,
            fqdn = dstFqdn,
            host = dstIp.getOrElse(dstHostname.getOrElse(Constants.unknown)),
            ip = dstIp
        )
    }

    private def mapSource(isoc: InternalSocEvent): InteractingAssetLocation = {
        val srcIp = isoc.event.extractOpt("SourceAddress") ~> isoc.event.extractOpt("IpAddress") ~> isoc.event.extractOpt("ClientAddress")
        // i've collected some messages and this value appears to be Hostname or FQDN from time to time
        val srcAddress = isoc.event.extractOpt("WorkstationName") ~> isoc.event.extractOpt("Workstation") ~> isoc.event.extractOpt("CallerWorkname")
        // so let's handle that gently
        val (srcFqdn, srcHost) = srcAddress.fold[(Option[String], Option[String])]((None, None))(str => HostnameVsFqdn(None, Some(str)))
        InteractingAssetLocation(
            ip = srcIp,
            port = isoc.event.extractOpt(int"IpPort"),
            hostname = srcHost,
            fqdn = srcFqdn,
            host = srcIp.getOrElse(srcHost.getOrElse(Constants.unknown))
        )
    }

    /**
     * Maps Event Ids "4624" and "4801" and "4625"
     */
    def mapWindowsEventLogon(isoc: InternalSocEvent, vendor: DeviceVendor, windowsEventId: String): SocEvent = {
        val lgnType: Option[Int] = isoc.event.extractOpt(int"LogonType")
        val eventSrc: Option[EventSourceInfo] = Some(mapEventSource(isoc, vendor))

        val (sourceLocation, destinationLocation) = lgnType match {
            // for interactive logon destination is source
            case Some(2) =>
                val dst = mapDestination(isoc, eventSrc)
                (dst, dst)
            case _ =>
                (mapSource(isoc), mapDestination(isoc, eventSrc))
        }

        val objectInfo = windowsEventId match {
            case "4625" =>
                ObjectInfo(
                    category = Counterpart.account
                )
            case _ =>
                ObjectInfo(
                    category = Counterpart.host
                )
        }

        // for logon event Target is subject on a system where logon process happening
        val subjectInfo = SubjectInfo(
            name = isoc.event.extractOpt("TargetUserName"),
            domain = isoc.event.extractOpt("TargetDomainName"),
            id = isoc.event.extractOpt("TargetSid"),
            category = Counterpart.account
        )

        // for logon subject usually is no use. we consider it as an auxiliary info
        val auxInfo = mapSubjectInfo(isoc, Counterpart.account)

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = ZonedDateTime.parse(isoc.event.extract("EventTime")).toEpochSecond,
            time = isoc.message.eventReceivedTime.toEpochSecond,
            msgId = Some(windowsEventId),
            aux1 = auxInfo.name,
            aux2 = auxInfo.domain,
            aux3 = auxInfo.id,
            aux4 = isoc.event.extractOpt("Status"),
            aux5 = isoc.event.extractOpt("ProcessName"),
            aux6 = isoc.event.extractOpt("AuthenticationPackageName"),
            aux7 = isoc.event.extractOpt("LogonProcessName")
        )

        val interactionStatus = windowsEventId match {
            case "4625" =>
                InteractionStatus.failure
            case _ =>
                InteractionStatus.success
        }

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = WindowsSecurityMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = eventSrc,
            source = Some(sourceLocation),
            destination = Some(destinationLocation),
            interaction = Some(mapInteractionDescription(isoc, InteractionCategory.login, lgnType, status = interactionStatus)),
            subject = Some(subjectInfo),
            `object` = Some(objectInfo),
            collector = Some(mapCollectorInfo(isoc)),
            data = Some(payload)
        )

    }

    /**
     * Maps Event Ids "5140", "5145" and "4663"
     * "4663" - file access
     * "5140", "5145" - share access
     */
    def mapWindowsEventAudit(isoc: InternalSocEvent, vendor: DeviceVendor, windowsEventId: String): SocEvent = {
        val objectInfo = windowsEventId match {
            case "4663" =>
                ObjectInfo(
                    path = isoc.event.extractOpt("ObjectName"),
                    category = Counterpart.file
                )
            case _ =>
                ObjectInfo(
                    name = isoc.event.extractOpt("ShareName"),
                    path = isoc.event.extractOpt("ShareLocalPath"),
                    category = Counterpart.url
                )
        }

        val action = isoc.event
                         .extractOpt("AccessMask")
                         .fold[InteractionCategory](InteractionCategory.UnknownInteractionCategory)(acl => java.lang.Integer.decode(acl) match {
                             case acl if permissionSet(acl, DELETE)         => InteractionCategory.remove
                             case acl if permissionSet(acl, DELETE_DIR)     => InteractionCategory.remove
                             case acl if permissionSet(acl, WRITE)          => InteractionCategory.modify
                             case acl if permissionSet(acl, WRITE_ATTR)     => InteractionCategory.modify
                             case acl if permissionSet(acl, WRITE_EXT_ATTR) => InteractionCategory.modify
                             case acl if permissionSet(acl, WRITE_SACL)     => InteractionCategory.modify
                             case acl if permissionSet(acl, APPEND)         => InteractionCategory.modify
                             case acl if permissionSet(acl, READ)           => InteractionCategory.access
                             case acl if permissionSet(acl, READ_ATTR)      => InteractionCategory.access
                             case acl if permissionSet(acl, READ_EXT_ATTR)  => InteractionCategory.access
                             case acl if permissionSet(acl, READ_SACL)      => InteractionCategory.access
                             case acl if permissionSet(acl, EXECUTE)        => InteractionCategory.execute
                             case acl if permissionSet(acl, CHMOD)          => InteractionCategory.grant
                             case acl if permissionSet(acl, CHOWN)          => InteractionCategory.grant
                             case acl if permissionSet(acl, SYNC)           => InteractionCategory.sync
                             case _ => InteractionCategory.UnknownInteractionCategory
                         })

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = ZonedDateTime.parse(isoc.event.extract("EventTime")).toEpochSecond,
            time = isoc.message.eventReceivedTime.toEpochSecond,
            msgId = Some(windowsEventId),
            aux1 = isoc.event.extractOpt("RelativeTargetName"),
            aux2 = isoc.event.extractOpt("AccessMask"),
            aux3 = isoc.event.extractOpt("AccessList"),
            aux4 = isoc.event.extractOpt("AccessReason"),
            aux5 = isoc.event.extractOpt("ProcessName"),
            aux6 = isoc.event.extractOpt("ProcessId"),
            aux7 = isoc.event.extractOpt("ObjectType"),
            aux8 = isoc.event.extractOpt("ObjectServer")
        )

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = WindowsSecurityMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(mapEventSource(isoc, vendor)),
            source = Some(mapSource(isoc)),
            destination = Some(mapDestination(isoc)),
            interaction = Some(mapInteractionDescription(isoc, action)),
            subject = Some(mapSubjectInfo(isoc, Counterpart.account)),
            `object` = Some(objectInfo),
            collector = Some(mapCollectorInfo(isoc)),
            data = Some(payload)
        )

    }

    /**
     * Maps Event Ids "4729", "4733", "4747", "4752", "4757", "4762",
     * "4728", "4732", "4746", "4751", "4756", "4761", "4764", "4785",
     * "4786", "4787" and "4788"
     */
    def mapWindowsEventGroupAd(isoc: InternalSocEvent, vendor: DeviceVendor, windowsEventId: String): SocEvent = {
        val objectInfo = ObjectInfo(
            name = isoc.event.extractOpt("TargetUserName"),
            domain = isoc.event.extractOpt("TargetDomainName"),
            id = isoc.event.extractOpt("TargetSid"),
            property = Some("GroupMember"),
            value = isoc.event.extractOpt("MemberUser") ~> isoc.event.extractOpt("member_user") ~> isoc.event.extractOpt("MemberName") ~> isoc.event.extractOpt("member_name") ~> isoc.event.extractOpt("MemberSid"),
            category = Counterpart.system
        )

        //Fill information about interaction
        val interactionType = if      (windowsEventId == "4732") InteractionCategory.enable
                              else if (windowsEventId == "4728") InteractionCategory.enable
                              else if (windowsEventId == "4746") InteractionCategory.enable
                              else if (windowsEventId == "4751") InteractionCategory.enable
                              else if (windowsEventId == "4756") InteractionCategory.enable
                              else if (windowsEventId == "4761") InteractionCategory.enable
                              else if (windowsEventId == "4764") InteractionCategory.modify
                              else if (windowsEventId == "4785") InteractionCategory.enable
                              else if (windowsEventId == "4787") InteractionCategory.enable
                              else                               InteractionCategory.disable

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = ZonedDateTime.parse(isoc.event.extract("EventTime")).toEpochSecond,
            time = isoc.message.eventReceivedTime.toEpochSecond,
            msgId = Some(windowsEventId),
            aux1 = isoc.event.extractOpt("MemberSid"),
            aux2 = isoc.event.extractOpt("GroupTypeChange")
        )

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = WindowsSecurityMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(mapEventSource(isoc, vendor)),
            source = Some(mapSource(isoc)),
            destination = Some(mapDestination(isoc)),
            interaction = Some(mapInteractionDescription(isoc, interactionType)),
            subject = Some(mapSubjectInfo(isoc, Counterpart.account)),
            `object` = Some(objectInfo),
            collector = Some(mapCollectorInfo(isoc)),
            data = Some(payload)
        )

    }

    /**
     * Maps Event Ids "4722", "4725", "4720", "4726", "4723" and "4724"
     */
    def mapWindowsEventModifyUser(isoc: InternalSocEvent, vendor: DeviceVendor, windowsEventId: String): SocEvent = {
        val objectInfo = ObjectInfo(
            name = isoc.event.extractOpt("TargetUserName"),
            domain = isoc.event.extractOpt("TargetDomainName"),
            id = isoc.event.extractOpt("TargetSid"),
            category = Counterpart.account
        )

        //Fill information about interaction
        val interactionType = if      (windowsEventId == "4722") InteractionCategory.enable
                              else if (windowsEventId == "4725") InteractionCategory.disable
                              else if (windowsEventId == "4720") InteractionCategory.create
                              else if (windowsEventId == "4726") InteractionCategory.remove
                              else                               InteractionCategory.modify

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = ZonedDateTime.parse(isoc.event.extract("EventTime")).toEpochSecond,
            time = isoc.message.eventReceivedTime.toEpochSecond,
            msgId = Some(windowsEventId)
        )

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = WindowsSecurityMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(mapEventSource(isoc, vendor)),
            source = Some(mapSource(isoc)),
            destination = Some(mapDestination(isoc)),
            interaction = Some(mapInteractionDescription(isoc, interactionType)),
            subject = Some(mapSubjectInfo(isoc, Counterpart.account)),
            `object` = Some(objectInfo),
            collector = Some(mapCollectorInfo(isoc)),
            data = Some(payload)
        )
    }

    def mapWindowsEventKerberos(isoc: InternalSocEvent, vendor: DeviceVendor, windowsEventId: String): SocEvent = {
        val objectInfo = ObjectInfo(
            category = Counterpart.account
        )

        val interactionStatus = windowsEventId match {
            case "4771" =>
                InteractionStatus.failure
            case "4768" =>
                InteractionStatus.ongoing
        }

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = ZonedDateTime.parse(isoc.event.extract("EventTime")).toEpochSecond,
            time = isoc.message.eventReceivedTime.toEpochSecond,
            msgId = Some(windowsEventId),
            aux2 = isoc.event.extractOpt("PreAuthType"),
            aux3 = isoc.event.extractOpt("TicketOptions")
        )

        val subject = SubjectInfo(
            name = isoc.event.extractOpt("TargetUserName"),
            domain = isoc.event.extractOpt("ServiceName").map(_.replace("krbtgt/", "")).orElse(isoc.event.extractOpt("TargetDomainName")),
            id = isoc.event.extractOpt("TargetSid"),
            category = Counterpart.account
        )

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = WindowsSecurityMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(mapEventSource(isoc, vendor)),
            source = Some(mapSource(isoc)),
            destination = Some(mapDestination(isoc)),
            interaction = Some(mapInteractionDescription(isoc, InteractionCategory.login, status = interactionStatus)),
            subject = Some(subject),
            `object` = Some(objectInfo),
            collector = Some(mapCollectorInfo(isoc)),
            data = Some(payload)
        )
    }

    def mapWindowsEventNTML(isoc: InternalSocEvent, vendor: DeviceVendor, windowsEventId: String): SocEvent = {
        val objectInfo = ObjectInfo(
            category = Counterpart.account
        )

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = ZonedDateTime.parse(isoc.event.extract("EventTime")).toEpochSecond,
            time = isoc.message.eventReceivedTime.toEpochSecond,
            msgId = Some(windowsEventId)
        )

        val subject = SubjectInfo(
            name = isoc.event.extractOpt("TargetUserName"),
            category = Counterpart.account
        )

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = WindowsSecurityMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(mapEventSource(isoc, vendor)),
            source = Some(mapSource(isoc)),
            destination = Some(mapDestination(isoc)),
            interaction = Some(mapInteractionDescription(isoc, InteractionCategory.login, status = InteractionStatus.ongoing)),
            subject = Some(subject),
            `object` = Some(objectInfo),
            collector = Some(mapCollectorInfo(isoc)),
            data = Some(payload)
        )
    }

    /**
     * Maps Event Ids "4794"
     */
    def mapWindowsEventSetPass(isoc: InternalSocEvent, vendor: DeviceVendor, windowsEventId: String): SocEvent = {
        val objectInfo = ObjectInfo(
            category = Counterpart.account
        )

        val subject = SubjectInfo(
            name = isoc.event.extractOpt("SubjectUserName"),
            domain = isoc.event.extractOpt("SubjectDomainName"),
            id = isoc.event.extractOpt("SubjectUserSid"),
            category = Counterpart.account
        )

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = ZonedDateTime.parse(isoc.event.extract("EventTime")).toEpochSecond,
            aux2 = isoc.event.extractOpt("SubjectLogonId"),
            time = isoc.message.eventReceivedTime.toEpochSecond,
            msgId = Some(windowsEventId)
        )

        val interactionStatus = isoc.event.extractOpt("Status") match {
            case Some("0x0") =>
                InteractionStatus.success
            case _ =>
                InteractionStatus.failure
        }

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = WindowsSecurityMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(mapEventSource(isoc, vendor)),
            source = Some(mapSource(isoc)),
            destination = Some(mapDestination(isoc)),
            interaction = Some(mapInteractionDescription(isoc, InteractionCategory.modify, status = interactionStatus)),
            subject = Some(subject),
            `object` = Some(objectInfo),
            collector = Some(mapCollectorInfo(isoc)),
            data = Some(payload)
        )
    }

    /**
     * Maps Event Ids "4765" "4766"
     */
    def mapWindowsEventAddSidHistory(isoc: InternalSocEvent, vendor: DeviceVendor, windowsEventId: String): SocEvent = {
        val objectInfo = ObjectInfo(
            name = isoc.event.extractOpt("TargetUserName"),
            domain = isoc.event.extractOpt("TargetDomainName"),
            id = isoc.event.extractOpt("TargetSid"),
            category = Counterpart.account
        )

        val interactionStatus = windowsEventId match {
            case "4765" =>
                InteractionStatus.success
            case "4766" =>
                InteractionStatus.failure
        }

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = ZonedDateTime.parse(isoc.event.extract("EventTime")).toEpochSecond,
            aux2 = isoc.event.extractOpt("SubjectLogonId"),
            aux3 = isoc.event.extractOpt("PrivilegeList"),
            aux4 = isoc.event.extractOpt("SourceUserName"),
            aux5 = isoc.event.extractOpt("SourceSid"),
            time = isoc.message.eventReceivedTime.toEpochSecond,
            msgId = Some(windowsEventId)
        )

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = WindowsSecurityMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(mapEventSource(isoc, vendor)),
            source = Some(mapSource(isoc)),
            destination = Some(mapDestination(isoc)),
            interaction = Some(mapInteractionDescription(isoc, InteractionCategory.modify, status = interactionStatus)),
            subject = Some(mapSubjectInfo(isoc, Counterpart.account)),
            `object` = Some(objectInfo),
            collector = Some(mapCollectorInfo(isoc)),
            data = Some(payload)
        )
    }

    /**
     * Maps Event Ids "4769"
     */
    def mapWindowsEventKerberService(isoc: InternalSocEvent, vendor: DeviceVendor, windowsEventId: String): SocEvent = {
        val subject = SubjectInfo(
            name = isoc.event.extractOpt("TargetUserName").map(_.replaceFirst("@.*","")).orElse(isoc.event.extractOpt("TargetUserName")),
            domain = isoc.event.extractOpt("TargetDomainName"),
            category = Counterpart.account
        )

        val objectInfo = ObjectInfo(
            name = isoc.event.extractOpt("ServiceName"),
            id = isoc.event.extractOpt("ServiceSid"),
            category = Counterpart.account
        )

        val interactionStatus = isoc.event.extractOpt("Status") match {
            case Some("0x0") =>
                InteractionStatus.success
            case _ =>
                InteractionStatus.failure
        }

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = ZonedDateTime.parse(isoc.event.extract("EventTime")).toEpochSecond,
            aux2 = isoc.event.extractOpt("LogonGuid"),
            aux3 = isoc.event.extractOpt("TicketOptions"),
            aux4 = isoc.event.extractOpt("TicketEncryptionType"),
            aux5 = isoc.event.extractOpt("Status"),
            time = isoc.message.eventReceivedTime.toEpochSecond,
            msgId = Some(windowsEventId)
        )

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = WindowsSecurityMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(mapEventSource(isoc, vendor)),
            source = Some(mapSource(isoc)),
            destination = Some(mapDestination(isoc)),
            interaction = Some(mapInteractionDescription(isoc, InteractionCategory.login, status = interactionStatus)),
            subject = Some(subject),
            `object` = Some(objectInfo),
            collector = Some(mapCollectorInfo(isoc)),
            data = Some(payload)
        )
    }
    /**
     * Maps Event Ids "4738"
     */
    def mapWindowsEventChangeUser(isoc: InternalSocEvent, vendor: DeviceVendor, windowsEventId: String): SocEvent = {
        val objectInfo = ObjectInfo(
            name = isoc.event.extractOpt("TargetUserName"),
            domain = isoc.event.extractOpt("TargetDomainName"),
            id = isoc.event.extractOpt("TargetSid"),
            path = isoc.event.extractOpt("ProfilePath"),
            value = isoc.event.extractOpt("UserParameters"),
            group = isoc.event.extractOpt("PrimaryGroupId"),
            category = Counterpart.account
        )

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = ZonedDateTime.parse(isoc.event.extract("EventTime")).toEpochSecond,
            aux2 = isoc.event.extractOpt("SubjectLogonId"),
            aux3 = isoc.event.extractOpt("PasswordLastSet"),
            aux4 = isoc.event.extractOpt("OldUacValue"),
            aux5 = isoc.event.extractOpt("NewUacValue"),
            aux6 = isoc.event.extractOpt("UserAccountControl"),
            aux7 = isoc.event.extractOpt("DisplayName"),
            aux8 = isoc.event.extractOpt("HomeDirectory"),
            aux9 = isoc.event.extractOpt("UserWorkstations"),
            aux10 = isoc.event.extractOpt("LogonHours"),
            time = isoc.message.eventReceivedTime.toEpochSecond,
            msgId = Some(windowsEventId)
        )

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = WindowsSecurityMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(mapEventSource(isoc, vendor)),
            source = Some(mapSource(isoc)),
            destination = Some(mapDestination(isoc)),
            interaction = Some(mapInteractionDescription(isoc, InteractionCategory.modify)),
            subject = Some(mapSubjectInfo(isoc,Counterpart.account)),
            `object` = Some(objectInfo),
            collector = Some(mapCollectorInfo(isoc)),
            data = Some(payload)
        )
    }
    /**
     * Maps Event Ids "4719"
     */
    def mapWindowsEventChangeAudit(isoc: InternalSocEvent, vendor: DeviceVendor, windowsEventId: String): SocEvent = {
        val objectInfo = ObjectInfo(
            name = isoc.event.extractOpt("SubcategoryId"),
            group = isoc.event.extractOpt("CategoryId"),
            id = isoc.event.extractOpt("SubcategoryGuid"),
            value = isoc.event.extractOpt("AuditPolicyChanges"),
            category = Counterpart.rule
        )

        val payload = DataPayload(
            rawIds = Seq(isoc.rawId),
            originTime = ZonedDateTime.parse(isoc.event.extract("EventTime")).toEpochSecond,
            aux2 = isoc.event.extractOpt("SubjectLogonId"),
            time = isoc.message.eventReceivedTime.toEpochSecond,
            msgId = Some(windowsEventId)
        )

        SocEvent(
            id = isoc.normId,
            category = Constants.normalized,
            normalizerVersion = WindowsSecurityMapper.version,
            eventTime = isoc.message.eventReceivedTime.toEpochSecond,
            eventSource = Some(mapEventSource(isoc, vendor)),
            source = Some(mapSource(isoc)),
            destination = Some(mapDestination(isoc)),
            interaction = Some(mapInteractionDescription(isoc, InteractionCategory.modify)),
            subject = Some(mapSubjectInfo(isoc,Counterpart.account)),
            `object` = Some(objectInfo),
            collector = Some(mapCollectorInfo(isoc)),
            data = Some(payload)
        )
    }
}


object WindowsSecurityMapper {
    val name: String = "windows_security"
    val version: Int = 2
}