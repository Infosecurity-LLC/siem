package ru.gkis.soc.siem.normalizer.mappers


import org.json4s.JObject
import org.json4s.jackson.JsonMethods
import org.junit.runner.RunWith
import org.scalatest.{Matchers, WordSpec}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.model.{Counterpart, DeviceVendor, ImportanceLevel, InteractionCategory, InteractionStatus, ParsedLog, SocEvent}
import ru.gkis.soc.siem.normalizer.{InternalSocEvent, ParsedEvent, ParsedMessage}
import ru.gkis.soc.siem.normalizer.parsers.WindowsSecurityParser
import ru.gkis.soc.siem.normalizer.validators.WindowsSecurityValidator

import java.time.{ZoneOffset, ZonedDateTime}

@RunWith(classOf[JUnitRunner])
class WindowsSecurityMapperSpec extends WordSpec with Matchers {
  "WindowsSecurityMapper" when {
      "event_4766" should {
        val event_4766_1 = """{"EventTime": "2021-02-05t02:05:20.088130+03:00", "Hostname": "hostname1", "Keywords": "9232379236109516800", "EventType": "AUDIT_SUCCESS", "SeverityValue": 2, "Severity": "INFO", "EventID": 4766, "SourceName": "microsoft-windows-security-auditing", "ProviderGuid": "54849625-5478-4994-a5ba-3e3b0328c30d", "Version": 0, "TaskValue": 12804, "OpcodeValue": 0, "RecordNumber": 212581297, "ActivityId": "8116666b-fb49-0005-7266-168149fbd601", "ExecutionProcessID": 740, "ExecutionThreadID": 820, "Channel": "security", "Computer": "hostname2", "SubjectUserSid": "s-1-5-21-3641220510-1468267075-587743419-11657", "SubjectUserName": "petrov", "SubjectDomainName": "someorg", "SubjectLogonId": "0x21480f990", "TargetUserName": "petrov", "TargetDomainName": "someorg", "TargetSid": "s-1-5-21-3641220510-1468267075-587743419-11657", "PrivilegeList": "-", "SourceUserName": "sidorov"}"""
        s"correct map $event_4766_1" in new setup {
        override def raw: JObject =  JsonMethods.parse(event_4766_1).asInstanceOf[JObject]
        result.getObject.getId shouldBe  "s-1-5-21-3641220510-1468267075-587743419-11657"
        result.getObject.getName shouldBe  "petrov"
        result.getObject.getDomain shouldBe  "someorg"
        result.getObject.category shouldBe Counterpart.account

        result.getSubject.getId shouldBe  "s-1-5-21-3641220510-1468267075-587743419-11657"
        result.getSubject.getName shouldBe  "petrov"
        result.getSubject.getDomain shouldBe  "someorg"
        result.getSubject.category shouldBe Counterpart.account

        result.getInteraction.action shouldBe InteractionCategory.modify
        result.getInteraction.status shouldBe InteractionStatus.failure

        result.getData.getMsgId shouldBe "4766"
        result.getData.getAux2 shouldBe "0x21480f990"
        result.getData.getAux4 shouldBe "sidorov"
      }
    }

    "event_4765" should {
      val event_4765_1 = """{"EventTime": "2021-03-30T11:35:23.977235+03:00", "Hostname": "hostname2", "Keywords": "9232379236109516800", "EventType": "AUDIT_SUCCESS", "SeverityValue": 2, "Severity": "INFO", "EventID": 4765, "SourceName": "Microsoft-Windows-Security-Auditing", "ProviderGuid": "54849625-5478-4994-A5BA-3E3B0328C30D", "Version": 1, "TaskValue": 12804, "OpcodeValue": 0, "RecordNumber": 167185502, "ActivityId": "8116666b-fb49-0005-7266-168149fbd601", "ExecutionProcessID": 40, "ExecutionThreadID": 821, "Channel": "Security", "Computer": "hostname2", "SubjectUserSid": "S-1-5-18", "SubjectUserName": "ivanov", "SubjectDomainName": "someorg", "SubjectLogonId": "0x3e7", "TargetUserName": "ivanov", "TargetDomainName": "someorg", "TargetSid": "S-1-5-18", "PrivilegeList": "-", "SourceUserName": "vpupkin"}"""
      s"correct map $event_4765_1" in new setup {
        override def raw: JObject =  JsonMethods.parse(event_4765_1).asInstanceOf[JObject]
        result.getObject.getId shouldBe  "S-1-5-18"
        result.getObject.getName shouldBe  "ivanov"
        result.getObject.getDomain shouldBe  "someorg"
        result.getObject.category shouldBe Counterpart.account

        result.getSubject.getId shouldBe  "S-1-5-18"
        result.getSubject.getName shouldBe  "ivanov"
        result.getSubject.getDomain shouldBe  "someorg"
        result.getSubject.category shouldBe Counterpart.account

        result.getInteraction.action shouldBe InteractionCategory.modify
        result.getInteraction.status shouldBe InteractionStatus.success

        result.getData.getMsgId shouldBe "4765"
        result.getData.getAux2 shouldBe "0x3e7"
        result.getData.getAux4 shouldBe "vpupkin"
      }
    }

    "event_4769" should {
      val event_4769_1 = """{"EventTime":"2021-03-31T12:03:46.974060+03:00","Hostname":"hostname3","Keywords":"9232379236109516800","EventType":"AUDIT_SUCCESS","SeverityValue":2,"Severity":"INFO","EventID":4769,"SourceName":"Microsoft-Windows-Security-Auditing","ProviderGuid":"54849625-5478-4994-A5BA-3E3B0328C30D","Version":0,"TaskValue":14337,"OpcodeValue":0,"RecordNumber":152410252,"ExecutionProcessID":596,"ExecutionThreadID":1748,"Channel":"Security","Category":"Kerberos Service Ticket Operations","Opcode":"Info","TargetUserName":"user1$@DOMAIN.RU","TargetDomainName":"DOMAIN.RU","ServiceName":"SRV1$","ServiceSid":"S-1-5-21-31881595-2612140365-1407298719-2602","TicketOptions":"0x40810000","TicketEncryptionType":"0x12","IpAddress":"::ffff:10.22.23.24","IpPort":"53942","Status":"0x0","LogonGuid":"F1720C32-F360-1638-52ED-1318CE6E6558","TransmittedServices":"-","EventReceivedTime":"2021-03-31T12:03:56.514071+03:00","SourceModuleName":"in_msvistalog_welf","SourceModuleType":"im_msvistalog","md5":"421cfea4d5348090d4a11ed24df69616","DevType":"Windows2k8Security00001"}"""
      val event_4769_2 = """{"EventTime":"2021-03-31T12:03:33.169332+03:00","Hostname":"hostname4","Keywords":"9232379236109516800","EventType":"AUDIT_SUCCESS","SeverityValue":2,"Severity":"INFO","EventID":4769,"SourceName":"Microsoft-Windows-Security-Auditing","ProviderGuid":"54849625-5478-4994-A5BA-3E3B0328C30D","Version":0,"TaskValue":14337,"OpcodeValue":0,"RecordNumber":166405411,"ExecutionProcessID":596,"ExecutionThreadID":1208,"Channel":"Security","Category":"Kerberos Service Ticket Operations","Opcode":"Info","TargetUserName":"user2@DOMAIN.RU","TargetDomainName":"DOMAIN.RU","ServiceName":"SRV2$","ServiceSid":"S-1-5-21-31881595-2612140365-1407298719-2614","TicketOptions":"0x40810000","TicketEncryptionType":"0x12","IpAddress":"::ffff:10.22.23.25","IpPort":"45411","Status":"0x0","LogonGuid":"EC08B3BD-4F34-A679-FFD4-E725A3863A7D","TransmittedServices":"-","EventReceivedTime":"2021-03-31T12:03:56.498471+03:00","SourceModuleName":"in_msvistalog_welf","SourceModuleType":"im_msvistalog","md5":"c6d640a3dfa9ddfc5d7fe842cbee6885","DevType":"Windows2k8Security00001"}"""
      s"correct map $event_4769_1" in new setup {
        override def raw: JObject = JsonMethods.parse(event_4769_1).asInstanceOf[JObject]
        result.getObject.getName shouldBe  "SRV1$"
        result.getObject.getId shouldBe  "S-1-5-21-31881595-2612140365-1407298719-2602"
        result.getObject.category shouldBe Counterpart.account

        result.getSubject.getName shouldBe  "user1$"
        result.getSubject.getDomain shouldBe  "DOMAIN.RU"
        result.getSubject.category shouldBe Counterpart.account

        result.getInteraction.action shouldBe InteractionCategory.login
        result.getInteraction.status shouldBe InteractionStatus.success

        result.getData.getMsgId shouldBe "4769"
        result.getData.getAux2 shouldBe "F1720C32-F360-1638-52ED-1318CE6E6558"
        result.getData.getAux3 shouldBe "0x40810000"
        result.getData.getAux4 shouldBe "0x12"
        result.getData.getAux5 shouldBe "0x0"
      }
      s"correct map $event_4769_2" in new setup {
        override def raw: JObject = JsonMethods.parse(event_4769_2).asInstanceOf[JObject]
        result.getObject.getName shouldBe  "SRV2$"
        result.getObject.getId shouldBe  "S-1-5-21-31881595-2612140365-1407298719-2614"
        result.getObject.category shouldBe Counterpart.account

        result.getSubject.getName shouldBe  "user2"
        result.getSubject.getDomain shouldBe  "DOMAIN.RU"
        result.getSubject.category shouldBe Counterpart.account

        result.getInteraction.action shouldBe InteractionCategory.login
        result.getInteraction.status shouldBe InteractionStatus.success

        result.getData.getMsgId shouldBe "4769"
        result.getData.getAux2 shouldBe "EC08B3BD-4F34-A679-FFD4-E725A3863A7D"
        result.getData.getAux3 shouldBe "0x40810000"
        result.getData.getAux4 shouldBe "0x12"
        result.getData.getAux5 shouldBe "0x0"
      }
    }

    "event_4738" should {
      val event_4738_1 = """{"EventTime":"2021-04-05T09:58:08.946524+03:00","Hostname":"hostname4","Keywords":"9232379236109516800","EventType":"AUDIT_SUCCESS","SeverityValue":2,"Severity":"INFO","EventID":4738,"SourceName":"Microsoft-Windows-Security-Auditing","ProviderGuid":"54849625-5478-4994-A5BA-3E3B0328C30D","Version":0,"TaskValue":13824,"OpcodeValue":0,"RecordNumber":674060,"ExecutionProcessID":748,"ExecutionThreadID":5404,"Channel":"Security","Category":"Управление учетными записями","Opcode":"Сведения","Dummy":"-","TargetUserName":"Гость","TargetDomainName":"WORKGROUP","TargetSid":"S-1-5-21-3665584217-1726469349-4127012909-501","SubjectUserSid":"S-1-5-18","SubjectUserName":"WORKGROUP$","SubjectDomainName":"ORG.RU","SubjectLogonId":"0x3e7","PrivilegeList":"-","SamAccountName":"Гость","DisplayName":"%%1793","UserPrincipalName":"-","HomeDirectory":"%%1793","HomePath":"%%1793","ScriptPath":"%%1793","ProfilePath":"%%1793","UserWorkstations":"%%1793","PasswordLastSet":"14.06.2017 16:55:58","AccountExpires":"28.04.2014 0:00:00","PrimaryGroupId":"513","AllowedToDelegateTo":"-","OldUacValue":"0x15","NewUacValue":"0x15","UserAccountControl":"-","UserParameters":"%%1793","SidHistory":"-","LogonHours":"%%1797","EventReceivedTime":"2021-04-05T09:58:30.064925+03:00","SourceModuleName":"in_msvistalog_welf","SourceModuleType":"im_msvistalog","md5":"c099875371592d075188aa96723e9ce9","DevType":"Windows2k8Security00001"}"""
      s"correct map $event_4738_1" in new setup {
        override def raw: JObject = JsonMethods.parse(event_4738_1).asInstanceOf[JObject]

        result.getObject.getName shouldBe "Гость"
        result.getObject.getDomain shouldBe "WORKGROUP"
        result.getObject.getId shouldBe "S-1-5-21-3665584217-1726469349-4127012909-501"
        result.getObject.getGroup shouldBe "513"
        result.getObject.getPath shouldBe "%%1793"
        result.getObject.getValue shouldBe "%%1793"
        result.getObject.category shouldBe Counterpart.account

        result.getSubject.getId shouldBe "S-1-5-18"
        result.getSubject.getName shouldBe "WORKGROUP$"
        result.getSubject.getDomain shouldBe "ORG.RU"
        result.getSubject.category shouldBe Counterpart.account

        result.getInteraction.action shouldBe InteractionCategory.modify
        result.getInteraction.status shouldBe InteractionStatus.success

        result.getData.getMsgId shouldBe "4738"
        result.getData.getAux1 shouldBe ""
        result.getData.getAux2 shouldBe "0x3e7"
        result.getData.getAux3 shouldBe "14.06.2017 16:55:58"
        result.getData.getAux4 shouldBe "0x15"
        result.getData.getAux5 shouldBe "0x15"
        result.getData.getAux6 shouldBe ""
        result.getData.getAux7 shouldBe "%%1793"
        result.getData.getAux8 shouldBe "%%1793"
        result.getData.getAux9 shouldBe "%%1793"
        result.getData.getAux9 shouldBe "%%1793"
        result.getData.getAux10 shouldBe "%%1797"
      }
    }

    "event_4719" should {
      val event_4719_1 = """{"EventTime":"2021-04-05T09:53:05.792097+03:00","Hostname":"hostname5","Keywords":"9232379236109516800","EventType":"AUDIT_SUCCESS","SeverityValue":2,"Severity":"INFO","EventID":4719,"SourceName":"Microsoft-Windows-Security-Auditing","ProviderGuid":"54849625-5478-4994-A5BA-3E3B0328C30D","Version":0,"TaskValue":13568,"OpcodeValue":0,"RecordNumber":130287232,"ActivityID":"5A571FCA-5B6D-0002-DB1F-575A6D5BD601","ExecutionProcessID":688,"ExecutionThreadID":9048,"Channel":"Security","Category":"Audit Policy Change","Opcode":"Info","SubjectUserSid":"S-1-5-18","SubjectUserName":"user3$","SubjectDomainName":"ORG.RU","SubjectLogonId":"0x3e7","CategoryId":"%%8279","SubcategoryId":"%%14081","SubcategoryGuid":"0CCE923C-69AE-11D9-BED3-505054503030","AuditPolicyChanges":"%%8449, %%8451","EventReceivedTime":"2021-04-05T09:53:09.712598+03:00","SourceModuleName":"in_welf","SourceModuleType":"im_msvistalog","md5":"1bbbfd0fa726fbb8f432252d3651ae00","DevType":"Windows2k8Security00001"}"""
      s"correct map $event_4719_1" in new setup {
        override def raw: JObject = JsonMethods.parse(event_4719_1).asInstanceOf[JObject]

        result.getObject.getName shouldBe "%%14081"
        result.getObject.getGroup shouldBe "%%8279"
        result.getObject.getValue shouldBe "%%8449, %%8451"
        result.getObject.getId shouldBe "0CCE923C-69AE-11D9-BED3-505054503030"
        result.getObject.category shouldBe Counterpart.rule

        result.getSubject.getName shouldBe "user3$"
        result.getSubject.getDomain shouldBe "ORG.RU"
        result.getSubject.getId shouldBe "S-1-5-18"
        result.getSubject.category shouldBe Counterpart.account

        result.getInteraction.action shouldBe InteractionCategory.modify
        result.getInteraction.status shouldBe InteractionStatus.success

        result.getData.getMsgId shouldBe "4719"
        result.getData.getAux2 shouldBe "0x3e7"
      }
    }
  }


  val parser = new WindowsSecurityParser
  val mapper = new WindowsSecurityMapper
  val validator = new WindowsSecurityValidator

  @transient
  trait setup {
    def raw: JObject

    protected val msg = ParsedMessage(
      raw = Right(raw),
      eventReceivedTime = ZonedDateTime.now(ZoneOffset.UTC),
      organization = "organization",
      chain = "",
      eventDevType = "Windows2k8Security00001",
      collectorHostname = "local.com",
      collectorHostIP = "127.0.0.1",
      severityId = 0,
      severity = "unknown",
      eventHostname = Some("eventSource"),
      eventHostIP = "10.2.2.1",
      inputId = "windows-security"
    )
    protected val parsedEvent: ParsedLog = parser.parse(msg.raw)
    protected val internalSocEvent = InternalSocEvent(
      message = msg,
      event = parsedEvent,
      normId = "norm_id",
      rawId = "raw_id",
      eventSourceHost = "127.0.0.1"
    )

    validator.check(ParsedEvent(msg, parsedEvent)) shouldBe List.empty

    val result: SocEvent = mapper
      .map((Map("Windows2k8Security00001" -> DeviceVendor("Windows2k8Security00001", "Microsoft", "Microsoft", "xxx")), internalSocEvent))
  }
}
