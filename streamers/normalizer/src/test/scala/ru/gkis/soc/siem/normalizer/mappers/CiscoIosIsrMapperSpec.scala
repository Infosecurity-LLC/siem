package ru.gkis.soc.siem.normalizer.mappers

import org.junit.runner.RunWith
import org.scalatest.{Matchers, WordSpec}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.model.{Counterpart, DeviceVendor, ImportanceLevel, InteractionCategory, InteractionStatus, ParsedLog, SocEvent}
import ru.gkis.soc.siem.normalizer.parsers.CiscoIosIsrParser
import ru.gkis.soc.siem.normalizer.{InternalSocEvent, ParsedEvent, ParsedMessage}
import ru.gkis.soc.siem.normalizer.validators.CiscoIosIsrValidator

import java.time.{ZoneOffset, ZonedDateTime}

@RunWith(classOf[JUnitRunner])
class CiscoIosIsrMapperSpec extends WordSpec with Matchers {
    "CiscoIosIsrMapper" when {
        "sec_login-4-login_failed" should {
            val rawMessage = """<172>25851633: 25851629: mar 18 14:43:43.961 msk: %sec_login-4-login_failed: login failed [user: ] [source: 192.168.11.22] [localport: 22] [reason: login authentication failed] at 14:43:43 msk thu mar 18 2021"""

            s"correct map $rawMessage" in new setup {
                override def raw: String = rawMessage

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.status shouldBe InteractionStatus.failure
                result.getInteraction.importance shouldBe ImportanceLevel.MEDIUM
                result.getInteraction.getReason shouldBe "login authentication failed"

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.name shouldBe None

                result.getSource.getIp shouldBe "192.168.11.22"

                result.getDestination.getIp shouldBe "127.0.0.1"
                result.getDestination.getHostname shouldBe "test"
                result.getDestination.getFqdn shouldBe "test.local.com"
                result.getDestination.getPort shouldBe 22

                result.getData.getMsgId shouldBe "sec_login-4-login_failed"
                result.getData.originTime shouldBe 1616067823
            }
        }

        "sec_login-5-login_success" should {
            val rawMessage = """<189>2812: mar 18 13:43:49: %sec_login-5-login_success: login success [user: v.pupkin] [source: 192.168.0.1] [localport: 22] at 13:43:49 msk thu mar 18 2021"""

            s"correct map $rawMessage" in new setup {
                override def raw: String = rawMessage

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.status shouldBe InteractionStatus.success
                result.getInteraction.importance shouldBe ImportanceLevel.INFO

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.name shouldBe Some("v.pupkin")

                result.getSource.getIp shouldBe "192.168.0.1"

                result.getDestination.getIp shouldBe "127.0.0.1"
                result.getDestination.getHostname shouldBe "test"
                result.getDestination.getFqdn shouldBe "test.local.com"
                result.getDestination.getPort shouldBe 22

                result.getData.getMsgId shouldBe "sec_login-5-login_success"
                result.getData.originTime shouldBe 1616064229
            }
        }

        "sec_login-5-ssh2_userauth" should {
            val ssh2Userauth_01 = """<173>25851636: 25851632: mar 18 14:43:45.623 msk: %ssh-5-ssh2_userauth: user 'sidorov' authentication for ssh2 session from 192.168.11.22 (tty = 0) using crypto cipher 'aes256-ctr', hmac 'hmac-sha1' succeeded"""
            val ssh2Userauth_02 = """<181>678747: *mar 15 16:18:00.634 msk: %ssh-5-ssh2_userauth: user '' authentication for ssh2 session from 192.168.99.77 (tty = 0) using crypto cipher 'aes256-ctr', hmac 'hmac-sha1' failed"""
            val ssh2Userauth_03 = """<181>6598078: 6598074: mar 12 13:55:00.322 moscow: %ssh-5-ssh2_userauth: user 'sidorov' authentication for ssh2 session from 192.168.11.22 (tty = 0) using crypto cipher 'aes256-cbc', hmac 'hmac-sha1' failed"""

            s"correct map $ssh2Userauth_01" in new setup {
                override def raw: String = ssh2Userauth_01

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.status shouldBe InteractionStatus.success
                result.getInteraction.importance shouldBe ImportanceLevel.INFO

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.name shouldBe Some("sidorov")

                result.getSource.getIp shouldBe "192.168.11.22"

                result.getDestination.getIp shouldBe "127.0.0.1"
                result.getDestination.getHostname shouldBe "test"
                result.getDestination.getFqdn shouldBe "test.local.com"

                result.getData.getMsgId shouldBe "ssh-5-ssh2_userauth"
                result.getData.originTime shouldBe 1616067825
            }

            s"correct map $ssh2Userauth_02" in new setup {
                override def raw: String = ssh2Userauth_02

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.status shouldBe InteractionStatus.failure
                result.getInteraction.importance shouldBe ImportanceLevel.INFO

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.name shouldBe None

                result.getSource.getIp shouldBe "192.168.99.77"

                result.getDestination.getIp shouldBe "127.0.0.1"
                result.getDestination.getHostname shouldBe "test"
                result.getDestination.getFqdn shouldBe "test.local.com"

                result.getData.getMsgId shouldBe "ssh-5-ssh2_userauth"
                result.getData.originTime shouldBe 1615814280
            }

            s"correct map $ssh2Userauth_03" in new setup {
                override def raw: String = ssh2Userauth_03

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.status shouldBe InteractionStatus.failure
                result.getInteraction.importance shouldBe ImportanceLevel.INFO

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.name shouldBe Some("sidorov")

                result.getSource.getIp shouldBe "192.168.11.22"

                result.getDestination.getIp shouldBe "127.0.0.1"
                result.getDestination.getHostname shouldBe "test"
                result.getDestination.getFqdn shouldBe "test.local.com"

                result.getData.getMsgId shouldBe "ssh-5-ssh2_userauth"
                result.getData.originTime shouldBe 1615557300
            }
        }

        "sys-6-logout" should {
            val rawMessage = """<174>25850082: 25850078: mar 18 14:15:38.085 msk: %sys-6-logout: user petrov has exited tty session 2(192.168.66.77)"""

            s"correct map $rawMessage" in new setup {
                override def raw: String = rawMessage

                result.getInteraction.action shouldBe InteractionCategory.logout
                result.getInteraction.status shouldBe InteractionStatus.success
                result.getInteraction.importance shouldBe ImportanceLevel.INFO

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.name shouldBe Some("petrov")

                result.getSource.getIp shouldBe "192.168.66.77"

                result.getDestination.getIp shouldBe "127.0.0.1"
                result.getDestination.getHostname shouldBe "test"
                result.getDestination.getFqdn shouldBe "test.local.com"

                result.getData.getMsgId shouldBe "sys-6-logout"
                result.getData.originTime shouldBe 1616066138
            }
        }

        "sys-5-config_i" should {
            val config_i_01 = """<181>308461: 308457: *mar 18 14:39:38.453 moscow: %sys-5-config_i: configured from console by sidorov on vty0 (192.168.11.22)"""
            val config_i_02 = """<133>347564: 10.11.12.13: mar 18 11:12:01.367: %sys-5-config_i: configured from ftp://robot:*@ftp-server.local/~/update_ru.cfg by vty0"""
            val config_i_03 = """<181>340878: 340874: mar 18 11:58:42.021 msk: %sys-5-config_i: configured from console by petrov on vty0 (192.168.66.77)"""
            val config_i_04 = """<189>38702: *mar  9 06:50:48.163: %dmi-5-config_i: r0/0: dmiauthd: configured from netconf/restconf by some-admin, transaction-id 164615"""
            val config_i_05 = """<189>148321: *mar  9 06:30:45.175: %dmi-5-config_i: r0/0: dmiauthd: configured from netconf/restconf by some-admin, transaction-id 833200"""

            s"correct map $config_i_01" in new setup {
                override def raw: String = config_i_01

                result.getInteraction.action shouldBe InteractionCategory.modify
                result.getInteraction.status shouldBe InteractionStatus.success
                result.getInteraction.importance shouldBe ImportanceLevel.INFO

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "sidorov"

                result.getSource.getIp shouldBe "192.168.11.22"

                result.getDestination.getIp shouldBe "127.0.0.1"
                result.getDestination.getHostname shouldBe "test"
                result.getDestination.getFqdn shouldBe "test.local.com"

                result.getData.getMsgId shouldBe "sys-5-config_i"
                result.getData.originTime shouldBe 1616078378
                result.getData.getAux1 shouldBe "console"
            }

            s"correct map $config_i_02" in new setup {
                override def raw: String = config_i_02

                result.getInteraction.action shouldBe InteractionCategory.modify
                result.getInteraction.status shouldBe InteractionStatus.success
                result.getInteraction.importance shouldBe ImportanceLevel.INFO

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.name shouldBe None

                result.getSource.ip shouldBe None

                result.getDestination.getIp shouldBe "127.0.0.1"
                result.getDestination.getHostname shouldBe "test"
                result.getDestination.getFqdn shouldBe "test.local.com"

                result.getData.getMsgId shouldBe "sys-5-config_i"
                result.getData.originTime shouldBe 1616065921
                result.getData.getAux1 shouldBe "ftp://robot:*@ftp-server.local/~/update_ru.cfg"
            }

            s"correct map $config_i_03" in new setup {
                override def raw: String = config_i_03

                result.getInteraction.action shouldBe InteractionCategory.modify
                result.getInteraction.status shouldBe InteractionStatus.success
                result.getInteraction.importance shouldBe ImportanceLevel.INFO

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "petrov"

                result.getSource.getIp shouldBe "192.168.66.77"

                result.getDestination.getIp shouldBe "127.0.0.1"
                result.getDestination.getHostname shouldBe "test"
                result.getDestination.getFqdn shouldBe "test.local.com"

                result.getData.getMsgId shouldBe "sys-5-config_i"
                result.getData.originTime shouldBe 1616057922
                result.getData.getAux1 shouldBe "console"
            }

            s"correct map $config_i_04" in new setup {
                override def raw: String = config_i_04

                result.getInteraction.action shouldBe InteractionCategory.modify
                result.getInteraction.status shouldBe InteractionStatus.success
                result.getInteraction.importance shouldBe ImportanceLevel.INFO

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "some-admin"

                result.getDestination.getIp shouldBe "127.0.0.1"
                result.getDestination.getHostname shouldBe "test"
                result.getDestination.getFqdn shouldBe "test.local.com"

                result.getData.getMsgId shouldBe "dmi-5-config_i"
                result.getData.originTime shouldBe 1615272648
                result.getData.getAux1 shouldBe "netconf/restconf"
                result.getData.getAux2 shouldBe "164615"
            }

            s"correct map $config_i_05" in new setup {
                override def raw: String = config_i_05

                result.getInteraction.action shouldBe InteractionCategory.modify
                result.getInteraction.status shouldBe InteractionStatus.success
                result.getInteraction.importance shouldBe ImportanceLevel.INFO

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "some-admin"

                result.getDestination.getIp shouldBe "127.0.0.1"
                result.getDestination.getHostname shouldBe "test"
                result.getDestination.getFqdn shouldBe "test.local.com"

                result.getData.getMsgId shouldBe "dmi-5-config_i"
                result.getData.originTime shouldBe 1615271445
                result.getData.getAux1 shouldBe "netconf/restconf"
                result.getData.getAux2 shouldBe "833200"
            }
        }
    }

    lazy val parser = new CiscoIosIsrParser
    lazy val mapper = new CiscoIosIsrMapper
    lazy val validator = new CiscoIosIsrValidator

    @transient
    trait setup {
        def raw: String

        protected val msg: ParsedMessage = ParsedMessage(
            raw = Left(raw),
            eventReceivedTime = ZonedDateTime.now(ZoneOffset.UTC),
            organization = "organization",
            chain = "",
            eventDevType = "ios/isr00401",
            collectorHostname = "test.local.com",
            collectorHostIP = "127.0.0.1",
            severityId = 0,
            severity = "unknown",
            eventHostname = Some("test.local.com"),
            eventHostIP = "127.0.0.1",
            inputId = "id"
        )
        protected val parsedEvent: ParsedLog = parser.parse(msg.raw)
        protected val ise: InternalSocEvent = InternalSocEvent(
            message = msg,
            event = parsedEvent,
            normId = "norm_id",
            rawId = "raw_id",
            eventSourceHost = "127.0.0.1"
        )

        validator.check(ParsedEvent(msg, parsedEvent)) shouldBe List.empty

        val result: SocEvent = mapper
            .map((Map("ios/isr00401" -> DeviceVendor("ios00401", "Cisco", "IOS", "401")), ise))
    }

}
