package ru.gkis.soc.siem.normalizer.mappers

import org.junit.runner.RunWith
import org.scalatest.{Matchers, WordSpec}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.normalizer.parsers.CiscoAsaParser
import ru.gkis.soc.siem.normalizer.validators.CiscoAsaValidator
import ru.gkis.soc.siem.normalizer.{InternalSocEvent, ParsedEvent, ParsedMessage}

import java.time.{ZoneOffset, ZonedDateTime}

@RunWith(classOf[JUnitRunner])
class CiscoAsaMapperSpec extends WordSpec with Matchers {
    "CiscoAsaMapper" when {
        "common" should {
            val asa113004_1 = """<166>:Jan 13 2020 15:51:28 MSK: %ASA-auth-6-113004: AAA user authentication Successful : server =  11.22.33.44 : user = somebody"""

            s"map common fields" in new setup {
                override def raw: String = asa113004_1

                result.getEventSource.getSubsys shouldBe "ASA"
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getData.originTime shouldBe 1578919888l
                result.getData.getMsgId shouldBe "113004"
            }
        }

        "113004" should {
            val asa113004_1 = """<166>:Jan 13 15:51:28 MSK: %ASA-auth-6-113004: AAA user authentication Successful : server =  11.22.33.44 : user = somebody"""
            val asa113004_2 = """<166>:Oct 07 22:27:16 MSK: %FWSM-auth-6-113004: AAA user accounting Successful : server =  10.20.30.40 : user = somebody"""
            val asa113004_3 = """<166>:Jan 13 15:44:18 MSK 10.20.30.40: %PIX-auth-6-113004: AAA user authentication Successful : server =  192.168.0.1 : user = somebody"""

            s"map $asa113004_1" in new setup {
                override def raw: String = asa113004_1

                result.getObject.category shouldBe Counterpart.system
                result.getSubject.getName shouldBe "somebody"
                result.getSubject.category shouldBe Counterpart.account
                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "successfully authenticated"
                result.getInteraction.status shouldBe InteractionStatus.success
                result.getData.getAux1 shouldBe "11.22.33.44"
            }

            s"map $asa113004_2" in new setup {
                override def raw: String = asa113004_2

                result.getObject.category shouldBe Counterpart.system
                result.getSubject.getName shouldBe "somebody"
                result.getSubject.category shouldBe Counterpart.account
                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "successfully authenticated"
                result.getInteraction.status shouldBe InteractionStatus.success
                result.getData.getAux1 shouldBe "10.20.30.40"
            }

            s"map $asa113004_3" in new setup {
                override def raw: String = asa113004_2

                result.getObject.category shouldBe Counterpart.system
                result.getSubject.getName shouldBe "somebody"
                result.getSubject.category shouldBe Counterpart.account
                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "successfully authenticated"
                result.getInteraction.status shouldBe InteractionStatus.success
                result.getData.getAux1 shouldBe "10.20.30.40"
            }
        }

        "113012" should {
            val asa113012_1 = """<166>:Oct 09 15:19:43 MSK: %ASA-auth-6-113012: AAA user authentication Successful : local database : user = somebody"""
            val asa113012_2 = """<166>Dec 13 2013 16:28:40 10.11.12.15 : %ASA-6-113012: AAA user authentication Successful : local database : user = somebody"""
            val asa113012_3 = """<166>Dec 13 2013 16:28:40 10.11.12.15 : %PIX-6-113012: AAA user authentication Successful : local database : user = somebody"""

            s"map $asa113012_1" in new setup {
                override def raw: String = asa113012_1

                result.getObject.category shouldBe Counterpart.system
                result.getSubject.getName shouldBe "somebody"
                result.getSubject.category shouldBe Counterpart.account
                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "successfully authenticated to the local user database"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"map $asa113012_2" in new setup {
                override def raw: String = asa113012_2

                result.getObject.category shouldBe Counterpart.system
                result.getSubject.getName shouldBe "somebody"
                result.getSubject.category shouldBe Counterpart.account
                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "successfully authenticated to the local user database"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"map $asa113012_3" in new setup {
                override def raw: String = asa113012_3

                result.getObject.category shouldBe Counterpart.system
                result.getSubject.getName shouldBe "somebody"
                result.getSubject.category shouldBe Counterpart.account
                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "successfully authenticated to the local user database"
                result.getInteraction.status shouldBe InteractionStatus.success
            }
        }

        "113015" should {
            val asa113015_1 = """<166>:Oct 08 17:27:49 MSK: %ASA-auth-6-113015: AAA user authentication Rejected : reason = Invalid password : local database : user = somebody"""
            val asa113015_2 = """<166>Dec 13 2013 16:22:38 10.11.12.15 : %ASA-6-113015: AAA user authentication Rejected : reason = Invalid password : local database : user = somebody"""
            val asa113015_3 = """<166>Dec 13 2013 16:22:38 10.11.12.15 : %PIX-6-113015: AAA user authentication Rejected : reason = Invalid password : local database : user = somebody"""
            val asa113015_4 = """<166>Jan 25 2016 17:03:04 10.0.208.158 : %ASA-6-113015: AAA user authentication Rejected : reason = Invalid password : local database : user = ***** : user IP = 10.01.10.01"""

            s"parse $asa113015_1" in new setup {
                override def raw: String = asa113015_1

                result.getObject.category shouldBe Counterpart.system
                result.getSubject.getName shouldBe "somebody"
                result.getSubject.category shouldBe Counterpart.account
                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "Invalid password"
                result.getInteraction.status shouldBe InteractionStatus.failure
            }

            s"parse $asa113015_2" in new setup {
                override def raw: String = asa113015_2

                result.getObject.category shouldBe Counterpart.system
                result.getSubject.getName shouldBe "somebody"
                result.getSubject.category shouldBe Counterpart.account
                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "Invalid password"
                result.getInteraction.status shouldBe InteractionStatus.failure
            }

            s"parse $asa113015_3" in new setup {
                override def raw: String = asa113015_3

                result.getObject.category shouldBe Counterpart.system
                result.getSubject.getName shouldBe "somebody"
                result.getSubject.category shouldBe Counterpart.account
                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "Invalid password"
                result.getInteraction.status shouldBe InteractionStatus.failure
            }

            s"parse $asa113015_4" in new setup {
                override def raw: String = asa113015_4

                result.getObject.category shouldBe Counterpart.system
                result.getSubject.getName shouldBe "*****"
                result.getSubject.category shouldBe Counterpart.account
                result.getSource.getIp shouldBe "10.01.10.01"
                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "Invalid password"
                result.getInteraction.status shouldBe InteractionStatus.failure
            }
        }

        "605005" should {
            val asa605005_1 = """<166>:Jan 15 02:19:08 MSK: %ASA-sys-6-605005: Login permitted from 233.124.53.23/36809 to outside:55.44.33.22/ssh for user "someone"""""
            val asa605005_2 = """<166>Nov 07 2013 09:59:27: %ASA-6-605005: Login permitted from 42.42.42.42/48423 to outside:10.11.12.15/ssh for user "someone""""
            val asa605005_3 = """<166>:Aug 14 18:04:34 MSK: %FWSM-sys-6-605005: Login permitted from 10.10.10.10/58960 to fwsm_to_mm:10.14.88.01/https for user "someone""""
            val asa605005_4 = """<166>:Jan 09 09:01:19 MSK 10.20.30.40: %PIX-sys-6-605005: Login permitted from 10.9.8.7/11904 to inside:77.88.99.10/ssh for user "someone""""
            val asa605005_5 = """<166>Dec 30 2014 13:42:09: %ASA-6-605005: Login permitted from serial to console for user "someone""""

            s"parse $asa605005_1" in new setup {
                override def raw: String = asa605005_1

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "someone"

                result.getSource.getIp shouldBe "233.124.53.23"
                result.getSource.getPort shouldBe 36809

                result.getDestination.getIp shouldBe "55.44.33.22"

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "successfully authenticated"
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getAux10 shouldBe "ssh"
            }

            s"parse $asa605005_2" in new setup {
                override def raw: String = asa605005_2

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "someone"

                result.getSource.getIp shouldBe "42.42.42.42"
                result.getSource.getPort shouldBe 48423

                result.getDestination.getIp shouldBe "10.11.12.15"

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "successfully authenticated"
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getAux10 shouldBe "ssh"
            }

            s"parse $asa605005_3" in new setup {
                override def raw: String = asa605005_3

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "someone"

                result.getSource.getIp shouldBe "10.10.10.10"
                result.getSource.getPort shouldBe 58960

                result.getDestination.getIp shouldBe "10.14.88.01"

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "successfully authenticated"
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getAux10 shouldBe "https"
            }

            s"parse $asa605005_4" in new setup {
                override def raw: String = asa605005_4

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "someone"

                result.getSource.getIp shouldBe "10.9.8.7"
                result.getSource.getPort shouldBe 11904

                result.getDestination.getIp shouldBe "77.88.99.10"

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "successfully authenticated"
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getAux10 shouldBe "ssh"
            }

            s"parse $asa605005_5" in new setup {
                override def raw: String = asa605005_5

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "someone"

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "successfully authenticated"
                result.getInteraction.status shouldBe InteractionStatus.success
            }
        }

        "611101" should {
            val asa611101_1 = """<166>:Jan 15 02:19:08 MSK: %ASA-vpnc-6-611101: User authentication succeeded: Uname: someone"""
            val asa611101_2 = """<166>Nov 07 2013 09:59:32: %ASA-6-611101: User authentication succeeded: Uname: someone"""
            val asa611101_3 = """<166>:Jul 02 22:28:29 MSK 10.20.30.40: %FWSM-vpnc-6-611101: User authentication succeeded: Uname: someone"""

            s"parse $asa611101_1" in new setup {
                override def raw: String = asa611101_1

                result.getObject.category shouldBe Counterpart.system
                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "someone"

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "User authentication succeeded"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa611101_2" in new setup {
                override def raw: String = asa611101_2

                result.getObject.category shouldBe Counterpart.system
                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "someone"

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "User authentication succeeded"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa611101_3" in new setup {
                override def raw: String = asa611101_3

                result.getObject.category shouldBe Counterpart.system
                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "someone"

                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.getReason shouldBe "User authentication succeeded"
                result.getInteraction.status shouldBe InteractionStatus.success
            }
        }

        "111008" should {
            val asa111008_1 = """<165>:Aug 30 12:26:30 MSK: %ASA-config-5-111008: User 'somebody' executed the 'configure terminal' command.""""
            val asa111008_2 = """<165>Nov 14 2013 11:23:36: %ASA-5-111008: User 'somebody' executed the 'write memory' command."""
            val asa111008_3 = """<165>:Oct 02 15:20:37 MSK: %PIX-config-5-111008: User 'somebody' executed the 'write' command."""
            val asa111008_4 = """<165>:Jan 14 18:10:27 MSK 10.20.30.40: %FWSM-config-5-111008: User 'somebody' executed the 'policy-map POLICY_test_2' command."""
            val asa111008_5 = """<165>:Jan 14 18:10:27 MSK :%ASA-5-111008: User 'somebody' executed the 'logging host inside 192.168.0.2' command."""

            s"parse $asa111008_1" in new setup {
                override def raw: String = asa111008_1

                result.getObject.category shouldBe Counterpart.command
                result.getObject.getValue shouldBe "configure terminal"

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "somebody"

                result.getInteraction.action shouldBe InteractionCategory.execute
                result.getInteraction.getReason shouldBe "User executed the command"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa111008_2" in new setup {
                override def raw: String = asa111008_2

                result.getObject.category shouldBe Counterpart.command
                result.getObject.getValue shouldBe "write memory"

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "somebody"

                result.getInteraction.action shouldBe InteractionCategory.execute
                result.getInteraction.getReason shouldBe "User executed the command"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa111008_3" in new setup {
                override def raw: String = asa111008_3

                result.getObject.category shouldBe Counterpart.command
                result.getObject.getValue shouldBe "write"

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "somebody"

                result.getInteraction.action shouldBe InteractionCategory.execute
                result.getInteraction.getReason shouldBe "User executed the command"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa111008_4" in new setup {
                override def raw: String = asa111008_4

                result.getObject.category shouldBe Counterpart.command
                result.getObject.getValue shouldBe "policy-map POLICY_test_2"

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "somebody"

                result.getInteraction.action shouldBe InteractionCategory.execute
                result.getInteraction.getReason shouldBe "User executed the command"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa111008_5" in new setup {
                override def raw: String = asa111008_5

                result.getObject.category shouldBe Counterpart.command
                result.getObject.getValue shouldBe "logging host inside 192.168.0.2"

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "somebody"

                result.getInteraction.action shouldBe InteractionCategory.execute
                result.getInteraction.getReason shouldBe "User executed the command"
                result.getInteraction.status shouldBe InteractionStatus.success
            }
        }

        "111010" should {
            val asa111010_1 = """<165>Nov 08 2013 10:18:30: %ASA-5-111010: User 'somebody', running 'CLI' from IP 42.42.42.42, executed 'logging on'""""
            val asa111010_2 = """<165>Nov 08 2013 10:18:30 10.20.30.40: %PIX-5-111010: User 'somebody', running 'CLI' from IP 42.42.42.42, executed 'logging on'"""
            val asa111010_3 = """<165>Nov 08 2013 10:18:30: %ASA-5-111010: User 'somebody', running 'N/A' from IP 147.148.149.150, executed 'logging host inside 192.168.0.2'"""

            s"parse $asa111010_1" in new setup {
                override def raw: String = asa111010_1

                result.getObject.category shouldBe Counterpart.command
                result.getObject.getValue shouldBe "logging on"

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "somebody"

                result.getSource.getIp shouldBe "42.42.42.42"

                result.getInteraction.action shouldBe InteractionCategory.execute
                result.getInteraction.getReason shouldBe "User made a configuration change."
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa111010_2" in new setup {
                override def raw: String = asa111010_2

                result.getObject.category shouldBe Counterpart.command
                result.getObject.getValue shouldBe "logging on"

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "somebody"

                result.getSource.getIp shouldBe "42.42.42.42"

                result.getInteraction.action shouldBe InteractionCategory.execute
                result.getInteraction.getReason shouldBe "User made a configuration change."
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa111010_3" in new setup {
                override def raw: String = asa111010_3

                result.getObject.category shouldBe Counterpart.command
                result.getObject.getValue shouldBe "logging host inside 192.168.0.2"

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "somebody"

                result.getSource.getIp shouldBe "147.148.149.150"

                result.getInteraction.action shouldBe InteractionCategory.execute
                result.getInteraction.getReason shouldBe "User made a configuration change."
                result.getInteraction.status shouldBe InteractionStatus.success
            }
        }

        "106023" should {
            val asa106023_1 = """<164>:Jan 15 01:34:00 MSK: %ASA-session-4-106023: Deny protocol 115 src px_interface3_name:10.11.12.13 dst px_interface6_name:10.11.12.14 by access-group "I_MM_TEST" [0x0, 0x0]"""
            val asa106023_2 = """<164>:Jan 14 23:53:28 MSK 10.20.30.40: %FWSM-session-4-106023: Deny protocol 132 src px_interface3_name:33.44.55.66 dst px_interface5_name:11.22.33.44 by access-group "I_MM_TEST" [0x0, 0x0]"""
            val asa106023_3 = """<164>:Jan 14 17:19:04 MSK 10.20.30.40: %ASA-session-4-106023: Deny icmp src px_interface7_name:10.11.12.16 dst px_interface6_name:172.178.99.44 (type 8, code 0) by access-group "TEST_1_IN" [0x0, 0x0]"""
            val asa106023_4 = """<164>:Jun 25 15:59:50 MSK 10.20.30.40: %ASA-session-4-106023: Deny udp src px_interface3_name:10.11.12.17/65501 dst px_interface6_name:10.11.13.24/123 by access-group "I_MM_TEST" [0x0, 0x0]"""
            val asa106023_5 = """<164>Nov 13 15:35:10 10.39.78.109 %ASA-4-106023: Deny udp src dv2interface:10.11.12.18/50426 dst dv3interface:test.example.com/389 by access-group "ACL_111" [0x0, 0x0]"""
            val asa106023_6 = """<164>Nov 13 15:38:03 10.39.78.109 %ASA-4-106023: Deny udp src dv3interface:test.example.com/63228 dst dv4interface:10.11.13.23/514 by access-group "ACL_222" [0x0, 0x0]"""
            val asa106023_7 = """<172>Mar 19 2015 12:53:28: %ASA-4-106023: Deny udp src AB-CD:10.11.12.19/59140 dst DC:10.11.13.22/53 by access-group "AB-CD-EF" [0x1800007b, 0x0]"""
            val asa106023_8 = """<140>Jul 21 2017 00:42:51 Abc-ASA : %ASA-4-106023: Deny tcp src Inside:10.11.13.20/56198 dst Inside:10.11.13.21/7680(LOCAL\sidorov) by access-group "Inside_access_in" [0x51fd3ce2, 0x0]"""

            s"parse $asa106023_1" in new setup {
                override def raw: String = asa106023_1

                result.getObject.category shouldBe Counterpart.connection

                result.getData.getInterface shouldBe "px_interface3_name"
                result.getData.getAux1 shouldBe "px_interface6_name"
                result.getData.getAux10 shouldBe "I_MM_TEST"

                result.getSource.getIp shouldBe "10.11.12.13"
                result.getSource.port shouldBe None

                result.getDestination.getIp shouldBe "10.11.12.14"
                result.getDestination.port shouldBe None

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.getProtocol shouldBe "L2TP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106023_2" in new setup {
                override def raw: String = asa106023_2

                result.getObject.category shouldBe Counterpart.connection

                result.getData.getInterface shouldBe "px_interface3_name"
                result.getData.getAux1 shouldBe "px_interface5_name"
                result.getData.getAux10 shouldBe "I_MM_TEST"

                result.getSource.getIp shouldBe "33.44.55.66"
                result.getSource.port shouldBe None

                result.getDestination.getIp shouldBe "11.22.33.44"
                result.getDestination.port shouldBe None

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.getProtocol shouldBe "SCTP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106023_3" in new setup {
                override def raw: String = asa106023_3

                result.getObject.category shouldBe Counterpart.connection

                result.getData.getInterface shouldBe "px_interface7_name"
                result.getData.getAux1 shouldBe "px_interface6_name"
                result.getData.getAux10 shouldBe "TEST_1_IN"

                result.getSource.getIp shouldBe "10.11.12.16"
                result.getSource.port shouldBe None

                result.getDestination.getIp shouldBe "172.178.99.44"
                result.getDestination.port shouldBe None

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.getProtocol shouldBe "ICMP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106023_4" in new setup {
                override def raw: String = asa106023_4

                result.getObject.category shouldBe Counterpart.connection

                result.getData.getInterface shouldBe "px_interface3_name"
                result.getData.getAux1 shouldBe "px_interface6_name"
                result.getData.getAux10 shouldBe "I_MM_TEST"

                result.getSource.getIp shouldBe "10.11.12.17"
                result.getSource.port shouldBe Some(65501)

                result.getDestination.getIp shouldBe "10.11.13.24"
                result.getDestination.port shouldBe Some(123)

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.getProtocol shouldBe "UDP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106023_5" in new setup {
                override def raw: String = asa106023_5

                result.getObject.category shouldBe Counterpart.connection

                result.getData.getInterface shouldBe "dv2interface"
                result.getData.getAux1 shouldBe "dv3interface"
                result.getData.getAux10 shouldBe "ACL_111"

                result.getSource.getIp shouldBe "10.11.12.18"
                result.getSource.port shouldBe Some(50426)

                result.getDestination.getIp shouldBe "test.example.com"
                result.getDestination.port shouldBe Some(389)

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.getProtocol shouldBe "UDP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106023_6" in new setup {
                override def raw: String = asa106023_6

                result.getObject.category shouldBe Counterpart.connection

                result.getData.getInterface shouldBe "dv3interface"
                result.getData.getAux1 shouldBe "dv4interface"
                result.getData.getAux10 shouldBe "ACL_222"

                result.getSource.getIp shouldBe "test.example.com"
                result.getSource.port shouldBe Some(63228)

                result.getDestination.getIp shouldBe "10.11.13.23"
                result.getDestination.port shouldBe Some(514)

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.getProtocol shouldBe "UDP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106023_7" in new setup {
                override def raw: String = asa106023_7

                result.getObject.category shouldBe Counterpart.connection

                result.getData.getInterface shouldBe "AB-CD"
                result.getData.getAux1 shouldBe "DC"
                result.getData.getAux10 shouldBe "AB-CD-EF"

                result.getSource.getIp shouldBe "10.11.12.19"
                result.getSource.port shouldBe Some(59140)

                result.getDestination.getIp shouldBe "10.11.13.22"
                result.getDestination.port shouldBe Some(53)

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.getProtocol shouldBe "UDP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106023_8" in new setup {
                override def raw: String = asa106023_8

                result.getObject.category shouldBe Counterpart.connection

                result.getData.getInterface shouldBe "Inside"
                result.getData.getAux1 shouldBe "Inside"
                result.getData.getAux10 shouldBe "Inside_access_in"

                result.getSource.getIp shouldBe "10.11.13.20"
                result.getSource.port shouldBe Some(56198)

                result.getDestination.getIp shouldBe "10.11.13.21"
                result.getDestination.port shouldBe Some(7680)

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.getProtocol shouldBe "TCP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }
        }

        "710003" should {
            val asa710003_1 = """<163>Jan 15 2014 03:28:52 device1_host_name : %PIX-3-710003: ESP access denied by ACL from 192.168.0.1/46492 to outside:234.63.46.89/31688"""
            val asa710003_2 = """<163>Jan 15 2014 03:28:52 : %PIX-3-710003: ESP access denied by ACL from 192.168.0.1/46492 to outside:234.63.46.89/31688"""

            s"parse $asa710003_1" in new setup {
                override def raw: String = asa710003_1

                result.getSource.getIp shouldBe "192.168.0.1"
                result.getSource.getPort shouldBe 46492

                result.getDestination.getIp shouldBe "234.63.46.89"
                result.getDestination.getPort shouldBe 31688

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.getProtocol shouldBe "ESP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa710003_2" in new setup {
                override def raw: String = asa710003_2

                result.getSource.getIp shouldBe "192.168.0.1"
                result.getSource.getPort shouldBe 46492

                result.getDestination.getIp shouldBe "234.63.46.89"
                result.getDestination.getPort shouldBe 31688

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.getProtocol shouldBe "ESP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }
        }

        "104001" should {
            val asa104001_1 = """ <161>Sep 28 2016 13:51:57 192.168.1.254 : %ASA-1-104001: (Secondary) Switching to ACTIVE - HELLO not heard from mate."""
            val asa104001_2 = """ <161>Sep 28 2016 13:51:57 192.168.1.254 : %ASA-1-104001: (Secondary) Switching to ACTIVE - mate want me Active"""

            s"parse $asa104001_1" in new setup {
                override def raw: String = asa104001_1

                result.getInteraction.action shouldBe InteractionCategory.info
                result.getInteraction.importance shouldBe ImportanceLevel.HIGH
                result.getInteraction.getReason shouldBe "HELLO not heard from mate."
            }

            s"parse $asa104001_2" in new setup {
                override def raw: String = asa104001_2

                result.getInteraction.action shouldBe InteractionCategory.info
                result.getInteraction.importance shouldBe ImportanceLevel.HIGH
                result.getInteraction.getReason shouldBe "mate want me Active"
            }
        }

        "104002" should {
            val asa104002_1 = """ <161>Sep 28 2016 13:51:57 192.168.1.253 : %ASA-1-104002: (Primary) Switching to STNDBY - interface check, mate is healthier"""

            s"parse $asa104002_1" in new setup {
                override def raw: String = asa104002_1

                result.getInteraction.action shouldBe InteractionCategory.info
                result.getInteraction.importance shouldBe ImportanceLevel.HIGH
                result.getInteraction.getReason shouldBe "interface check, mate is healthier"
            }
        }

        "105005" should {
            val asa105005_1 = """ <161>Sep 28 2016 13:51:53 192.168.1.254 : %ASA-1-105005: (Secondary) Lost Failover communications with mate on interface intACS"""

            s"parse $asa105005_1" in new setup {
                override def raw: String = asa105005_1

                result.getInteraction.action shouldBe InteractionCategory.alert
                result.getInteraction.importance shouldBe ImportanceLevel.MEDIUM
                result.getInteraction.getReason shouldBe "Lost Failover communications with mate on interface intACS"
                result.getInteraction.status shouldBe InteractionStatus.success
            }
        }


        "105008" should {
            val asa105008_1 = """<161>Sep 28 2016 10:49:03 10.125.1.28 : %ASA-1-105008: (Primary) Testing Interface outside"""
            val asa105008_2 = """<161>Dec 27 2016 07:42:52 192.168.59.254 : %ASA-1-105008: (Secondary) Testing Interface out"""

            s"parse $asa105008_1" in new setup {
                override def raw: String = asa105008_1

                result.getObject.category shouldBe Counterpart.interface
                result.getInteraction.action shouldBe InteractionCategory.check
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.getReason shouldBe "Interface_checked"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa105008_2" in new setup {
                override def raw: String = asa105008_2

                result.getObject.category shouldBe Counterpart.interface
                result.getInteraction.action shouldBe InteractionCategory.check
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.getReason shouldBe "Interface_checked"
                result.getInteraction.status shouldBe InteractionStatus.success
            }
        }

        "105009" should {
            val asa105009_1 = """<161>Sep 28 2016 10:49:03 10.125.1.28 : %ASA-1-105009: (Primary) Testing on interface outside Passed"""
            val asa105009_2 = """<161>Sep 28 2016 10:49:03 10.125.1.28 : %ASA-1-105009: (Primary) Testing on interface outside Failed"""
            val asa105009_3 = """<161> Dec 27 2016 07:43:48 192.168.59.254 : %ASA-1-105009: (Secondary_group_1) Testing on interface ins Status Undetermined"""
            val asa105009_4 = """<161> Dec 27 2016 07:46:41 192.168.59.253 : %ASA-1-105009: (Primary_group_1) Testing on interface out Passed"""

            s"parse $asa105009_1" in new setup {
                override def raw: String = asa105009_1

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getValue shouldBe "outside"

                result.getInteraction.action shouldBe InteractionCategory.check
                result.getInteraction.getReason shouldBe "Interface_checked"
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa105009_2" in new setup {
                override def raw: String = asa105009_2

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getValue shouldBe "outside"

                result.getInteraction.action shouldBe InteractionCategory.check
                result.getInteraction.importance shouldBe ImportanceLevel.MEDIUM
                result.getInteraction.getReason shouldBe "Interface_checked"
                result.getInteraction.status shouldBe InteractionStatus.failure
            }

            s"parse $asa105009_3" in new setup {
                override def raw: String = asa105009_3

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getValue shouldBe "ins"

                result.getInteraction.action shouldBe InteractionCategory.check
                result.getInteraction.importance shouldBe ImportanceLevel.MEDIUM
                result.getInteraction.getReason shouldBe "Interface_checked"
                result.getInteraction.status shouldBe InteractionStatus.failure
            }

            s"parse $asa105009_4" in new setup {
                override def raw: String = asa105009_4

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getValue shouldBe "out"

                result.getInteraction.action shouldBe InteractionCategory.check
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.getReason shouldBe "Interface_checked"
                result.getInteraction.status shouldBe InteractionStatus.success
            }
        }

        "106001" should {
            val asa106001_1 = """<162>Jan 13 2014 16:14:48 device1_host_name : %PIX-2-106001: Inbound TCP connection denied from 192.168.0.3/17990 to 1.2.3.4/60314 flags ACK  on interface px_interface1_name"""
            val asa106001_2 = """<162>Jan 13 2014 16:21:32 device1_host_name : %PIX-2-106001: Inbound TCP connection denied from 192.168.0.3/443 to 1.2.3.4/60247 flags FIN PSH ACK  on interface px_interface1_name"""
            val asa106001_3 = """<162>Jan 14 2014 16:57:16 device2_host_name : %ASA-2-106001: Inbound TCP connection denied from 44.33.55.66/9443 to 5.6.7.8/4502 flags ACK  on interface inside"""
            val asa106001_4 = """<162>Jan 13 2014 16:10:21 device3_host_name : %ASA-2-106001: Inbound TCP connection denied from 22.78.90.12/31030 to 9.10.12.13/57376 flags FIN ACK  on interface inside"""
            val asa106001_5 = """<170>Mar 19 2015 12:10:28: %ASA-2-106001: Inbound TCP connection denied from 10.20.30.40/65061 to 10.55.78.95/2270 flags SYN  on interface ABC-DEF"""

            s"parse $asa106001_1" in new setup {
                override def raw: String = asa106001_1

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getName shouldBe "px_interface1_name"

                result.getSource.getIp shouldBe "192.168.0.3"
                result.getSource.getPort shouldBe 17990

                result.getDestination.getIp shouldBe "1.2.3.4"
                result.getDestination.getPort shouldBe 60314

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.protocol shouldBe Some("TCP")
                result.getInteraction.getReason shouldBe "Inbound TCP connection denied by the security policy"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106001_2" in new setup {
                override def raw: String = asa106001_2

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getName shouldBe "px_interface1_name"

                result.getSource.getIp shouldBe "192.168.0.3"
                result.getSource.getPort shouldBe 443

                result.getDestination.getIp shouldBe "1.2.3.4"
                result.getDestination.getPort shouldBe 60247

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.protocol shouldBe Some("TCP")
                result.getInteraction.getReason shouldBe "Inbound TCP connection denied by the security policy"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106001_3" in new setup {
                override def raw: String = asa106001_3

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getName shouldBe "inside"

                result.getSource.getIp shouldBe "44.33.55.66"
                result.getSource.getPort shouldBe 9443

                result.getDestination.getIp shouldBe "5.6.7.8"
                result.getDestination.getPort shouldBe 4502

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.protocol shouldBe Some("TCP")
                result.getInteraction.getReason shouldBe "Inbound TCP connection denied by the security policy"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106001_4" in new setup {
                override def raw: String = asa106001_4

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getName shouldBe "inside"

                result.getSource.getIp shouldBe "22.78.90.12"
                result.getSource.getPort shouldBe 31030

                result.getDestination.getIp shouldBe "9.10.12.13"
                result.getDestination.getPort shouldBe 57376

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.protocol shouldBe Some("TCP")
                result.getInteraction.getReason shouldBe "Inbound TCP connection denied by the security policy"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106001_5" in new setup {
                override def raw: String = asa106001_5

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getName shouldBe "ABC-DEF"

                result.getSource.getIp shouldBe "10.20.30.40"
                result.getSource.getPort shouldBe 65061

                result.getDestination.getIp shouldBe "10.55.78.95"
                result.getDestination.getPort shouldBe 2270

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.protocol shouldBe Some("TCP")
                result.getInteraction.getReason shouldBe "Inbound TCP connection denied by the security policy"
                result.getInteraction.status shouldBe InteractionStatus.success
            }
        }

        "106006" should {
            val asa106006_1 = """<162>Jan 13 2014 15:39:14 device3_host_name : %ASA-2-106006: Deny inbound UDP from 23.34.32.78/161 to 21.44.56.75/32001 on interface inside"""
            val asa106006_2 = """<162>Jan 13 2014 15:07:54 device1_host_name : %PIX-2-106006: Deny inbound UDP from 123.45.67.89/161 to 100.200.100.001/32000 on interface px_interface2_name"""

            s"parse $asa106006_1" in new setup {
                override def raw: String = asa106006_1

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getName shouldBe "inside"

                result.getSource.getIp shouldBe "23.34.32.78"
                result.getSource.getPort shouldBe 161

                result.getDestination.getIp shouldBe "21.44.56.75"
                result.getDestination.getPort shouldBe 32001

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.protocol shouldBe Some("UDP")
                result.getInteraction.getReason shouldBe "Deny inbound UDP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106006_2" in new setup {
                override def raw: String = asa106006_2

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getName shouldBe "px_interface2_name"

                result.getSource.getIp shouldBe "123.45.67.89"
                result.getSource.getPort shouldBe 161

                result.getDestination.getIp shouldBe "100.200.100.001"
                result.getDestination.getPort shouldBe 32000

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.protocol shouldBe Some("UDP")
                result.getInteraction.getReason shouldBe "Deny inbound UDP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }
        }

        "106007" should {
            val asa106007_1 = """<162>Jan 15 2014 03:06:18 device1_host_name : %PIX-2-106007: Deny inbound UDP from 3.4.5.6/43113 to 4.5.6.7/53 due to DNS Query"""
            val asa106007_2 = """<162>:Jan 15 01:34:34 MSK: %FWSM-session-2-106007: Deny inbound UDP from 192.168.0.5/53 to 10.11.12.13/65308 due to DNS Response"""
            val asa106007_3 = """<162>:Jan 15 01:34:34 MSK 10.20.30.40: %FWSM-session-2-106007: Deny inbound UDP from 192.168.0.5/53 to 10.11.12.13/65308 due to DNS Response"""

            s"parse $asa106007_1" in new setup {
                override def raw: String = asa106007_1

                result.getObject.category shouldBe Counterpart.interface

                result.getSource.getIp shouldBe "3.4.5.6"
                result.getSource.getPort shouldBe 43113

                result.getDestination.getIp shouldBe "4.5.6.7"
                result.getDestination.getPort shouldBe 53

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.protocol shouldBe Some("UDP")
                result.getInteraction.getReason shouldBe "Deny inbound UDP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106007_2" in new setup {
                override def raw: String = asa106007_2

                result.getObject.category shouldBe Counterpart.interface

                result.getSource.getIp shouldBe "192.168.0.5"
                result.getSource.getPort shouldBe 53

                result.getDestination.getIp shouldBe "10.11.12.13"
                result.getDestination.getPort shouldBe 65308

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.protocol shouldBe Some("UDP")
                result.getInteraction.getReason shouldBe "Deny inbound UDP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106007_3" in new setup {
                override def raw: String = asa106007_3

                result.getObject.category shouldBe Counterpart.interface

                result.getSource.getIp shouldBe "192.168.0.5"
                result.getSource.getPort shouldBe 53

                result.getDestination.getIp shouldBe "10.11.12.13"
                result.getDestination.getPort shouldBe 65308

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.protocol shouldBe Some("UDP")
                result.getInteraction.getReason shouldBe "Deny inbound UDP"
                result.getInteraction.status shouldBe InteractionStatus.success
            }
        }

        "106011" should {
            val asa106011_1 = """<163>:Jan 14 23:15:55 MSK: %FWSM-session-3-106011: Deny inbound (No xlate) tcp src px_interface3_name:10.22.33.44/40389 dst px_interface3_name:10.100.10.100/23"""
            val asa106011_2 = """<163>:Jun 25 15:59:51 MSK 10.20.30.40: %FWSM-session-3-106011: Deny inbound (No xlate) udp src px_interface4_name:10.55.66.77/137 dst px_interface4_name:10.01.11.11/137"""
            val asa106011_3 = """<163>:Jan 15 03:45:42 MSK: %FWSM-session-3-106011: Deny inbound (No xlate) icmp src px_interface3_name:34.52.22.33 dst px_interface3_name:58.91.25.64 (type 8, code 0)"""
            val asa106011_4 = """<163>:Jan 15 03:45:42 MSK 10.20.30.40: %ASA-session-3-106011: Deny inbound (No xlate) icmp src px_interface3_name:34.52.22.33 dst px_interface3_name:58.91.25.64 (type 8, code 0)"""

            s"parse $asa106011_1" in new setup {
                override def raw: String = asa106011_1

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getName shouldBe "px_interface3_name"

                result.getSubject.category shouldBe Counterpart.interface
                result.getSubject.getName shouldBe "px_interface3_name"

                result.getSource.getIp shouldBe "10.22.33.44"
                result.getSource.getPort shouldBe 40389

                result.getDestination.getIp shouldBe "10.100.10.100"
                result.getDestination.getPort shouldBe 23

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.protocol shouldBe Some("TCP")
                result.getInteraction.getReason shouldBe "Deny_inbound_no_xlate"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106011_2" in new setup {
                override def raw: String = asa106011_2

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getName shouldBe "px_interface4_name"

                result.getSubject.category shouldBe Counterpart.interface
                result.getSubject.getName shouldBe "px_interface4_name"

                result.getSource.getIp shouldBe "10.55.66.77"
                result.getSource.getPort shouldBe 137

                result.getDestination.getIp shouldBe "10.01.11.11"
                result.getDestination.getPort shouldBe 137

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.protocol shouldBe Some("UDP")
                result.getInteraction.getReason shouldBe "Deny_inbound_no_xlate"
                result.getInteraction.status shouldBe InteractionStatus.success
            }

            s"parse $asa106011_3" in new setup {
                override def raw: String = asa106011_3

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getName shouldBe "px_interface3_name"

                result.getSubject.category shouldBe Counterpart.interface
                result.getSubject.getName shouldBe "px_interface3_name"

                result.getSource.getIp shouldBe "34.52.22.33"

                result.getDestination.getIp shouldBe "58.91.25.64"

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.protocol shouldBe Some("ICMP")
                result.getInteraction.getReason shouldBe "Deny_inbound_no_xlate"
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getAux4 shouldBe "type 8"
                result.getData.getAux5 shouldBe "code 0"
            }

            s"parse $asa106011_4" in new setup {
                override def raw: String = asa106011_4

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getName shouldBe "px_interface3_name"

                result.getSubject.category shouldBe Counterpart.interface
                result.getSubject.getName shouldBe "px_interface3_name"

                result.getSource.getIp shouldBe "34.52.22.33"

                result.getDestination.getIp shouldBe "58.91.25.64"

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.protocol shouldBe Some("ICMP")
                result.getInteraction.getReason shouldBe "Deny_inbound_no_xlate"
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getAux4 shouldBe "type 8"
                result.getData.getAux5 shouldBe "code 0"
            }
        }

        "106014" should {
            val asa106014_1 = """<163>Jan 14 2014 19:33:41 device1_host_name : %PIX-3-106014: Deny inbound icmp src outside:234.42.53.67 dst outside:144.52.34.66 (type 3, code 3)"""
            val asa106014_2 = """<163>Jan 14 2014 19:33:41 : %PIX-3-106014: Deny inbound icmp src outside:234.42.53.67 dst outside:144.52.34.66 (type 3, code 3)"""

            s"parse $asa106014_1" in new setup {
                override def raw: String = asa106014_1

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getName shouldBe "icmp"

                result.getSource.getIp shouldBe "234.42.53.67"
                result.getDestination.getIp shouldBe "144.52.34.66"

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.getReason shouldBe "Deny inbound icmp"
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getAux4 shouldBe "type 3"
                result.getData.getAux5 shouldBe "code 3"
            }

            s"parse $asa106014_2" in new setup {
                override def raw: String = asa106014_2

                result.getObject.category shouldBe Counterpart.interface
                result.getObject.getName shouldBe "icmp"

                result.getSource.getIp shouldBe "234.42.53.67"
                result.getDestination.getIp shouldBe "144.52.34.66"

                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.getReason shouldBe "Deny inbound icmp"
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getData.getAux4 shouldBe "type 3"
                result.getData.getAux5 shouldBe "code 3"
            }
        }
    }

    lazy val parser = new CiscoAsaParser
    lazy val mapper = new CiscoAsaMapper
    lazy val validator = new CiscoAsaValidator

    @transient
    trait setup {
        def raw: String

        protected val msg: ParsedMessage = ParsedMessage(
            raw = Left(raw),
            eventReceivedTime = ZonedDateTime.now(ZoneOffset.UTC),
            organization = "organization",
            chain = "",
            eventDevType = "asa00401",
            collectorHostname = "local.com",
            collectorHostIP = "127.0.0.1",
            severityId = 0,
            severity = "unknown",
            eventHostname = None,
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
            .map((Map("asa00401" -> DeviceVendor("asa00401", "Cisco", "ASA", "401")), ise))
    }

}
