package ru.gkis.soc.siem.normalizer.parsers

import org.junit.runner.RunWith
import org.scalatest.{Matchers, WordSpec}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.model.ParsedLog

@RunWith(classOf[JUnitRunner])
class CiscoAsaParserSpec extends WordSpec with Matchers {
    val parser = new CiscoAsaParser

    "CiscoAsaParser" when {
        "any message" should {
            "correct parse timestamp parts" in {
                val source = """<166>:Jan 13 2012 15:51:28 MSK: %ASA-auth-6-113004: AAA user authentication Successful : server =  10.20.30.153 : user = johntheuser"""
                val result: ParsedLog = parser.parse(Left(source))
                result should contain("month" -> "Jan")
                result should contain("day" -> "13")
                result should contain("year" -> "2012")
                result should contain("time" -> "15:51:28")
                result should contain("timezone" -> "MSK")
            }
        }

        "113004" should {
            val asa113004_1 = """<166>:Jan 13 15:51:28 MSK: %ASA-auth-6-113004: AAA user authentication Successful : server =  10.20.30.153 : user = johntheuser"""
            val asa113004_2 = """<166>:Oct 07 22:27:16 MSK: %FWSM-auth-6-113004: AAA user accounting Successful : server =  10.30.20.173 : user = johntheuser"""
            val asa113004_3 = """<166>:Jan 13 15:44:18 MSK 10.113.219.101: %PIX-auth-6-113004: AAA user authentication Successful : server =  192.168.5.130 : user = johntheuse"""

            s"parse $asa113004_1" in {
                val result: ParsedLog = parser.parse(Left(asa113004_1))

                result should not be empty
                result should contain("originTime" -> "Jan 13 15:51:28 MSK")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "113004")
                result should contain("subjectName" -> "johntheuser")
            }

            s"parse $asa113004_2" in {
                val result: ParsedLog = parser.parse(Left(asa113004_2))

                result should not be empty
                result should contain("originTime" -> "Oct 07 22:27:16 MSK")
                result should contain("eventSourceSubsys" -> "FWSM")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "113004")
                result should contain("subjectName" -> "johntheuser")
            }

            s"parse $asa113004_3" in {
                val result: ParsedLog = parser.parse(Left(asa113004_3))

                result should not be empty
                result should contain("originTime" -> "Jan 13 15:44:18 MSK")
                result should contain("eventSourceSubsys" -> "PIX")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "113004")
                result should contain("subjectName" -> "johntheuse")
            }
        }

        "113012" should {
            val asa113012_1 = """<166>:Oct 09 15:19:43 MSK: %ASA-auth-6-113012: AAA user authentication Successful : local database : user = johntheuser"""
            val asa113012_2 = """<166>Dec 13 2013 16:28:40 10.234.151.32 : %ASA-6-113012: AAA user authentication Successful : local database : user = johntheuser"""
            val asa113012_3 = """<166>Dec 13 2013 16:28:40 10.234.151.32 : %PIX-6-113012: AAA user authentication Successful : local database : user = johntheuse"""

            s"parse $asa113012_1" in {
                val result: ParsedLog = parser.parse(Left(asa113012_1))

                result should not be empty
                result should contain("originTime" -> "Oct 09 15:19:43 MSK")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "113012")
                result should contain("subjectName" -> "johntheuser")
            }

            s"parse $asa113012_2" in {
                val result: ParsedLog = parser.parse(Left(asa113012_2))

                result should not be empty
                result should contain("originTime" -> "Dec 13 2013 16:28:40")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "113012")
                result should contain("subjectName" -> "johntheuser")
            }

            s"parse $asa113012_3" in {
                val result: ParsedLog = parser.parse(Left(asa113012_3))

                result should not be empty
                result should contain("originTime" -> "Dec 13 2013 16:28:40")
                result should contain("eventSourceSubsys" -> "PIX")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "113012")
                result should contain("subjectName" -> "johntheuse")
            }
        }

        "113015" should {
            val asa113015_1 = """<166>:Oct 08 17:27:49 MSK: %ASA-auth-6-113015: AAA user authentication Rejected : reason = Invalid password : local database : user = johntheuser"""
            val asa113015_2 = """<166>Dec 13 2013 16:22:38 10.234.151.32 : %ASA-6-113015: AAA user authentication Rejected : reason = Invalid password : local database : user = johntheuser"""
            val asa113015_3 = """<166>Dec 13 2013 16:22:38 10.234.151.32 : %PIX-6-113015: AAA user authentication Rejected : reason = Invalid password : local database : user = johntheuser"""
            val asa113015_4 = """<166>Jan 25 2016 17:03:04 10.0.208.158 : %ASA-6-113015: AAA user authentication Rejected : reason = Invalid password : local database : user = ***** : user IP = 10.0.72.132"""

            s"parse $asa113015_1" in {
                val result: ParsedLog = parser.parse(Left(asa113015_1))

                result should not be empty
                result should contain("originTime" -> "Oct 08 17:27:49 MSK")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "113015")
                result should contain("subjectName" -> "johntheuser")
                result should contain("interactionReason" -> "Invalid password")
            }

            s"parse $asa113015_2" in {
                val result: ParsedLog = parser.parse(Left(asa113015_2))

                result should not be empty
                result should contain("originTime" -> "Dec 13 2013 16:22:38")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "113015")
                result should contain("subjectName" -> "johntheuser")
                result should contain("interactionReason" -> "Invalid password")
            }

            s"parse $asa113015_3" in {
                val result: ParsedLog = parser.parse(Left(asa113015_3))

                result should not be empty
                result should contain("originTime" -> "Dec 13 2013 16:22:38")
                result should contain("eventSourceSubsys" -> "PIX")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "113015")
                result should contain("subjectName" -> "johntheuser")
                result should contain("interactionReason" -> "Invalid password")
            }

            s"parse $asa113015_4" in {
                val result: ParsedLog = parser.parse(Left(asa113015_4))

                result should not be empty
                result should contain("originTime" -> "Jan 25 2016 17:03:04")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "113015")
                result should contain("subjectName" -> "*****")
                result should contain("sourceLocationIp" -> "10.0.72.132")
                result should contain("interactionReason" -> "Invalid password")
            }
        }

        "605005" should {
            val asa605005_1 = """<166>:Jan 15 02:19:08 MSK: %ASA-sys-6-605005: Login permitted from 133.239.111.32/36809 to outside:75.254.110.191/ssh for user "john_theuser"""""
            val asa605005_2 = """<166>Nov 07 2013 09:59:27: %ASA-6-605005: Login permitted from 10.57.127.191/48423 to outside:10.234.151.32/ssh for user "john_theuser""""
            val asa605005_3 = """<166>:Aug 14 18:04:34 MSK: %FWSM-sys-6-605005: Login permitted from 10.72.35.92/58960 to fwsm_to_mm:10.144.66.38/https for user "john_theuser""""
            val asa605005_4 = """<166>:Jan 09 09:01:19 MSK 10.113.219.101: %PIX-sys-6-605005: Login permitted from 10.199.102.105/11904 to inside:10.96.246.219/ssh for user "john_theuser""""
            val asa605005_5 = """<166>Dec 30 2014 13:42:09: %ASA-6-605005: Login permitted from serial to console for user "john_theuser""""

            s"parse $asa605005_1" in {
                val result: ParsedLog = parser.parse(Left(asa605005_1))

                result should not be empty
                result should contain("originTime" -> "Jan 15 02:19:08 MSK")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "605005")
                result should contain("sourceLocationIp" -> "133.239.111.32")
                result should contain("sourceLocationPort" -> "36809")
                result should contain("destinationLocationIp" -> "75.254.110.191")
                result should contain("aux10" -> "ssh")
                result should contain("subjectName" -> "john_theuser")
            }

            s"parse $asa605005_2" in {
                val result: ParsedLog = parser.parse(Left(asa605005_2))

                result should not be empty
                result should contain("originTime" -> "Nov 07 2013 09:59:27")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "605005")
                result should contain("sourceLocationIp" -> "10.57.127.191")
                result should contain("sourceLocationPort" -> "48423")
                result should contain("destinationLocationIp" -> "10.234.151.32")
                result should contain("aux10" -> "ssh")
                result should contain("subjectName" -> "john_theuser")
            }

            s"parse $asa605005_3" in {
                val result: ParsedLog = parser.parse(Left(asa605005_3))

                result should not be empty
                result should contain("originTime" -> "Aug 14 18:04:34 MSK")
                result should contain("eventSourceSubsys" -> "FWSM")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "605005")
                result should contain("sourceLocationIp" -> "10.72.35.92")
                result should contain("sourceLocationPort" -> "58960")
                result should contain("destinationLocationIp" -> "10.144.66.38")
                result should contain("aux10" -> "https")
                result should contain("subjectName" -> "john_theuser")
            }

            s"parse $asa605005_4" in {
                val result: ParsedLog = parser.parse(Left(asa605005_4))

                result should not be empty
                result should contain("originTime" -> "Jan 09 09:01:19 MSK")
                result should contain("eventSourceSubsys" -> "PIX")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "605005")
                result should contain("sourceLocationIp" -> "10.199.102.105")
                result should contain("sourceLocationPort" -> "11904")
                result should contain("destinationLocationIp" -> "10.96.246.219")
                result should contain("aux10" -> "ssh")
                result should contain("subjectName" -> "john_theuser")
            }

            s"parse $asa605005_5" in {
                val result: ParsedLog = parser.parse(Left(asa605005_5))

                result should not be empty
                result should contain("originTime" -> "Dec 30 2014 13:42:09")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "605005")
                result should contain("subjectName" -> "john_theuser")
            }
        }

        "611101" should {
            val asa611101_1 = """<166>:Jan 15 02:19:08 MSK: %ASA-vpnc-6-611101: User authentication succeeded: Uname: john_theuser"""
            val asa611101_2 = """<166>Nov 07 2013 09:59:32: %ASA-6-611101: User authentication succeeded: Uname: john_theuser"""
            val asa611101_3 = """<166>:Jul 02 22:28:29 MSK 10.113.219.101: %FWSM-vpnc-6-611101: User authentication succeeded: Uname: john_theuse"""

            s"parse $asa611101_1" in {
                val result: ParsedLog = parser.parse(Left(asa611101_1))

                result should not be empty
                result should contain("originTime" -> "Jan 15 02:19:08 MSK")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "611101")
                result should contain("subjectName" -> "john_theuser")
            }

            s"parse $asa611101_2" in {
                val result: ParsedLog = parser.parse(Left(asa611101_2))

                result should not be empty
                result should contain("originTime" -> "Nov 07 2013 09:59:32")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "611101")
                result should contain("subjectName" -> "john_theuser")
            }

            s"parse $asa611101_3" in {
                val result: ParsedLog = parser.parse(Left(asa611101_3))

                result should not be empty
                result should contain("originTime" -> "Jul 02 22:28:29 MSK")
                result should contain("eventSourceSubsys" -> "FWSM")
                result should contain("interactionImportance" -> "6")
                result should contain("datapayloadMsgId" -> "611101")
                result should contain("subjectName" -> "john_theuse")
            }
        }

        "111008" should {
            val asa111008_1 = """<165>:Aug 30 12:26:30 MSK: %ASA-config-5-111008: User 'johntheuser' executed the 'configure terminal' command.""""
            val asa111008_2 = """<165>Nov 14 2013 11:23:36: %ASA-5-111008: User 'johntheuser' executed the 'write memory' command."""
            val asa111008_3 = """<165>:Oct 02 15:20:37 MSK: %PIX-config-5-111008: User 'johntheuser' executed the 'write' command."""
            val asa111008_4 = """<165>:Jan 14 18:10:27 MSK 10.113.219.101: %FWSM-config-5-111008: User 'johntheuser' executed the 'policy-map POLICY_global_2' command."""
            val asa111008_5 = """<165>:Jan 14 18:10:27 MSK :%ASA-5-111008: User 'johntheuser' executed the 'logging host inside 192.168.186.173' command."""

            s"parse $asa111008_1" in {
                val result: ParsedLog = parser.parse(Left(asa111008_1))

                result should not be empty
                result should contain("originTime" -> "Aug 30 12:26:30 MSK")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "5")
                result should contain("datapayloadMsgId" -> "111008")
                result should contain("subjectName" -> "johntheuser")
                result should contain("command" -> "configure terminal")
            }

            s"parse $asa111008_2" in {
                val result: ParsedLog = parser.parse(Left(asa111008_2))

                result should not be empty
                result should contain("originTime" -> "Nov 14 2013 11:23:36")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "5")
                result should contain("subjectName" -> "johntheuser")
                result should contain("datapayloadMsgId" -> "111008")
                result should contain("command" -> "write memory")
            }

            s"parse $asa111008_3" in {
                val result: ParsedLog = parser.parse(Left(asa111008_3))

                result should not be empty
                result should contain("originTime" -> "Oct 02 15:20:37 MSK")
                result should contain("eventSourceSubsys" -> "PIX")
                result should contain("interactionImportance" -> "5")
                result should contain("datapayloadMsgId" -> "111008")
                result should contain("subjectName" -> "johntheuser")
                result should contain("command" -> "write")
            }

            s"parse $asa111008_4" in {
                val result: ParsedLog = parser.parse(Left(asa111008_4))

                result should not be empty
                result should contain("originTime" -> "Jan 14 18:10:27 MSK")
                result should contain("eventSourceSubsys" -> "FWSM")
                result should contain("interactionImportance" -> "5")
                result should contain("datapayloadMsgId" -> "111008")
                result should contain("subjectName" -> "johntheuser")
                result should contain("command" -> "policy-map POLICY_global_2")
            }

            s"parse $asa111008_5" in {
                val result: ParsedLog = parser.parse(Left(asa111008_5))

                result should not be empty
                result should contain("originTime" -> "Jan 14 18:10:27 MSK")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "5")
                result should contain("datapayloadMsgId" -> "111008")
                result should contain("subjectName" -> "johntheuser")
                result should contain("command" -> "logging host inside 192.168.186.173")
            }
        }

        "111010" should {
            val asa111010_1 = """<165>Nov 08 2013 10:18:30: %ASA-5-111010: User 'johntheuser', running 'CLI' from IP 10.57.127.191, executed 'logging on'""""
            val asa111010_2 = """<165>Nov 08 2013 10:18:30 10.113.219.101: %PIX-5-111010: User 'johntheuser', running 'CLI' from IP 10.57.127.191, executed 'logging on'"""
            val asa111010_3 = """<165>Nov 08 2013 10:18:30: %ASA-5-111010: User 'johntheuser', running 'N/A' from IP 147.2.32.22, executed 'logging host inside 192.168.186.173'"""

            s"parse $asa111010_1" in {
                val result: ParsedLog = parser.parse(Left(asa111010_1))

                result should not be empty
                result should contain("originTime" -> "Nov 08 2013 10:18:30")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "5")
                result should contain("datapayloadMsgId" -> "111010")
                result should contain("subjectName" -> "johntheuser")
                result should contain("sourceLocationIp" -> "10.57.127.191")
                result should contain("command" -> "logging on")
            }

            s"parse $asa111010_2" in {
                val result: ParsedLog = parser.parse(Left(asa111010_2))

                result should not be empty
                result should contain("originTime" -> "Nov 08 2013 10:18:30")
                result should contain("eventSourceSubsys" -> "PIX")
                result should contain("interactionImportance" -> "5")
                result should contain("datapayloadMsgId" -> "111010")
                result should contain("subjectName" -> "johntheuser")
                result should contain("sourceLocationIp" -> "10.57.127.191")
                result should contain("command" -> "logging on")
            }

            s"parse $asa111010_3" in {
                val result: ParsedLog = parser.parse(Left(asa111010_3))

                result should not be empty
                result should contain("originTime" -> "Nov 08 2013 10:18:30")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "5")
                result should contain("datapayloadMsgId" -> "111010")
                result should contain("subjectName" -> "johntheuser")
                result should contain("sourceLocationIp" -> "147.2.32.22")
                result should contain("command" -> "logging host inside 192.168.186.173")
            }
        }

        //        "106002" should {
        //            val asa106002_1 = """%ASA-2-106002: protocol (TCP|UDP) Connection denied by outbound list acl_ID src inside_address dest outside_address""""
        //
        //            s"parse $asa106002_1" in {
        //                val result: ParsedLog = parser.parse(Left(asa106002_1))
        //
        //                result should not be empty
        //                result should contain("originTime" -> "Nov 08 2013 10:18:30")
        //                result should contain("eventSourceSubsys" -> "ASA")
        //                result should contain("interactionImportance" -> "5")
        //                result should contain("subjectName" -> "johntheuser")
        //                result should contain("sourceLocationIp" -> "147.2.32.22")
        //                result should contain("command" -> "logging host inside 192.168.186.173")
        //            }
        //        }

        "106023" should {
            val asa106023_1 = """<164>:Jan 15 01:34:00 MSK: %ASA-session-4-106023: Deny protocol 115 src px_interface3_name:10.27.192.99 dst px_interface6_name:10.251.129.105 by access-group "I_MM_TEST" [0x0, 0x0]"""
            val asa106023_2 = """<164>:Jan 14 23:53:28 MSK 10.113.219.101: %FWSM-session-4-106023: Deny protocol 132 src px_interface3_name:79.254.37.32 dst px_interface5_name:165.211.40.55 by access-group "I_MM_TEST" [0x0, 0x0]"""
            val asa106023_3 = """<164>:Jan 14 17:19:04 MSK 10.113.219.101: %ASA-session-4-106023: Deny icmp src px_interface7_name:10.230.184.142 dst px_interface6_name:172.22.83.203 (type 8, code 0) by access-group "TEST_1_IN" [0x0, 0x0]"""
            val asa106023_4 = """<164>:Jun 25 15:59:50 MSK 10.113.219.101: %ASA-session-4-106023: Deny udp src px_interface3_name:10.56.118.37/65501 dst px_interface6_name:10.43.59.124/123 by access-group "I_MM_TEST" [0x0, 0x0]"""
            val asa106023_5 = """<164>Nov 13 15:35:10 10.39.78.109 %ASA-4-106023: Deny udp src dv2interface:10.72.27.32/50426 dst dv3interface:hh-dd5.example.com/389 by access-group "ACL_111" [0x0, 0x0]"""
            val asa106023_6 = """<164>Nov 13 15:38:03 10.39.78.109 %ASA-4-106023: Deny udp src dv3interface:hh-cc5.example.com/63228 dst dv4interface:10.40.71.98/514 by access-group "ACL_222" [0x0, 0x0]"""
            val asa106023_7 = """<172>Mar 19 2015 12:53:28: %ASA-4-106023: Deny udp src AB-CD:10.229.81.38/59140 dst DC:10.158.130.107/53 by access-group "AB-CD-EF" [0x1800007b, 0x0]"""
            val asa106023_8 = """<140>Jul 21 2017 00:42:51 Abc-ASA : %ASA-4-106023: Deny tcp src Inside:10.110.40.230/56198 dst Inside:10.30.250.200/7680(LOCAL\ab.vgdeev) by access-group "Inside_access_in" [0x51fd3ce2, 0x0]"""

            s"parse $asa106023_1" in {
                val result: ParsedLog = parser.parse(Left(asa106023_1))

                result should not be empty
                result should contain("originTime" -> "Jan 15 01:34:00 MSK")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "4")
                result should contain("datapayloadMsgId" -> "106023")

                result should contain("interactionProtocol" -> "115")
                result should contain("sourceLocationIp" -> "10.27.192.99")
                result should contain("destinationLocationIp" -> "10.251.129.105")
                result should contain("aux10" -> "I_MM_TEST")
            }

            s"parse $asa106023_2" in {
                val result: ParsedLog = parser.parse(Left(asa106023_2))

                result should not be empty
                result should contain("originTime" -> "Jan 14 23:53:28 MSK")
                result should contain("eventSourceSubsys" -> "FWSM")
                result should contain("interactionImportance" -> "4")
                result should contain("datapayloadMsgId" -> "106023")

                result should contain("interactionProtocol" -> "132")
                result should contain("sourceLocationIp" -> "79.254.37.32")
                result should contain("destinationLocationIp" -> "165.211.40.55")
                result should contain("aux10" -> "I_MM_TEST")
            }

            s"parse $asa106023_3" in {
                val result: ParsedLog = parser.parse(Left(asa106023_3))

                result should not be empty
                result should contain("originTime" -> "Jan 14 17:19:04 MSK")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "4")
                result should contain("datapayloadMsgId" -> "106023")

                result should contain("interactionProtocol" -> "icmp")
                result should contain("sourceLocationIp" -> "10.230.184.142")
                result should contain("destinationLocationIp" -> "172.22.83.203")
                result should contain("aux10" -> "TEST_1_IN")
            }

            s"parse $asa106023_4" in {
                val result: ParsedLog = parser.parse(Left(asa106023_4))

                result should not be empty
                result should contain("originTime" -> "Jun 25 15:59:50 MSK")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "4")
                result should contain("datapayloadMsgId" -> "106023")

                result should contain("interactionProtocol" -> "udp")
                result should contain("sourceLocationIp" -> "10.56.118.37")
                result should contain("sourceLocationPort" -> "65501")
                result should contain("destinationLocationIp" -> "10.43.59.124")
                result should contain("destinationLocationPort" -> "123")
                result should contain("aux10" -> "I_MM_TEST")
            }

            s"parse $asa106023_5" in {
                val result: ParsedLog = parser.parse(Left(asa106023_5))

                result should not be empty
                result should contain("originTime" -> "Nov 13 15:35:10")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "4")
                result should contain("datapayloadMsgId" -> "106023")

                result should contain("interactionProtocol" -> "udp")
                result should contain("sourceLocationIp" -> "10.72.27.32")
                result should contain("sourceLocationPort" -> "50426")
                result should contain("destinationLocationIp" -> "hh-dd5.example.com")
                result should contain("destinationLocationPort" -> "389")
                result should contain("aux10" -> "ACL_111")
            }

            s"parse $asa106023_6" in {
                val result: ParsedLog = parser.parse(Left(asa106023_6))

                result should not be empty
                result should contain("originTime" -> "Nov 13 15:38:03")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "4")
                result should contain("datapayloadMsgId" -> "106023")

                result should contain("interactionProtocol" -> "udp")
                result should contain("sourceLocationIp" -> "hh-cc5.example.com")
                result should contain("sourceLocationPort" -> "63228")
                result should contain("destinationLocationIp" -> "10.40.71.98")
                result should contain("destinationLocationPort" -> "514")
                result should contain("aux10" -> "ACL_222")
            }

            s"parse $asa106023_7" in {
                val result: ParsedLog = parser.parse(Left(asa106023_7))

                result should not be empty
                result should contain("originTime" -> "Mar 19 2015 12:53:28")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "4")
                result should contain("datapayloadMsgId" -> "106023")

                result should contain("interactionProtocol" -> "udp")
                result should contain("sourceLocationIp" -> "10.229.81.38")
                result should contain("sourceLocationPort" -> "59140")
                result should contain("destinationLocationIp" -> "10.158.130.107")
                result should contain("destinationLocationPort" -> "53")
                result should contain("aux10" -> "AB-CD-EF")
            }

            s"parse $asa106023_8" in {
                val result: ParsedLog = parser.parse(Left(asa106023_8))

                result should not be empty
                result should contain("originTime" -> "Jul 21 2017 00:42:51")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "4")
                result should contain("datapayloadMsgId" -> "106023")

                result should contain("interactionProtocol" -> "tcp")
                result should contain("sourceLocationIp" -> "10.110.40.230")
                result should contain("sourceLocationPort" -> "56198")
                result should contain("destinationLocationIp" -> "10.30.250.200")
                result should contain("destinationLocationPort" -> "7680")
                result should contain("aux10" -> "Inside_access_in")
            }
        }

        "710003" should {
            val asa710003_1 = """<163>Jan 15 2014 03:28:52 device1_host_name : %PIX-3-710003: ESP access denied by ACL from 101.55.83.30/46492 to outside:126.150.62.16/31688"""
            val asa710003_2 = """<163>Jan 15 2014 03:28:52 : %PIX-3-710003: ESP access denied by ACL from 101.55.83.30/46492 to outside:126.150.62.16/31688"""

            s"parse $asa710003_1" in {
                val result: ParsedLog = parser.parse(Left(asa710003_1))

                result should not be empty
                result should contain("originTime" -> "Jan 15 2014 03:28:52")
                result should contain("eventSourceSubsys" -> "PIX")
                result should contain("interactionImportance" -> "3")
                result should contain("datapayloadMsgId" -> "710003")

                result should contain("interactionProtocol" -> "ESP")
                result should contain("sourceLocationIp" -> "101.55.83.30")
                result should contain("sourceLocationPort" -> "46492")
                result should contain("destinationLocationIp" -> "126.150.62.16")
                result should contain("destinationLocationPort" -> "31688")
            }

            s"parse $asa710003_2" in {
                val result: ParsedLog = parser.parse(Left(asa710003_2))

                result should not be empty
                result should contain("originTime" -> "Jan 15 2014 03:28:52")
                result should contain("eventSourceSubsys" -> "PIX")
                result should contain("interactionImportance" -> "3")
                result should contain("datapayloadMsgId" -> "710003")

                result should contain("interactionProtocol" -> "ESP")
                result should contain("sourceLocationIp" -> "101.55.83.30")
                result should contain("sourceLocationPort" -> "46492")
                result should contain("destinationLocationIp" -> "126.150.62.16")
                result should contain("destinationLocationPort" -> "31688")
            }
        }

        "104001" should {
            val asa104001_1 = """ <161>Sep 28 2016 13:51:57 192.168.1.254 : %ASA-1-104001: (Secondary) Switching to ACTIVE - HELLO not heard from mate."""
            val asa104001_2 = """ <161>Sep 28 2016 13:51:57 192.168.1.254 : %ASA-1-104001: (Secondary) Switching to ACTIVE - mate want me Active"""

            s"parse $asa104001_1" in {
                val result: ParsedLog = parser.parse(Left(asa104001_1))

                result should not be empty
                result should contain("originTime" -> "Sep 28 2016 13:51:57")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "1")
                result should contain("datapayloadMsgId" -> "104001")

                result should contain("interactionReason" -> "HELLO not heard from mate.")
            }

            s"parse $asa104001_2" in {
                val result: ParsedLog = parser.parse(Left(asa104001_2))

                result should not be empty
                result should contain("originTime" -> "Sep 28 2016 13:51:57")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "1")
                result should contain("datapayloadMsgId" -> "104001")

                result should contain("interactionReason" -> "mate want me Active")
            }
        }

        "104002" should {
            val asa104002_1 = """ <161>Sep 28 2016 13:51:57 192.168.1.253 : %ASA-1-104002: (Primary) Switching to STNDBY - interface check, mate is healthier"""

            s"parse $asa104002_1" in {
                val result: ParsedLog = parser.parse(Left(asa104002_1))

                result should not be empty
                result should contain("originTime" -> "Sep 28 2016 13:51:57")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "1")
                result should contain("datapayloadMsgId" -> "104002")

                result should contain("interactionReason" -> "interface check, mate is healthier")
            }
        }

        "105005" should {
            val asa105005_1 = """ <161>Sep 28 2016 13:51:53 192.168.1.254 : %ASA-1-105005: (Secondary) Lost Failover communications with mate on interface intACS"""

            s"parse $asa105005_1" in {
                val result: ParsedLog = parser.parse(Left(asa105005_1))

                result should not be empty
                result should contain("originTime" -> "Sep 28 2016 13:51:53")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "1")
                result should contain("datapayloadMsgId" -> "105005")

                result should contain("interactionReason" -> "Lost Failover communications with mate on interface intACS")
            }
        }

        "105008" should {
            val asa105008_1 = """<161>Sep 28 2016 10:49:03 10.125.1.28 : %ASA-1-105008: (Primary) Testing Interface outside"""
            val asa105008_2 = """<161>Dec 27 2016 07:42:52 192.168.59.254 : %ASA-1-105008: (Secondary) Testing Interface out"""

            s"parse $asa105008_1" in {
                val result: ParsedLog = parser.parse(Left(asa105008_1))

                result should not be empty
                result should contain("originTime" -> "Sep 28 2016 10:49:03")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "1")
                result should contain("datapayloadMsgId" -> "105008")
            }

            s"parse $asa105008_2" in {
                val result: ParsedLog = parser.parse(Left(asa105008_2))

                result should not be empty
                result should contain("originTime" -> "Dec 27 2016 07:42:52")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "1")
                result should contain("datapayloadMsgId" -> "105008")
            }
        }

        "105009" should {
            val asa105009_1 = """<161>Sep 28 2016 10:49:03 10.125.1.28 : %ASA-1-105009: (Primary) Testing on interface outside Passed"""
            val asa105009_2 = """<161>Sep 28 2016 10:49:03 10.125.1.28 : %ASA-1-105009: (Primary) Testing on interface outside Failed"""
            val asa105009_3 = """<161> Dec 27 2016 07:43:48 192.168.59.254 : %ASA-1-105009: (Secondary_group_1) Testing on interface ins Status Undetermined"""
            val asa105009_4 = """<161> Dec 27 2016 07:46:41 192.168.59.253 : %ASA-1-105009: (Primary_group_1) Testing on interface out Passed"""

            s"parse $asa105009_1" in {
                val result: ParsedLog = parser.parse(Left(asa105009_1))

                result should not be empty
                result should contain("originTime" -> "Sep 28 2016 10:49:03")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "1")
                result should contain("datapayloadMsgId" -> "105009")

                result should contain("objectValue" -> "outside")
                result should contain("interactionStatus" -> "Passed")
            }

            s"parse $asa105009_2" in {
                val result: ParsedLog = parser.parse(Left(asa105009_2))

                result should not be empty
                result should contain("originTime" -> "Sep 28 2016 10:49:03")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "1")
                result should contain("datapayloadMsgId" -> "105009")

                result should contain("objectValue" -> "outside")
                result should contain("interactionStatus" -> "Failed")
            }
            s"parse $asa105009_3" in {
                val result: ParsedLog = parser.parse(Left(asa105009_3))

                result should not be empty
                result should contain("originTime" -> "Dec 27 2016 07:43:48")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "1")
                result should contain("datapayloadMsgId" -> "105009")

                result should contain("objectValue" -> "ins")
                result should contain("interactionStatus" -> "Undetermined")
            }
            s"parse $asa105009_4" in {
                val result: ParsedLog = parser.parse(Left(asa105009_4))

                result should not be empty
                result should contain("originTime" -> "Dec 27 2016 07:46:41")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "1")
                result should contain("datapayloadMsgId" -> "105009")

                result should contain("objectValue" -> "out")
                result should contain("interactionStatus" -> "Passed")
            }
        }

        "106001" should {
            val asa106001_1 = """<162>Jan 13 2014 16:14:48 device1_host_name : %PIX-2-106001: Inbound TCP connection denied from 197.215.28.166/17990 to 7.179.94.19/60314 flags ACK  on interface px_interface1_name"""
            val asa106001_2 = """<162>Jan 13 2014 16:21:32 device1_host_name : %PIX-2-106001: Inbound TCP connection denied from 197.215.28.166/443 to 7.179.94.19/60247 flags FIN PSH ACK  on interface px_interface1_name"""
            val asa106001_3 = """<162>Jan 14 2014 16:57:16 device2_host_name : %ASA-2-106001: Inbound TCP connection denied from 231.203.251.135/9443 to 143.37.165.164/4502 flags ACK  on interface inside"""
            val asa106001_4 = """<162>Jan 13 2014 16:10:21 device3_host_name : %ASA-2-106001: Inbound TCP connection denied from 225.11.168.234/31030 to 139.141.168.124/57376 flags FIN ACK  on interface inside"""
            val asa106001_5 = """<170>Mar 19 2015 12:10:28: %ASA-2-106001: Inbound TCP connection denied from 10.170.160.190/65061 to 10.193.177.71/2270 flags SYN  on interface ABC-DEF"""

            s"parse $asa106001_1" in {
                val result: ParsedLog = parser.parse(Left(asa106001_1))

                result should not be empty
                result should contain("originTime" -> "Jan 13 2014 16:14:48")
                result should contain("eventSourceSubsys" -> "PIX")
                result should contain("interactionImportance" -> "2")
                result should contain("datapayloadMsgId" -> "106001")

                result should contain("sourceLocationIp" -> "197.215.28.166")
                result should contain("sourceLocationPort" -> "17990")
                result should contain("destinationLocationIp" -> "7.179.94.19")
                result should contain("destinationLocationPort" -> "60314")
                result should contain("objectName" -> "px_interface1_name")
            }

            s"parse $asa106001_2" in {
                val result: ParsedLog = parser.parse(Left(asa106001_2))

                result should not be empty
                result should contain("originTime" -> "Jan 13 2014 16:21:32")
                result should contain("eventSourceSubsys" -> "PIX")
                result should contain("interactionImportance" -> "2")
                result should contain("datapayloadMsgId" -> "106001")

                result should contain("sourceLocationIp" -> "197.215.28.166")
                result should contain("sourceLocationPort" -> "443")
                result should contain("destinationLocationIp" -> "7.179.94.19")
                result should contain("destinationLocationPort" -> "60247")
                result should contain("objectName" -> "px_interface1_name")
            }

            s"parse $asa106001_3" in {
                val result: ParsedLog = parser.parse(Left(asa106001_3))

                result should not be empty
                result should contain("originTime" -> "Jan 14 2014 16:57:16")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "2")
                result should contain("datapayloadMsgId" -> "106001")

                result should contain("sourceLocationIp" -> "231.203.251.135")
                result should contain("sourceLocationPort" -> "9443")
                result should contain("destinationLocationIp" -> "143.37.165.164")
                result should contain("destinationLocationPort" -> "4502")
                result should contain("objectName" -> "inside")
            }

            s"parse $asa106001_4" in {
                val result: ParsedLog = parser.parse(Left(asa106001_4))

                result should not be empty
                result should contain("originTime" -> "Jan 13 2014 16:10:21")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "2")
                result should contain("datapayloadMsgId" -> "106001")

                result should contain("sourceLocationIp" -> "225.11.168.234")
                result should contain("sourceLocationPort" -> "31030")
                result should contain("destinationLocationIp" -> "139.141.168.124")
                result should contain("destinationLocationPort" -> "57376")
                result should contain("objectName" -> "inside")
            }

            s"parse $asa106001_5" in {
                val result: ParsedLog = parser.parse(Left(asa106001_5))

                result should not be empty
                result should contain("originTime" -> "Mar 19 2015 12:10:28")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "2")
                result should contain("datapayloadMsgId" -> "106001")

                result should contain("sourceLocationIp" -> "10.170.160.190")
                result should contain("sourceLocationPort" -> "65061")
                result should contain("destinationLocationIp" -> "10.193.177.71")
                result should contain("destinationLocationPort" -> "2270")
                result should contain("objectName" -> "ABC-DEF")
            }
        }

        "106006" should {
            val asa106006_1 = """<162>Jan 13 2014 15:39:14 device3_host_name : %ASA-2-106006: Deny inbound UDP from 211.69.184.202/161 to 41.162.37.34/32001 on interface inside"""
            val asa106006_2 = """<162>Jan 13 2014 15:07:54 device1_host_name : %PIX-2-106006: Deny inbound UDP from 105.222.88.165/161 to 109.86.26.223/32000 on interface px_interface2_name"""

            s"parse $asa106006_1" in {
                val result: ParsedLog = parser.parse(Left(asa106006_1))

                result should not be empty
                result should contain("originTime" -> "Jan 13 2014 15:39:14")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "2")
                result should contain("datapayloadMsgId" -> "106006")

                result should contain("sourceLocationIp" -> "211.69.184.202")
                result should contain("sourceLocationPort" -> "161")
                result should contain("destinationLocationIp" -> "41.162.37.34")
                result should contain("destinationLocationPort" -> "32001")
                result should contain("objectName" -> "inside")
            }

            s"parse $asa106006_2" in {
                val result: ParsedLog = parser.parse(Left(asa106006_2))

                result should not be empty
                result should contain("originTime" -> "Jan 13 2014 15:07:54")
                result should contain("eventSourceSubsys" -> "PIX")
                result should contain("interactionImportance" -> "2")
                result should contain("datapayloadMsgId" -> "106006")

                result should contain("sourceLocationIp" -> "105.222.88.165")
                result should contain("sourceLocationPort" -> "161")
                result should contain("destinationLocationIp" -> "109.86.26.223")
                result should contain("destinationLocationPort" -> "32000")
                result should contain("objectName" -> "px_interface2_name")
            }
        }

        "106007" should {
            val asa106007_1 = """<162>Jan 15 2014 03:06:18 device1_host_name : %PIX-2-106007: Deny inbound UDP from 8.159.139.30/43113 to 12.163.147.235/53 due to DNS Query"""
            val asa106007_2 = """<162>:Jan 15 01:34:34 MSK: %FWSM-session-2-106007: Deny inbound UDP from 192.168.196.89/53 to 10.36.2.180/65308 due to DNS Response"""
            val asa106007_3 = """<162>:Jan 15 01:34:34 MSK 10.113.219.101: %FWSM-session-2-106007: Deny inbound UDP from 192.168.196.89/53 to 10.36.2.180/65308 due to DNS Response"""

            s"parse $asa106007_1" in {
                val result: ParsedLog = parser.parse(Left(asa106007_1))

                result should not be empty
                result should contain("originTime" -> "Jan 15 2014 03:06:18")
                result should contain("eventSourceSubsys" -> "PIX")
                result should contain("interactionImportance" -> "2")
                result should contain("datapayloadMsgId" -> "106007")

                result should contain("sourceLocationIp" -> "8.159.139.30")
                result should contain("sourceLocationPort" -> "43113")
                result should contain("destinationLocationIp" -> "12.163.147.235")
                result should contain("destinationLocationPort" -> "53")
            }

            s"parse $asa106007_2" in {
                val result: ParsedLog = parser.parse(Left(asa106007_2))

                result should not be empty
                result should contain("originTime" -> "Jan 15 01:34:34 MSK")
                result should contain("eventSourceSubsys" -> "FWSM")
                result should contain("interactionImportance" -> "2")
                result should contain("datapayloadMsgId" -> "106007")

                result should contain("sourceLocationIp" -> "192.168.196.89")
                result should contain("sourceLocationPort" -> "53")
                result should contain("destinationLocationIp" -> "10.36.2.180")
                result should contain("destinationLocationPort" -> "65308")
            }

            s"parse $asa106007_3" in {
                val result: ParsedLog = parser.parse(Left(asa106007_3))

                result should not be empty
                result should contain("originTime" -> "Jan 15 01:34:34 MSK")
                result should contain("eventSourceSubsys" -> "FWSM")
                result should contain("interactionImportance" -> "2")
                result should contain("datapayloadMsgId" -> "106007")

                result should contain("sourceLocationIp" -> "192.168.196.89")
                result should contain("sourceLocationPort" -> "53")
                result should contain("destinationLocationIp" -> "10.36.2.180")
                result should contain("destinationLocationPort" -> "65308")
            }
        }

        "106011" should {
            val asa106011_1 = """<163>:Jan 14 23:15:55 MSK: %FWSM-session-3-106011: Deny inbound (No xlate) tcp src px_interface3_name:10.235.82.29/40389 dst px_interface3_name:10.140.73.199/23"""
            val asa106011_2 = """<163>:Jun 25 15:59:51 MSK 10.113.219.101: %FWSM-session-3-106011: Deny inbound (No xlate) udp src px_interface4_name:10.208.105.52/137 dst px_interface4_name:10.36.217.6/137"""
            val asa106011_3 = """<163>:Jan 15 03:45:42 MSK: %FWSM-session-3-106011: Deny inbound (No xlate) icmp src px_interface3_name:57.198.203.213 dst px_interface3_name:26.28.58.56 (type 8, code 0)"""
            val asa106011_4 = """<163>:Jan 15 03:45:42 MSK 10.113.219.101: %ASA-session-3-106011: Deny inbound (No xlate) icmp src px_interface3_name:57.198.203.213 dst px_interface3_name:26.28.58.56 (type 8, code 0)"""

            s"parse $asa106011_1" in {
                val result: ParsedLog = parser.parse(Left(asa106011_1))

                result should not be empty
                result should contain("originTime" -> "Jan 14 23:15:55 MSK")
                result should contain("eventSourceSubsys" -> "FWSM")
                result should contain("interactionImportance" -> "3")
                result should contain("datapayloadMsgId" -> "106011")

                result should contain("interactionProtocol" -> "tcp")
                result should contain("objectName" -> "px_interface3_name")

                result should contain("sourceLocationIp" -> "10.235.82.29")
                result should contain("sourceLocationPort" -> "40389")

                result should contain("subjectName" -> "px_interface3_name")
                result should contain("destinationLocationIp" -> "10.140.73.199")
                result should contain("destinationLocationPort" -> "23")
            }

            s"parse $asa106011_2" in {
                val result: ParsedLog = parser.parse(Left(asa106011_2))

                result should not be empty
                result should contain("originTime" -> "Jun 25 15:59:51 MSK")
                result should contain("eventSourceSubsys" -> "FWSM")
                result should contain("interactionImportance" -> "3")
                result should contain("datapayloadMsgId" -> "106011")

                result should contain("interactionProtocol" -> "udp")
                result should contain("objectName" -> "px_interface4_name")

                result should contain("sourceLocationIp" -> "10.208.105.52")
                result should contain("sourceLocationPort" -> "137")

                result should contain("subjectName" -> "px_interface4_name")
                result should contain("destinationLocationIp" -> "10.36.217.6")
                result should contain("destinationLocationPort" -> "137")
            }

            s"parse $asa106011_3" in {
                val result: ParsedLog = parser.parse(Left(asa106011_3))

                result should not be empty
                result should contain("originTime" -> "Jan 15 03:45:42 MSK")
                result should contain("eventSourceSubsys" -> "FWSM")
                result should contain("interactionImportance" -> "3")
                result should contain("datapayloadMsgId" -> "106011")

                result should contain("interactionProtocol" -> "icmp")
                result should contain("objectName" -> "px_interface3_name")

                result should contain("sourceLocationIp" -> "57.198.203.213")

                result should contain("subjectName" -> "px_interface3_name")
                result should contain("destinationLocationIp" -> "26.28.58.56")

                result should contain("aux4" -> "type 8")
                result should contain("aux5" -> "code 0")
            }

            s"parse $asa106011_4" in {
                val result: ParsedLog = parser.parse(Left(asa106011_4))

                result should not be empty
                result should contain("originTime" -> "Jan 15 03:45:42 MSK")
                result should contain("eventSourceSubsys" -> "ASA")
                result should contain("interactionImportance" -> "3")
                result should contain("datapayloadMsgId" -> "106011")

                result should contain("interactionProtocol" -> "icmp")
                result should contain("objectName" -> "px_interface3_name")

                result should contain("sourceLocationIp" -> "57.198.203.213")

                result should contain("subjectName" -> "px_interface3_name")
                result should contain("destinationLocationIp" -> "26.28.58.56")

                result should contain("aux4" -> "type 8")
                result should contain("aux5" -> "code 0")
            }
        }

        "106014" should {
            val asa106014_1 = """<163>Jan 14 2014 19:33:41 device1_host_name : %PIX-3-106014: Deny inbound icmp src outside:214.243.57.254 dst outside:133.121.201.196 (type 3, code 3)"""
            val asa106014_2 = """<163>Jan 14 2014 19:33:41 : %PIX-3-106014: Deny inbound icmp src outside:214.243.57.254 dst outside:133.121.201.196 (type 3, code 3)"""

            s"parse $asa106014_1" in {
                val result: ParsedLog = parser.parse(Left(asa106014_1))

                result should not be empty
                result should contain("originTime" -> "Jan 14 2014 19:33:41")
                result should contain("eventSourceSubsys" -> "PIX")
                result should contain("interactionImportance" -> "3")
                result should contain("datapayloadMsgId" -> "106014")

                result should contain("objectName" -> "icmp")

                result should contain("sourceLocationIp" -> "214.243.57.254")

                result should contain("destinationLocationIp" -> "133.121.201.196")

                result should contain("aux4" -> "type 3")
                result should contain("aux5" -> "code 3")
            }

            s"parse $asa106014_2" in {
                val result: ParsedLog = parser.parse(Left(asa106014_2))

                result should not be empty
                result should contain("originTime" -> "Jan 14 2014 19:33:41")
                result should contain("eventSourceSubsys" -> "PIX")
                result should contain("interactionImportance" -> "3")
                result should contain("datapayloadMsgId" -> "106014")

                result should contain("objectName" -> "icmp")

                result should contain("sourceLocationIp" -> "214.243.57.254")

                result should contain("destinationLocationIp" -> "133.121.201.196")

                result should contain("aux4" -> "type 3")
                result should contain("aux5" -> "code 3")
            }
        }
    }
}
