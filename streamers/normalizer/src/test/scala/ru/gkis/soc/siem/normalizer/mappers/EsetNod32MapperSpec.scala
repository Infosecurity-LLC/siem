package ru.gkis.soc.siem.normalizer.mappers

import org.junit.runner.RunWith
import org.scalatest.{Matchers, WordSpec}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.normalizer.parsers.EsetNod32Parser
import ru.gkis.soc.siem.normalizer.validators.EsetNod32Validator
import ru.gkis.soc.siem.normalizer.{InternalSocEvent, ParsedEvent, ParsedMessage}

import java.time.{ZoneOffset, ZonedDateTime}

@RunWith(classOf[JUnitRunner])
class EsetNod32MapperSpec extends WordSpec with Matchers {
    "EsetMapper" when {
        "audit_event" should {
            val audit_event_1 = """{"event_type":"audit_event","ipv4":"192.168.11.22","hostname":"hostname1.domain.ru","source_uuid":"0861d834-44ac-4484-ac7e-bb42a5c63630","occured":"21-jan-2021 12:42:06","severity":"information","domain":"domain group","action":"login attempt","target":"3668349a-4da4-4456-8d56-3e5a5f6ade14","detail":"authenticating domain user 'v.pupkin'.","user":"","result":"success"}"""
            val audit_event_2 = """{"event_type":"audit_event","ipv4":"192.168.11.22","hostname":"hostname1.domain.ru","source_uuid":"0861d834-44ac-4484-ac7e-bb42a5c63630","occured":"21-jan-2021 13:05:28","severity":"information","domain":"domain group","action":"logout","target":"3668349a-4da4-4456-8d56-3e5a5f6ade14","detail":"logging out domain user 'v.pupkin'.","user":"v.pupkin","result":"success"}"""
            val audit_event_3 = """{"event_type":"audit_event","ipv4":"192.168.11.22","hostname":"hostname1.domain.ru","source_uuid":"0861d834-44ac-4484-ac7e-bb42a5c63630","occured":"21-jan-2021 11:08:05","severity":"error","domain":"domain group","action":"login attempt","detail":"authenticating domain user 'v.pupkin'.","user":"","result":"failed"}"""
            val audit_event_4 = """{"event_type":"audit_event","ipv4":"192.168.33.44","hostname":"hostname2","source_uuid":"d7640d7d-b867-4585-8587-24fa131258f3","occured":"25-mar-2020 13:08:06","severity":"information","domain":"native user","action":"login attempt","target":"admin","detail":"authenticating native user 'admin'.","user":"bb77b966-370e-4600-a303-c83fb50d1acc","result":"success"}"""

            s"correct map $audit_event_1" in new setup {
                override def raw: String = audit_event_1

                result.getDestination.getIp shouldBe "192.168.11.22"
                result.getDestination.getHostname shouldBe "hostname1"
                result.getDestination.getFqdn shouldBe "hostname1.domain.ru"

                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.status shouldBe InteractionStatus.success
                result.getInteraction.getReason shouldBe "authenticating domain user 'v.pupkin'."

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "v.pupkin"
                result.getSubject.getDomain shouldBe "domain group"

                result.getData.getMsgId shouldBe "audit_event"
                result.getData.getAux2 shouldBe "0861d834-44ac-4484-ac7e-bb42a5c63630"
            }

            s"correct map $audit_event_2" in new setup {
                override def raw: String = audit_event_2

                result.getDestination.getIp shouldBe "192.168.11.22"
                result.getDestination.getHostname shouldBe "hostname1"
                result.getDestination.getFqdn shouldBe "hostname1.domain.ru"

                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.action shouldBe InteractionCategory.logout
                result.getInteraction.status shouldBe InteractionStatus.success
                result.getInteraction.getReason shouldBe "logging out domain user 'v.pupkin'."

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "v.pupkin"
                result.getSubject.getDomain shouldBe "domain group"

                result.getData.getMsgId shouldBe "audit_event"
                result.getData.getAux2 shouldBe "0861d834-44ac-4484-ac7e-bb42a5c63630"
            }

            s"correct map $audit_event_3" in new setup {
                override def raw: String = audit_event_3

                result.getDestination.getIp shouldBe "192.168.11.22"
                result.getDestination.getHostname shouldBe "hostname1"
                result.getDestination.getFqdn shouldBe "hostname1.domain.ru"

                result.getInteraction.importance shouldBe ImportanceLevel.MEDIUM
                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.status shouldBe InteractionStatus.failure
                result.getInteraction.getReason shouldBe "authenticating domain user 'v.pupkin'."

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "v.pupkin"
                result.getSubject.getDomain shouldBe "domain group"

                result.getData.getMsgId shouldBe "audit_event"
                result.getData.getAux2 shouldBe "0861d834-44ac-4484-ac7e-bb42a5c63630"
            }

            s"correct map $audit_event_4" in new setup {
                override def raw: String = audit_event_4

                result.getDestination.getIp shouldBe "192.168.33.44"
                result.getDestination.getHostname shouldBe "hostname2"

                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.action shouldBe InteractionCategory.login
                result.getInteraction.status shouldBe InteractionStatus.success
                result.getInteraction.getReason shouldBe "authenticating native user 'admin'."

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "bb77b966-370e-4600-a303-c83fb50d1acc"
                result.getSubject.getDomain shouldBe "native user"

                result.getData.getMsgId shouldBe "audit_event"
                result.getData.getAux2 shouldBe "d7640d7d-b867-4585-8587-24fa131258f3"
            }
        }

        "firewallaggregated_event" should {
            val firewallaggregated_event_1 = """{"event_type":"firewallaggregated_event","ipv4":"192.168.55.66","hostname":"hostname3","source_uuid":"87d9f72f-db5d-418a-bc33-86a781bbba7e","occured":"20-jan-2021 16:44:49","severity":"warning","event":"security vulnerability exploitation attempt","source_address":"44.55.66.77","source_address_type":"ipv4","source_port":63187,"target_address":"192.168.55.66","target_address_type":"ipv4","target_port":5900,"protocol":"tcp","account":"nt authority\\система","process_name":"c:\\program files\\tightvnc\\tvnserver.exe","inbound":true,"threat_name":"incoming.attack.generic","aggregate_count":1}"""

            s"correct map $firewallaggregated_event_1" in new setup {
                override def raw: String = firewallaggregated_event_1

                result.getSource.getIp shouldBe "44.55.66.77"
                result.getSource.getPort shouldBe 63187

                result.getDestination.getIp shouldBe "192.168.55.66"
                result.getDestination.getHostname shouldBe "hostname3"
                result.getDestination.getPort shouldBe 5900

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.connect
                result.getInteraction.getReason shouldBe "security vulnerability exploitation attempt"
                result.getInteraction.getProtocol shouldBe "tcp"

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "система"
                result.getSubject.getDomain shouldBe "nt authority"

                result.getObject.category shouldBe Counterpart.process
                result.getObject.getName shouldBe "c:\\program files\\tightvnc\\tvnserver.exe"

                result.getData.getMsgId shouldBe "firewallaggregated_event"
                result.getData.getAux2 shouldBe "87d9f72f-db5d-418a-bc33-86a781bbba7e"
                result.getData.getAux3 shouldBe "incoming.attack.generic"
                result.getData.getAux4 shouldBe "true"
                result.getData.getAux5 shouldBe "1"
            }
        }

        "filteredwebsites_event" should {
            val filteredwebsites_event_1 = """{"event_type":"filteredwebsites_event","ipv4":"10.10.11.22","hostname":"hostname5.org.ru","source_uuid":"1d00eef5-ca97-4d70-8401-62dae4aab82a","occured":"21-jan-2021 13:35:41","severity":"warning","event":"an attempt to connect to url","target_address":"11.22.33.44","target_address_type":"ipv4","scanner_id":"http filter","action_taken":"blocked","object_uri":"site1.ru","hash":"FC702D1A482F7087699ACC0752C300D22B065285","username":"domain\\v.pupkin","processname":"c:\\users\\v.pupkin\\appdata\\local\\google\\chrome\\application\\chrome.exe","rule_id":"website certificate revoked"}"""
            val filteredwebsites_event_2 = """{"event_type":"filteredwebsites_event","ipv4":"192.168.0.11","hostname":"hostname6.org.ru","source_uuid":"5fbcbd83-9777-4ab9-8c37-daf9c0c7150d","occured":"22-jan-2021 07:14:54","severity":"warning","event":"an attempt to connect to url","target_address":"55.66.77.88","target_address_type":"ipv4","scanner_id":"http filter","action_taken":"blocked","object_uri":"https://site2.ru","hash":"fc702d1a482f7087699acc0752c300d22b065285","username":"domain\\petrov","processname":"c:\\program files (x86)\\google\\chrome\\application\\chrome.exe","rule_id":"blocked by internal blacklist"}"""
            val filteredwebsites_event_3 = """{"event_type":"filteredwebsites_event","ipv4":"10.10.13.14","hostname":"hostname7.org.ru","source_uuid":"f374b845-9f54-4a46-81c3-2ad33b165595","occured":"21-jan-2021 07:34:08","severity":"warning","event":"an attempt to connect to url","target_address":"99.100.111.112","target_address_type":"ipv4","scanner_id":"http filter","action_taken":"blocked","object_uri":"site3.ru","hash":"6347678f34d5e5179970ba2c1e10976ed4b08ae8","username":"domain\\ivanov","processname":"c:\\program files (x86)\\mozilla firefox\\firefox.exe","rule_id":"website certificate revoked"}"""
            val filteredwebsites_event_4 = """{"event_type":"filteredwebsites_event","ipv4":"192.168.33.44","hostname":"hostname8","source_uuid":"6dd49f03-c105-4775-9ffa-cce34bd21a4c","occured":"22-jan-2021 09:32:51","severity":"warning","event":"an attempt to connect to url","target_address":"200.211.212.213","target_address_type":"ipv4","scanner_id":"http filter","action_taken":"blocked","object_uri":"https://site4.ru","hash":"5d381c304ba78bb30861b9ea4fd01a700164355d","username":"other-domain\\пользователь10","processname":"c:\\users\\пользователь10\\appdata\\local\\yandex\\yandexbrowser\\application\\browser.exe","rule_id":"blocked by pua blacklist"}"""

            s"correct map $filteredwebsites_event_1" in new setup {
                override def raw: String = filteredwebsites_event_1

                result.getSource.getIp shouldBe "10.10.11.22"
                result.getSource.getHostname shouldBe "hostname5"
                result.getSource.getFqdn shouldBe "hostname5.org.ru"

                result.getDestination.getIp shouldBe "11.22.33.44"

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.lock
                result.getInteraction.getReason shouldBe "an attempt to connect to url"

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "v.pupkin"
                result.getSubject.getDomain shouldBe "domain"

                result.getObject.category shouldBe Counterpart.process
                result.getObject.getPath shouldBe "site1.ru"

                result.getData.getMsgId shouldBe "filteredwebsites_event"
                result.getData.getAux1 shouldBe "fc702d1a482f7087699acc0752c300d22b065285"
                result.getData.getAux2 shouldBe "1d00eef5-ca97-4d70-8401-62dae4aab82a"
                result.getData.getAux3 shouldBe "website certificate revoked"
                result.getData.getAux4 shouldBe "c:\\users\\v.pupkin\\appdata\\local\\google\\chrome\\application\\chrome.exe"
                result.getData.getAux5 shouldBe "http filter"
            }

            s"correct map $filteredwebsites_event_2" in new setup {
                override def raw: String = filteredwebsites_event_2

                result.getSource.getIp shouldBe "192.168.0.11"
                result.getSource.getHostname shouldBe "hostname6"
                result.getSource.getFqdn shouldBe "hostname6.org.ru"

                result.getDestination.getIp shouldBe "55.66.77.88"

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.lock
                result.getInteraction.getReason shouldBe "an attempt to connect to url"

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "petrov"
                result.getSubject.getDomain shouldBe "domain"

                result.getObject.category shouldBe Counterpart.process
                result.getObject.getPath shouldBe "https://site2.ru"

                result.getData.getMsgId shouldBe "filteredwebsites_event"
                result.getData.getAux1 shouldBe "fc702d1a482f7087699acc0752c300d22b065285"
                result.getData.getAux2 shouldBe "5fbcbd83-9777-4ab9-8c37-daf9c0c7150d"
                result.getData.getAux3 shouldBe "blocked by internal blacklist"
                result.getData.getAux4 shouldBe "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe"
                result.getData.getAux5 shouldBe "http filter"
            }

            s"correct map $filteredwebsites_event_3" in new setup {
                override def raw: String = filteredwebsites_event_3

                result.getSource.getIp shouldBe "10.10.13.14"
                result.getSource.getHostname shouldBe "hostname7"
                result.getSource.getFqdn shouldBe "hostname7.org.ru"

                result.getDestination.getIp shouldBe "99.100.111.112"

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.lock
                result.getInteraction.getReason shouldBe "an attempt to connect to url"

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "ivanov"
                result.getSubject.getDomain shouldBe "domain"

                result.getObject.category shouldBe Counterpart.process
                result.getObject.getPath shouldBe "site3.ru"

                result.getData.getMsgId shouldBe "filteredwebsites_event"
                result.getData.getAux1 shouldBe "6347678f34d5e5179970ba2c1e10976ed4b08ae8"
                result.getData.getAux2 shouldBe "f374b845-9f54-4a46-81c3-2ad33b165595"
                result.getData.getAux3 shouldBe "website certificate revoked"
                result.getData.getAux4 shouldBe "c:\\program files (x86)\\mozilla firefox\\firefox.exe"
                result.getData.getAux5 shouldBe "http filter"
            }

            s"correct map $filteredwebsites_event_4" in new setup {
                override def raw: String = filteredwebsites_event_4

                result.getSource.getIp shouldBe "192.168.33.44"
                result.getSource.getHostname shouldBe "hostname8"

                result.getDestination.getIp shouldBe "200.211.212.213"

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.lock
                result.getInteraction.getReason shouldBe "an attempt to connect to url"

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "пользователь10"
                result.getSubject.getDomain shouldBe "other-domain"

                result.getObject.category shouldBe Counterpart.process
                result.getObject.getPath shouldBe "https://site4.ru"

                result.getData.getMsgId shouldBe "filteredwebsites_event"
                result.getData.getAux1 shouldBe "5d381c304ba78bb30861b9ea4fd01a700164355d"
                result.getData.getAux2 shouldBe "6dd49f03-c105-4775-9ffa-cce34bd21a4c"
                result.getData.getAux3 shouldBe "blocked by pua blacklist"
                result.getData.getAux4 shouldBe "c:\\users\\пользователь10\\appdata\\local\\yandex\\yandexbrowser\\application\\browser.exe"
                result.getData.getAux5 shouldBe "http filter"
            }
        }

        "threat_event" should {
            val threat_event_1 = """{"event_type":"threat_event","ipv4":"192.168.66.77","hostname":"hostname8.domain.loc","source_uuid":"42d18ee8-e293-4baf-a9fc-a136f77f0fae","occured":"22-jan-2021 07:25:13","severity":"warning","threat_type":"trojan","threat_name":"html/scrinject.b","scanner_id":"http filter","scan_id":"virlog.dat","engine_version":"22686 (20210122)","object_type":"file","object_uri":"http://site6.ru","action_taken":"connection terminated","threat_handled":true,"need_restart":false,"username":"domain\\vpupkin","processname":"c:\\program files\\mozilla firefox\\firefox.exe","circumstances":"event occurred during an attempt to access the web.","hash":"c258b0bdbc8e53632ac0df4582f86226e86fdfec"}"""
            val threat_event_2 = """{"event_type":"threat_event","ipv4":"10.10.22.33","hostname":"hostname9.domain.loc","source_uuid":"e01d8203-8aa0-4127-9170-c6d9d123e40d","occured":"21-jan-2021 12:36:49","severity":"warning","threat_type":"application","threat_name":"win32/adware.toolbar.shopper.af","threat_flags":"variant","scanner_id":"on-demand scanner","scan_id":"ndl1959085605.dat","engine_version":"22681 (20210121)","object_type":"file","object_uri":"file:///d:/windows/setupsetuphlp.dll","action_taken":"cleaned by deleting","threat_handled":true,"need_restart":false,"hash":"10ec2be7f89f24974b7eb273b72b48c46f9e0ebf"}"""
            val threat_event_3 = """{"event_type":"threat_event","ipv4":"192.168.66.77","hostname":"hostname8.domain.loc","source_uuid":"42d18ee8-e293-4baf-a9fc-a136f77f0fae","occured":"21-jan-2021 06:22:29","severity":"warning","threat_type":"trojan","threat_name":"html/scrinject.b","scanner_id":"http filter","scan_id":"virlog.dat","engine_version":"22680 (20210121)","object_type":"file","object_uri":"http://site6.ru","action_taken":"connection terminated","threat_handled":true,"need_restart":false,"username":"domain\\vpupkin","processname":"c:\\program files\\mozilla firefox\\firefox.exe","circumstances":"event occurred during an attempt to access the web.","hash":"c258b0bdbc8e53632ac0df4582f86226e86fdfec"}"""
            val threat_event_4 = """{"event_type":"threat_event","ipv4":"10.10.44.55","hostname":"hostname10.domain.loc","source_uuid":"d178c1d3-d8bd-4aee-8b61-cf8e02622c51","occured":"21-jan-2021 12:03:16","severity":"warning","threat_type":"trojan","threat_name":"win32/kryptik.gqtw","threat_flags":"variant","scanner_id":"on-demand scanner","scan_id":"ndl2856519416.dat","engine_version":"22681 (20210121)","object_type":"file","object_uri":"file:///e:/windows/user/рабочий стол/1111111/все документы 12.03.2019.exe","action_taken":"cleaned by deleting","threat_handled":true,"need_restart":false,"firstseen":"12-mar-2019 07:19:58","hash":"115cab31eaaaa8804cff5cd54ec2d103b6f2034d"}"""
            val threat_event_5 = """{"event_type":"threat_event","ipv4":"10.10.44.55","hostname":"hostname10.domain.loc","source_uuid":"d178c1d3-d8bd-4aee-8b61-cf8e02622c51","occured":"21-jan-2021 12:02:58","severity":"warning","threat_type":"trojan","threat_name":"win32/spy.rtm.w","scanner_id":"on-demand scanner","scan_id":"ndl2856519416.dat","engine_version":"22681 (20210121)","object_type":"file","object_uri":"file:///e:/windows/user/рабочий стол/$recycle.bin/$rxdfdww.exe","action_taken":"cleaned by deleting","threat_handled":true,"need_restart":false,"firstseen":"11-mar-2019 07:56:57","hash":"7a99a486cc004ef092bd397047e9f464489e1cb0"}"""
            val threat_event_6 = """{"event_type":"threat_event","hostname":"hostname11","source_uuid":"940dcecb-47df-4efd-9b0c-8bd66dd6f046","occured":"19-jan-2021 09:35:22","severity":"warning","threat_type":"potentially unwanted application","threat_name":"win32/webcompanion.b","threat_flags":"variant","scanner_id":"on-demand scanner","scan_id":"ndl2570938683.dat","engine_version":"22668 (20210119)","object_type":"file","object_uri":"file:///c:/users/1/downloads/utorrent.exe/installer.exe","action_taken":"cleaned by deleting","threat_handled":true,"need_restart":false,"hash":"3477e3aa1a52ad7bfbc7c25b97d544e5024217ca"}"""
            val threat_event_7 = """{"event_type":"threat_event","ipv4":"172.16.21.9","hostname":"hostname12.domain.loc","source_uuid":"fe59022f-a7b2-442a-9429-75ffee4f4193","occured":"20-jan-2021 12:51:28","severity":"warning","threat_type":"application","threat_name":"win32/riskware.mimikatz.j","threat_flags":"variant","scanner_id":"http filter","scan_id":"virlog.dat","engine_version":"22674 (20210120)","object_type":"file","object_uri":"https://site7.com ... ion=attachment; filename=mimikatz.7z","action_taken":"connection terminated","threat_handled":true,"need_restart":false,"username":"domain\\v.pupkin","processname":"c:\\program files (x86)\\google\\chrome\\application\\chrome.exe","circumstances":"event occurred during an attempt to access the web.","hash":"3daf54f1f5edc7f723c2d2587b46f70eb9584be2"}"""
            val threat_event_8 = "<12>1 2021-03-31T08:25:31.131Z hostname1.domain.ru ERAServer 84355 - - {\"event_type\":\"Threat_Event\",\"ipv4\":\"192.168.88.99\",\"hostname\":\"hostname100500\",\"source_uuid\":\"8e51a8ca-bfd4-4ab7-83cb-2383bb997fe6\",\"occured\":\"31-Mar-2021 08:25:26\",\"severity\":\"Warning\",\"threat_type\":\"potentially unwanted application\",\"threat_name\":\"JS/Yandex.Sovetnik.A\",\"scanner_id\":\"HTTP filter\",\"scan_id\":\"virlog.dat\",\"engine_version\":\"23053 (20210331)\",\"object_type\":\"file\",\"object_uri\":\"https://site8.com/scripts/script.min.js\",\"action_taken\":\"connection terminated\",\"threat_handled\":true,\"need_restart\":false,\"username\":\"IVANOV\\\\User\",\"processname\":\"C:\\\\Users\\\\User\\\\AppData\\\\Local\\\\Programs\\\\Opera\\\\74.0.3911.218\\\\opera.exe\",\"circumstances\":\"Event occurred during an attempt to access the web.\",\"hash\":\"0B3759DD9703BDC938E136ABE24DDC59B8C782F8\"}\n"

            s"correct map $threat_event_1" in new setup {
                override def raw: String = threat_event_1

                result.getDestination.getIp shouldBe "192.168.66.77"
                result.getDestination.getHostname shouldBe "hostname8"
                result.getDestination.getFqdn shouldBe "hostname8.domain.loc"

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.terminate
                result.getInteraction.getReason shouldBe "event occurred during an attempt to access the web."

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "vpupkin"
                result.getSubject.getDomain shouldBe "domain"

                result.getObject.category shouldBe Counterpart.malwareObject
                result.getObject.getPath shouldBe "http://site6.ru"

                result.getData.getMsgId shouldBe "threat_event"
                result.getData.getAux1 shouldBe "c258b0bdbc8e53632ac0df4582f86226e86fdfec"
                result.getData.getAux2 shouldBe "42d18ee8-e293-4baf-a9fc-a136f77f0fae"
                result.getData.getAux3 shouldBe "html/scrinject.b"
                result.getData.getAux4 shouldBe "c:\\program files\\mozilla firefox\\firefox.exe"
                result.getData.getAux5 shouldBe "trojan"
                result.getData.getAux6 shouldBe "true"
                result.getData.getAux7 shouldBe "false"
                result.getData.aux8 shouldBe None
                result.getData.getAux9 shouldBe "http filter"
                result.getData.getAux10 shouldBe "virlog.dat"
            }

            s"correct map $threat_event_2" in new setup {
                override def raw: String = threat_event_2

                result.getDestination.getIp shouldBe "10.10.22.33"
                result.getDestination.getHostname shouldBe "hostname9"
                result.getDestination.getFqdn shouldBe "hostname9.domain.loc"

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.remove
                result.getInteraction.reason shouldBe None

                result.getSubject.category shouldBe Counterpart.account

                result.getObject.category shouldBe Counterpart.malwareObject
                result.getObject.getPath shouldBe "file:///d:/windows/setupsetuphlp.dll"

                result.getData.getMsgId shouldBe "threat_event"
                result.getData.getAux1 shouldBe "10ec2be7f89f24974b7eb273b72b48c46f9e0ebf"
                result.getData.getAux2 shouldBe "e01d8203-8aa0-4127-9170-c6d9d123e40d"
                result.getData.getAux3 shouldBe "win32/adware.toolbar.shopper.af"
                result.getData.aux4 shouldBe None
                result.getData.getAux5 shouldBe "application"
                result.getData.getAux6 shouldBe "true"
                result.getData.getAux7 shouldBe "false"
                result.getData.aux8 shouldBe None
                result.getData.getAux9 shouldBe "on-demand scanner"
                result.getData.getAux10 shouldBe "ndl1959085605.dat"
            }

            s"correct map $threat_event_3" in new setup {
                override def raw: String = threat_event_3

                result.getDestination.getIp shouldBe "192.168.66.77"
                result.getDestination.getHostname shouldBe "hostname8"
                result.getDestination.getFqdn shouldBe "hostname8.domain.loc"

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.terminate
                result.getInteraction.getReason shouldBe "event occurred during an attempt to access the web."

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "vpupkin"
                result.getSubject.getDomain shouldBe "domain"

                result.getObject.category shouldBe Counterpart.malwareObject
                result.getObject.getPath shouldBe "http://site6.ru"

                result.getData.getMsgId shouldBe "threat_event"
                result.getData.getAux1 shouldBe "c258b0bdbc8e53632ac0df4582f86226e86fdfec"
                result.getData.getAux2 shouldBe "42d18ee8-e293-4baf-a9fc-a136f77f0fae"
                result.getData.getAux3 shouldBe "html/scrinject.b"
                result.getData.getAux4 shouldBe "c:\\program files\\mozilla firefox\\firefox.exe"
                result.getData.getAux5 shouldBe "trojan"
                result.getData.getAux6 shouldBe "true"
                result.getData.getAux7 shouldBe "false"
                result.getData.aux8 shouldBe None
                result.getData.getAux9 shouldBe "http filter"
                result.getData.getAux10 shouldBe "virlog.dat"
            }

            s"correct map $threat_event_4" in new setup {
                override def raw: String = threat_event_4

                result.getDestination.getIp shouldBe "10.10.44.55"
                result.getDestination.getHostname shouldBe "hostname10"
                result.getDestination.getFqdn shouldBe "hostname10.domain.loc"

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.remove
                result.getInteraction.reason shouldBe None

                result.getSubject.category shouldBe Counterpart.account

                result.getObject.category shouldBe Counterpart.malwareObject
                result.getObject.getPath shouldBe "file:///e:/windows/user/рабочий стол/1111111/все документы 12.03.2019.exe"

                result.getData.getMsgId shouldBe "threat_event"
                result.getData.getAux1 shouldBe "115cab31eaaaa8804cff5cd54ec2d103b6f2034d"
                result.getData.getAux2 shouldBe "d178c1d3-d8bd-4aee-8b61-cf8e02622c51"
                result.getData.getAux3 shouldBe "win32/kryptik.gqtw"
                result.getData.aux4 shouldBe None
                result.getData.getAux5 shouldBe "trojan"
                result.getData.getAux6 shouldBe "true"
                result.getData.getAux7 shouldBe "false"
                result.getData.getAux8 shouldBe "12-mar-2019 07:19:58"
                result.getData.getAux9 shouldBe "on-demand scanner"
                result.getData.getAux10 shouldBe "ndl2856519416.dat"
            }

            s"correct map $threat_event_5" in new setup {
                override def raw: String = threat_event_5

                result.getDestination.getIp shouldBe "10.10.44.55"
                result.getDestination.getHostname shouldBe "hostname10"
                result.getDestination.getFqdn shouldBe "hostname10.domain.loc"

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.remove

                result.getSubject.category shouldBe Counterpart.account

                result.getObject.category shouldBe Counterpart.malwareObject
                result.getObject.getPath shouldBe "file:///e:/windows/user/рабочий стол/$recycle.bin/$rxdfdww.exe"

                result.getData.getMsgId shouldBe "threat_event"
                result.getData.getAux1 shouldBe "7a99a486cc004ef092bd397047e9f464489e1cb0"
                result.getData.getAux2 shouldBe "d178c1d3-d8bd-4aee-8b61-cf8e02622c51"
                result.getData.getAux3 shouldBe "win32/spy.rtm.w"
                result.getData.aux4 shouldBe None
                result.getData.getAux5 shouldBe "trojan"
                result.getData.getAux6 shouldBe "true"
                result.getData.getAux7 shouldBe "false"
                result.getData.getAux8 shouldBe "11-mar-2019 07:56:57"
                result.getData.getAux9 shouldBe "on-demand scanner"
                result.getData.getAux10 shouldBe "ndl2856519416.dat"
            }

            s"correct map $threat_event_6" in new setup {
                override def raw: String = threat_event_6

                result.getDestination.ip shouldBe None
                result.getDestination.getHostname shouldBe "hostname11"

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.remove

                result.getSubject.category shouldBe Counterpart.account

                result.getObject.category shouldBe Counterpart.malwareObject
                result.getObject.getPath shouldBe "file:///c:/users/1/downloads/utorrent.exe/installer.exe"

                result.getData.getMsgId shouldBe "threat_event"
                result.getData.getAux1 shouldBe "3477e3aa1a52ad7bfbc7c25b97d544e5024217ca"
                result.getData.getAux2 shouldBe "940dcecb-47df-4efd-9b0c-8bd66dd6f046"
                result.getData.getAux3 shouldBe "win32/webcompanion.b"
                result.getData.aux4 shouldBe None
                result.getData.getAux5 shouldBe "potentially unwanted application"
                result.getData.getAux6 shouldBe "true"
                result.getData.getAux7 shouldBe "false"
                result.getData.aux8 shouldBe None
                result.getData.getAux9 shouldBe "on-demand scanner"
                result.getData.getAux10 shouldBe "ndl2570938683.dat"
            }

            s"correct map $threat_event_7" in new setup {
                override def raw: String = threat_event_7

                result.getDestination.getIp shouldBe "172.16.21.9"
                result.getDestination.getHostname shouldBe "hostname12"
                result.getDestination.getFqdn shouldBe "hostname12.domain.loc"

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.terminate
                result.getInteraction.getReason shouldBe "event occurred during an attempt to access the web."

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "v.pupkin"
                result.getSubject.getDomain shouldBe "domain"

                result.getObject.category shouldBe Counterpart.malwareObject
                result.getObject.getPath shouldBe "https://site7.com ... ion=attachment; filename=mimikatz.7z"

                result.getData.getMsgId shouldBe "threat_event"
                result.getData.getAux1 shouldBe "3daf54f1f5edc7f723c2d2587b46f70eb9584be2"
                result.getData.getAux2 shouldBe "fe59022f-a7b2-442a-9429-75ffee4f4193"
                result.getData.getAux3 shouldBe "win32/riskware.mimikatz.j"
                result.getData.getAux4 shouldBe "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe"
                result.getData.getAux5 shouldBe "application"
                result.getData.getAux6 shouldBe "true"
                result.getData.getAux7 shouldBe "false"
                result.getData.aux8 shouldBe None
                result.getData.getAux9 shouldBe "http filter"
                result.getData.getAux10 shouldBe "virlog.dat"
            }

            s"correct map $threat_event_8" in new setup {
                override def raw: String = threat_event_8

                result.getDestination.getIp shouldBe "192.168.88.99"
                result.getDestination.getHostname shouldBe "hostname100500"
                result.getDestination.fqdn shouldBe None

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.terminate
                result.getInteraction.getReason shouldBe "Event occurred during an attempt to access the web."

                result.getSubject.category shouldBe Counterpart.account
                result.getSubject.getName shouldBe "User"
                result.getSubject.getDomain shouldBe "IVANOV"

                result.getObject.category shouldBe Counterpart.malwareObject
                result.getObject.getPath shouldBe "https://site8.com/scripts/script.min.js"

                result.getData.getMsgId shouldBe "threat_event"
                result.getData.getAux1 shouldBe "0b3759dd9703bdc938e136abe24ddc59b8c782f8"
                result.getData.getAux2 shouldBe "8e51a8ca-bfd4-4ab7-83cb-2383bb997fe6"
                result.getData.getAux3 shouldBe "JS/Yandex.Sovetnik.A"
                result.getData.getAux4 shouldBe "C:\\Users\\User\\AppData\\Local\\Programs\\Opera\\74.0.3911.218\\opera.exe"
                result.getData.getAux5 shouldBe "potentially unwanted application"
                result.getData.getAux6 shouldBe "true"
                result.getData.getAux7 shouldBe "false"
                result.getData.aux8 shouldBe None
                result.getData.getAux9 shouldBe "HTTP filter"
                result.getData.getAux10 shouldBe "virlog.dat"
            }
        }
    }

    val parser = new EsetNod32Parser
    val mapper = new EsetNod32Mapper
    val validator = new EsetNod32Validator

    @transient
    trait setup {
        def raw: String

        protected val msg = ParsedMessage(
            raw = Left(raw),
            eventReceivedTime = ZonedDateTime.now(ZoneOffset.UTC),
            organization = "organization",
            chain = "",
            eventDevType = "esetnode02701",
            collectorHostname = "local.com",
            collectorHostIP = "127.0.0.1",
            severityId = 0,
            severity = "unknown",
            eventHostname = None,
            eventHostIP = "127.0.0.1",
            inputId = "id"
        )

        protected val parsedEvent: ParsedLog = parser.parse(Left(raw))
        protected val internalSocEvent = InternalSocEvent(
            message = msg,
            event = parsedEvent,
            normId = "norm_id",
            rawId = "raw_id",
            eventSourceHost = "127.0.0.1"
        )

        validator.check(ParsedEvent(msg, parsedEvent)) shouldBe List.empty

        val result: SocEvent = mapper
            .map((Map("esetnode02701" -> DeviceVendor("esetnode02701", "ESET", "NOD", "xxx")), internalSocEvent))
    }

}
