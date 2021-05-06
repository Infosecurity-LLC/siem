package ru.gkis.soc.siem.normalizer.mappers

import org.junit.runner.RunWith
import org.scalatest.{Matchers, WordSpec}
import org.scalatestplus.junit.JUnitRunner
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.normalizer.parsers.Fail2BanParser
import ru.gkis.soc.siem.normalizer.validators.Fail2BanValidator
import ru.gkis.soc.siem.normalizer.{InternalSocEvent, ParsedEvent, ParsedMessage}

import java.time.{ZoneOffset, ZonedDateTime}

@RunWith(classOf[JUnitRunner])
class Fail2BanMapperSpec extends WordSpec with Matchers {
    "Fail2Ban" when {
        "ban" should {
            val ban_1 = """jan 21 16:34:22 hostname1 fail2ban-action 2021-01-21 14:59:27,143 fail2ban.actions[23401]: warning [ssh-iptables] ban 22.33.44.55"""
            val ban_2 = """1 2021-01-14t15:02:49.211024+03:00 hostname2 fail2ban-log - - - 2019-06-21 21:45:25,436 fail2ban.actions        [47791]: notice  [sshd] ban 55.66.77.88"""

            s"correct map $ban_1" in new setup {
                override def raw: String = ban_1

                result.getObject.getName shouldBe  "fail2ban"
                result.getObject.category shouldBe Counterpart.application

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getSource.getIp shouldBe "22.33.44.55"

                result.getData.getMsgId shouldBe "fail2ban.actions"
                result.getData.getAux1 shouldBe "ssh-iptables"
                result.getData.getAux2 shouldBe "ban"
            }

            s"correct map $ban_2" in new setup {
                override def raw: String = ban_2

                result.getObject.getName shouldBe  "fail2ban"
                result.getObject.category shouldBe Counterpart.application

                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.action shouldBe InteractionCategory.deny
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getSource.getIp shouldBe "55.66.77.88"

                result.getData.getMsgId shouldBe "fail2ban.actions"
                result.getData.getAux1 shouldBe "sshd"
                result.getData.getAux2 shouldBe "ban"
            }
        }

        "unban" should {
            val ban_1 = """jan 21 16:34:22 hostname1 fail2ban-action 2021-01-21 15:56:32,799 fail2ban.actions[15476]: warning [ssh-iptables] unban 22.33.44.55"""
            val ban_2 = """1 2021-01-14t15:02:49.198829+03:00 hostname2 fail2ban-log - - - 2019-06-21 20:30:32,096 fail2ban.actions        [45703]: notice  [sshd] unban 55.66.77.88"""

            s"correct map $ban_1" in new setup {
                override def raw: String = ban_1

                result.getObject.getName shouldBe  "fail2ban"
                result.getObject.category shouldBe Counterpart.application

                result.getInteraction.importance shouldBe ImportanceLevel.LOW
                result.getInteraction.action shouldBe InteractionCategory.allow
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getSource.getIp shouldBe "22.33.44.55"

                result.getData.getMsgId shouldBe "fail2ban.actions"
                result.getData.getAux1 shouldBe "ssh-iptables"
                result.getData.getAux2 shouldBe "unban"
            }

            s"correct map $ban_2" in new setup {
                override def raw: String = ban_2

                result.getObject.getName shouldBe  "fail2ban"
                result.getObject.category shouldBe Counterpart.application

                result.getInteraction.importance shouldBe ImportanceLevel.INFO
                result.getInteraction.action shouldBe InteractionCategory.allow
                result.getInteraction.status shouldBe InteractionStatus.success

                result.getSource.getIp shouldBe "55.66.77.88"

                result.getData.getMsgId shouldBe "fail2ban.actions"
                result.getData.getAux1 shouldBe "sshd"
                result.getData.getAux2 shouldBe "unban"
            }
        }
    }

    val parser = new Fail2BanParser
    val mapper = new Fail2BanMapper
    val validator = new Fail2BanValidator


    @transient
    trait setup {
        def raw: String

        protected val msg = ParsedMessage(
            raw = Left(raw),
            eventReceivedTime = ZonedDateTime.now(ZoneOffset.UTC),
            organization = "organization",
            chain = "",
            eventDevType = "fail2ban02901",
            collectorHostname = "local.com",
            collectorHostIP = "127.0.0.1",
            severityId = 0,
            severity = "unknown",
            eventHostname = None,
            eventHostIP = "127.0.0.1",
            inputId = "id"
        )

        val parsedEvent: ParsedLog = parser.parse(msg.raw)
        validator.check(ParsedEvent(msg, parsedEvent)) shouldBe List.empty

        protected val internalSocEvent = InternalSocEvent(
            message = msg,
            event = parser.parse(Left(raw)),
            normId = "norm_id",
            rawId = "raw_id",
            eventSourceHost = "127.0.0.1"
        )

        val result: SocEvent = mapper
            .map((Map("fail2ban02901" -> DeviceVendor("fail2ban02901", "F2B", "F2B", "xxx")), internalSocEvent))
    }
}
