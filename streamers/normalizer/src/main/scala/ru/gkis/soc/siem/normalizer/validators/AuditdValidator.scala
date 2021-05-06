package ru.gkis.soc.siem.normalizer.validators

import com.google.common.net.InetAddresses
import ru.gkis.soc.siem.normalizer.ParsedEvent

class AuditdValidator extends AbstractValidator[ParsedEvent] {
    private val allowedSingleLineMessageTypes: Set[String] = Set(
        "ADD_GROUP",
        "ADD_USER",
        "DEL_GROUP",
        "DEL_USER",
        "EXECVE",
        "AVC",
        "SERVICE_START",
        "SERVICE_STOP",
        "USER_AUTH",
        "USER_CHAUTHTOK",
        "USER_CMD",
        "USER_END",
        "USER_LOGIN"
    )

    private val allowedMultiLineMessageTypes: Set[Set[String]] = Set(
        Set("CWD", "PATH", "SYSCALL")
    )

    "message type" is "supported by Mapper" in { evt =>
        evt.event.get("type") match {
            case Some(value: String) =>
                allowedSingleLineMessageTypes.contains(value.toUpperCase)
            case Some(raw: Seq[_]) =>
                val value = raw.map(_.toString.toUpperCase).toSet
                allowedMultiLineMessageTypes.contains(value)
            case _ =>
                false
        }
    }

    "Field addr" should "be a valid ip address" in {
        evt => !evt.event.contains("addr") || InetAddresses.isInetAddress(evt.event("addr").toString)
    }

    "Field saddr" should "be a valid ip address" in {
        evt => !evt.event.contains("saddr") || InetAddresses.isInetAddress(evt.event("saddr").toString)
    }

    "Field daddr" should "be a valid ip address" in {
        evt => !evt.event.contains("daddr") || InetAddresses.isInetAddress(evt.event("daddr").toString)
    }

    "Field laddr" should "be a valid ip address" in {
        evt => !evt.event.contains("laddr") || InetAddresses.isInetAddress(evt.event("laddr").toString)
    }

    "Field rport" should "be a valid port" in {
        evt => !evt.event.contains("rport") || evt.event.get("rport").map(_.toString).exists(_.forall(Character.isDigit))
    }

    "Field sport" should "be a valid port" in {
        evt => !evt.event.contains("sport") || evt.event.get("sport").map(_.toString).exists(_.forall(Character.isDigit))
    }

    "Field src" should "be a valid port" in {
        evt => !evt.event.contains("src") || evt.event.get("src").map(_.toString).exists(_.forall(Character.isDigit))
    }

    "Field dest" should "be a valid port" in {
        evt => !evt.event.contains("dest") || evt.event.get("dest").map(_.toString).exists(_.forall(Character.isDigit))
    }

    "Field dport" should "be a valid port" in {
        evt => !evt.event.contains("dport") || evt.event.get("dport").map(_.toString).exists(_.forall(Character.isDigit))
    }

    "Field lport" should "be a valid port" in {
        evt => !evt.event.contains("lport") || evt.event.get("lport").map(_.toString).exists(_.forall(Character.isDigit))
    }
}

object AuditdValidator {
    val name: String = "reassembledAuditD01"
    val version: Int = 1
}