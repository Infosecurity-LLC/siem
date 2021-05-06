package ru.gkis.soc.siem.normalizer.validators

import com.google.common.net.InetAddresses
import ru.gkis.soc.siem.normalizer.ParsedEvent

import java.time.format.DateTimeFormatter
import scala.util.Try

class Fail2BanValidator extends AbstractValidator[ParsedEvent] {
    import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._

    "Field originTime" should "have correct format" in { evt =>
        evt.event.contains("originTime") && isValidDate(evt.event.extract("originTime"))
    }

    "Field aux2" should "have value" in { evt =>
        evt.event.contains("aux2")
    }

    "Field importance" should "have value" in { evt =>
        evt.event.contains("importance")
    }

    "Field sourceIp" should "be a valid ip address" in { evt =>
        !evt.event.contains("sourceIp") || InetAddresses.isInetAddress(evt.event("sourceIp"))
    }

    private[this] def formatter: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss,SSS")
    private[this] def isValidDate(value: String): Boolean = {
        Try(formatter.parse(value)).isSuccess
    }
}

object Fail2BanValidator {
    val name: String = "fail2ban02901"
    val version: Int = 1
}