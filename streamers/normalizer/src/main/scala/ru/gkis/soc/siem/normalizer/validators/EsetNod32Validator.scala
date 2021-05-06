package ru.gkis.soc.siem.normalizer.validators

import com.google.common.net.InetAddresses
import ru.gkis.soc.siem.normalizer.ParsedEvent

import java.time.format.{DateTimeFormatter, DateTimeFormatterBuilder}
import java.util.Locale
import scala.util.Try

class EsetNod32Validator extends AbstractValidator[ParsedEvent] {

    import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._

    private val allowedEventTypes = Set(
        "audit_event",
        "filteredwebsites_event",
        "firewallaggregated_event",
        "filteredwebsites_event",
        "threat_event"
    )

    "Event type"  should s"be one of $allowedEventTypes" in { evt =>
        evt.event.extractOpt("event_type").map(_.toLowerCase).fold(false)(allowedEventTypes.contains)
    }

    "Field occured" should "have correct format" in { evt =>
        isValidDate(evt.event.extract("occured"))
    }

    "Field target_address" should "be a valid ip address" in {
        evt => !evt.event.contains("target_address") || InetAddresses.isInetAddress(evt.event("target_address"))
    }

    "Field ipv4" should "be a valid ip address" in {
        evt => !evt.event.contains("ipv4") || InetAddresses.isInetAddress(evt.event("ipv4"))
    }

    "Field ipv6" should "be a valid ip address" in {
        evt => !evt.event.contains("ipv6") || InetAddresses.isInetAddress(evt.event("ipv6"))
    }

    private[this] val formatter: DateTimeFormatter = new DateTimeFormatterBuilder()
        .parseCaseInsensitive()
        .appendPattern("dd-MMM-yyyy HH:mm:ss")
        .toFormatter(Locale.ENGLISH)

    private[this] def isValidDate(value: String): Boolean = {
        Try(formatter.parse(value)).isSuccess
    }

}

object EsetNod32Validator {
    val name: String = "esetnode02701"
    val version: Int = 1
}
