package ru.gkis.soc.siem.normalizer.validators

import ru.gkis.soc.siem.normalizer.ParsedEvent
import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._

class CiscoIosIsrValidator  extends AbstractValidator[ParsedEvent] {
    private val allowedEventTypes: Set[String] = Set(
        "login_failed",
        "login_success",
        "ssh2_userauth",
        "logout",
        "config_i"
    )

    "event type" should s"be one of $allowedEventTypes" in { evt =>
        evt.event.extractOpt("eventType").fold(false)(allowedEventTypes.contains)
    }

    "importance" is s"available" in { evt =>
        evt.event.contains("importance")
    }

}

object CiscoIosIsrValidator {
    val name: String = "ios/isr00401"
    val version: Int = 1
}