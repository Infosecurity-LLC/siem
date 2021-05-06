package ru.gkis.soc.siem.normalizer.validators

import com.google.common.net.InetAddresses
import ru.gkis.soc.siem.normalizer.ParsedEvent
import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._

class KasperskyValidator extends AbstractValidator[ParsedEvent] {

      "Field DetectionTime" is "required" in {
        evt => evt.event.contains("DetectionTime")
      }

      "Field EventTime" is "required" in {
        evt => evt.event.contains("EventTime")
      }

      "Field ID" is "required" in {
          evt => evt.event.contains("ID")
      }

      "Field EventType" is "required" in {
          evt => evt.event.contains("EventType")
      }

      "Field SensorName" is "required" in {
          evt => evt.event.contains("SensorName")
      }

      "Field ModuleName" is "required" in {
          evt => evt.event.contains("ModuleName")
      }

      "Field Severity" is "required" in {
          evt => evt.event.contains("Severity")
      }

      "Field Organization" is "required" in {
          evt => evt.event.contains("Organization")
      }

      "Field TypeActivity" is "required" in {
          evt => evt.event.contains("TypeActivity")
      }

      "Field Block" is "required" in {
          _.event.contains("Block")
      }

      "Field Deleted" is "required" in {
          _.event.contains("Deleted")
      }

    "Field SourceIP" should "be a valid ip address" in {
        evt => !evt.event.contains("SourceIP") || InetAddresses.isInetAddress(evt.event("SourceIP"))
    }

    "Field IP" should "be a valid ip address" in {
        evt => !evt.event.contains("IP") || InetAddresses.isInetAddress(evt.event("IP"))
    }

}

object KasperskyValidator {
    val name: String = "kaspersky"
    val version: Int = 1
}
