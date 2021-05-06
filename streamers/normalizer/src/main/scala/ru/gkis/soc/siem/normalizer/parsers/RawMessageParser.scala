package ru.gkis.soc.siem.normalizer.parsers

import java.time.{ZoneOffset, ZonedDateTime}

import org.json4s._
import org.json4s.jackson.JsonMethods
import ru.gkis.soc.siem.normalizer.ParsedMessage

class RawMessageParser extends LogParser[List[ParsedMessage]] {

    private implicit val formats: DefaultFormats = DefaultFormats

    override def parse(msg: Either[String, JObject]): List[ParsedMessage] = {
        msg match {
            case Right(_) =>
                throw new RuntimeException(s"Expected String message but got JSON")
            case Left(msg) =>
                for {
                    message <- List(JsonMethods.parse(msg))
                    raw = (message \ "raw") match {
                        case JString(str) =>
                            Left(str)
                        case obj: JObject =>
                            Right(obj)
                        case other => throw new RuntimeException(s"Unsupported `raw` field type: $other")
                    }
                    //                   here we expect ISO8601 with Timezone formatted timestamps. For example: 2019-08-10T00:00:00.253665+03:00
                    eventReceivedTime = ZonedDateTime.parse((message \ "EventReceivedTime").extract[String]).withZoneSameInstant(ZoneOffset.UTC)
                    JString(organization) = message \ "Organization"
                    chain = JsonMethods.compact(JsonMethods.render(message \ "chain"))
                    JString(eventDevType) = message \ "DevType"
                    Some(collector) = (message \ "chain").children.find(obj => (obj \ "number").extract[Int] == 1) // todo: this is not cool actually
                    JString(collectorHostname) = collector \ "fqdn"
                    JString(collectorHostIP) = collector \ "ip"
                    JInt(severityId) = message \ "SeverityValue"
                    JString(severity) = message \ "Severity"
                    eventHostname = (message \ "eventHostname").extractOpt[String]
                    JString(eventHostIP) = message \ "MessageSourceAddress"
                    JString(inputId) = collector \ "modname"
                } yield {
                    ParsedMessage(raw, eventReceivedTime, organization, chain, eventDevType, collectorHostname, collectorHostIP, severityId.intValue(), severity, eventHostname, eventHostIP, inputId)
                }
        }
    }

}

object RawMessageParser {
    val name: String = "rawMessage"
    val version: Int = 1
}