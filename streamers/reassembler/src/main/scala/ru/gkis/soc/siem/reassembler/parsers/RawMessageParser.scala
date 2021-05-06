package ru.gkis.soc.siem.reassembler.parsers

import org.json4s._
import org.json4s.jackson.JsonMethods

object RawMessageParser {

    private implicit lazy val formats: DefaultFormats = DefaultFormats

    def parse(msg: String): ParsedMessage = {
        val message = JsonMethods.parse(msg)

        val eventReceivedTime = (message \ "EventReceivedTime").extract[String]
        val chain = JsonMethods.compact(JsonMethods.render(message \ "chain"))
        val JString(messageSourceAddress) = message \ "MessageSourceAddress"
        val eventTime = (message \ "EventTime").extract[String]
        val JString(hostname) = message \ "Hostname"
        val JString(sourceName) = message \ "SourceName"
        val JString(devCat) = message \ "DevCat"
        val JString(devSubCat) = message \ "DevSubCat"
        val JString(devType) = message \ "DevType"
        val JString(organization) = message \ "Organization"
        val JInt(orgID) = message \ "OrgID"

        val raw = (message \ "raw") match {
            case JString(str) =>
                str
            case obj: JObject =>
                JsonMethods.compact(JsonMethods.render(obj))
            case JNothing =>
                message \ "Message" match {
                    case JString(str) =>
                        str
                    case obj: JObject =>
                        JsonMethods.compact(JsonMethods.render(obj))
                    case other =>
                        throw new RuntimeException(s"Unsupported `raw` field type: $other")
                }
            case other =>
                throw new RuntimeException(s"Unsupported `raw` field type: $other")
        }

        ParsedMessage(eventReceivedTime, chain, messageSourceAddress, eventTime, hostname, sourceName, devCat, devSubCat, devType, organization, orgID.intValue(), raw)
    }
}