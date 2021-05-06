package ru.gkis.soc.siem.normalizer

import java.time.ZonedDateTime

import org.json4s.JObject
import org.json4s.JsonAST.JString
import org.json4s.jackson.JsonMethods
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.normalizer.FinalStates.State

sealed trait ParseError

sealed trait KafkaRecord

sealed trait NxParsed

sealed trait CanParse

sealed trait LogParsed

sealed trait Validated

sealed trait Split

sealed trait Mapped

sealed trait Statistical

// recieve
case class RawMessage(key: Option[String], nxMessage: String) extends KafkaRecord

// parse NX
case class NxParseError(nxMessage: String, exception: Throwable) extends NxParsed with CanParse with ParseError with LogParsed with Validated

case class ParsedMessage(
                            raw: Either[String, JObject],
                            eventReceivedTime: ZonedDateTime,
                            organization: String,
                            chain: String,
                            eventDevType: String,
                            collectorHostname: String,
                            collectorHostIP: String,
                            severityId: Int,
                            severity: String,
                            eventHostname: Option[String],
                            eventHostIP: String,
                            inputId: String
                        ) extends NxParsed with CanParse {
    def rawMessage: String = {
        raw match {
            case Left(string) => string
            case Right(json) =>
                json \ "SourceStr" match {
                    case JString(rawMessage) =>
                        rawMessage
                    case _ =>
                        // FIXME: Currently Unicon parsers not support 'SourceStr'
                        JsonMethods.compact(JsonMethods.render(json))
                }
        }
    }

    def preparsedMessage: Option[String] = {
        raw match {
            case Left(_) => None
            case Right(json) =>
                val filtered = json.removeField { case (name, _) => name == "SourceStr" }
                if (filtered == json) None
                else Some(JsonMethods.compact(JsonMethods.render(filtered)))
        }
    }
}

// validate devType
case class UnknownDevType(message: ParsedMessage, reason: String) extends CanParse with LogParsed

// parse log
case class ParsedEvent(message: ParsedMessage, event: ParsedLog) extends LogParsed

case class LogParseError(message: ParsedMessage, exception: Throwable) extends LogParsed with ParseError with Validated

// validate
case class Valid(message: ParsedMessage, event: ParsedLog) extends Validated

case class Invalid(message: ParsedMessage, event: Option[ParsedLog], reason: String) extends Validated

// split
case class InternalSocEvent(message: ParsedMessage, event: ParsedLog, normId: String, rawId: String, eventSourceHost: String) extends Split

case class InternalRawEvent(message: ParsedMessage, normId: Option[String], rawId: String, eventSourceHost: String) extends Split

case class InternalChainEvent(message: ParsedMessage, normId: Option[String], rawId: String, eventSourceHost: String) extends Split

case class InternalInvalidEvent(message: ParsedMessage, reason: String, rawId: String, eventSourceHost: String) extends Split

case class InternalErrorEvent(message: Either[ParsedMessage, String], exception: Throwable, rawId: String, eventSourceHost: String) extends Split

// normalize
case class NormalizedSocEvent(normalized: SocEvent, devType: String, eventSourceHost: String) extends Mapped with Statistical {
    val state: State = FinalStates.NORMALIZED
}

case class NormalizedRawEvent(normalized: RawEvent, devType: String, eventSourceHost: String) extends Mapped with Statistical {
    val state: State = FinalStates.RAW
}

case class NormalizedChainEvent(normalized: ChainEvent, devType: String, eventSourceHost: String) extends Mapped with Statistical {
    val state: State = FinalStates.CHAIN
}

case class NormalizedInvalidEvent(normalized: InvalidEvent, devType: String, eventSourceHost: String) extends Mapped with Statistical {
    val state: State = FinalStates.INVALID
}

case class NormalizedErrorEvent(normalized: ErrorEvent, devType: String, eventSourceHost: String) extends Mapped with Statistical {
    val state: State = FinalStates.ERROR
}

// stats
case class Statistics(
                         organization: String,
                         devType: String,
                         collectorHost: String,
                         eventSourceHost: String,
                         status: State,
                         bytesOut: Long,
                         outOfTime: Int,
                         messageCount: Int = 1
                     ) extends Statistical {

    val key = s"$organization.$devType.$collectorHost.$eventSourceHost.$status"

    override def toString: String = s"(org=$organization, source=$devType, collector=$collectorHost, " +
        s"eventSource=$eventSourceHost, status=$status, totalBytesOut=$bytesOut messageCount=$messageCount)"
}
