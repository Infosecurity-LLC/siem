package ru.gkis.soc.siem.normalizer.parsers

import ru.gkis.soc.siem.model.ParsedLog
import ru.gkis.soc.siem.normalizer.mappers.helpers.UnknownSynonyms

class UniconParser extends LogParser[ParsedLog] {

    import org.json4s._

    private implicit val formats: DefaultFormats = DefaultFormats

    override def parse(msg: Either[String, JObject]): ParsedLog = {
        msg match {
            case Left(_) =>
                throw new RuntimeException(s"Expected JSON message but got String")
            case Right(json) =>
                json
                    .noNulls
                    .extract[ParsedLog]
                    .map {
                        case (key, value: String) => (key, value.trim)
                        case other => other
                    }
                    .filterNot(UnknownSynonyms.checkValueMeansNull)
        }
    }

}

object UniconParser {
    val name: String = "unicon"
    val version: Int = 1
}
