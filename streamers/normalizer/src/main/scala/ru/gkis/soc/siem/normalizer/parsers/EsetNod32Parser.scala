package ru.gkis.soc.siem.normalizer.parsers

import io.krakens.grok.api.Grok
import org.json4s.jackson.JsonMethods
import org.json4s.{DefaultFormats, JObject, JValue}
import ru.gkis.soc.siem.model.ParsedLog

class EsetNod32Parser extends LogParser[ParsedLog] with GrokParser {
    private implicit val formats: DefaultFormats = DefaultFormats

    override val grokSource = Seq("/grok/eset-nod32")

    private lazy val extractAuditEvent: Grok = grokCompiler.compile("%{ESET_AUDIT_EVENT}", true)
    private lazy val extractuserAndDomain: Grok = grokCompiler.compile("%{ESET_USER_AND_DOMAIN}", true)

    override def parse(msg: Either[String, JObject]): ParsedLog = {
        msg match {
            case Right(_) =>
                throw new RuntimeException(s"Expected String message but got JSON")
            case Left(string) =>
                val json: JValue = JsonMethods.parse(string.dropWhile(_ != '{'))
                val result = json.extract[ParsedLog]
                result.flatMap {
                    case (key, value: String) if key == "detail" =>
                        val result = parse(extractAuditEvent, value).toSeq

                        Seq((key, value)) ++ result
                    case (key, value: String) if key == "account" =>
                        val result = parse(extractuserAndDomain, value).toSeq

                        Seq((key, value)) ++ result
                    case (key, value: String) if key == "username" =>
                        val result = parse(extractuserAndDomain, value).toSeq

                        Seq((key, value)) ++ result
                    case other =>
                        Seq(other)
                }
        }
    }
}

object EsetNod32Parser {
    val name: String = "esetnode02701"
    val version: Int = 1
}