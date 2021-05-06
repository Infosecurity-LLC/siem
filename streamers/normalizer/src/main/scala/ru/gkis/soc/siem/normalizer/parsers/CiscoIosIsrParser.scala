package ru.gkis.soc.siem.normalizer.parsers

import io.krakens.grok.api.Grok
import org.json4s.JObject
import ru.gkis.soc.siem.model.ParsedLog

class CiscoIosIsrParser extends LogParser[ParsedLog] with GrokParser {
    override val grokSource = Seq("/grok/common", "/grok/cisco-ios-isr")

    private lazy val header: Grok = grokCompiler.compile("%{CISCO_IOS_ISR_HEADER}", true)
    private lazy val groks: Map[String, Grok] = Map(
        "login_failed" -> "%{CISCO_IOS_ISR_LOGIN}",
        "login_success" -> "%{CISCO_IOS_ISR_LOGIN}",
        "ssh2_userauth" -> "%{CISCO_IOS_ISR_SSH2}",
        "logout" -> "%{CISCO_IOS_ISR_LOGOUT}",
        "config_i" -> "%{CISCO_IOS_ISR_CONFIG_I}"
    ).mapValues(grokCompiler.compile(_, true))

    override def parse(msg: Either[String, JObject]): ParsedLog = {
        msg match {
            case Right(_) =>
                throw new RuntimeException(s"Expected String message but got JSON")
            case Left(raw) =>
                val headerMap = parse(header, raw)

                headerMap
                    .get("eventType")
                    .flatMap { case eventType: String =>
                        groks.get(eventType)
                    }
                    .map(grok =>
                        parse(grok, raw) ++ headerMap
                    )
                    .getOrElse(Map.empty[String, AnyRef])
        }
    }
}

object CiscoIosIsrParser {
    val name: String = "ios/isr00401"
    val version: Int = 1
}