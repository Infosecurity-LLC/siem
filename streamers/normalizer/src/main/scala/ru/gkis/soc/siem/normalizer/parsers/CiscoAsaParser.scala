package ru.gkis.soc.siem.normalizer.parsers

import io.krakens.grok.api.Grok
import org.json4s.JObject
import ru.gkis.soc.siem.model.ParsedLog

class CiscoAsaParser extends LogParser[ParsedLog] with GrokParser {
    override val grokSource = Seq("/grok/common", "/grok/cisco-asa")

    private lazy val extractId: Grok = grokCompiler.compile("%{CISCOASA_ID}", true)
    private lazy val groks: Map[String, Grok] = Map(
        "113004" -> "%{CISCOASA_113004}",
        "113012" -> "%{CISCOASA_113012}",
        "113015" -> "%{CISCOASA_113015}",
        "605005" -> "%{CISCOASA_605005}",
        "611101" -> "%{CISCOASA_611101}",
        "111008" -> "%{CISCOASA_111008}",
        "111010" -> "%{CISCOASA_111010}",
        "106023" -> "%{CISCOASA_106023}",
        "710003" -> "%{CISCOASA_710003}",
        "104001" -> "%{CISCOASA_104001}",
        "104002" -> "%{CISCOASA_104002}",
        "105005" -> "%{CISCOASA_105005}",
        "105008" -> "%{CISCOASA_105008}",
        "105009" -> "%{CISCOASA_105009}",
        "106001" -> "%{CISCOASA_106001}",
        "106006" -> "%{CISCOASA_106006}",
        "106007" -> "%{CISCOASA_106007}",
        "106011" -> "%{CISCOASA_106011}",
        "106014" -> "%{CISCOASA_106014}"
    ).mapValues(grokCompiler.compile(_, true))

    override def parse(msg: Either[String, JObject]): ParsedLog = {
        msg match {
            case Right(_) =>
                throw new RuntimeException(s"Expected String message but got JSON")
            case Left(raw) =>
                parse(extractId, raw).get("id").map(_.toString).flatMap(groks.get) match {
                    case Some(grok) =>
                        parse(grok, raw)
                    case None =>
                        Map.empty[String, AnyRef]
                }
        }
    }
}

object CiscoAsaParser {
    val name: String = "asa00401"
    val version: Int = 1
}