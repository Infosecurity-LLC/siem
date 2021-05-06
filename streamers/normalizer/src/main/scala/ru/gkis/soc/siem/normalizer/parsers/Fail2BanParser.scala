package ru.gkis.soc.siem.normalizer.parsers

import io.krakens.grok.api.Grok
import org.json4s.JObject
import ru.gkis.soc.siem.model.ParsedLog

class Fail2BanParser extends LogParser[ParsedLog] with GrokParser {
    override val grokSource = Seq("/grok/fail2ban")

    private lazy val fail2Ban: Grok = grokCompiler.compile("%{FAIL_2_BAN}", true)

    override def parse(msg: Either[String, JObject]): ParsedLog = {
        msg match {
            case Right(_) =>
                throw new RuntimeException(s"Expected String message but got JSON")
            case Left(raw) =>
                parse(fail2Ban, raw)
        }
    }
}

object Fail2BanParser {
    val name: String = "fail2ban02901"
    val version: Int = 1
}