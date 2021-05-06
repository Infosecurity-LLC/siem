package ru.gkis.soc.siem.normalizer.parsers

import org.json4s.JObject
import ru.gkis.soc.siem.model.{ParsedLog, ProviderKey}
import ru.gkis.soc.siem.normalizer.ParsedMessage

trait LogParser[T] {
    def parse(msg: Either[String, JObject]): T
}

object LogParser {

    private lazy val provider = new ParserProvider

    def apply[A](implicit parser: LogParser[A]): LogParser[A] = parser

    object ops {

        def parse[A: LogParser](msg: Either[String, JObject]) = LogParser[A].parse(msg)

        implicit class LogParseOps[A: LogParser](msg: Either[String, JObject]) {
            def parse = LogParser[A].parse(msg)
        }

    }

    implicit def canParseRaw(implicit key: ProviderKey): LogParser[List[ParsedMessage]] = key match {
        case ProviderKey(RawMessageParser.name, RawMessageParser.version, _) => provider.getParser(key, _ => new RawMessageParser)
    }

    implicit def canParseOther(implicit key: ProviderKey): LogParser[ParsedLog] = key match {
        case ProviderKey(FortigateParser.name, FortigateParser.version, _) => provider.getParser(key, _ => new FortigateParser)
        case ProviderKey(UniconParser.name, UniconParser.version, _) => provider.getParser(key, _ => new UniconParser)
        case ProviderKey(WindowsSecurityParser.name, WindowsSecurityParser.version, _) => provider.getParser(key, _ => new WindowsSecurityParser)
        case ProviderKey(CiscoAsaParser.name, CiscoAsaParser.version, _) => provider.getParser(key, _ => new CiscoAsaParser)
        case ProviderKey(EsetNod32Parser.name, EsetNod32Parser.version, _) => provider.getParser(key, _ => new EsetNod32Parser)
        case ProviderKey(AuditdParser.name, AuditdParser.version, _) => provider.getParser(key, _ => new AuditdParser)
        case ProviderKey(Fail2BanParser.name, Fail2BanParser.version, _) => provider.getParser(key, _ => new Fail2BanParser)
        case ProviderKey(CiscoIosIsrParser.name, CiscoIosIsrParser.version, _) => provider.getParser(key, _ => new CiscoIosIsrParser)
    }

}