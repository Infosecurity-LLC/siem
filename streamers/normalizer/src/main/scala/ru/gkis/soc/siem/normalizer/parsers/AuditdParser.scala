package ru.gkis.soc.siem.normalizer.parsers

import com.github.lolo.ltsv.LtsvParser
import io.krakens.grok.api.Grok
import org.json4s.JObject
import ru.gkis.soc.siem.model.ParsedLog
import ru.gkis.soc.siem.normalizer.mappers.helpers.UnknownSynonyms

import java.nio.charset.StandardCharsets

class AuditdParser extends LogParser[ParsedLog] with GrokParser {

    import scala.collection.JavaConversions._

    override val grokSource = Seq("/grok/auditd")

    private val ltsv = LtsvParser
        .builder()
        .withQuoteChar(''')
        .withEntryDelimiter(' ')
        .withKvDelimiter('=')
        .lenient()
        .build()

    private lazy val parseHeader: Grok = grokCompiler.compile("%{AUDITD_HEADER}", true)
    private lazy val auditdAVC: Grok = grokCompiler.compile("%{AUDITD_AVC}", true)

    override def parse(msg: Either[String, JObject]): ParsedLog = {
        msg match {
            case Right(_) =>
                throw new RuntimeException(s"Expected String message but got JSON")
            case Left(raw) =>
                raw
                    .split('\n')
                    .flatMap { line =>
                        val ltsvResult: Seq[(String, String)] = parse(line)
                        ltsvResult.find(_._1 == "type") match {
                            case Some((_, "AVC")) =>
                                val grokResult: Seq[(String, String)] = parse(auditdAVC, line).map { case (k, v) => (k, v.toString) }.toSeq
                                ltsvResult ++ grokResult
                            case _ =>
                                val grokResult: Seq[(String, String)] = parse(parseHeader, line).map { case (k, v) => (k, v.toString) }.toSeq
                                ltsvResult ++ grokResult
                        }
                    }
                    .flatMap {
                        case ("msg", value) =>
                            parse(value)
                        case (key, value) =>
                            Seq((key, value))
                    }
                    .groupBy(_._1)
                    .map { case (k, v) =>
                        val values = v.map(_._2).toSeq.map(clean)

                        if (values.size == 1) {
                            k -> values.head
                        } else {
                            k -> values
                        }
                    }
        }
    }

    private def clean(value: String): String = {
        if (value.startsWith("\"")) {
            value.substring(1, value.length - 1)
        } else {
            value
        }
    }

    private def parse(line: String): Seq[(String, String)] = {
        ltsv
            .parse(line, StandardCharsets.UTF_8)
            .next()
            .toMap
            .filter { case (_, value) => value ne null }
            .map { case (key, value) => (key, value.trim) }
            .filterNot(UnknownSynonyms.checkValueMeansNull)
            .toSeq
    }
}

object AuditdParser {
    val name: String = "reassembledAuditD01"
    val version: Int = 1
}