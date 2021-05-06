package ru.gkis.soc.siem.normalizer.parsers

import java.nio.charset.StandardCharsets

import com.github.lolo.ltsv.LtsvParser
import org.json4s.JObject
import ru.gkis.soc.siem.model.ParsedLog
import ru.gkis.soc.siem.normalizer.mappers.helpers.UnknownSynonyms

class FortigateParser extends LogParser[ParsedLog] {

    import scala.collection.JavaConversions._

    private val ltsv = LtsvParser.builder().withEntryDelimiter(' ').withKvDelimiter('=').lenient().build()

    override def parse(msg: Either[String, JObject]): ParsedLog = {
        msg match {
            case Right(_) =>
                throw new RuntimeException(s"Expected String message but got JSON")
            case Left(string) =>
                ltsv
                    // magic number 5 to skip `<123>` prefix at every line
                    .parse(string.substring(5), StandardCharsets.UTF_8)
                    .next()
                    .toMap
                    .filter { case (_, value) => value ne null }
                    .map { case (key, value) => (key, value.trim)}
                    .filterNot(UnknownSynonyms.checkValueMeansNull)
        }
    }
}

object FortigateParser {
    val name: String = "fortigate"
    val version: Int = 1
}
