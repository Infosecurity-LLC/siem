package ru.gkis.soc.siem.normalizer.parsers

import io.krakens.grok.api.{Grok, GrokCompiler}
import ru.gkis.soc.siem.normalizer.mappers.helpers.UnknownSynonyms

trait GrokParser {
    def grokSource: Seq[String]

    protected lazy val grokCompiler: GrokCompiler = {
        val result = GrokCompiler.newInstance()
        grokSource.foreach(result.registerPatternFromClasspath)
        result
    }

    protected def parse(grok: Grok, source: String): Map[String, AnyRef] = {
        import scala.collection.JavaConversions._

        grok
            .capture(source)
            .collect {
                case (key, value: String) if value != null =>
                    (key, value.trim)
                case (key, value) if value != null =>
                    (key, value)
            }
            .filterNot(UnknownSynonyms.checkValueMeansNull).toMap
    }
}
