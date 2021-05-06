package ru.gkis.soc.siem.reassembler.parsers

import io.krakens.grok.api.GrokCompiler
import org.json4s._
import org.json4s.jackson.{JsonMethods, compactJson}

object AuditdParser {
    val failureParsing = "failure"

    private val grokCompiler: GrokCompiler = {
        val result = GrokCompiler.newInstance()
        result.registerPatternFromClasspath("/grok/common")
        result.registerPatternFromClasspath("/grok/auditd")
        result
    }
    private val grok = grokCompiler.compile("%{AUDITD_HEADER}")

    def extractTimestamp: Seq[String] => String = { seq =>
        seq.head
    }

    def extractId: Seq[String] => String = { seq =>
        seq.last
    }

    def extract: String => Seq[String] = { raw =>
        val result = parse(raw)

        Seq(
            result.getOrElse("timestamp", failureParsing),
            result.getOrElse("id", failureParsing)
        )
    }

    def flatRaw: Seq[String] => String = { lines =>
        lines.mkString("\n")
    }

    def addChain: (String, String) => String = { case (leftRaw, rightRaw) =>
        val left = JsonMethods.parse(leftRaw)
        val right = JsonMethods.parse(rightRaw)
        val result = left.merge(JObject("chain" -> right))

        compactJson(result)
    }

    private[this] def parse(source: String): Map[String, String] = {
        import scala.collection.JavaConversions._

        grok
            .capture(source)
            .collect {
                case (key, value: String) if value != null =>
                    (key, value.trim)
                case (key, value) if value != null =>
                    (key, value.toString)
            }
            .toMap
    }
}