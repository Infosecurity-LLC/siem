package ru.gkis.soc.siem.normalizer.dsl

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.model.{ParsedLog, ProviderKey, TransformationPreferences}
import ru.gkis.soc.siem.normalizer._
import ru.gkis.soc.siem.io.spark.EditableBroadcast

import scala.util.{Failure, Success, Try}

trait LogParser {

    implicit class LogParser(rdd: RDD[CanParse]) extends Serializable {

        import ru.gkis.soc.siem.normalizer.parsers.LogParser.ops._

        def parseLogs(prefs: EditableBroadcast[TransformationPreferences]): RDD[LogParsed] = {
            rdd.mapPartitionsWithIndex((part, it) => {
                it.map {
                    case parsed: ParsedMessage =>
                        val preference = prefs.value(parsed.organization)(parsed.eventDevType).parser
                        implicit val mapperInfo: ProviderKey = ProviderKey(preference.name, preference.version, part)
                        Try(parse[ParsedLog](parsed.raw)) match {
                            case Success(event) => ParsedEvent(parsed, event)
                            case Failure(ex) => LogParseError(parsed, ex)
                        }
                    case invalid: UnknownDevType => invalid
                    case error: ParseError with LogParsed => error
                }
            }, preservesPartitioning = true)
        }

    }

}
