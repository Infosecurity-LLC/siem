package ru.gkis.soc.siem.normalizer.dsl

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.model.ProviderKey
import ru.gkis.soc.siem.normalizer.{KafkaRecord, NxParseError, NxParsed, ParsedMessage, RawMessage}
import ru.gkis.soc.siem.normalizer.parsers.{ParserProvider, ParseException, RawMessageParser}

import scala.util.{Failure, Success, Try}

trait MessageParser {

    implicit class NxMessageParser(rdd: RDD[KafkaRecord]) extends Serializable {

        import ru.gkis.soc.siem.normalizer.parsers.LogParser.ops._

        def parseMessages: RDD[NxParsed] = {
            rdd.mapPartitionsWithIndex((part, it) => {
                implicit val mapperInfo: ProviderKey = ProviderKey(RawMessageParser.name, RawMessageParser.version, part)
                it
                    .map {
                        case raw: RawMessage => (raw, Try(parse[List[ParsedMessage]](Left(raw.nxMessage))))
                    }
                    .flatMap {
                        case (_, Success(msg)) => msg
                        case (raw, Failure(ex)) => Iterator.single(new ParseException(ex, raw.nxMessage))
                    }
                    .map {
                        case msg: ParsedMessage => msg
                        case ex: ParseException => NxParseError(ex.src, ex.root)
                    }
            }, preservesPartitioning = true)
        }

    }

}
