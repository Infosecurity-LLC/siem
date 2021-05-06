package ru.gkis.soc.siem.normalizer.dsl

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.commons.Constants
import ru.gkis.soc.siem.crypto.RipeMD160
import ru.gkis.soc.siem.normalizer._


trait Splitter {

    implicit class Splitter(rdd: RDD[Validated]) extends Serializable {

        private def createRawId(msg: ParsedMessage): String =
            RipeMD160(msg.rawMessage)

        private def createRawId(raw: String): String =
            RipeMD160(raw)

        private def createNormId(msg: ParsedMessage, rawId: String): String =
            RipeMD160(msg.organization, msg.eventHostname.getOrElse(msg.eventHostIP), rawId)

        def split: RDD[Split] = {
            rdd.mapPartitions(_.flatMap {
                case valid: Valid =>
                    val rawId = createRawId(valid.message)
                    val normId = createNormId(valid.message, rawId)
                    val srcHost = valid.message.eventHostname.getOrElse(valid.message.eventHostIP)
                    Iterator(
                        InternalSocEvent(valid.message, valid.event, normId, rawId, srcHost),
                        InternalRawEvent(valid.message, Some(normId), rawId, srcHost),
                        InternalChainEvent(valid.message, Some(normId), rawId, srcHost)
                    )
                case invalid: Invalid =>
                    val rawId = createRawId(invalid.message)
                    val srcHost = invalid.message.eventHostname.getOrElse(invalid.message.eventHostIP)
                    Iterator(
                        InternalInvalidEvent(invalid.message, invalid.reason, rawId, srcHost),
                        InternalRawEvent(invalid.message, None, rawId, srcHost),
                        InternalChainEvent(invalid.message, None, rawId, srcHost)
                    )
                case error: LogParseError =>
                    val rawId = createRawId(error.message)
                    val srcHost = error.message.eventHostname.getOrElse(error.message.eventHostIP)
                    Iterator single InternalErrorEvent(Left(error.message), error.exception, rawId, srcHost)
                case error: NxParseError =>
                    val rawId = createRawId(error.nxMessage)
                    Iterator single InternalErrorEvent(Right(error.nxMessage), error.exception, rawId, Constants.unknown)
            })
        }
    }

}
