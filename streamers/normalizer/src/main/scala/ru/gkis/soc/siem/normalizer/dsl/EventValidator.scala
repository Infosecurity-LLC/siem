package ru.gkis.soc.siem.normalizer.dsl

import com.typesafe.scalalogging.LazyLogging
import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.model.{ProviderKey, TransformationPreferences}
import ru.gkis.soc.siem.normalizer.{CanParse, Invalid, LogParsed, NxParsed, ParseError, ParsedEvent, ParsedMessage, UnknownDevType, Valid, Validated}
import ru.gkis.soc.siem.normalizer.validators.NxLogValidator
import ru.gkis.soc.siem.io.spark.EditableBroadcast


trait EventValidator extends LazyLogging {

    implicit class DevTypeValidator(rdd: RDD[NxParsed]) extends Serializable {

        import ru.gkis.soc.siem.normalizer.validators.Validator.ops._

        def validate(prefs: EditableBroadcast[TransformationPreferences]): RDD[CanParse] = {
            rdd.mapPartitionsWithIndex((part, it) => {
                implicit val mapperInfo: ProviderKey = ProviderKey(NxLogValidator.name, NxLogValidator.version, part)
                it.map {
                    case parsed: ParsedMessage =>
                        val validationResults = check((parsed, prefs.value))
                        if (validationResults.isEmpty) {
                            parsed
                        }
                        else {
                            val reason = validationResults.foldLeft(new StringBuilder)((sb, reason) => sb.append(reason).append('\n')).toString()
                            logger.debug(s"Event $parsed validation has failed with reason:\n$reason")
                            UnknownDevType(parsed, reason)
                        }
                    case error: ParseError with CanParse => error
                }
            }, preservesPartitioning = true)
        }
    }

    implicit class EventValidator(rdd: RDD[LogParsed]) extends Serializable {

        import ru.gkis.soc.siem.normalizer.validators.Validator.ops._

        def validate(prefs: EditableBroadcast[TransformationPreferences]): RDD[Validated] = {
            rdd.mapPartitionsWithIndex((part, it) => {
                it.map {
                    case parsed: ParsedEvent =>
                        val preference = prefs.value(parsed.message.organization)(parsed.message.eventDevType).validator
                        implicit val validatorInfo: ProviderKey = ProviderKey(preference.name, preference.version, part)
                        val validationResults = check(parsed)
                        if (validationResults.isEmpty) {
                            Valid(parsed.message, parsed.event)
                        }
                        else {
                            val reason = validationResults.foldLeft(new StringBuilder)((sb, reason) => sb.append(reason).append('\n')).toString()
                            logger.debug(s"Event $parsed validation has failed with reason:\n$reason")
                            Invalid(parsed.message, Some(parsed.event), reason)
                        }
                    case invalid: UnknownDevType =>Invalid(invalid.message, None, invalid.reason)
                    case error: ParseError with Validated => error
                }
            }, preservesPartitioning = true)
        }

    }
}
