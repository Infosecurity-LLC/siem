package ru.gkis.soc.siem.normalizer

import java.util.concurrent.TimeUnit

import com.typesafe.config.ConfigFactory
import ru.gkis.soc.siem.model.{Counterpart, ImportanceLevel, InteractionCategory, InteractionStatus}

import scalapb.{GeneratedEnum, GeneratedEnumCompanion}

import scala.collection.GenTraversableOnce

package object mappers {

    import scala.collection.JavaConversions._

    private val config = ConfigFactory.load("value_to_enum_mapping.conf")

    implicit def canFlattenStringAnyRef: PartialFunction[(String, AnyRef), GenTraversableOnce[(String, String)]] = {
        case (k: String, v: Array[String]) => v.map(i => i -> k)
        case (k: String, v: java.util.List[_]) => v.map {
            case i: String => i -> k
            case i: Int => i.toString -> k
        }
    }

    private def failOnAbsent[T <: GeneratedEnum](absentValue: String, enum: String): T = throw new RuntimeException(s"Value $absentValue not found in $enum")

    private def loadMappings[T <: GeneratedEnum](base: String, enum: GeneratedEnumCompanion[T], prev: Map[String, T] = Map.empty[String, T]): Map[String, T] = {
        config.getObject(base)
            .unwrapped()
            .flatten
            .foldLeft(prev) { case (result, (k, v)) =>
                val key = k.toLowerCase
                val value = enum.fromName(v).getOrElse(failOnAbsent(v, enum.scalaDescriptor.fullName))
                result.get(key) match {
                    case Some(existing) if existing != value =>
                        throw new RuntimeException(s"Invalid mapping configuration, duplicate key [$key] with different values [$existing,  $value]")
                    case Some(_) =>
                        result
                    case None =>
                        result + (key -> value)
                }
            }
    }

    private val actionName: Map[String, InteractionCategory] = loadMappings("AuditdTypeOrSyscallToInteractionCategory", InteractionCategory, loadMappings("DevActionNameToInteractionCategory", InteractionCategory))
    private val actionStatus: Map[String, InteractionStatus] = loadMappings("DevActionStatusToInteractionStatus", InteractionStatus)
    private val importanceLevel: Map[String, ImportanceLevel] = loadMappings("DevImportanceLevelToImportanceLevel", ImportanceLevel)
    private val counterpart: Map[String, Counterpart] = loadMappings("AuditdObjectCategoryToCounterpart", Counterpart, loadMappings("DevObjectCategoryToCounterpart", Counterpart))

    private def getOrUnknown[T <: GeneratedEnum](value: Either[String, Option[String]], mapping: Map[String, T], unknown: T): T =
        value.fold(str => mapping.getOrDefault(str.toLowerCase, unknown),
            opt => opt.fold(unknown)((str: String) => mapping.getOrDefault(str.toLowerCase, unknown)))

    private def toEnumInternal[T <: GeneratedEnum]: PartialFunction[GeneratedEnumCompanion[T], Either[String, Option[String]] => T] = {
        case InteractionCategory => (value) => getOrUnknown(value, actionName, InteractionCategory.UnknownInteractionCategory).asInstanceOf[T]
        case InteractionStatus => (value) => getOrUnknown(value, actionStatus, InteractionStatus.UnknownInteractionStatus).asInstanceOf[T]
        case ImportanceLevel => (value) => getOrUnknown(value, importanceLevel, ImportanceLevel.UnknownImportanceLevel).asInstanceOf[T]
        case Counterpart => (value) => getOrUnknown(value, counterpart, Counterpart.UnknownCounterpart).asInstanceOf[T]
    }

    implicit class StringConverter(value: String) {
        def toInteractionCategory: InteractionCategory = toEnumInternal(InteractionCategory)(Left(value))

        def toInteractionStatus: InteractionStatus = toEnumInternal(InteractionStatus)(Left(value))

        def toImportanceLevel: ImportanceLevel = toEnumInternal(ImportanceLevel)(Left(value))

        def toCounterpart: Counterpart = toEnumInternal(Counterpart)(Left(value))

        def toEpochTimeSeconds: Long = {
            value.length match {
                case 19 => TimeUnit.NANOSECONDS.toSeconds(value.toLong)
                case 16 => TimeUnit.MICROSECONDS.toSeconds(value.toLong)
                case 13 => TimeUnit.MILLISECONDS.toSeconds(value.toLong)
                case 10 => value.toLong
            }
        }
    }

    implicit class StringOptionConverter(value: Option[String]) {
        def toInteractionCategory: InteractionCategory = toEnumInternal(InteractionCategory)(Right(value))

        def toInteractionStatus: InteractionStatus = toEnumInternal(InteractionStatus)(Right(value))

        def toImportanceLevel: ImportanceLevel = toEnumInternal(ImportanceLevel)(Right(value))

        def toCounterpart: Counterpart = toEnumInternal(Counterpart)(Right(value))

    }

}
