package ru.gkis.soc.siem.normalizer.mappers.helpers

import ru.gkis.soc.siem.model.ParsedLog

sealed trait TypedExtractor[T] {
    val value: String
}
abstract class KeyedType[T](key: String) extends TypedExtractor[T] {
    override val value: String = key
}
final class StringType(key: String) extends KeyedType[String](key)
final class IntType(key: String) extends KeyedType[Int](key)
final class LongType(key: String) extends KeyedType[Long](key)
final class BooleanType(key: String) extends KeyedType[Boolean](key)
final class DoubleType(key: String) extends KeyedType[Double](key)
final class MapType(key: String) extends KeyedType[ParsedLog](key)

object TypedExtractor {

    import scala.language.implicitConversions

    implicit class ExtractHelper(val sc: StringContext) extends AnyVal {
        def string(args: Any*): TypedExtractor[String] = new StringType(sc.parts.iterator.next())
        def int(args: Any*): TypedExtractor[Int] = new IntType(sc.parts.iterator.next())
        def long(args: Any*): TypedExtractor[Long] = new LongType(sc.parts.iterator.next())
        def boolean(args: Any*): TypedExtractor[Boolean] = new BooleanType(sc.parts.iterator.next())
        def double(args: Any*): TypedExtractor[Double] = new DoubleType(sc.parts.iterator.next())
        def map(args: Any*): TypedExtractor[ParsedLog] = new MapType(sc.parts.iterator.next())
    }

    implicit class MapOps(log: ParsedLog) {
        def extractOpt[K](ext: TypedExtractor[K])(implicit f: AnyRef => K): Option[K] = (log get ext.value).map(x => f(x))
        def extract[K](key: TypedExtractor[K])(implicit f: AnyRef => K): K = f(log(key.value))
        def extractOpt(ext: String): Option[String] = (log get ext).map(x => canExtractString(x))
        def extract(key: String): String = canExtractString(log(key))
    }

    implicit def canExtractString(param: AnyRef): String = param match {
        case s: java.lang.String => s
        case bi: scala.math.BigInt => bi.toString()
    }

    implicit def canExtractInt(param: AnyRef): Int = param match {
        case bi: scala.math.BigInt => bi.intValue
        case s: java.lang.String => s.toInt
    }

    implicit def canExtractLong(param: AnyRef): Long = param match {
        case bi: scala.math.BigInt => bi.longValue
        case s: java.lang.String => s.toLong
    }

    implicit def canExtractBoolean(param: AnyRef): Boolean = param match {
        case b: java.lang.Boolean => b
        case s: java.lang.String => s.toBoolean
    }

    implicit def canExtractDouble(param: AnyRef): Double = param match {
        case d: java.lang.Double => d
        case s: java.lang.String => s.toDouble
    }

    implicit def canExtractMap(param: AnyRef): ParsedLog = param match {
        case m: Map[_, _] => m.asInstanceOf[Map[String, AnyRef]]
    }
}