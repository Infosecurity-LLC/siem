package ru.gkis.soc.siem.normalizer.mappers.helpers

import com.typesafe.config.ConfigFactory

object ProtocolResolver {

    import scala.collection.JavaConversions._
    import ru.gkis.soc.siem.normalizer.mappers._

    private val conversions: Map[String, String] = ConfigFactory
        .load("network_protocol_resolv.conf")
        .getObject("protocols")
        .unwrapped()
        .flatten
        .foldLeft(Map.empty[String, String]) { case (result, (key, value)) =>
            result.get(key) match {
                case Some(existing) if existing != value =>
                    throw new RuntimeException(s"Invalid mapping configuration, duplicate key [$key] with different values [$existing,  $value]")
                case Some(_) =>
                    result
                case None =>
                    result + (key -> value)
            }
        }

    def apply(proto: String): String =
        conversions.getOrElse(proto.toLowerCase, proto)

}
