package ru.gkis.soc.siem.normalizer.mappers.helpers

import com.typesafe.config.ConfigFactory

object UnknownSynonyms {

    import scala.collection.JavaConversions._

    private val config = ConfigFactory.load("value_of_unknown.conf")
    private val allowedValuesForUnknown = config.getStringList("AllowedValuesForUnknown.values").map(_.toLowerCase).toSet

    def checkValueMeansNull(entry: (_, _)): Boolean = entry match {
        case (_, value: String) => allowedValuesForUnknown.contains(value.toLowerCase)
        case _ => false
    }

}
