package ru.gkis.soc.siem.enricher

import com.typesafe.scalalogging.LazyLogging
import ru.gkis.soc.siem.enricher.cache.index.{Aux, Location, Object, Rule, Schedule, ScheduleGroup, Subject, TProtocol}
import ru.gkis.soc.siem.model.access.{Allowed, WindowsObject}
import com.google.common.collect.{Range => NumericRange}
import org.json4s.DefaultFormats
import org.json4s.jackson.Serialization.write

object Tesst extends App with LazyLogging {

}

