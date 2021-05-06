package ru.gkis.soc.siem.io.hbase

import com.typesafe.config.Config
import scalapb.{GeneratedMessage, GeneratedMessageCompanion}

class EventTypeConfig(conf: Config, companion: GeneratedMessageCompanion[_ <: GeneratedMessage]) extends Serializable {
    val topic: String = conf.getString("topic")
    val table: String = conf.getString("table")
    val spawner: GeneratedMessageCompanion[_ <: GeneratedMessage] = companion
}
