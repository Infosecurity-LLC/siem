package ru.gkis.soc.siem.io.kafka

import com.typesafe.config.Config

trait KafkaInputConfig {

    import scala.collection.JavaConversions._
    import scala.compat.java8.DurationConverters._

    protected val appConf: Config

    val kafkaInputProperties: Map[String, AnyRef] = appConf
        .getConfig("app.kafka.input")
        .entrySet()
        .filterNot(_.getKey.contains("topics"))
        .map(e => e.getKey -> e.getValue.unwrapped())
        .toMap
    val kafkaInputTopics: List[String] = appConf
        .getList("app.kafka.input.topics")
        .unwrapped()
        .map(String.valueOf)
        .toList
}
