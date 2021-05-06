package ru.gkis.soc.siem.io.kafka

import com.typesafe.config.Config

import scala.concurrent.duration.Duration

trait KafkaOutputConfig {

    import scala.collection.JavaConversions._
    import scala.compat.java8.DurationConverters._

    protected val appConf: Config
    private val basic = appConf.getConfig("app.kafka.output.basic.producer.settings")

    val kafkaWriteTimeout: Duration = appConf.getDuration("app.kafka.output.write.timeout").toScala
    val kafkaOutputProperties: Map[String, AnyRef] = appConf
                                                        .getConfig(s"app.kafka.output.producer")
                                                        .withFallback(basic)
                                                        .entrySet()
                                                        .filterNot(_.getKey.contains("topic.mappings"))
                                                        .map(e => e.getKey -> e.getValue.unwrapped())
                                                        .toMap
    val kafkaTopicMappings: Map[String, String] = appConf
                                                    .getConfig(s"app.kafka.output.producer.topic.mappings")
                                                    .entrySet()
                                                    .map(e => e.getKey -> String.valueOf(e.getValue.unwrapped()))
                                                    .toMap
}
