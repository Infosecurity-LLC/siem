package ru.gkis.soc.siem.io.elastic

import com.typesafe.config.Config

import scala.concurrent.duration.Duration

trait ElasticOutputConfig {

    import scala.collection.JavaConversions._

    protected val appConf: Config

    val esOutputProperties: Map[String, String] = appConf
                                                    .getConfig("app.elastic")
                                                    .entrySet()
                                                    .map(e => e.getKey -> String.valueOf(e.getValue.unwrapped()))
                                                    .toMap

}
