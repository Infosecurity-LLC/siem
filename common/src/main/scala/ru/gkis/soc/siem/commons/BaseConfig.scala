package ru.gkis.soc.siem.commons

import com.typesafe.config.{Config, ConfigFactory}
import com.typesafe.scalalogging.LazyLogging

abstract class BaseConfig extends Serializable with LazyLogging {

    import scala.collection.JavaConversions._

    protected val appConf: Config = ConfigFactory.load()

    logger.info(
        appConf
        .entrySet()
        .filterNot(_.getKey.contains("pass"))
        .foldLeft("Starting application with parameters: \n")((res, e) => s"$res\t${e.getKey} = ${e.getValue.unwrapped()}\n")
    )

    val applicationName: String = appConf.getString("app.spark.app.name")
    val metricSystemNamespace: String = appConf.getString("app.spark.metrics.namespace")
    val sparkProperties: Map[String, String] = appConf
                                                .getConfig("app.spark")
                                                .entrySet()
                                                .map(entry => s"spark.${entry.getKey}" -> String.valueOf(entry.getValue.unwrapped()))
                                                .toMap
    val streamingBatchDuration: Long = appConf.getDuration("app.streaming.batch.duration").getSeconds
}
