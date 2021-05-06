package ru.gkis.soc.siem.monitor

import com.typesafe.scalalogging.LazyLogging
import org.apache.spark.SparkConf
import org.apache.spark.metrics.source.{MetricsAgent, MonitorMetrics}
import org.apache.spark.streaming.kafka010.ConsumerStrategies.Subscribe
import org.apache.spark.streaming.kafka010.{CanCommitOffsets, HasOffsetRanges, KafkaUtils, LocationStrategies}
import org.apache.spark.streaming.{Seconds, StreamingContext}
import ru.gkis.soc.siem.commons.BaseConfig
import ru.gkis.soc.siem.io.kafka.KafkaInputConfig

object Main extends LazyLogging {

    import ru.gkis.soc.siem.monitor.dsl.Transformations._

    def main(args: Array[String]): Unit = {
        val conf = new BaseConfig with KafkaInputConfig
        val sparkConf = new SparkConf().setAll(conf.sparkProperties)

        val ctx = StreamingContext.getOrCreate(s"checkpoint/${conf.applicationName}",
            () => new StreamingContext(sparkConf, Seconds(conf.streamingBatchDuration)))
        val stream = KafkaUtils.createDirectStream[String, Array[Byte]](
            ctx,
            LocationStrategies.PreferConsistent,
            Subscribe[String, Array[Byte]](conf.kafkaInputTopics, conf.kafkaInputProperties)
        )

        val clientMetrics = MetricsAgent.inception(new MonitorMetrics(_, conf.metricSystemNamespace))

        stream
            .foreachRDD(rdd => {
                val offsetRanges = rdd.asInstanceOf[HasOffsetRanges].offsetRanges
                logger.info(s"Starting from offsets $offsetRanges")

                val stats = rdd
                    .map(_.value())
                    .deserialize
                    .parse
                    .stats
                    .collect

                clientMetrics.updateClientStats(stats)

                logger.info(s"Batch final stats: ${stats.mkString("\n")}")
                logger.info(s"Committing offsets $offsetRanges")

                stream.asInstanceOf[CanCommitOffsets].commitAsync(offsetRanges)
            })

        ctx.start()
        ctx.awaitTermination()
    }

}
