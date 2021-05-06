package ru.gkis.soc.siem.router

import com.typesafe.scalalogging.LazyLogging
import org.apache.spark.SparkConf
import org.apache.spark.broadcast.Broadcast
import org.apache.spark.metrics.source.{MetricsAgent, RouterMetrics}
import org.apache.spark.streaming.kafka010.ConsumerStrategies.Subscribe
import org.apache.spark.streaming.kafka010.{CanCommitOffsets, HasOffsetRanges, KafkaUtils, LocationStrategies}
import org.apache.spark.streaming.{Seconds, StreamingContext}
import ru.gkis.soc.siem.cache.CacheConfig
import ru.gkis.soc.siem.commons.BaseConfig
import ru.gkis.soc.siem.io.kafka.{KafkaInputConfig, KafkaOutputConfig}
import ru.gkis.soc.siem.router.dsl.model.Statistics

object Main extends LazyLogging {

    def main(args: Array[String]): Unit = {
        import ru.gkis.soc.siem.router.dsl.Transformations._

        val conf = new BaseConfig with RouterConfig with CacheConfig with KafkaInputConfig with KafkaOutputConfig
        val sparkConf = new SparkConf().setAll(conf.sparkProperties)

        val ctx = StreamingContext.getOrCreate(s"checkpoint/${conf.applicationName}",
            () => new StreamingContext(sparkConf, Seconds(conf.streamingBatchDuration)))
        val stream = KafkaUtils.createDirectStream[String, String](
            ctx,
            LocationStrategies.PreferConsistent,
            Subscribe[String, String](conf.kafkaInputTopics, conf.kafkaInputProperties)
        )

        val clientMetrics = MetricsAgent.inception(new RouterMetrics(_, conf.metricSystemNamespace))
        val bConf: Broadcast[KafkaOutputConfig with RouterConfig] = ctx.sparkContext.broadcast(conf)

        stream
            .foreachRDD(rdd => {
                val offsetRanges = rdd.asInstanceOf[HasOffsetRanges].offsetRanges
                logger.info(s"Starting from offsets $offsetRanges")

                val stats: Array[Statistics] = rdd
                    .receive
                    .send(bConf)
                    .collect

                clientMetrics.updateClientStats(stats)
                logger.info(s"Batch final stats: ${stats.reduce(_ + _)}")

                logger.info(s"Committing offsets $offsetRanges")
                stream.asInstanceOf[CanCommitOffsets].commitAsync(offsetRanges)
            })

        ctx.start()
        ctx.awaitTermination()
    }
}
