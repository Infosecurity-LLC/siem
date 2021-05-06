package ru.gkis.soc.siem.normalizer

import java.time.LocalDateTime

import com.typesafe.scalalogging.LazyLogging
import org.apache.spark.metrics.source.{MetricsAgent, NormalizerMetrics}
import org.apache.spark.{SparkConf, TaskMetrics}
import org.apache.spark.broadcast.Broadcast
import org.apache.spark.streaming.{Seconds, StreamingContext}
import org.apache.spark.streaming.kafka010.{CanCommitOffsets, HasOffsetRanges, KafkaUtils, LocationStrategies}
import org.apache.spark.streaming.kafka010.ConsumerStrategies.Subscribe
import ru.gkis.soc.siem.cache.{CacheConfig, MetaCache}
import ru.gkis.soc.siem.commons.BaseConfig
import ru.gkis.soc.siem.io.kafka.{KafkaInputConfig, KafkaOutputConfig}
import ru.gkis.soc.siem.normalizer.dsl.Transformations
import ru.gkis.soc.siem.io.spark.EditableBroadcast

object Main extends LazyLogging {

    import Transformations._

    def main(args: Array[String]): Unit = {
        val conf = new BaseConfig with KafkaInputConfig with KafkaOutputConfig with CacheConfig with NormalizerConfig
        val sparkConf = new SparkConf().setAll(conf.sparkProperties)

        val ctx = StreamingContext.getOrCreate(s"checkpoint/${conf.applicationName}",
                                                () => new StreamingContext(sparkConf, Seconds(conf.streamingBatchDuration)))
        val stream = KafkaUtils.createDirectStream[String, String](
            ctx,
            LocationStrategies.PreferConsistent,
            Subscribe[String, String](conf.kafkaInputTopics, conf.kafkaInputProperties)
        )
        val clientMetrics = MetricsAgent.inception(new NormalizerMetrics(_, conf.metricSystemNamespace))
        val meta = new MetaCache(conf)

        val bconf: Broadcast[KafkaOutputConfig with NormalizerConfig] = ctx.sparkContext.broadcast(conf)
        val transformPrefs = new EditableBroadcast(ctx, meta.transformationPreferences)
        val deviceVendors = new EditableBroadcast(ctx, meta.fetchDevTypeToVendorMapping)

        stream
            .foreachRDD(rdd => {
                val offsetRanges = rdd.asInstanceOf[HasOffsetRanges].offsetRanges
                logger.info(s"Starting from offsets $offsetRanges")
                transformPrefs.update(meta.transformationPreferences)
                deviceVendors.update(meta.fetchDevTypeToVendorMapping)
                val now = LocalDateTime.now()
                val stats = rdd
                               .receive
                               .parseMessages
                               .validate(transformPrefs)
                               .parseLogs(transformPrefs)
                               .validate(transformPrefs)
                               .split
                               .mapToTargetStruct(transformPrefs, deviceVendors)
                               .shiftTime(bconf)
                               .collectStatistics(now)
                               .send(bconf)
                               .summarize

                clientMetrics.updateClientStats(stats)
                clientMetrics.updateBatchStats(ctx.sparkContext, offsetRanges)
                logger.info(s"Batch final stats:\n${stats.map(_.toString).mkString("\n")}")

                logger.info(s"Committing offsets $offsetRanges")
                stream.asInstanceOf[CanCommitOffsets].commitAsync(offsetRanges)
            })

        ctx.start()
        ctx.awaitTermination()
    }

}
