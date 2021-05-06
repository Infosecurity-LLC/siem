package ru.gkis.soc.siem.downloader

import com.typesafe.scalalogging.LazyLogging
import org.apache.spark.SparkConf
import org.apache.spark.broadcast.Broadcast
import org.apache.spark.streaming.kafka010.ConsumerStrategies.Subscribe
import org.apache.spark.streaming.kafka010.{CanCommitOffsets, HasOffsetRanges, KafkaUtils, LocationStrategies}
import org.apache.spark.streaming.{Seconds, StreamingContext}
import ru.gkis.soc.siem.commons.BaseConfig
import ru.gkis.soc.siem.io.hbase.{EventTypeConfig, HBaseOutputConfig}
import ru.gkis.soc.siem.io.kafka.KafkaInputConfig

object Main extends LazyLogging {

    def main(args: Array[String]): Unit = {

        import ru.gkis.soc.siem.downloader.dsl.Transformations._

        val conf = new BaseConfig with KafkaInputConfig with HBaseOutputConfig
        val sparkConf = new SparkConf().setAll(conf.sparkProperties)

        val ctx = StreamingContext.getOrCreate(s"checkpoint/${conf.applicationName}",
            () => new StreamingContext(sparkConf, Seconds(conf.streamingBatchDuration)))
        val stream = KafkaUtils.createDirectStream[String, Array[Byte]](
            ctx,
            LocationStrategies.PreferConsistent,
            Subscribe[String, Array[Byte]](conf.kafkaInputTopics, conf.kafkaInputProperties)
        )

        val eventTypeConfigs: Broadcast[Map[String, EventTypeConfig]] = ctx.sparkContext.broadcast(
            List(conf.socEventMapping, conf.rawEventMapping, conf.chainEventMapping)
                .map(etc => etc.topic -> etc)
                .toMap)
        val bconf: Broadcast[HBaseOutputConfig] = ctx.sparkContext.broadcast(conf)

        stream
            .foreachRDD(rdd => {
                val offsetRanges = rdd.asInstanceOf[HasOffsetRanges].offsetRanges
                logger.info(s"Starting from offsets $offsetRanges")

                val cnt = rdd
                    .map(rec => rec.topic() -> rec.value)
                    .deserialize(eventTypeConfigs)
                    .write(bconf)
                    .count()

                logger.info(s"Written $cnt events to HBase")
                logger.info(s"Committing offsets $offsetRanges")
                stream.asInstanceOf[CanCommitOffsets].commitAsync(offsetRanges)
            })

        ctx.start()
        ctx.awaitTermination()
    }
}