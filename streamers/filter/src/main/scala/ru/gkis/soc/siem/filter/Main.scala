package ru.gkis.soc.siem.filter

import com.typesafe.scalalogging.LazyLogging
import org.apache.spark.SparkConf
import org.apache.spark.broadcast.Broadcast
import org.apache.spark.streaming.kafka010.ConsumerStrategies.Subscribe
import org.apache.spark.streaming.kafka010.{CanCommitOffsets, HasOffsetRanges, KafkaUtils, LocationStrategies}
import org.apache.spark.streaming.{Seconds, StreamingContext}
import ru.gkis.soc.siem.cache.{CacheConfig, MetaCache}
import ru.gkis.soc.siem.commons.BaseConfig
import ru.gkis.soc.siem.io.kafka.{KafkaInputConfig, KafkaOutputConfig}
import ru.gkis.soc.siem.io.spark.EditableBroadcast

object Main extends LazyLogging {

    import dsl.Transformations._

    def main(args: Array[String]): Unit = {

        val conf = new BaseConfig with FilterConfig with CacheConfig with KafkaInputConfig with KafkaOutputConfig
        val sparkConf = new SparkConf().setAll(conf.sparkProperties)

        val ctx = StreamingContext.getOrCreate(s"checkpoint/${conf.applicationName}",
            () => new StreamingContext(sparkConf, Seconds(conf.streamingBatchDuration)))
        val stream = KafkaUtils.createDirectStream[String, String](
            ctx,
            LocationStrategies.PreferConsistent,
            Subscribe[String, String](conf.kafkaInputTopics, conf.kafkaInputProperties)
        )

        val meta: MetaCache = new MetaCache(conf)
        val bconf: Broadcast[KafkaOutputConfig] = ctx.sparkContext.broadcast(conf)

        val cache = new EditableBroadcast(ctx, meta.scripts(), period = conf.scriptsUpdateInterval)

        stream
            .foreachRDD(rdd => {
                val offsetRanges = rdd.asInstanceOf[HasOffsetRanges].offsetRanges
                updateCaches()
                logger.info(s"Starting from offsets $offsetRanges")
                val script = Builder.build(cache.value)
                script match {
                    case Some(script) =>
                        logger.info(s"""Building script $script""")
                        val (filtered, approved) = rdd
                            .deserialize()
                            .transform()
                            .run(script)
                            .serialize
                            .send(bconf)
                            .collect()
                            .foldLeft((0, 0)) { case ((filtered, approved), el) =>
                                (filtered + el.filteredCount, approved + el.approvedCount)
                            }

                        logger.info(s"Skipped events count = $filtered")
                        logger.info(s"Approved events count = $approved")
                    case None =>
                        logger.info("Script is empty, skipping...")
                        rdd.mapPartitions(_.map(_.value())).send(bconf)
                }

                logger.info(s"Committing offsets $offsetRanges")
                stream.asInstanceOf[CanCommitOffsets].commitAsync(offsetRanges)
            })

        def updateCaches(): Unit = {
            cache.update(meta.scripts())
        }

        ctx.start()
        ctx.awaitTermination()
    }
}
