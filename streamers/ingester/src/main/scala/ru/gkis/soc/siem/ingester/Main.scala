package ru.gkis.soc.siem.ingester

import com.typesafe.scalalogging.LazyLogging
import org.apache.spark.SparkConf
import org.apache.spark.streaming.kafka010.ConsumerStrategies.Subscribe
import org.apache.spark.streaming.{Seconds, StreamingContext}
import org.apache.spark.streaming.kafka010.{CanCommitOffsets, HasOffsetRanges, KafkaUtils, LocationStrategies}
import ru.gkis.soc.siem.commons.BaseConfig
import ru.gkis.soc.siem.io.elastic.ElasticOutputConfig
import ru.gkis.soc.siem.io.kafka.KafkaInputConfig
import ru.gkis.soc.siem.model.SocEvent

object Main extends LazyLogging {

    import org.elasticsearch.spark._
    import ru.gkis.soc.siem.ingester.dsl.Transformer._

    def main(args: Array[String]): Unit = {
        val conf = new BaseConfig with KafkaInputConfig with ElasticOutputConfig
        val sparkConf = new SparkConf().setAll(conf.sparkProperties)

        val ctx = StreamingContext.getOrCreate(s"checkpoint/${conf.applicationName}",
                                                () => new StreamingContext(sparkConf, Seconds(conf.streamingBatchDuration)))
        val stream = KafkaUtils.createDirectStream[String, SocEvent](
            ctx,
            LocationStrategies.PreferConsistent,
            Subscribe[String, SocEvent](conf.kafkaInputTopics, conf.kafkaInputProperties)
        )

        stream
            .foreachRDD(rdd => {
                val offsetRanges = rdd.asInstanceOf[HasOffsetRanges].offsetRanges
                logger.info(s"Starting from offsets $offsetRanges")

                rdd
                    .map(_.value)
                    .eventsToMap
                    .saveToEs(conf.esOutputProperties)

                logger.info(s"Committing offsets $offsetRanges")
                stream.asInstanceOf[CanCommitOffsets].commitAsync(offsetRanges)
            })

        ctx.start()
        ctx.awaitTermination()
    }

}
