package ru.gkis.soc.siem.reassembler

import com.typesafe.scalalogging.LazyLogging
import org.apache.commons.lang.exception.ExceptionUtils
import org.apache.spark.SparkConf
import org.apache.spark.metrics.source.{MetricsAgent, ReassemblerMetrics}
import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.streaming.StreamingQueryListener
import org.apache.spark.sql.types.TimestampType
import org.apache.spark.streaming.{Seconds, StreamingContext}
import ru.gkis.soc.siem.commons.BaseConfig
import ru.gkis.soc.siem.crypto.RipeMD160
import ru.gkis.soc.siem.io.kafka.{KafkaInputConfig, KafkaOutputConfig}
import ru.gkis.soc.siem.model.ErrorEvent
import ru.gkis.soc.siem.reassembler.parsers.{ParserError, RawMessageParser}

import scala.util.{Failure, Success, Try}

object Main extends LazyLogging {
    def main(args: Array[String]): Unit = {

        val conf = new BaseConfig with ReassemblyConfig with KafkaInputConfig with KafkaOutputConfig
        val sparkConf = new SparkConf().setAll(conf.sparkProperties)
            .set("spark.sql.streaming.checkpointLocation", "/tmp/spark/checkpoint")

        val ctx = StreamingContext.getOrCreate(s"checkpoint/${conf.applicationName}",
            () => new StreamingContext(sparkConf, Seconds(conf.streamingBatchDuration)))

        val spark = SparkSession
            .builder()
            .getOrCreate()

        import org.apache.spark.sql.functions._
        import ru.gkis.soc.siem.reassembler.parsers.AuditdParser._
        import spark.implicits._

        val udfExtract = udf(extract)
        val udfTimeStamp = udf(extractTimestamp)
        val udfExtractId = udf(extractId)
        val udfFlatRaw = udf(flatRaw)
        val udfAddChain = udf(addChain)

        val parser = udf((value: String) => {
            Try(RawMessageParser.parse(value)) match {
                case Success(result) =>
                    (None, Some(result))
                case Failure(exception) =>
                    (Some(ParserError(value, ExceptionUtils.getStackTrace(exception))), None)
            }
        })

        def createRawId(raw: String): String =
            RipeMD160(raw)

        val error = udf((message: String, stackTrace: String) => {
            val rawId = createRawId(message)
            ErrorEvent(rawId, message, stackTrace).toByteArray
        })

        val metrics: ReassemblerMetrics = MetricsAgent.inception(new ReassemblerMetrics(_, conf.metricSystemNamespace))

        spark.streams.addListener(new StreamingQueryListener() {
            override def onQueryStarted(event: StreamingQueryListener.QueryStartedEvent): Unit = {}

            override def onQueryProgress(event: StreamingQueryListener.QueryProgressEvent): Unit = {
                import scala.collection.JavaConversions._
                metrics.updateClientStats(
                    event.progress.durationMs.filter(m => m._1 != "getBatch" && m._1 != "addBatch").map(_._2.toLong).sum,
                    event.progress.stateOperators.map(_.numRowsUpdated).sum,
                    event.progress.durationMs.find(_._1 == "getBatch").map(_._2.toLong).getOrElse(0L),
                    event.progress.durationMs.find(_._1 == "addBatch").map(_._2.toLong).getOrElse(0L),
                    event.progress.stateOperators.map(_.memoryUsedBytes).sum
                )
            }

            override def onQueryTerminated(event: StreamingQueryListener.QueryTerminatedEvent): Unit = {}
        })

        val source = spark
            .readStream
            .format("kafka")
            .option("kafka.bootstrap.servers", conf.kafkaInputProperties.get("bootstrap.servers").mkString(","))
            .option("subscribe", conf.kafkaInputTopics.mkString(","))
            .options(conf.kafkaInputProperties.get("security.protocol").map(value => "kafka.security.protocol" -> s"$value").toMap)
            .options(conf.kafkaInputProperties.get("sasl.kerberos.service.name").map(value => "kafka.sasl.kerberos.service.name" -> s"$value").toMap)
            .load()
            .selectExpr("CAST(value AS STRING)")
            .withColumn("value", parser($"value"))


        val success = source
            .filter("value._1 is null")
            .select($"value._2.*")

        success
            .withColumn("parsed", udfExtract($"raw"))
            // Extract AuditD event timestamp (String)
            .withColumn("a_timestamp", udfTimeStamp($"parsed"))
            // Extract AuditD event ID (String)
            .withColumn("a_id", udfExtractId($"parsed"))
            // Filter out all event without timestamp and ID, because we can't aggregate it
            .filter(s"a_id != '$failureParsing' and a_timestamp != '$failureParsing'")
            // Parse timestamp string to Timestamp type for future aggregation
            .withColumn("EventTimestamp", from_unixtime($"a_timestamp").cast(TimestampType))
            // Collect events to
            .withWatermark("EventTimestamp", "1 minutes")
            // Group incoming event by (Organization, MessageSourceAddress, AuditdMessageId)
            .groupBy(
                window($"EventTimestamp", "30 seconds"),
                $"OrgID",
                $"MessageSourceAddress",
                $"a_id"
            )
            // Take values from first event for all fields except `raw` (because we need concatenate it)
            .agg(
                first($"EventTimestamp") as "EventTimestamp",
                first($"EventReceivedTime") as "EventReceivedTime",
                first($"chain") as "chain",
                first($"EventTime") as "EventTime",
                first($"Hostname") as "Hostname",
                first($"SourceName") as "SourceName",
                first($"DevCat") as "DevCat",
                first($"DevSubCat") as "DevSubCat",
                first($"DevType") as "DevType",
                first($"Organization") as "Organization",
                collect_set($"raw") as "raw",
                first($"a_id") as "a_id"
            )
            // Add correct DevType and missing fields to event
            .withColumn("DevType", lit("reassembledAuditD01"))
            .withColumn("SeverityValue", lit(0))
            .withColumn("Severity", lit("unknown"))
            // Create result event from collected columns (to_json + struct), also flat Seq[Raw] to String (udfFlatRaw)
            // Add chain information to result as a JSON object by call `udfAddChain`, because Spark `to_json` output is Map[String, String]
            // and it completely broke `chain` JSON to string
            .select(
                udfAddChain(
                    to_json(
                        struct(
                            $"EventReceivedTime",
                            $"MessageSourceAddress",
                            $"EventTime",
                            $"Hostname",
                            $"SourceName",
                            $"DevCat",
                            $"DevSubCat",
                            $"DevType",
                            $"Organization",
                            $"OrgID",
                            $"SeverityValue",
                            $"Severity",
                            udfFlatRaw($"raw") as "raw"
                        )
                    ),
                    $"chain"
                ) as "value"
            )
            .writeStream
            .format("kafka")
            .option("kafka.bootstrap.servers", conf.kafkaOutputProperties.get("bootstrap.servers").mkString(","))
            .options(conf.kafkaOutputProperties.get("security.protocol").map(value => "kafka.security.protocol" -> s"$value").toMap)
            .options(conf.kafkaOutputProperties.get("sasl.kerberos.service.name").map(value => "kafka.sasl.kerberos.service.name" -> s"$value").toMap)
            .option("topic", conf.kafkaTopicMappings.get("reassembled").mkString(","))
            .start()
            .awaitTermination()

        source.filter("value._2 is null")
            .select($"value._1.*")
            .withColumn("value", error($"message", $"stackTrace"))
            .writeStream
            .format("kafka")
            .option("kafka.bootstrap.servers", conf.kafkaOutputProperties.get("bootstrap.servers").mkString(","))
            .options(conf.kafkaOutputProperties.get("security.protocol").map(value => "kafka.security.protocol" -> s"$value").toMap)
            .options(conf.kafkaOutputProperties.get("sasl.kerberos.service.name").map(value => "kafka.sasl.kerberos.service.name" -> s"$value").toMap)
            .option("topic", conf.kafkaTopicMappings.get("error").mkString(","))
            .start()
            .awaitTermination()

        ctx.start()
        ctx.awaitTermination()
    }
}