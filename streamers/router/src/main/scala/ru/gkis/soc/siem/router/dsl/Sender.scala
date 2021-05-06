package ru.gkis.soc.siem.router.dsl

import org.apache.kafka.clients.producer.RecordMetadata
import org.apache.spark.broadcast.Broadcast
import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.io.kafka.{KafkaOutputConfig, ProducerProvider}
import ru.gkis.soc.siem.router.RouterConfig
import ru.gkis.soc.siem.router.dsl.model.{ParsedMessage, Statistics}

import scala.concurrent.{Await, Future}
import scala.util.{Failure, Success, Try}

trait Sender {

    sealed trait Enriched

    case object Enriched extends Enriched

    private lazy val prod = new ProducerProvider[String, String]

    implicit class Sender(rdd: RDD[ParsedMessage]) extends Serializable {

        import scala.concurrent.ExecutionContext.Implicits.global

        /**
         * Try get topic mapping buy DevType with fallback to "any" == * mapping otherwise skip that message
         */
        private def topicMappingKey(org: String, devType: String, cfg: KafkaOutputConfig): Option[String] = {
            if (cfg.kafkaTopicMappings.contains(s"$org.$devType")) {
                Some(s"$org.$devType")
            } else {
                Some(s"$org.any").filter(cfg.kafkaTopicMappings.contains)
            }
        }

        private def sendInternal(it: Iterator[ParsedMessage],
                                 cfg: KafkaOutputConfig with RouterConfig): (List[Option[ParsedMessage]], List[Option[Future[RecordMetadata]]]) = {
            it
                .map {
                    case msg: ParsedMessage if cfg.dropDevTypes.contains(msg.devType) =>
                        None -> None
                    case msg: ParsedMessage if cfg.kafkaTopicMappings.contains(msg.devType) =>
                        None -> Some(prod.getProducer(msg.devType, cfg.kafkaOutputProperties, cfg.kafkaTopicMappings)(msg.key, msg.raw))
                    case msg: ParsedMessage if cfg.kafkaTopicMappings.contains(s"${msg.org}.${msg.devType}") =>
                        None -> Some(prod.getProducer(s"${msg.org}.${msg.devType}", cfg.kafkaOutputProperties, cfg.kafkaTopicMappings)(msg.key, msg.raw))
                    case msg: ParsedMessage if cfg.kafkaTopicMappings.contains(s"${msg.org}.any") =>
                        None -> Some(prod.getProducer(s"${msg.org}.any", cfg.kafkaOutputProperties, cfg.kafkaTopicMappings)(msg.key, msg.raw))
                    case msg =>
                        Some(msg) -> None
                }
                .toList
                .unzip
        }

        private def sendGarbage(it: List[ParsedMessage],
                                cfg: KafkaOutputConfig): List[Future[RecordMetadata]] = {
            it.map {
                case ParsedMessage(key, _, _, raw) =>
                    prod.getProducer("garbage", cfg.kafkaOutputProperties, cfg.kafkaTopicMappings)(key, raw)
            }
        }

        def send(cfg: Broadcast[KafkaOutputConfig with RouterConfig]): RDD[Statistics] = {
            rdd.mapPartitions(it => {
                // Send messages by topics
                val (notMapped, sent) = sendInternal(it, cfg.value)

                val sentFutures = sent.flatten

                val metadata: List[RecordMetadata] = Try(Await.result(Future.sequence(sentFutures), cfg.value.kafkaWriteTimeout)) match {
                    case Success(value) =>
                        value
                    case Failure(ex) =>
                        throw new RuntimeException("Could not send data to Kafka", ex)
                }

                val sentResult: Map[String, Int] = metadata.map(_.topic).groupBy(identity).map {
                    case (k, v) =>
                        (k, v.size)
                }
                val garbagePortion: Int = (notMapped.flatten.size.toDouble / 100.0 * cfg.value.garbagePercentage.toDouble).toInt

                val garbage: List[RecordMetadata] = Try(Await.result(Future.sequence(sendGarbage(notMapped.flatten.take(garbagePortion), cfg.value)), cfg.value.kafkaWriteTimeout)) match {
                    case Success(value) =>
                        value
                    case Failure(ex) =>
                        throw new RuntimeException("Could not send data to Kafka", ex)
                }

                // Return information for Grafana
                val total = sentFutures.size + notMapped.flatten.size
                val result = Iterator.single(
                    Statistics(
                        total = total,
                        garbage = garbage.size,
                        skipped = total - garbage.size - sentFutures.size,
                        sent = sentResult
                    )
                )

                result
            },
                preservesPartitioning = true
            )
        }
    }

}
