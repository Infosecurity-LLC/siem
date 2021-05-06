package ru.gkis.soc.siem.enricher.dsl

import org.apache.spark.broadcast.Broadcast
import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.enricher.{InternalSocEvent, InternalStatistics, Split}
import ru.gkis.soc.siem.io.kafka.{KafkaOutputConfig, ProducerProvider}
import ru.gkis.soc.siem.kafka.KafkaFuture
import scalapb.GeneratedMessage

import scala.concurrent.{Await, Future}
import scala.util.{Failure, Success}

trait Sender {

    sealed trait Enriched

    case object Enriched extends Enriched

    private lazy val prod = new ProducerProvider[Enriched, GeneratedMessage]

    implicit class Sender(rdd: RDD[Split]) extends Serializable {

        import scala.concurrent.ExecutionContext.Implicits.global

        private def sendInternal(it: Iterator[Split], cfg: KafkaOutputConfig) =
            it
                .map {
                    case InternalSocEvent(event) =>
                        None -> Some(prod.getProducer(Enriched, cfg.kafkaOutputProperties, cfg.kafkaTopicMappings)(None, event))
                    case is: InternalStatistics =>
                        Some(is) -> None
                }
                .toList
                .unzip


        private def processSent(futures: List[KafkaFuture]): Unit =
            futures.foreach(_.onComplete {
                case Success(meta) => meta
                case Failure(ex) => throw new RuntimeException("Could not send data to Kafka", ex)
            })

        def send(cfg: Broadcast[_ <: KafkaOutputConfig]): RDD[InternalStatistics] = {
            rdd.mapPartitions(it => {
                // trigger all previous transformations
                val (events, option) = sendInternal(it, cfg.value)

                val futures = option.flatten
                // wait for all messages to be sent
                Await.ready(Future.sequence(futures), cfg.value.kafkaWriteTimeout)

                // check status (if something goes wrong this throws RuntimeException)
                processSent(futures)

                // proceed with original events list
                events.flatten.iterator
            },
                preservesPartitioning = true
            )
        }
    }

}
