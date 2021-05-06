package ru.gkis.soc.siem.filter.dsl

import org.apache.spark.broadcast.Broadcast
import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.filter.{Event, Split, Statistic}
import ru.gkis.soc.siem.io.kafka.{KafkaOutputConfig, ProducerProvider}
import ru.gkis.soc.siem.kafka.KafkaFuture

import scala.concurrent.{Await, Future}
import scala.util.{Failure, Success}

trait Sender {

    sealed trait Filtered

    case object Filtered extends Filtered

    private lazy val prod = new ProducerProvider[Filtered, String]

    implicit class Sender(rdd: RDD[Split]) extends Serializable {

        import scala.concurrent.ExecutionContext.Implicits.global

        private def sendInternal(it: Iterator[Split], cfg: KafkaOutputConfig) =
            it.map {
                case Event(event) => None -> Some(prod.getProducer(Filtered, cfg.kafkaOutputProperties, cfg.kafkaTopicMappings)(None, event))
                case s@Statistic(_, _) => Some(s) -> None
            }.toList.unzip


        private def processSent(futures: List[KafkaFuture]): Unit =
            futures.foreach(_.onComplete {
                case Success(meta) => meta
                case Failure(ex) => throw new RuntimeException("Could not send data to Kafka", ex)
            })

        def send(cfg: Broadcast[_ <: KafkaOutputConfig]): RDD[Statistic] = {
            rdd.mapPartitions(it => {
                // trigger all previous transformations
                val (stats, events) = sendInternal(it, cfg.value)

                val futures = events.flatten

                // wait for all messages to be sent
                Await.ready(Future.sequence(futures), cfg.value.kafkaWriteTimeout)

                // check status (if something goes wrong this throws RuntimeException)
                processSent(futures)

                stats.flatten.iterator
            }, preservesPartitioning = true)
        }
    }

}
