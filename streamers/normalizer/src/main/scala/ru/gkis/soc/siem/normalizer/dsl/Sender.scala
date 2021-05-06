package ru.gkis.soc.siem.normalizer.dsl

import org.apache.spark.broadcast.Broadcast
import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.io.kafka._
import ru.gkis.soc.siem.kafka.KafkaFuture
import ru.gkis.soc.siem.normalizer._
import scalapb.GeneratedMessage

import scala.concurrent.{Await, Future}
import scala.util.{Failure, Success}

trait Sender {

    private lazy val prod = new ProducerProvider[FinalStates.State, GeneratedMessage]

    implicit class Sender(rdd: RDD[Statistical]) extends Serializable {

        import scala.concurrent.ExecutionContext.Implicits.global

        private def sendInternal(it: Iterator[Statistical], appConf: KafkaOutputConfig): (List[Statistical], List[Option[KafkaFuture]]) =
            it
                .map {
                    case evt: NormalizedSocEvent =>
                        evt -> Some(prod.getProducer(evt.state, appConf.kafkaOutputProperties, appConf.kafkaTopicMappings)(None, evt.normalized))
                    case evt: NormalizedRawEvent =>
                        evt -> Some(prod.getProducer(evt.state, appConf.kafkaOutputProperties, appConf.kafkaTopicMappings)(None, evt.normalized))
                    case evt: NormalizedChainEvent =>
                        evt -> Some(prod.getProducer(evt.state, appConf.kafkaOutputProperties, appConf.kafkaTopicMappings)(None, evt.normalized))
                    case evt: NormalizedInvalidEvent =>
                        evt -> Some(prod.getProducer(evt.state, appConf.kafkaOutputProperties, appConf.kafkaTopicMappings)(None, evt.normalized))
                    case evt: NormalizedErrorEvent =>
                        evt -> Some(prod.getProducer(evt.state, appConf.kafkaOutputProperties, appConf.kafkaTopicMappings)(None, evt.normalized))
                    case stats: Statistics =>
                        stats -> None
                }
                .toList
                .unzip

        private def processSent(futures: List[KafkaFuture]): Unit =
            futures.foreach(_.onComplete {
                                    case Success(meta) => meta
                                    case Failure(ex) => throw new RuntimeException("Could not send data to Kafka", ex)
                                }
                            )

        def send(appConf: Broadcast[_ <: KafkaOutputConfig]): RDD[Statistical] = {
            rdd
                .mapPartitions(it => {
                    // trigger all previous transformations
                    val (events, options) = sendInternal(it, appConf.value)

                    // wait for all messages to be sent
                    val futures = options.flatten
                    Await.ready(Future.sequence(futures), appConf.value.kafkaWriteTimeout)

                    // check status (if something goes wrong this throws RuntimeException)
                    processSent(futures)

                    // proceed with original events list
                    events.iterator
                }, preservesPartitioning = true)
        }

    }

}
