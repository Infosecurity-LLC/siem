package ru.gkis.soc.siem.filter.dsl

import org.apache.spark.broadcast.Broadcast
import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.io.kafka.{KafkaOutputConfig, ProducerProvider}
import ru.gkis.soc.siem.kafka.KafkaFuture

import scala.concurrent.{Await, Future}
import scala.util.{Failure, Success}

trait UnmodifiedSender {

    sealed trait Plain

    case object Plain extends Plain

    private lazy val prod = new ProducerProvider[Plain, String]

    implicit class UnmodifiedSender(rdd: RDD[String]) extends Serializable {

        import scala.concurrent.ExecutionContext.Implicits.global

        private def sendInternal(it: Iterator[String], cfg: KafkaOutputConfig) =
            it.map { evt => prod.getProducer(Plain, cfg.kafkaOutputProperties, cfg.kafkaTopicMappings)(None, evt) }


        private def processSent(futures: List[KafkaFuture]): Unit =
            futures.foreach(_.onComplete {
                case Success(meta) => meta
                case Failure(ex) => throw new RuntimeException("Could not send data to Kafka", ex)
            })

        def send(cfg: Broadcast[_ <: KafkaOutputConfig]): Unit = {
            rdd.foreachPartition(it => {
                // trigger all previous transformations
                val events = sendInternal(it, cfg.value)

                // wait for all messages to be sent
                Await.ready(Future.sequence(events), cfg.value.kafkaWriteTimeout)

                // check status (if something goes wrong this throws RuntimeException)
                processSent(events.toList)

            })
        }
    }

}
