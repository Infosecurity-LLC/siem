package ru.gkis.soc.siem

import org.apache.kafka.clients.producer.{KafkaProducer, RecordMetadata}
import scalapb.GeneratedMessage

import scala.concurrent.Future

package object kafka {

    type Producer[V] = KafkaProducer[Option[String], V]
    type Sender[V] = (Option[String], V) => Future[RecordMetadata]
    type KafkaFuture = Future[RecordMetadata]

}
