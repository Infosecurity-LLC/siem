package ru.gkis.soc.siem.io.kafka

import org.apache.kafka.clients.producer.{Callback, ProducerRecord, RecordMetadata}
import ru.gkis.soc.siem.commons.Provider
import ru.gkis.soc.siem.kafka.{Producer, Sender}

import scala.concurrent.Promise
import scala.util.{Failure, Success}

class ProducerProvider[K, V: ByteSerialized] extends Provider[ProducerKey, Producer[V]] with Serializable {

    import scala.collection.JavaConversions._

    private def failOnTopicAbsent(id: String): String = {
        throw new RuntimeException(s"Config does not have kafka topic mapping for id $id")
    }

    private def producerCallback(promise: Promise[RecordMetadata]): Callback = {
        new Callback {
            override def onCompletion(metadata: RecordMetadata, exception: Exception): Unit = {
                val result = if (exception == null) Success(metadata) else Failure(exception)
                promise.complete(result)
            }
        }
    }

    def getProducer(id: K, producerConfig: Map[String, AnyRef], mappings: Map[String, String]): Sender[V] = {
        val strId = id.toString.toLowerCase()
        val topic = mappings.getOrElse(strId, failOnTopicAbsent(strId))
        val producer = get(ProducerKey(conf = producerConfig), spawn)

        (key: Option[String], value: V) => {
            val promise = Promise[RecordMetadata]()
            producer.send(new ProducerRecord(topic, key, value), producerCallback(promise))
            promise.future
        }
    }

    private def spawn: PartialFunction[ProducerKey, Producer[V]] = {
        case ProducerKey("default", producerConfig) => new Producer(producerConfig, new KeySerializer, new ValueSerializer)
    }

}
