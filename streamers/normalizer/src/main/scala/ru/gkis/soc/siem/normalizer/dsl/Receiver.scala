package ru.gkis.soc.siem.normalizer.dsl

import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.normalizer.{KafkaRecord, RawMessage}

trait Receiver {

    implicit class KafkaReceiver(rdd: RDD[ConsumerRecord[String, String]]) {

        def receive: RDD[KafkaRecord] = rdd.map(r => RawMessage(Option(r.key()), r.value()))

    }

}
