package ru.gkis.soc.siem.io.kafka

import java.util

import org.apache.kafka.common.serialization.Serializer

class ValueSerializer[V: ByteSerialized] extends Serializer[V] {

    import ByteSerialized.ops._

    override def configure(configs: util.Map[String, _], isKey: Boolean): Unit = {}

    override def serialize(topic: String, data: V): Array[Byte] = data.toByteArray

    override def close(): Unit = {}

}
