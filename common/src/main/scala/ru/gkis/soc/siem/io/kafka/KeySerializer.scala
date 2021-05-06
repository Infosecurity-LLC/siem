package ru.gkis.soc.siem.io.kafka

import java.nio.charset.StandardCharsets
import java.util

import org.apache.kafka.common.serialization.Serializer

class KeySerializer extends Serializer[Option[String]] {

    override def configure(configs: util.Map[String, _], isKey: Boolean): Unit = {}

    override def serialize(topic: String, data: Option[String]): Array[Byte] = data match {
        case Some(value) => value.getBytes(StandardCharsets.UTF_8)
        case None => null
    }

    override def close(): Unit = {}

}
