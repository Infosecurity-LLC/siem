package ru.gkis.soc.siem.io.kafka

import java.util

import org.apache.kafka.common.serialization.Deserializer
import ru.gkis.soc.siem.model.SocEvent

class NormalizedDeserializer extends Deserializer[SocEvent] {

    override def configure(configs: util.Map[String, _], isKey: Boolean): Unit = {}

    override def deserialize(topic: String, data: Array[Byte]): SocEvent = SocEvent.parseFrom(data)

    override def close(): Unit = {}

}
