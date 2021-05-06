package ru.gkis.soc.siem.io.kafka

import scalapb.GeneratedMessage

trait ByteSerialized[V] extends Serializable {
    def toByteArray(data: V): Array[Byte]
}

object ByteSerialized {

    def apply[V](implicit bs: ByteSerialized[V]): ByteSerialized[V] = bs

    def toByteArray[V: ByteSerialized](data: V): Array[Byte] = ByteSerialized[V].toByteArray(data)

    implicit val generatedMessageByteArray: ByteSerialized[GeneratedMessage] = new ByteSerialized[GeneratedMessage] {
        override def toByteArray(data: GeneratedMessage): Array[Byte] = data.toByteArray
    }

    implicit val stringByteArray: ByteSerialized[String] = new ByteSerialized[String] {
        override def toByteArray(data: String): Array[Byte] = data.getBytes
    }

    object ops {

        implicit class ByteSerializedOps[V](val data: V) extends AnyVal {
            def toByteArray(implicit bs: ByteSerialized[V]): Array[Byte] = bs.toByteArray(data)
        }

    }

}
