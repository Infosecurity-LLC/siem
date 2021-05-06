package ru.gkis.soc.siem.io

import com.google.protobuf.v39.wrappers.WrappersProto
import scalapb.GeneratedMessage
import scalapb.descriptors._
import scalapb.lenses.Lens

package object elastic {

    type UntypedMap = Map[String, Any]

    implicit class ProtoToMap(gm: GeneratedMessage) {

        import scala.collection.JavaConversions._

        // build default protobuf wrappers set to check if we need to unwrap them
        private val wrappers = WrappersProto.scalaDescriptor.messages.map(_.fullName).toSet

        private def handleMessages(fd: FieldDescriptor, msg: PMessage): Option[(String, Any)] = {
            val descriptor = fd.scalaType.asInstanceOf[ScalaType.Message].descriptor
            if (wrappers.contains(descriptor.fullName)) {
                // wrappers always have only one field - "value". this code logic relies on it
                extract(fd)(msg.value.head._2)
            }
            else {
                Some(fd.scalaName -> toMap(msg))
            }
        }

        private def extract(fd: FieldDescriptor): PartialFunction[PValue, Option[(String, Any)]] = {
            case v: PString => Some(fd.scalaName -> v.value)
            case v: PBoolean => Some(fd.scalaName -> v.value)
            case v: PByteString => Some(fd.scalaName -> v.value)
            case v: PDouble => Some(fd.scalaName -> v.value)
            case    PEmpty => None
            case v: PEnum => Some(fd.scalaName -> v.value.name)
            case v: PFloat => Some(fd.scalaName -> v.value)
            case v: PLong => Some(fd.scalaName -> v.value)
            case v: PRepeated => Some(fd.scalaName -> v.value.flatMap(el => extract(fd)(el)).map(_._2))
            case v: PInt => Some(fd.scalaName -> v.value)
            case v: PMessage => handleMessages(fd, v)
        }

        private def toMap(gm: PMessage): Map[String, Any] = {
            gm
                .value
                .flatMap {
                    case (fd, value) => extract(fd)(value)
                }
        }

        def toMap: Map[String, Any] = toMap(gm.toPMessage)

    }

    def objectLens(field: String): Lens[UntypedMap, UntypedMap] = Lens[UntypedMap, UntypedMap](_(field).asInstanceOf[UntypedMap])((c, p) => c + (field -> p))
    def longValueLens(field: String): Lens[UntypedMap, Long] = Lens[UntypedMap, Long](_(field).asInstanceOf[Long])((c, p) => c + (field -> p))
    def stringValueLens(field: String): Lens[UntypedMap, String] = Lens[UntypedMap, String](_(field).asInstanceOf[String])((c, p) => c + (field -> p))
    def untypedValueLens(field: String): Lens[UntypedMap, Any] = Lens[UntypedMap, Any](_(field))((c, p) => c + (field -> p))

}
