package ru.gkis.soc.siem

import com.google.protobuf.v39.ByteString
import com.google.protobuf.v39.descriptor.FieldDescriptorProto.Type._
import scalapb.GeneratedMessage
import scalapb.descriptors._
import scalapb.lenses.Lens

package object archiver {

    type AnyLens[T] = Lens[Option[GeneratedMessage], Option[T]]

    private implicit def messageReads: Reads[PMessage] = Reads {
        case p: PMessage => p
        case other => throw new RuntimeException(s"$other is not a PMessage")
    }

    private implicit def repeatedReads: Reads[PRepeated] = Reads {
        case p: PRepeated => p
        case other => throw new RuntimeException(s"$other is not a PRepeated")
    }

    private def readOnlyException[T]: (Option[GeneratedMessage], Option[T]) => Option[GeneratedMessage] = {
        (_, _) => throw new RuntimeException("This object is read-only!")
    }

    private def extractValue[T](msg: GeneratedMessage, desc: FieldDescriptor): Option[T] = {
        desc.protoType match {
            case TYPE_ENUM if desc.isRepeated =>
                Option(msg.getFieldByNumber(desc.number)).map(_.asInstanceOf[Seq[T]].map(_.toString)).asInstanceOf[Option[T]]
            case TYPE_ENUM =>
                Option(msg.getFieldByNumber(desc.number)).map(_.toString).asInstanceOf[Option[T]]
            case _ =>
                Option(msg.getFieldByNumber(desc.number)).flatMap {
                                                                      case o: Option[_] => o.asInstanceOf[Option[T]]
                                                                      case other: Any => Option(other.asInstanceOf[T])
                                                                  }
        }
    }

    def valueLens[T](desc: FieldDescriptor): AnyLens[T] = Lens[Option[GeneratedMessage], Option[T]](_.fold(Option.empty[T])(extractValue[T](_, desc)))(readOnlyException[T])

    def seqLens[T](desc: FieldDescriptor): AnyLens[Seq[T]] = Lens[Option[GeneratedMessage], Option[Seq[T]]](_.fold(Option.empty[Seq[T]])(extractValue(_, desc)))(readOnlyException[Seq[T]])

    def objectLens(desc: FieldDescriptor): AnyLens[GeneratedMessage] = valueLens(desc)

    def intLens(desc: FieldDescriptor): AnyLens[Int] = valueLens(desc)

    def stringLens(desc: FieldDescriptor): AnyLens[String] = valueLens(desc)

    def booleanLens(desc: FieldDescriptor): AnyLens[Boolean] = valueLens(desc)

    def byteStringLens(desc: FieldDescriptor): AnyLens[ByteString] = valueLens(desc)

    def longLens(desc: FieldDescriptor): AnyLens[Long] = valueLens(desc)

    def doubleLens(desc: FieldDescriptor): AnyLens[Double] = valueLens(desc)

    def floatLens(desc: FieldDescriptor): AnyLens[Float] = valueLens(desc)

    def enumLens(desc: FieldDescriptor): AnyLens[String] = valueLens(desc)

}
