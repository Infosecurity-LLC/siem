package ru.gkis.soc.siem.archiver

import com.google.protobuf.v39.WrappersProto
import org.apache.spark.sql.types.{DataType, DataTypes}
import ru.gkis.soc.siem.archiver.model.ProtoField
import scalapb.descriptors._

object ProtoSchema extends Serializable {

    import scala.collection.JavaConversions._

    private val separator = "_"
    private val wrappers = WrappersProto.getDescriptor.getMessageTypes.map(_.getFullName).toSet

    private def handleMessage(fd: FieldDescriptor, path: Vector[FieldDescriptor]): Vector[(String, ProtoField)] = {
        if (fd.isRepeated) {
            Vector(guessType(fd, path))
        }
        else
            fd.scalaType match {
                case m: ScalaType.Message =>
                    if (wrappers.contains(m.descriptor.fullName))
                        Vector(guessType(fd, path))
                    else
                        flattenInternal(m.descriptor, path)
                case _ =>
                    Vector(guessType(fd, path))
            }
    }

    private def createAccessor(path: Vector[FieldDescriptor], finale: FieldDescriptor => AnyLens[_], isRepeated: Boolean): AnyLens[_] =
        path.dropRight(1).foldRight(if (isRepeated) seqLens(path.last).asInstanceOf[AnyLens[_]] else finale(path.last))((fd, l) =>  objectLens(fd) compose l)

    private def createType(elementType: DataType, isRepeated: Boolean): DataType =
        if (isRepeated) DataTypes.createArrayType(elementType) else elementType

    private def guessType(fd: FieldDescriptor, path: Vector[FieldDescriptor]): (String, ProtoField) = {
        val field = fd.scalaType match {
            case ScalaType.String     => ProtoField(createAccessor(path, stringLens,     fd.isRepeated), createType(DataTypes.StringType,  fd.isRepeated))
            case ScalaType.Boolean    => ProtoField(createAccessor(path, booleanLens,    fd.isRepeated), createType(DataTypes.BooleanType, fd.isRepeated))
            case ScalaType.ByteString => ProtoField(createAccessor(path, byteStringLens, fd.isRepeated), createType(DataTypes.ByteType,    fd.isRepeated))
            case ScalaType.Double     => ProtoField(createAccessor(path, doubleLens,     fd.isRepeated), createType(DataTypes.DoubleType,  fd.isRepeated))
            case ScalaType.Float      => ProtoField(createAccessor(path, floatLens,      fd.isRepeated), createType(DataTypes.FloatType,   fd.isRepeated))
            case ScalaType.Long       => ProtoField(createAccessor(path, longLens,       fd.isRepeated), createType(DataTypes.LongType,    fd.isRepeated))
            case ScalaType.Int        => ProtoField(createAccessor(path, intLens,        fd.isRepeated), createType(DataTypes.IntegerType, fd.isRepeated))
            case _: ScalaType.Enum    => ProtoField(createAccessor(path, enumLens,       fd.isRepeated), createType(DataTypes.StringType,  fd.isRepeated))
            case msg: ScalaType.Message => // this is for wrappers
                val valueField: FieldDescriptor = msg.descriptor.fields.head // this code relies on a fact that any protobuf wrapper has only one field - 'value'
                val guessed = guessType(valueField,  Vector(valueField))
                ProtoField(createAccessor(path, (fd: FieldDescriptor) => objectLens(fd).compose(guessed._2.accessor), fd.isRepeated), createType(guessed._2.sqlType,  fd.isRepeated))
        }
        path.map(_.name).mkString(separator) -> field
    }

    private def flattenInternal(desc: Descriptor, path: Vector[FieldDescriptor]): Vector[(String, ProtoField)] = {
        desc
            .fields
            .map(fd => handleMessage(fd, path :+ fd))
            .foldLeft(Vector.empty[(String, ProtoField)])((acc, m) => acc ++ m)
    }

    def apply(desc: Descriptor): Vector[(String, ProtoField)] = flattenInternal(desc, Vector.empty[FieldDescriptor])

}
