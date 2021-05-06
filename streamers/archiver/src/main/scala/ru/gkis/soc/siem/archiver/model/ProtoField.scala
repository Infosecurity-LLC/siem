package ru.gkis.soc.siem.archiver.model

import org.apache.spark.sql.types.DataType
import ru.gkis.soc.siem.archiver.AnyLens

import scala.language.existentials

case class ProtoField(accessor: AnyLens[_], sqlType: DataType)