package ru.gkis.soc.siem.archiver

import java.util.Date
import java.util.concurrent.atomic.AtomicLong

import org.apache.spark.broadcast.Broadcast
import org.apache.spark.sql.Row
import ru.gkis.soc.siem.archiver.model.ProtoField
import ru.gkis.soc.siem.commons.Provider
import ru.gkis.soc.siem.io.hbase.HBaseInputConfig
import scalapb.GeneratedMessage

class SchemaProvider extends Provider[String, Vector[(String, ProtoField)]] with Serializable {

    def schemaToRow(evt: GeneratedMessage, conf: Broadcast[HBaseInputConfig]): Row = {
        val schema = get("schema", _ => spawn(conf.value))
        Row.fromSeq(schema.map(_._2.accessor.get(Option(evt)).fold(null.asInstanceOf[Any])(identity)))
    }

    private def spawn(conf: HBaseInputConfig) = ProtoSchema(conf.eventType.scalaDescriptor)

}
