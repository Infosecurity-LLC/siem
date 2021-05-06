package ru.gkis.soc.siem.archiver.dsl

import java.nio.charset.StandardCharsets

import org.apache.hadoop.hbase.client.Result
import org.apache.hadoop.hbase.io.ImmutableBytesWritable
import org.apache.spark.broadcast.Broadcast
import org.apache.spark.rdd.RDD
import org.apache.spark.sql.Row
import ru.gkis.soc.siem.archiver.SchemaProvider
import ru.gkis.soc.siem.io.hbase.HBaseInputConfig

trait RowConverter {

    private lazy val schemaProvider = new SchemaProvider

    implicit class RowConverter(rdd: RDD[(ImmutableBytesWritable, Result)]) extends Serializable {

        private def extractBytes(row: Result, column: Array[Byte], columnFamily: Array[Byte]): Array[Byte] = {
            val cell = row.getColumnLatestCell(columnFamily, column)
            cell.getValueArray.slice(cell.getValueOffset, cell.getValueOffset + cell.getValueLength)
        }

        def toDataframeRows(from: Long, to: Long, conf: Broadcast[HBaseInputConfig]): RDD[Row] = {
            val eventType = conf.value.eventType
            val eventColumn = conf.value.eventColumn
            val columnFamily = conf.value.columnFamily.getBytes(StandardCharsets.UTF_8)

            rdd.mapPartitions(
                _.filter {  // filter out all entries within execution day
                    case (_, row) =>
                        Option(row.getColumnLatestCell(columnFamily, eventColumn)) match {
                            case Some(value) =>
                                val time = value.getTimestamp
                                from <= time && time <= to
                            case None => false
                        }
                    }
                .map {  // convert events to Dataframe rows with schema
                    case (_, row) =>
                        val evt = eventType.parseFrom(extractBytes(row, eventColumn, columnFamily))
                        schemaProvider.schemaToRow(evt, conf)
                },
                preservesPartitioning = true
            )
        }

    }

}
