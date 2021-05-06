package ru.gkis.soc.siem.io.hbase

import java.util

import ru.gkis.soc.siem.model.{ChainEvent, RawEvent, SocEvent}
import scalapb.descriptors.Descriptor
import collection.JavaConverters._

trait HBaseInputConfig extends HBaseConfig {

    val outputDir: String = appConf.getString("app.archiver.outputDir")

    val hbaseTable: String = basic.getString("table.name")
    val eventType = basic.getString("table.eventType") match {
        case "SocEvent" => SocEvent
        case "RawEvent" => RawEvent
        case "ChainEvent" => ChainEvent
        case _ => throw new IllegalArgumentException("Unknown event type")
    }

    val partitionColumnOrg: String = basic.getString("table.partitionColumns.org")

    val partitionColumnDate: String = basic.getString("table.partitionColumns.date")
}
