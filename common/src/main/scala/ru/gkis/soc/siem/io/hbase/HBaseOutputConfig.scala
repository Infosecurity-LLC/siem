package ru.gkis.soc.siem.io.hbase

import ru.gkis.soc.siem.model.{ChainEvent, RawEvent, SocEvent}

import scala.concurrent.duration.Duration

trait HBaseOutputConfig extends HBaseConfig {

    import scala.compat.java8.DurationConverters._

    val hbaseConnectionParallelism: Int = basic.getInt("connection.parallelism")
    val hbaseWriteTimeout: Duration = basic.getDuration("write.timeout").toScala

    val socEventMapping = new EventTypeConfig(basic.getConfig("table.mappings.soc_event"), SocEvent)
    val rawEventMapping = new EventTypeConfig(basic.getConfig("table.mappings.raw_event"), RawEvent)
    val chainEventMapping = new EventTypeConfig(basic.getConfig("table.mappings.chain_event"), ChainEvent)

}
