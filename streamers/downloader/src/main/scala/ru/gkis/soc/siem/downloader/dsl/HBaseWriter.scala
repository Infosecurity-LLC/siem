package ru.gkis.soc.siem.downloader.dsl

import java.nio.charset.StandardCharsets

import org.apache.spark.broadcast.Broadcast
import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.io.hbase.{HBaseMutator, HBaseOutputConfig, MutatorProvider}
import ru.gkis.soc.siem.model.{ChainEvent, RawEvent, SocEvent}
import scalapb.GeneratedMessage

trait HBaseWriter {

    private lazy val provider = new MutatorProvider

    implicit class HBaseWriter(rdd: RDD[GeneratedMessage]) extends Serializable {

        private def longToBytes(value: Long): Array[Byte] = {
            Array(
                (value      ).toByte,
                (value >>  8).toByte,
                (value >> 16).toByte,
                (value >> 24).toByte,
                (value >> 32).toByte,
                (value >> 40).toByte,
                (value >> 48).toByte,
                (value >> 56).toByte
            )
        }

        private def writeRow(writer: HBaseMutator, id: String, organization: String, time: Long, evt: GeneratedMessage, conf: HBaseOutputConfig): Unit = {
            val org = organization.getBytes(StandardCharsets.UTF_8)
            val timestamp = longToBytes(time)
            writer.put(id, conf.organizationColumn -> org, conf.timeColumn -> timestamp, conf.eventColumn -> evt.toByteArray)
        }

        def write(conf: Broadcast[HBaseOutputConfig]): RDD[GeneratedMessage] = {
            rdd.mapPartitions(it => {
                // we should create a new mutator for every batch, cause it creates a single future for the whole operation set
                val socEventWriter   = provider.createMutator(SocEvent, conf.value)
                val rawEventWriter   = provider.createMutator(RawEvent, conf.value)
                val chainEventWriter = provider.createMutator(ChainEvent, conf.value)
                val events = it.map {
                    case evt: SocEvent =>
                        writeRow(socEventWriter, evt.id, evt.getCollector.organization, evt.getData.time, evt, conf.value)
                        evt
                    case evt: RawEvent =>
                        writeRow(rawEventWriter, evt.id, evt.getCollector.organization, evt.eventTime, evt, conf.value)
                        evt
                    case evt: ChainEvent =>
                        writeRow(chainEventWriter, evt.rawId, evt.getCollector.organization, evt.eventTime, evt, conf.value)
                        evt
                }.toList

                socEventWriter.close
                rawEventWriter.close
                chainEventWriter.close

                events.iterator
            }, preservesPartitioning = true)
        }
    }

}
