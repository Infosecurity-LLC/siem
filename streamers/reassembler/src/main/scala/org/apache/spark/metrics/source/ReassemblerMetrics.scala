package org.apache.spark.metrics.source

import com.codahale.metrics.MetricRegistry

class ReassemblerMetrics(registry: MetricRegistry, metricSystemNamespace: String) extends Metrics {
    override val sourceName: String = "ReassemblerMetrics"

    override val metricRegistry: MetricRegistry = registry

    def updateClientStats(processingTime: Long, processedCount: Long, readDelay: Long, writeDelay: Long, memoryUsedBytes: Long): Unit = {
        set(s"$metricSystemNamespace.${sourceName}.reassembler.events.processed.time", processingTime)
        set(s"$metricSystemNamespace.${sourceName}.reassembler.events.processed.count", processedCount)
        add(s"$metricSystemNamespace.${sourceName}.reassembler.events.processed.total", processedCount)
        set(s"$metricSystemNamespace.${sourceName}.reassembler.readDelay", readDelay)
        set(s"$metricSystemNamespace.${sourceName}.reassembler.writeDelay", writeDelay)
        set(s"$metricSystemNamespace.${sourceName}.reassembler.memoryUsedBytes", memoryUsedBytes)
    }
}