package org.apache.spark.metrics.source

import com.codahale.metrics.MetricRegistry
import org.apache.spark.streaming.kafka010.OffsetRange
import org.apache.spark.{SparkContext, TaskMetrics, TaskStatus}
import ru.gkis.soc.siem.normalizer.Statistics

class NormalizerMetrics(registry: MetricRegistry, metricSystemNamespace: String) extends Metrics {

    override val sourceName: String = "ClientMetrics"
    private val batchStatsName: String = "BatchStats"
    private val inputStatsName: String = "InputStats"

    override val metricRegistry: MetricRegistry = registry

    def updateClientStats(stats: Array[Statistics]): Unit = {
        stats.foreach(fs => {
            add(s"${buildClientStats(fs)}.msgCount", fs.messageCount)
            add(s"${buildClientStats(fs)}.totalBytes", fs.bytesOut)
            add(s"${buildClientStats(fs)}.outOfTime", fs.outOfTime)
        })
    }

    def updateBatchStats(ctx: SparkContext, offsets: Array[OffsetRange]): Unit = {
        val batchStats = TaskMetrics(ctx)
        batchStats.foreach(ts =>
            hist(s"${buildBatchStats(ts)}.executionTime", ts.execTime)
        )
        offsets.foreach(or =>
            hist(s"${buildInputStats(or)}.msgCount", or.untilOffset - or.fromOffset)
        )
    }

    private def buildInputStats(or: OffsetRange): String =
        s"$metricSystemNamespace" +
            s".$inputStatsName" +
            s".${replaceInvalidCharacters(or.topic)}" +
            s".${or.partition}"

    private def buildBatchStats(ts: TaskStatus): String =
        s"$metricSystemNamespace" +
            s".$batchStatsName" +
            s".${replaceInvalidCharacters(ts.host)}" +
            s".${ts.executorId}" +
            s".${replaceInvalidCharacters(ts.stageName)}" +
            s".${ts.taskIndex}"


    private def buildClientStats(sc: Statistics): String =
        s"$metricSystemNamespace" +
            s".$sourceName" +
            s".${sc.organization}" +
            s".${sc.status.toString.toLowerCase}" +
            s".${replaceInvalidCharacters(sc.eventSourceHost)}" +
            s".${replaceInvalidCharacters(sc.collectorHost)}" +
            s".${replaceInvalidCharacters(sc.devType)}"

}
