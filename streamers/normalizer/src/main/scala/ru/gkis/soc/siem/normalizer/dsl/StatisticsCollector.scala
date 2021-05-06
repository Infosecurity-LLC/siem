package ru.gkis.soc.siem.normalizer.dsl

import java.time.{LocalDateTime, ZoneOffset}

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.commons.Constants
import ru.gkis.soc.siem.normalizer.FinalStates.State
import ru.gkis.soc.siem.normalizer._

trait StatisticsCollector {

    implicit class StatisticsSpawner(rdd: RDD[Mapped]) extends Serializable {
        private def socEventStats(status: State, evt: NormalizedSocEvent, now: Long) =
            Statistics(
                evt.normalized.getCollector.organization,
                evt.devType,
                evt.normalized.getCollector.getLocation.host,
                evt.eventSourceHost,
                status,
                evt.normalized.serializedSize,
                isOutOfTime(now, evt.normalized.eventTime)
            )

        private def rawEventStats(status: State, evt: NormalizedRawEvent, now: Long) =
            Statistics(
                evt.normalized.getCollector.organization,
                evt.devType,
                evt.normalized.getCollector.getLocation.host,
                evt.eventSourceHost,
                status,
                evt.normalized.serializedSize,
                isOutOfTime(now, evt.normalized.eventTime)
            )

        private def chainEventStats(status: State, evt: NormalizedChainEvent, now: Long) =
            Statistics(
                evt.normalized.getCollector.organization,
                evt.devType,
                evt.normalized.getCollector.getLocation.host,
                evt.eventSourceHost,
                status,
                evt.normalized.serializedSize,
                isOutOfTime(now, evt.normalized.eventTime)
            )

        private def invalidEventStats(status: State, evt: NormalizedInvalidEvent) =
            Statistics(
                evt.normalized.getCollector.organization,
                evt.devType,
                evt.normalized.getCollector.getLocation.host,
                evt.eventSourceHost,
                status,
                evt.normalized.serializedSize,
                0
            )

        private def errorEventStats(status: State, evt: NormalizedErrorEvent) =
            Statistics(
                evt.normalized.getCollector.organization,
                evt.devType,
                evt.normalized.getCollector.getLocation.host,
                evt.eventSourceHost,
                status,
                evt.normalized.serializedSize,
                0
            )

        def collectStatistics(now: LocalDateTime): RDD[Statistical] = {
            val normalizerTime = now.toInstant(ZoneOffset.UTC).getEpochSecond

            rdd.mapPartitions(it => {
                it.flatMap {
                    case evt: NormalizedSocEvent => Iterator(evt, socEventStats(evt.state, evt, normalizerTime))
                    case evt: NormalizedRawEvent => Iterator(evt, rawEventStats(evt.state, evt, normalizerTime))
                    case evt: NormalizedChainEvent => Iterator(evt, chainEventStats(evt.state, evt, normalizerTime))
                    case evt: NormalizedInvalidEvent => Iterator(evt, invalidEventStats(evt.state, evt))
                    case evt: NormalizedErrorEvent => Iterator(evt, errorEventStats(evt.state, evt))
                }
            })
        }

        private[this] def isOutOfTime(now: Long, eventTime: Long): Int = {
            if (eventTime >= now) {
                1
            } else {
                0
            }
        }
    }

    implicit class StatisticsCollector(rdd: RDD[Statistical]) extends Serializable {

        private val id = Statistics(
            Constants.unknown,
            Constants.unknown,
            Constants.unknown,
            Constants.unknown,
            FinalStates.IDENTITY,
            0,
            0,
            0)

        private def agg(combined: Statistics, stats: Statistics): Statistics = {
            stats.copy(
                outOfTime = combined.outOfTime + stats.outOfTime,
                bytesOut = stats.bytesOut + combined.bytesOut,
                messageCount = stats.messageCount + combined.messageCount
            )
        }

        def summarize: Array[Statistics] = {
            rdd
                .flatMap {
                    case stats: Statistics => Some(stats)
                    case _ => None
                }
                .map(stats => stats.key -> stats)
                .aggregateByKey(id)(agg, agg)
                .map(_._2)
                .collect()
        }

    }

}
