package ru.gkis.soc.siem.normalizer.dsl

import java.time.Instant

import org.apache.spark.broadcast.Broadcast
import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.normalizer.{Mapped, NormalizedSocEvent, NormalizerConfig}

trait TimeShifter {

    implicit class LogParser(rdd: RDD[Mapped]) extends Serializable {

        import ru.gkis.soc.siem.model.SocEvent._

        private def shiftToNow(evt: NormalizedSocEvent): NormalizedSocEvent =
            evt.copy(normalized = evt.normalized.update(_.data.time := Instant.now().getEpochSecond))

        private def shiftByValue(evt: NormalizedSocEvent, shiftValue: Long): NormalizedSocEvent = {
            evt.copy(normalized = evt.normalized.update(e => e.data.time := e.data.time.get(evt.normalized) + shiftValue))
        }

        def shiftTime(appConf: Broadcast[_ <: NormalizerConfig]): RDD[Mapped] = {
            val conf = appConf.value
            rdd.mapPartitions(it => {
                it.map {
                    case evt: NormalizedSocEvent if conf.timeShiftMode == conf.NOW   => shiftToNow(evt)
                    case evt: NormalizedSocEvent if conf.timeShiftMode == conf.SHIFT => shiftByValue(evt, conf.timeShiftValue)
                    case other => other
                }
            }, preservesPartitioning = true)
        }

    }

}
