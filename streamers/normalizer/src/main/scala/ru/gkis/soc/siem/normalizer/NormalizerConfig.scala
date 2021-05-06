package ru.gkis.soc.siem.normalizer

import com.typesafe.config.Config

trait NormalizerConfig {

    import scala.compat.java8.DurationConverters._

    sealed trait TimeShiftMode extends Serializable
    object AS_IS extends TimeShiftMode
    object NOW extends TimeShiftMode
    object SHIFT extends TimeShiftMode

    protected val appConf: Config
    private val basic = appConf.getConfig("app.normalizer")

    val timeShiftMode: TimeShiftMode = basic.getString("time.shift.mode") match {
        case "as-is" => AS_IS
        case "now" => NOW
        case "shift" => SHIFT
    }

    val timeShiftValue: Long = basic.getDuration("time.shift.value").toScala.toSeconds

}
