package ru.gkis.soc.siem.normalizer.mappers

import org.apache.commons.lang.exception.ExceptionUtils
import ru.gkis.soc.siem.commons.Constants
import ru.gkis.soc.siem.model.{AssetLocation, CollectorInfo, ErrorEvent}
import ru.gkis.soc.siem.normalizer.InternalErrorEvent

class ErrorMapper extends Mapper[InternalErrorEvent] {

    override def map(src: InternalErrorEvent): ErrorEvent = {
        val collectorLocation = AssetLocation(
            host = src.message.fold(_.collectorHostIP, _ => Constants.unknown),
            hostname = src.message.fold(m => Some(m.collectorHostname), _ => None),
            ip = src.message.fold(m => Some(m.collectorHostIP), _ => None)
        )

        val collectorInfo = CollectorInfo(
            location = Some(collectorLocation),
            organization = src.message.fold(_.organization, _ => Constants.unknown),
            inputId = src.message.fold(_.inputId, _ => Constants.unknown)
        )

        ErrorEvent(
            id = src.rawId,
            raw = src.message.fold(_.rawMessage, raw => raw),
            stacktrace = ExceptionUtils.getStackTrace(src.exception),
            collector = Some(collectorInfo)
        )
    }

}

object ErrorMapper {
    val name: String = "error"
    val version: Int = 1
}

