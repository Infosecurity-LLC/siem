package ru.gkis.soc.siem.normalizer.mappers

import ru.gkis.soc.siem.model.{AssetLocation, CollectorInfo, InvalidEvent}
import ru.gkis.soc.siem.normalizer.InternalInvalidEvent

class InvalidMapper extends Mapper[InternalInvalidEvent] {

    override def map(src: InternalInvalidEvent): InvalidEvent = {
        val collectorLocation = AssetLocation(
            hostname = Some(src.message.collectorHostname),
            host = src.message.collectorHostIP,
            ip = Some(src.message.collectorHostIP)
        )

        val collectorInfo = CollectorInfo(
            location = Some(collectorLocation),
            organization = src.message.organization,
            inputId = src.message.inputId
        )

        InvalidEvent(
            rawId = src.rawId,
            reason = src.reason,
            collector = Some(collectorInfo)
        )
    }

}

object InvalidMapper {
    val name: String = "invalid"
    val version: Int = 1
}
