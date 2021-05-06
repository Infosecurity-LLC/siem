package ru.gkis.soc.siem.normalizer.dsl

import org.apache.spark.rdd.RDD
import ru.gkis.soc.siem.commons.Constants
import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.normalizer._
import ru.gkis.soc.siem.normalizer.mappers._
import ru.gkis.soc.siem.io.spark.EditableBroadcast

trait EventMapper {

    implicit class EventMapper(rdd: RDD[Split]) extends Serializable {

        import ru.gkis.soc.siem.normalizer.mappers.Mapper.ops._

        def mapToTargetStruct(prefs: EditableBroadcast[TransformationPreferences], deviceVendors: EditableBroadcast[DevTypeToVendorMapping]): RDD[Mapped] = {
            rdd.mapPartitionsWithIndex((part, it) => {
                it.map {
                    case evt: InternalSocEvent =>
                        val preference = prefs.value(evt.message.organization)(evt.message.eventDevType).mapper
                        implicit val mapperInfo: ProviderKey = ProviderKey(preference.name, preference.version, part)
                        NormalizedSocEvent(map((deviceVendors.value, evt)), evt.message.eventDevType, evt.eventSourceHost)
                    case evt: InternalRawEvent =>
                        implicit val mapperInfo: ProviderKey = ProviderKey(RawMapper.name, RawMapper.version, part)
                        NormalizedRawEvent(map(evt), evt.message.eventDevType, evt.eventSourceHost)
                    case evt: InternalChainEvent =>
                        implicit val mapperInfo: ProviderKey = ProviderKey(ChainMapper.name, ChainMapper.version, part)
                        NormalizedChainEvent(map(evt), evt.message.eventDevType, evt.eventSourceHost)
                    case evt: InternalInvalidEvent =>
                        implicit val mapperInfo: ProviderKey = ProviderKey(InvalidMapper.name, InvalidMapper.version, part)
                        NormalizedInvalidEvent(map(evt), evt.message.eventDevType, evt.eventSourceHost)
                    case evt: InternalErrorEvent =>
                        implicit val mapperInfo: ProviderKey = ProviderKey(ErrorMapper.name, ErrorMapper.version, part)
                        NormalizedErrorEvent(map(evt), evt.message.fold(_.eventDevType, _ => Constants.unknown), evt.eventSourceHost)
                }
            }, preservesPartitioning = true)
        }

    }

}
