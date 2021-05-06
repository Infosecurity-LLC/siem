package ru.gkis.soc.siem.normalizer.mappers

import ru.gkis.soc.siem.model._
import ru.gkis.soc.siem.normalizer._
import scalapb.GeneratedMessage

trait Mapper[T] {
    def map(src: T): GeneratedMessage
}

object Mapper {

    private lazy val provider = new MapperProvider

    def apply[A](implicit mapper: Mapper[A]): Mapper[A] = mapper

    object ops {

        def map[A: Mapper, B <: GeneratedMessage](a: A): B = Mapper[A].map(a).asInstanceOf[B]

        implicit class MapOps[A: Mapper](a: A) {
            def map[B <: GeneratedMessage]: B = Mapper[A].map(a).asInstanceOf[B]
        }

    }

    implicit def canMapChain(implicit key: ProviderKey): Mapper[InternalChainEvent] = key match {
        case ProviderKey(ChainMapper.name, ChainMapper.version, _) => provider.getMapper(key, _ => new ChainMapper)
    }

    implicit def canMapRaw(implicit key: ProviderKey): Mapper[InternalRawEvent] = key match {
        case ProviderKey(RawMapper.name, RawMapper.version, _) => provider.getMapper(key, _ => new RawMapper)
    }

    implicit def canMapError(implicit key: ProviderKey): Mapper[InternalErrorEvent] = key match {
        case ProviderKey(ErrorMapper.name, ErrorMapper.version, _) => provider.getMapper(key, _ => new ErrorMapper)
    }

    implicit def canMapInvalid(implicit key: ProviderKey): Mapper[InternalInvalidEvent] = key match {
        case ProviderKey(InvalidMapper.name, InvalidMapper.version, _) => provider.getMapper(key, _ => new InvalidMapper)
    }

    implicit def canMapOther(implicit key: ProviderKey): Mapper[(DevTypeToVendorMapping, InternalSocEvent)] = key match {
        case ProviderKey(FortigateMapper.name, FortigateMapper.version, _) => provider.getMapper(key, _ => new FortigateMapper)
        case ProviderKey(KasperskyMapper.name, KasperskyMapper.version, _) => provider.getMapper(key, _ => new KasperskyMapper)
        case ProviderKey(WindowsSecurityMapper.name, WindowsSecurityMapper.version, _) => provider.getMapper(key, _ => new WindowsSecurityMapper)
        case ProviderKey(SymantecMapper.name, SymantecMapper.version, _) => provider.getMapper(key, _ => new SymantecMapper)
        case ProviderKey(CiscoAsaMapper.name, CiscoAsaMapper.version, _) => provider.getMapper(key, _ => new CiscoAsaMapper)
        case ProviderKey(EsetNod32Mapper.name, EsetNod32Mapper.version, _) => provider.getMapper(key, _ => new EsetNod32Mapper)
        case ProviderKey(AuditdMapper.name, AuditdMapper.version, _) => provider.getMapper(key, _ => new AuditdMapper)
        case ProviderKey(Fail2BanMapper.name, Fail2BanMapper.version, _) => provider.getMapper(key, _ => new Fail2BanMapper)
        case ProviderKey(CiscoIosIsrMapper.name, CiscoIosIsrMapper.version, _) => provider.getMapper(key, _ => new CiscoIosIsrMapper)
    }
}
