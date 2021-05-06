package ru.gkis.soc.siem.normalizer.validators

import ru.gkis.soc.siem.model.{ProviderKey, TransformationPreferences}
import ru.gkis.soc.siem.normalizer.{ParsedEvent, ParsedMessage}

trait Validator[T] {
    def check(obj: T): List[String]
}

object Validator {

    private lazy val provider = new ValidatorProvider

    def apply[A](implicit validator: Validator[A]): Validator[A] = validator

    object ops {

        def check[A: Validator](a: A): List[String] = Validator[A].check(a)

        implicit class MapOps[A: Validator](a: A) {
            def check: List[String] = Validator[A].check(a)
        }

    }

    implicit def canValidateNxLog(implicit key: ProviderKey): Validator[(ParsedMessage, TransformationPreferences)] = key match {
        case ProviderKey(NxLogValidator.name, NxLogValidator.version, _) => provider.getValidator(key, _ => new NxLogValidator)
    }

    implicit def canValidateParsedEvents(implicit key: ProviderKey): Validator[ParsedEvent] = key match {
        case ProviderKey(FortigateValidator.name, FortigateValidator.version, _) => provider.getValidator(key, _ => new FortigateValidator)
        case ProviderKey(KasperskyValidator.name, KasperskyValidator.version, _) => provider.getValidator(key, _ => new KasperskyValidator)
        case ProviderKey(WindowsSecurityValidator.name, WindowsSecurityValidator.version, _) => provider.getValidator(key, _ => new WindowsSecurityValidator)
        case ProviderKey(SymantecValidator.name, SymantecValidator.version, _) => provider.getValidator(key, _ => new SymantecValidator)
        case ProviderKey(CiscoAsaValidator.name, CiscoAsaValidator.version, _) => provider.getValidator(key, _ => new CiscoAsaValidator)
        case ProviderKey(EsetNod32Validator.name, EsetNod32Validator.version, _) => provider.getValidator(key, _ => new EsetNod32Validator)
        case ProviderKey(AuditdValidator.name, AuditdValidator.version, _) => provider.getValidator(key, _ => new AuditdValidator)
        case ProviderKey(Fail2BanValidator.name, Fail2BanValidator.version, _) => provider.getValidator(key, _ => new Fail2BanValidator)
        case ProviderKey(CiscoIosIsrValidator.name, CiscoIosIsrValidator.version, _) => provider.getValidator(key, _ => new CiscoIosIsrValidator)
    }
}