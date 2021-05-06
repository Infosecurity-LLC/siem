package ru.gkis.soc.siem.normalizer.validators

import ru.gkis.soc.siem.commons.Provider
import ru.gkis.soc.siem.model.ProviderKey

class ValidatorProvider extends Provider[ProviderKey, Validator[_]] with Serializable {

    def getValidator[T](key: ProviderKey, spawner: ProviderKey => Validator[T]): Validator[T] = {
        get(key, spawner).asInstanceOf[Validator[T]]
    }

}

