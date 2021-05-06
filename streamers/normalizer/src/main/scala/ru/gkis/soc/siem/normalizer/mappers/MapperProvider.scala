package ru.gkis.soc.siem.normalizer.mappers

import ru.gkis.soc.siem.commons.Provider
import ru.gkis.soc.siem.model.ProviderKey

class MapperProvider extends Provider[ProviderKey, Mapper[_]] with Serializable {

    def getMapper[T](key: ProviderKey, spawner: ProviderKey => Mapper[T]): Mapper[T] = {
        get(key, spawner).asInstanceOf[Mapper[T]]
    }

}

