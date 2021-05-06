package ru.gkis.soc.siem.normalizer.parsers

import ru.gkis.soc.siem.commons.Provider
import ru.gkis.soc.siem.model.ProviderKey

class ParserProvider extends Provider[ProviderKey, LogParser[_]] {
    def getParser[T](key: ProviderKey, spawner: ProviderKey => LogParser[T]): LogParser[T] = {
        get(key, spawner).asInstanceOf[LogParser[T]]
    }
}