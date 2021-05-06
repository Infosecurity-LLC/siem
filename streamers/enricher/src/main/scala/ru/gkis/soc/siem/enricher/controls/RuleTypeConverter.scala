package ru.gkis.soc.siem.enricher.controls

import ru.gkis.soc.siem.enricher.cache.index.Rule
import ru.gkis.soc.siem.model.access.{Rule => AccessRule}

trait RuleTypeConverter[K, V] {

    def convertAccessRule(src: List[AccessRule]): List[Rule[K, V]]

}
