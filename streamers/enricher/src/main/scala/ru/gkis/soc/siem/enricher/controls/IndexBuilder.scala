package ru.gkis.soc.siem.enricher.controls

import ru.gkis.soc.siem.enricher.cache.index.{LayeredIndex, Rule, Spec}
import ru.gkis.soc.siem.enricher.cache.index.layers.Layer

trait IndexBuilder[K, V] {

    protected def createLayers: List[Layer]
    protected def rulesToPathSpec(rules: List[Rule[K, V]]): List[Spec]
    def apply(rules: List[Rule[K, V]]): LayeredIndex[K, V]

}
