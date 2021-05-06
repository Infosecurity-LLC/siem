package ru.gkis.soc.siem.enricher.cache.index.layers

import ru.gkis.soc.siem.enricher.cache.index.PathNode

sealed trait Layer extends Serializable {
    type Comp
    def add(pathLevel: List[PathNode[Comp]], ruleId: Long): Unit
    def search(pathNode: List[PathNode[Comp]]): List[Set[Long]]
}

trait TypedLayer[T] extends Layer {
    override type Comp = T
}

