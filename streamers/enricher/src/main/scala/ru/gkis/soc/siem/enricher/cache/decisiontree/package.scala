package ru.gkis.soc.siem.enricher.cache

import scala.collection.mutable

package object decisiontree {
    type DMap = mutable.HashMap[String, DecisionTreeNode]
    type DMap2[T] = mutable.HashMap[T, DecisionTreeNode2[T]]
    type Path = List[PathNode]

    val any: String = "*"
}
