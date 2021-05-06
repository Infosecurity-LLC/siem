package ru.gkis.soc.siem.enricher.cache

package object index {

    type DecisionPath[T] = List[List[PathNode[T]]]

    implicit class Crossable[K](xs: List[K]) {
        def cross[V](ys: List[V]): List[(K, V)] = for { x <- xs; y <- ys } yield (x, y)
    }

}
