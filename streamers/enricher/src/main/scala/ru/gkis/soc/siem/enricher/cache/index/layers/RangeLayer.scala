package ru.gkis.soc.siem.enricher.cache.index.layers
import ru.gkis.soc.siem.enricher.cache.index.PathNode

import scala.collection.mutable
import com.google.common.collect.{Range => NumericRange}

class RangeLayer[T <: Comparable[T]](any: NumericRange[T]) extends TypedLayer[NumericRange[T]] {

    /*
     * @todo subject to be replaced by interval search tree!
     */
    private val data = new mutable.HashMap[NumericRange[T], Set[Long]]

    private def put(key: NumericRange[T], id: Long) = {
        val set = data.getOrElseUpdate(key, Set.empty)
        data.put(key, set + id)
    }

    override def add(pathLevel: List[PathNode[NumericRange[T]]], ruleId: Long): Unit = {
        pathLevel match {
            case Nil => put(any, ruleId)
            case level => level.foreach {
                case PathNode(Some(key), _) => put(key, ruleId)
                case PathNode(None, None) => put(any, ruleId)
                case PathNode(None, Some(_)) => Unit
                case other => throw new IllegalArgumentException(s"Wrong path node: $other")
            }
        }
    }

    override def search(pathNode: List[PathNode[NumericRange[T]]]): List[Set[Long]] = {
        val decisions = pathNode.flatMap {
            case PathNode(Some(key), _) => Iterator(key)
            case _ => Iterator.empty
        }
        // we're going from most to least specific: exact hit -> * hit
        (decisions :+ any).map(node => {
            assert(node.lowerEndpoint() == node.upperEndpoint())
            data.filterKeys(key => key.contains(node.lowerEndpoint())).flatMap(_._2).toSet
        })
    }

    override def toString: String = data.toString

}
