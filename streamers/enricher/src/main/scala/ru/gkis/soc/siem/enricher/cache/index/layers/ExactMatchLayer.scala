package ru.gkis.soc.siem.enricher.cache.index.layers

import com.typesafe.scalalogging.LazyLogging
import ru.gkis.soc.siem.enricher.cache.index.PathNode

import scala.collection.mutable

class ExactMatchLayer[T](cardinality: Int, any: T) extends TypedLayer[T] with LazyLogging {

    private val data = new mutable.HashMap[T, Set[Long]]

    private def put(key: T, id: Long) = {
        val set = data.getOrElseUpdate(key, Set.empty)
        data.put(key, set + id)
    }

    override def add(pathLevel: List[PathNode[T]], ruleId: Long): Unit = {
        assert(pathLevel.size <= cardinality)
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

    override def search(pathNode: List[PathNode[T]]): List[Set[Long]] = {
        val decisions = pathNode.flatMap {
            case PathNode(Some(key), _) => Iterator(key)
            case _ => Iterator.empty
        }
        // we're going from most to least specific: exact hit -> * hit
        logger.trace(pathNode + " --> " + (decisions :+ any).toString)
        (decisions :+ any).flatMap(key => data.get(key))
    }

    override def toString: String = data.toString()

}
