package ru.gkis.soc.siem.enricher.cache.index

import com.typesafe.scalalogging.LazyLogging
import ru.gkis.soc.siem.enricher.cache.index.layers.{Layer, TypedLayer}

import scala.collection.mutable

class LayeredIndex[K, V](layers: List[Layer]) extends Serializable with LazyLogging {

    private val rules = new mutable.HashMap[Long, Rule[K, V]]

    def add(spec: Spec): Unit = {
        if (spec.path.length != layers.size) throw new IllegalArgumentException("Path length must match index depth")
        rules += spec.rule.id -> spec.rule.asInstanceOf[Rule[K, V]]
        spec.path.zip(layers).foreach {
            case (node, layer) => layer.add(node.asInstanceOf[List[PathNode[layer.Comp]]], spec.rule.id)
        }
    }

    def addAll(path: List[Spec]): Unit = path.foreach(add)

    def search[T](path: DecisionPath[T]): Option[List[Rule[K, V]]] = {
        val view = layers.asInstanceOf[List[TypedLayer[T]]]
        val r = path.zip(view).drop(1).foldLeft(view.head.search(path.head)) {
            case (prev, (node, layer: TypedLayer[T])) =>
                val res = prev
                            .cross(layer.search(node))
                            .map {
                                // set intersection is a linear operation - smaller set should be on the left side
                                case (left, right) => if (left.size > right.size) right & left else left & right
                            }
                            .filterNot(_.isEmpty)
                logger.trace(s"${node.map(el => s"${el.key.getOrElse("*")}${el.selector.map(s => s":$s").getOrElse("")}")} --> $res")
                res
        }
        r.headOption.map(_.map(id => rules(id)).toList)
    }

    override def toString: String = layers.map(_.toString).mkString("\n")

}