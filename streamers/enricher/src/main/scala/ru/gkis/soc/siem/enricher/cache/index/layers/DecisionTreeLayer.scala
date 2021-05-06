package ru.gkis.soc.siem.enricher.cache.index.layers
import ru.gkis.soc.siem.enricher.cache.decisiontree.{DecisionTree2, RuleSpec2}
import ru.gkis.soc.siem.enricher.cache.index.PathNode

class DecisionTreeLayer[T](any: T) extends TypedLayer[T] {

    private val data = new DecisionTree2[T](any)

    private def toPath(pathLevel: List[PathNode[T]]) = pathLevel match {
        case Nil => List(any)
        case list => list.map {
                              case PathNode(Some(key), _) => key
                              case PathNode(None, _) => any
                          }
    }

    override def add(pathLevel: List[PathNode[T]], ruleId: Long): Unit = {
        data.add(RuleSpec2(toPath(pathLevel), ruleId))
    }

    override def search(pathNode: List[PathNode[T]]): List[Set[Long]] =
        data.search(toPath(pathNode))

    override def toString: String = data.toString()

}
