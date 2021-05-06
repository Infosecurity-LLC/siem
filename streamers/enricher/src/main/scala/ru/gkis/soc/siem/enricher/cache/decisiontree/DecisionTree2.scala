package ru.gkis.soc.siem.enricher.cache.decisiontree

import com.typesafe.scalalogging.LazyLogging
import org.json4s.DefaultFormats
import org.json4s.jackson.Serialization.write

class DecisionTree2[T](any: T) extends Serializable with LazyLogging {

    private val root: DecisionTreeNode2[T] = new DecisionTreeNode2[T](None, Set.empty)

    def add(spec: RuleSpec2[T]): Unit = {
        val node = spec.path.foldLeft(root)((branch, key) => {
            val next = branch.next.getOrElse(new DMap2[T])
            branch.next = Some(next)
            next.getOrElseUpdate(
                key,
                defaultValue = new DecisionTreeNode2[T](None, Set.empty)
            )
        })
        node.rules = node.rules + spec.ruleId
    }

    def addAll(rules: List[RuleSpec2[T]]): Unit = rules.foreach(add)

    override def toString: String = {
        implicit val formats: DefaultFormats = DefaultFormats
        write(root)
    }

    private def makeDecision(branch: Option[DecisionTreeNode2[T]], oldBranch: DecisionTreeNode2[T]): DecisionTreeNode2[T] = {

        def inheritRules(newBranch: DecisionTreeNode2[T]): Set[Long] =
            if (newBranch.rules.nonEmpty) newBranch.rules else oldBranch.rules

        val next = branch.flatMap(_.next)
        val rules = branch.map(inheritRules).getOrElse(Set.empty)

        new DecisionTreeNode2[T](next, rules)
    }

    private def search(node: T, base: DecisionTreeNode2[T]): Iterator[DecisionTreeNode2[T]] = {
        base.next match {
            case Some(n) if node == any =>
                Iterator.single(makeDecision(n.get(node), base))
            // create results for `strict` and `any` branches. order matters here!
            case Some(n) =>
                Iterator(makeDecision(n.get(node), base), makeDecision(n.get(any), base))
            case None =>
                Iterator.single(base)
        }
    }

    def search(decisionPath: List[T]): List[Set[Long]] =
        decisionPath
            .foldLeft(Iterator(root))((cur, node) => cur.flatMap(c => search(node, c)))
            .map(_.rules)
            .filter(_.nonEmpty)
            .toList

}
