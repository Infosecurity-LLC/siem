package ru.gkis.soc.siem.enricher.cache.decisiontree

import com.typesafe.scalalogging.LazyLogging
import ru.gkis.soc.siem.model.SocEvent
import scalapb.lenses.Lens
import org.json4s._
import org.json4s.jackson.Serialization.write
import ru.gkis.soc.siem.enricher.time.ProductionCalendar

import scala.collection.mutable


class DecisionTree[K, V] extends Serializable with LazyLogging {

    import ru.gkis.soc.siem.model.access.{Allowed, Restricted, RuleResult, Undefined}

    private val root: DecisionTreeNode = new DecisionTreeNode(None, Map.empty)
    private val rules = new mutable.HashMap[Long, Rule[K, V]]()

    def newControl(decisionPath: Path,
                   eventTime: Option[Lens[SocEvent, Long]] = None,
                   aux1: Option[Lens[SocEvent, K]] = None,
                   aux2: Option[Lens[SocEvent, V]] = None): Control = {
        Control(decisionPath, eventTime, aux1, aux2)
    }

    def add(path: List[Option[String]], selector: String, rule: Rule[K, V]): Unit = {
        val node = path.foldLeft(root)((branch, key) => {
            val next = branch.next.getOrElse(new DMap)
            branch.next = Some(next)
            next.getOrElseUpdate(
                key = key.getOrElse(any),
                defaultValue = new DecisionTreeNode(None, Map.empty)
            )
        })
        if (node.rules.contains(selector) && node.rules(selector) != rule.id) {
            logger.error(s"Conflicting rules detected for selector $selector at path: ${path.map(_.orNull).mkString(" -> ")}!\nIn cache: ${node.rules(selector)}\nNew ruleId: $rule")
        } else {
            rules += (rule.id -> rule)
            node.rules = node.rules + (selector -> rule.id)
        }
    }


    def addAll(rules: List[RuleSpec[K, V]]): Unit = rules.foreach(spec => {
        add(spec.path, spec.selector, spec.rule)
    })

    override def toString: String = {
        implicit val formats: DefaultFormats = DefaultFormats
        write(root)
    }

    // =================================================================================================================
    case class Control(decisionPath: Path, eventTime: Option[Lens[SocEvent, Long]], aux1: Option[Lens[SocEvent, K]], aux2: Option[Lens[SocEvent, V]]) {

        private def applySchedule(r: Rule[K, V], evt: SocEvent, pk: ProductionCalendar): Boolean = {
            eventTime.fold(true) { timeLens =>
                val time = timeLens.get(evt)
                r.schedule.intervals.exists { schedule =>
                    schedule.check(time, pk)
                }
            }
        }

        private def applyRule(r: Rule[K, V], evt: SocEvent, pk: ProductionCalendar): RuleResult = {

            def negate(r: RuleResult): RuleResult = if (r == Allowed) Restricted else Allowed

            val scd = applySchedule(r, evt, pk)
            val a1 = aux1.fold(true)(l => r.aux1.fold(true)(_.values.contains(l.get(evt))))
            val a2 = aux2.fold(true)(l => r.aux2.fold(true)(_.values.contains(l.get(evt))))
            val result = if (scd && a1 && a2) r.result else negate(r.result)
            result
        }

        private def makeDecision(branch: Option[DecisionTreeNode], oldBranch: DecisionTreeNode, node: PathNode): Decision = {
            // we should implement rule inheritance for deeper layers
            def inheritRules(newBranch: DecisionTreeNode): Option[Map[String, Long]] =
                node.selector match {
                    case Some(p) =>
                        newBranch.rules.get(p).map(r => oldBranch.rules + (p -> r))
                    case None =>
                        Some(oldBranch.rules ++ newBranch.rules)
                }

            val next = branch.flatMap(_.next)
            val rules = branch.flatMap(inheritRules).getOrElse(Map.empty)

            Decision(node.selector, Some(new DecisionTreeNode(next, rules)))
        }

        def search(node: PathNode, base: Decision): Iterator[Decision] = {
            base.node match {
                case Some(branch) =>
                    branch.next match {
                        case Some(n) if node.key == any =>
                            Iterator.single(makeDecision(n.get(node.key), branch, node))
                        // create results for `strict` and `any` branches. order matters here!
                        case Some(n) =>
                            Iterator(makeDecision(n.get(node.key), branch, node), makeDecision(n.get(any), branch, node))
                        case None =>
                            Iterator.single(base)
                    }
                case None =>
                    Iterator.empty
            }
        }

        def check(evt: SocEvent, pk: ProductionCalendar): RuleResult = {
            val base = Iterator.single(Decision(None, Option(root.asInstanceOf[DecisionTreeNode])))
            decisionPath
                .foldLeft(base)((cur, node) => cur.flatMap(c => search(node, c)))
                .flatMap {
                    case Decision(Some(selector), Some(node)) =>
                        node.rules.get(selector)
                    case Decision(None, Some(node)) =>
                        if (node.rules.size > 1) {
                            throw new IllegalStateException(s"Ambiguous rule set! Cannot choose between:\n${node.rules.mkString("\n")}")
                        } else {
                            node.rules.headOption.map(_._2)
                        }
                    case _ =>
                        None
                }
                .flatMap(rules.get)
                .find(_.result != Undefined)
                .fold[RuleResult](Undefined)(rule => applyRule(rule, evt, pk))
        }
    }

}
