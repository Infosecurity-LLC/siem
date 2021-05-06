package ru.gkis.soc.siem.enricher.controls

import ru.gkis.soc.siem.enricher.cache.decisiontree.{Path, PathNode, Rule, RuleSpec}
import ru.gkis.soc.siem.model.SocEvent

object VpnLogonControl {

    private[this] def buildSpec[K, V](r: Rule[K, V]) = List(
            Some(r.subj.org),
            r.subj.domain,
            r.subj.login
        )

    def apply[K, V](rules: List[Rule[K, V]]): List[RuleSpec[K, V]] = {
        rules.map(r => RuleSpec(buildSpec(r), "vpn", r))
    }

    def decisionPath(evt: SocEvent): Option[Path] = {
        val list = List(
            evt.collector.map(c => PathNode(c.organization)),
            evt.subject.flatMap(_.domain.map(PathNode(_))),
            evt.subject.flatMap(s => s.name.map(PathNode(_)))
        )
        val result: Option[List[PathNode]] = list.foldLeft(Option(List.empty[PathNode])) { case (res, maybeItem) =>
            maybeItem match {
                case Some(item) =>
                    res.map(_ :+ item)
                case None =>
                    None
            }
        }

        result
    }
}
