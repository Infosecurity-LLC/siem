package ru.gkis.soc.siem.enricher.controls

import java.util.regex.Pattern
import ru.gkis.soc.siem.enricher.cache.decisiontree._
import ru.gkis.soc.siem.model.{Counterpart, SocEvent}

object WindowsObjectControl {

    sealed trait CheckBy

    case object Path extends CheckBy

    private val pathPattern = Pattern.compile("""(:\\)|(\\+)""")

    private def pathToSegments(path: Option[String]): List[Some[String]] = {
        val result: List[String] = path match {
            case Some(p) if p.startsWith("""\\*\""") || p.startsWith("""\??\""") =>
                pathPattern.split(p.substring(4)).map(_.toLowerCase).toList
            case Some(p) =>
                pathPattern.split(p).map(_.toLowerCase).toList
            case None =>
                List.empty
        }

        result.map(el => Some(el))
    }

    private def rulesByHostname[K, V](r: Rule[K, V], addStar: Boolean): List[Option[String]] = {
        List(
            Some(r.subj.org),
            r.subj.domain,
            r.subj.login,
            r.source.flatMap(_.hostname)
        ) ++ ruleToPath(r, addStar)
    }

    private def rulesByIp[K, V](r: Rule[K, V], addStar: Boolean): List[Option[String]] = {
        List(
            Some(r.subj.org),
            r.subj.domain,
            r.subj.login,
            r.source.flatMap(_.ip)
        ) ++ ruleToPath(r, addStar)
    }

    private[this] def ruleToPath[K, V](r: Rule[K, V], addStar: Boolean): List[Some[String]] = {
        r.obj.map(o => if(addStar) pathToSegments(o.path):+ Some("*") else pathToSegments(o.path)).getOrElse(List.empty)
    }

    /**
     * In "raw" rule we don't have any information about what exactly in "path": fyull path of directory or full path to file
     * as solution introduced 'addStar' parameter, because wee need support:
     *  - C:\windows - restrict or allow access to windows folder and all sub-foldes. Required rule output is "C:\windows\*"
     *  - C:\windows\etc\host - restrict access to hosts file. Required rule output "C:\windows\etc\host"
     * to cover both cases we add two rule for both cases:
     *  - "C:\windows\*"
     *  - "C:\windows"
     *  - "C:\windows\etc\host"
     *  - "C:\windows\etc\host\*"
     *  As result we have some overhead in tree but cover all required cases
     */
    def apply[K, V](rules: List[Rule[K, V]]): List[RuleSpec[K, V]] = {
        rules
            .flatMap(r => {
                r.source match {
                    case Some(src) =>
                        Iterator(
                            src.hostname.map(_ => RuleSpec(rulesByHostname(r, addStar = false), Path.toString, r)),
                            src.ip.map(_ => RuleSpec(rulesByIp(r, addStar = false), Path.toString, r)),
                            src.hostname.map(_ => RuleSpec(rulesByHostname(r, addStar = true), Path.toString, r)),
                            src.ip.map(_ => RuleSpec(rulesByIp(r, addStar = true), Path.toString, r))
                        ).flatten
                    case None =>
                        Iterator(
                            RuleSpec(rulesByHostname(r, addStar = false), Path.toString, r),
                            RuleSpec(rulesByIp(r, addStar = false), Path.toString, r),
                            RuleSpec(rulesByHostname(r, addStar = true), Path.toString, r),
                            RuleSpec(rulesByIp(r, addStar = true), Path.toString, r)
                        )
                }
            })
    }

    def decisionPath(evt: SocEvent): Option[Path] = {
        val objectPath: Option[String] = evt.`object`.map(_.category).flatMap {
            case Counterpart.url => evt.`object`.flatMap(_.name)
            case _ => evt.`object`.flatMap(_.path)
        }
        val pathNodes: List[Option[PathNode]] = pathToSegments(objectPath).map(_.map(PathNode(_)))
        val eventSourceNode: Option[Option[PathNode]] = evt.eventSource.flatMap(es => es.location.flatMap(l => l.hostname.map(PathNode.some).orElse(l.ip.map(PathNode.some))))

        val list: List[Option[PathNode]] = List(
            evt.collector.map(c => PathNode.some(c.organization)),
            evt.subject.map(_.domain.map(PathNode(_))),
            evt.subject.map(_.name.map(PathNode(_))),
            eventSourceNode
        ).flatten ++ pathNodes

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
