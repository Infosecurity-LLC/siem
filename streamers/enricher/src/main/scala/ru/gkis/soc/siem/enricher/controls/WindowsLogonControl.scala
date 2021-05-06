package ru.gkis.soc.siem.enricher.controls

import ru.gkis.soc.siem.enricher.cache.decisiontree.{Path, PathNode, Rule, RuleSpec}
import ru.gkis.soc.siem.model.SocEvent

object WindowsLogonControl {

    sealed trait CheckBy

    case object Hostname extends CheckBy

    case object IpAddress extends CheckBy

    private def rulesByHostname[K, V](r: Rule[K, V]) = List(
        Some(r.subj.org),
        r.subj.domain,
        r.subj.login,
        r.source.flatMap(_.hostname),
        r.destination.flatMap(_.hostname)
    )

    private def rulesByIpAddress[K, V](r: Rule[K, V]) = List(
        Some(r.subj.org),
        r.subj.domain,
        r.subj.login,
        r.source.flatMap(_.ip),
        r.destination.flatMap(_.ip)
    )

    private def rulesByHostnameToIpAddress[K, V](r: Rule[K, V]) = List(
        Some(r.subj.org),
        r.subj.domain,
        r.subj.login,
        r.source.flatMap(_.hostname),
        r.destination.flatMap(_.ip)
    )

    private def rulesByIpAddressToHostname[K, V](r: Rule[K, V]) = List(
        Some(r.subj.org),
        r.subj.domain,
        r.subj.login,
        r.source.flatMap(_.ip),
        r.destination.flatMap(_.hostname)
    )

    def apply[K, V](rules: List[Rule[K, V]]): List[RuleSpec[K, V]] = {
        val result = rules
            .flatMap(r => {
                (r.source, r.destination) match {
                    case (Some(src), Some(dst)) =>
                        Iterator(
                            src.ip.map(_ => RuleSpec(rulesByIpAddress(r), IpAddress.toString, r)),
                            src.ip.map(_ => RuleSpec(rulesByIpAddressToHostname(r), Hostname.toString, r)),
                            src.hostname.map(_ => RuleSpec(rulesByHostname(r), Hostname.toString, r)),
                            src.hostname.map(_ => RuleSpec(rulesByHostnameToIpAddress(r), IpAddress.toString, r)),
                            dst.ip.map(_ => RuleSpec(rulesByIpAddress(r), IpAddress.toString, r)),
                            dst.ip.map(_ => RuleSpec(rulesByIpAddressToHostname(r), Hostname.toString, r)),
                            dst.hostname.map(_ => RuleSpec(rulesByHostname(r), Hostname.toString, r)),
                            dst.hostname.map(_ => RuleSpec(rulesByHostnameToIpAddress(r), IpAddress.toString, r))
                        ).flatten
                    case (Some(src), None) =>
                        Iterator(
                            src.ip.map(_ => RuleSpec(rulesByIpAddress(r), IpAddress.toString, r)),
                            src.hostname.map(_ => RuleSpec(rulesByHostname(r), Hostname.toString, r))
                        ).flatten
                    case (None, Some(dst)) =>
                        Iterator(
                            dst.ip.map(_ => RuleSpec(rulesByIpAddress(r), IpAddress.toString, r)),
                            dst.hostname.map(_ => RuleSpec(rulesByHostname(r), Hostname.toString, r))
                        ).flatten
                    case (None, None) =>
                        Iterator(
                            RuleSpec(rulesByIpAddress(r), IpAddress.toString, r),
                            RuleSpec(rulesByHostname(r), Hostname.toString, r)
                        )
                }
            })
        result
    }

    def decisionPath(evt: SocEvent): Option[Path] = {
        val list = List(
            evt.collector.map(c => PathNode(c.organization)),
            evt.subject.flatMap(_.domain.map(d => PathNode(d.toLowerCase))),
            evt.subject.flatMap(_.name.map(n => PathNode(n.toLowerCase))),
            evt.source.flatMap(_.hostname.map(hostname)).orElse(evt.source.flatMap(_.ip.map(ip))),
            evt.destination.flatMap(_.hostname.map(hostname)).orElse(evt.destination.flatMap(_.ip.map(ip)))
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

    private[this] def hostname(value: String): PathNode = {
        PathNode(value.toLowerCase, Some(Hostname.toString))
    }

    private[this] def ip(value: String): PathNode = {
        PathNode(value.toLowerCase, Some(IpAddress.toString))
    }
}
