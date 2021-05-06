package ru.gkis.soc.siem.controluploader

import com.google.common.collect.{BoundType, DiscreteDomain, TreeRangeSet, Range => NumericRange}
import org.apache.commons.cli.{Options, Option => CliOption}
import ru.gkis.soc.siem.model.access.{Allowed, FirewallConnection, Schedule}

case class FirewallConnectionsRule(
                                      org: String,
                                      sourceIp: Option[String],
                                      destinationIp: Option[String],
                                      allPortAllowed: Boolean,
                                      allProtocolAllowed: Boolean,
                                      protocolAllowed: Option[String],
                                      sourcePort: Option[Int],
                                      destinationPort: Option[Int]
                                  )

object FirewallConnectionsRuleUploader extends Uploader {

    import scala.collection.JavaConversions._

    def main(args: Array[String]): Unit = {
        println("FirewallConnectionsRuleUploader started")
        run(args, process)
    }

    private def any2none[T](value: Option[AnyRef], conv: String => T) =
        value.flatMap {
            case "any" => None
            case null => None
            case other => Some(conv(other.toString))
        }

    private def port2range(acc: TreeRangeSet[Integer], port: Option[Int]): TreeRangeSet[Integer] = {
        if (port.isDefined)
            acc.add(NumericRange.singleton[Integer](port.get).canonical(DiscreteDomain.integers()))

        acc
    }

    private def ranges2intervals(ranges: TreeRangeSet[Integer]): String =
        ranges.asRanges().map(r => {
            val (lower, upper) = (r.lowerBoundType(), r.lowerEndpoint(), r.upperBoundType(), r.upperEndpoint()) match {
                case (BoundType.CLOSED, l, BoundType.CLOSED, u) => (l, u)
                case (BoundType.CLOSED, l, BoundType.OPEN, u) => (l, u - 1)
                case (BoundType.OPEN, l, BoundType.CLOSED, u) => (l + 1, u)
                case (BoundType.OPEN, l, BoundType.OPEN, u) => (l + 1, u - 1)
            }
            if (lower == upper) lower.toString
            else s"$lower-$upper"
        }).mkString(",")

    override protected def process(file: String, url: String, user: String, password: String): Unit = {
        val cache = buildCache(url, user, password)
        val records: List[FirewallConnectionsRule] = parse(file).map(m =>
                FirewallConnectionsRule(
                    org = m("organization").toString,
                    sourceIp = any2none(m.get("src_host_ip"), identity),
                    destinationIp = any2none(m.get("target_host_ip"), identity),
                    allPortAllowed = m.get("allportallowed").fold(false)(_.toString.toBoolean),
                    allProtocolAllowed = m.get("allprotocolallowed").fold(false)(_.toString.toBoolean),
                    protocolAllowed = any2none(m.get("protocol_allowed").orElse(m.get("proto")), identity),
                    sourcePort = any2none(m.get("src_host_port"), v => v.toInt),
                    destinationPort = any2none(m.get("target_port_allowed").orElse(m.get("target_host_port")), v => v.toInt)
                )
        )

        val orgs: Map[String, Int] = findOrCreateOrg(cache, records.map(_.org).distinct)
        val hosts: List[(String, Option[String], Option[String])] =
            records.flatMap {
                case FirewallConnectionsRule(org, Some(srcIp), Some(dstIp), _, _, _, _, _) => Iterator(org -> srcIp, org -> dstIp)
                case FirewallConnectionsRule(org, Some(srcIp), None, _, _, _, _, _) => Iterator(org -> srcIp)
                case FirewallConnectionsRule(org, None, Some(dstIp), _, _, _, _, _) => Iterator(org -> dstIp)
                case FirewallConnectionsRule(_, None, None, _, _, _, _, _) => Iterator.empty
            }.map {
                case (org, ip) => (org, None, Some(ip))
            }.distinct
        val protocols = records.flatMap {
            case FirewallConnectionsRule(_, _, _, _, false, Some(proto), _, _) => Iterator(proto)
            case FirewallConnectionsRule(_, _, _, _, true, _, _, _) => Iterator.empty
        }.toSet
        val rules = records
            .groupBy(r => (r.org, r.sourceIp, r.destinationIp, r.protocolAllowed))
            .map {
                case (rule, ports) =>
                    rule -> ports.foldLeft((TreeRangeSet.create[Integer], TreeRangeSet.create[Integer]))((acc, p) => {
                                (port2range(acc._1, p.sourcePort), port2range(acc._2, p.destinationPort))
                            })
            }
            .map {
                case (rule, intervals) =>
                    (rule, ranges2intervals(intervals._1), ranges2intervals(intervals._2))
            }
            .map {
                case (rule, sourcePorts, destPorts) => (
                    rule,
                    if (sourcePorts.isEmpty) None else Some(sourcePorts),
                    if (destPorts.isEmpty) None else Some(destPorts)
                )
            }
        /* ========================================================================================================== */

        val scheduleGroupId = findOrCreateScheduleGroups(cache, cache.schedule(), List((0, 0, true)))
        val hostId = findOrCreateHosts(cache, orgs, hosts)
        val objectId = findOrCreateObjects(cache, protocols.map(p => ("protocol", None, Some(p))))
        /* ========================================================================================================== */

        rules.foreach {
            case ((org, srcIp, dstIp, proto), sourcePorts, destPorts) =>
                val subjectId = findOrCreateSubjects(cache, orgs, List((org, None, None)), scheduleGroupId.head._2)

                val foundRule: Option[Int] = cache.rule(
                    subject = subjectId((org, None, None)),
                    source = srcIp.map(ip => hostId((org, None, Some(ip)))),
                    destination = dstIp.map(ip => hostId((org, None, Some(ip)))),
                    `object` = proto.map(p => objectId(("protocol", None, Some(p)))),
                    result = Allowed,
                    usecaseId = "",
                    `type` = FirewallConnection,
                    schedule = scheduleGroupId.head._2,
                    aux1 = sourcePorts,
                    aux2 = destPorts).headOption

                foundRule match {
                    case Some(id) =>
                        println(s"Rule already persisted with id [$id]")
                    case None =>
                        println(s"Persist rule [$org, $subjectId, $srcIp, $dstIp, $proto $scheduleGroupId]")
                        cache.add(
                            subject = subjectId((org, None, None)),
                            source = srcIp.map(ip => hostId((org, None, Some(ip)))),
                            destination = dstIp.map(ip => hostId((org, None, Some(ip)))),
                            `object` = proto.map(p => objectId(("protocol", None, Some(p)))),
                            result = Allowed,
                            usecaseId = "",
                            `type` = FirewallConnection,
                            schedule = scheduleGroupId.head._2,
                            aux1 = sourcePorts,
                            aux2 = destPorts
                        )
                }
        }

    }

}