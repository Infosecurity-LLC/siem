package ru.gkis.soc.siem.controluploader

import ru.gkis.soc.siem.model.access._
import com.typesafe.config.{Config, ConfigFactory}
import org.apache.commons.cli.{CommandLine, DefaultParser, HelpFormatter, Options, Option => CliOption}
import ru.gkis.soc.siem.cache.{CacheConfig, WriteMetaCache}
import ru.gkis.soc.siem.model.access.{Host, Organization, Schedule}

import java.nio.charset.StandardCharsets
import java.time.{LocalDateTime, LocalTime}
import scala.util.{Failure, Success, Try}
import scala.io.Source

case class WindowsObjectAccessRule(org: String,
                                   hostname: String,
                                   ip: String,
                                   catalog: String,
                                   username: String,
                                   userDomain: String,
                                   filesMask: String,
                                   fromTime: Int,
                                   toTime: Int,
                                   isWeekendAllowed: Boolean)

object WindowsObjectAccessUploader {
    def main(args: Array[String]): Unit = {
        println("WindowsObjectAccessUploader started")
        run(args, process)
    }

    protected def process(file: String, url: String, user: String, password: String): Unit = {
        val cache = buildCache(url, user, password)
        val src = Source.fromFile(file, StandardCharsets.UTF_8.name())
        val source: Seq[String] = src.getLines().toArray.toSeq
        val lines: Seq[WindowsObjectAccessRule] = source.drop(1).map { line =>
            val r = line.split(',')

            WindowsObjectAccessRule(
                org = r(0),
                hostname = r(1),
                ip = r(2),
                catalog = r(3),
                username = r(4),
                userDomain = r(5),
                filesMask = r(6),
                fromTime = r(7).toInt,
                toTime = r(8).toInt,
                isWeekendAllowed = r(9).toBoolean
            )
        }

        val orgs: Map[String, Int] = findOrCreateOrg(cache, lines.map(_.org).distinct)
        val grouped: Map[(String, String, String), Seq[WindowsObjectAccessRule]] = lines.groupBy(l => (l.org, l.hostname, l.ip))
        val hosts: Map[(Int, String, String), Int] = findOrCreateHost(cache, orgs, grouped.keys)
        val scheduleGroups: Map[(Int, Int, Boolean), Int] = findOrCreateScheduleGroups(cache, cache.schedule(), lines.map(l => (l.fromTime, l.toTime, l.isWeekendAllowed)).distinct)

        val subjects: Map[(Int, String, String), Int] = lines.groupBy(l => (l.org, l.username, l.userDomain)).map { case ((org, login, domain), lines) =>
            val orgId = orgs(org)

            cache.subj(orgId, Some(login), Some(domain)).headOption match {
                case Some(s) =>
                    (orgs(org), login, domain) -> s.id
                case None =>
                    val schedule: (Int, Int, Boolean) = lines.groupBy(l => (l.fromTime, l.toTime, l.isWeekendAllowed)).keys.head
                    val scheduleId = scheduleGroups(schedule)

                    (orgs(org), login, domain) -> cache.add(Some(login), None, orgId, scheduleId, Some(domain))
            }
        }

        val typ = "file"
        val objects: Map[(String, String, String), Int]  = lines.map(l => (l.catalog, l.filesMask)).map { case (catalog, rawFilesMask) =>
            val filesMask = rawFilesMask match {
                case "*" =>
                    None
                case value =>
                    Some(value)
            }

            val roId = cache.obj(typ, Some(catalog), filesMask).headOption match {
                case Some(ro) =>
                    ro.id
                case None =>
                    cache.add(RuleObject(0, typ, Some(catalog), filesMask, None))
            }

            (typ, catalog, rawFilesMask) -> roId
        }.toMap

        lines.foreach { case WindowsObjectAccessRule(org, hostname, ip, catalog, username, domain, filesMask, fromTime, toTime, isWeekendAllowed) =>
            val orgId: Int = orgs(org)
            val subjectId: Int = subjects(orgId, username, domain)
            val sourceId: Int = hosts(orgId, hostname, ip)
            val scheduleGroupId: Int = scheduleGroups(fromTime, toTime, isWeekendAllowed)
            val objectId: Int = objects(typ, catalog, filesMask)

            val foundRule: Option[Int] = cache.rule(
                subject = subjectId,
                source = Some(sourceId),
                destination = None,
                `object` = Some(objectId),
                result = Allowed,
                usecaseId = "",
                `type` = WindowsObject,
                schedule = scheduleGroupId,
                aux1 = None,
                aux2 = None).headOption

            foundRule match {
                case Some(id) =>
                    println(s"Rule already persisted with id [$id]")
                case None =>
                    println(s"Persist rule [$orgId, $subjectId, $sourceId, $objectId, $scheduleGroupId]")
                    cache.add(
                        subject = subjectId,
                        source = Some(sourceId),
                        destination = None,
                        `object` = Some(objectId),
                        result = Allowed,
                        usecaseId = "",
                        `type` = WindowsObject,
                        schedule = scheduleGroupId,
                        aux1 = None,
                        aux2 = None
                    )
            }
        }

        println("Generation complete")
        src.close()
    }

    def run(args: Array[String], process: (String, String, String, String) => Unit): Unit = {
        val options = buildOptions()
        val parser = new DefaultParser

        def printHelp(): Unit = {
            System.err.println("Error parsing command-line arguments!")
            System.out.println("Please, follow the instructions below:")
            val formatter: HelpFormatter = new HelpFormatter
            formatter.printHelp("Log messages to sequence diagrams converter", options)
        }

        println("Try parse program options")

        Try(parser.parse(options, args)) match {
            case Failure(ex) =>
                System.err.println(s"Fail to parse argument, because: ${ex.getMessage}")
                printHelp()
            case Success(cmd) =>
                (cmd.maybeString('f'), cmd.maybeString('u'), cmd.maybeString('l'), cmd.maybeString('p')) match {
                    case (Some(file), Some(url), Some(login), Some(password)) =>
                        process(file, url, login, password)
                    case _ =>
                        printHelp()
                }
        }
    }

    def buildCache(url: String, user: String, password: String): WriteMetaCache = {
        val cfg: Config = {
            import collection.JavaConverters._

            ConfigFactory.parseMap(Map(
                "app.streamers_meta.jdbcUrl" -> url,
                "app.streamers_meta.username" -> user,
                "app.streamers_meta.password" -> password
            ).asJava)
        }

        val config: CacheConfig = new CacheConfig {
            override protected val appConf: Config = cfg
        }
        new WriteMetaCache(config)
    }

    def buildOptions() = {
        new Options()
            .addOption(
                CliOption
                    .builder("f")
                    .longOpt("file")
                    .hasArg(true)
                    .desc("source file [REQUIRED]")
                    .required(false)
                    .build)
            .addOption(
                CliOption
                    .builder("u")
                    .longOpt("url")
                    .hasArg(true)
                    .desc("JDBC URL [REQUIRED]")
                    .required(false)
                    .build)
            .addOption(
                CliOption
                    .builder("l")
                    .longOpt("l")
                    .hasArg(true)
                    .desc("login [REQUIRED]")
                    .required(false)
                    .build)
            .addOption(
                CliOption
                    .builder("p")
                    .longOpt("password")
                    .hasArg(true)
                    .desc("password [REQUIRED]")
                    .required
                    .build)
    }

    implicit class RichCommandLine(cmd: CommandLine) {
        def maybeString(char: Char): Option[String] = {
            Option(cmd.getOptionValue(char))
        }
    }

    def findOrCreateOrg(cache: WriteMetaCache, orgs: Seq[String]): Map[String, Int] = {
        orgs.map { org =>
            cache.org(org).headOption match {
                case Some(o) =>
                    org -> o.id
                case None =>
                    org -> cache.add(Organization(0, org, org, LocalDateTime.now(), None))
            }
        }.toMap
    }

    def findOrCreateHost(cache: WriteMetaCache, orgs: Map[String, Int], hosts: Iterable[(String, String, String)]): Map[(Int, String, String), Int] = {
        hosts
            .map { case (org, hostName, ip) =>
                val orgId: Int = orgs(org)

                cache.host(orgId, Some(hostName), Some(ip)).headOption match {
                    case Some(host) =>
                        (orgId, hostName, ip) -> host.id
                    case None =>
                        val id = cache.add(Host(0, Some(hostName), orgId, None, Some(ip), LocalDateTime.now(), None))
                        (orgId, hostName, ip) -> id
                }
            }
            .toMap
    }

    def findOrCreateScheduleGroups(cache: WriteMetaCache, schedules: List[Schedule], items: Iterable[(Int, Int, Boolean)]): Map[(Int, Int, Boolean), Int] = {
        items.map { case (fromTime, toTime, isWeekendAllowed) =>
            val (daysWork, daysWeekend) = if (isWeekendAllowed) (7, 0) else (5, 2)
            val fTime = LocalTime.of(fromTime, 0, 0)
            val tTime = if (toTime == 24) LocalTime.of(0, 0, 0) else LocalTime.of(toTime, 0, 0)

            schedules.find({ s =>
                s.daysWork == daysWork && s.daysWeekend == daysWeekend && s.timeFrom == fTime && s.timeTo == tTime
            }) match {
                case Some(schedule) =>
                    (fromTime, toTime, isWeekendAllowed) -> schedule.groupId
                case None =>
                    val sgId = cache.add("tmp")
                    cache.update(sgId, s"$sgId-group")
                    cache.add(Schedule(0, sgId, fTime, tTime, daysWork.toByte, daysWeekend.toByte, isCalendar = true))
                    (fromTime, toTime, isWeekendAllowed) -> sgId
            }
        }.toMap
    }
}
