package ru.gkis.soc.siem.controluploader

import com.typesafe.config.{Config, ConfigFactory}
import org.apache.commons.cli.{CommandLine, DefaultParser, HelpFormatter, Options, Option => CliOption}
import org.supercsv.cellprocessor.Optional
import org.supercsv.cellprocessor.ift.CellProcessor
import org.supercsv.io.CsvMapReader
import org.supercsv.prefs.CsvPreference
import ru.gkis.soc.siem.cache.adapters.SubjectAdapter
import ru.gkis.soc.siem.cache.{CacheConfig, WriteMetaCache}
import ru.gkis.soc.siem.model.access.{Host, Organization, RuleObject, Schedule, Subject}

import java.nio.charset.StandardCharsets
import java.time.{LocalDateTime, LocalTime}
import scala.io.Source
import scala.util.{Failure, Success, Try}

trait Uploader {

    import Uploader._
    import scala.collection.JavaConversions._

    protected def process(file: String, url: String, user: String, password: String): Unit

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

    protected def parse(file: String): List[Map[String, AnyRef]] = {
        val src = Source.fromFile(file, StandardCharsets.UTF_8.name()).bufferedReader()
        val prefs = new CsvPreference.Builder('"', ',', "\n")
            .ignoreEmptyLines(true)
            .build()
        new Iterator[Map[String, AnyRef]] {
            private val parser = new CsvMapReader(src, prefs)
            private val header: Array[String] = parser.getHeader(true)
            private val processors: Array[CellProcessor] = header.map(_ => new Optional)
            private var cur = Map.empty[String, AnyRef]

            override def hasNext: Boolean = {
                parser.getLineNumber -> Try(parser.read(header, processors)) match {
                    case (_, Success(value)) =>
                        Option(value).fold(false)(v => { cur = v.toMap; true })
                    case (lineNum, Failure(ex)) =>
                        throw new RuntimeException(s"Could not parse CSV source [$file] @row $lineNum", ex)
                }
            }

            override def next(): Map[String, AnyRef] = cur
        }
        .toList
    }

    protected def buildOptions: Options = {
        new Options()
            .addOption(
                CliOption
                    .builder("f")
                    .longOpt("file")
                    .hasArg(true)
                    .desc("source file [REQUIRED]")
                    .required
                    .build)
            .addOption(
                CliOption
                    .builder("u")
                    .longOpt("url")
                    .hasArg(true)
                    .desc("JDBC URL [REQUIRED]")
                    .required
                    .build)
            .addOption(
                CliOption
                    .builder("l")
                    .longOpt("login")
                    .hasArg(true)
                    .desc("login [REQUIRED]")
                    .required
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

    def run(args: Array[String], process: (String, String, String, String) => Unit): Unit = {
        val options = buildOptions
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

    def findOrCreateHosts(cache: WriteMetaCache, orgs: Map[String, Int], hosts: Iterable[(String, Option[String], Option[String])]): Map[(String, Option[String], Option[String]), Int] = {
        hosts
            .map { case (org, hostName, ip) =>
                val orgId: Int = orgs(org)

                cache.host(orgId, hostName, ip).headOption match {
                    case Some(host) =>
                        (org, hostName, ip) -> host.id
                    case None =>
                        val id = cache.add(Host(0, hostName, orgId, None, ip, LocalDateTime.now(), None))
                        (org, hostName, ip) -> id
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

    def findOrCreateSubjects(cache: WriteMetaCache, orgs: Map[String, Int], subjects: Iterable[(String, Option[String], Option[String])], groupId: Int): Map[(String, Option[String], Option[String]), Int] = {
        subjects
            .map { case (org, login, domain) =>
                val orgId: Int = orgs(org)

                cache.subj(orgId, login, domain).headOption match {
                    case Some(subj) =>
                        (org, login, domain) -> subj.id
                    case None =>
                        val id = cache.add(orgId, Subject(0, null, login, None, groupId, None, None, monitored = true, domain, LocalDateTime.now()))
                        (org, login, domain) -> id
                }
            }
            .toMap
    }

    def findOrCreateObjects(cache: WriteMetaCache, objects: Iterable[(String, Option[String], Option[String])]) = {
        objects
            .map { case (typ, path, name) =>

                cache.obj(typ, path, name).headOption match {
                    case Some(obj) =>
                        (typ, path, name) -> obj.id
                    case None =>
                        val id = cache.add(RuleObject(0, typ, path, name, None))
                        (typ, path, name) -> id
                }
            }
            .toMap
    }

}

object Uploader {

    implicit class RichCommandLine(cmd: CommandLine) {
        def maybeString(char: Char): Option[String] = {
            Option(cmd.getOptionValue(char))
        }
    }

}
