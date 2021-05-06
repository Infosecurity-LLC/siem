package ru.gkis.soc.siem.enricher.time

import org.json4s.DefaultFormats

import java.time.{Instant, LocalDate, ZoneId, ZonedDateTime}
import scala.io.Source

case class ProductionCalendar(holidays: Set[LocalDate]) {
    def isWorkingDay(timestamp: Long): Boolean = {
        val time: ZonedDateTime = Instant.ofEpochSecond(timestamp).atZone(ZoneId.of("UTC"))
        !holidays.contains(time.toLocalDate)
    }

    def isWorkingDay(dateTime: ZonedDateTime): Boolean = {
        !holidays.contains(dateTime.toLocalDate)
    }
}

/**
 * Data originally taken from https://github.com/d10xa/holidays-calendar
 */
object ProductionCalendar {

    case class RawData(holidays: Seq[String])

    def read(name: String): ProductionCalendar = {
        import org.json4s.jackson.Serialization.{read => readJson}

        implicit val formats = DefaultFormats
        val raw = Source.fromInputStream(getClass.getResourceAsStream(name)).getLines.mkString
        val result: Set[String] = readJson[RawData](raw).holidays.toSet
        init(result)
    }

    def init(raw: Set[String]): ProductionCalendar = {
        val fromYear: Int = LocalDate.now().getYear - 1
        val holidays: Set[LocalDate] = raw.map(LocalDate.parse).filter(_.getYear >= fromYear)

        new ProductionCalendar(holidays)
    }
}