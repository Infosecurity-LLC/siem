package ru.gkis.soc.siem.normalizer.mappers.helpers

import ru.gkis.soc.siem.normalizer.InternalSocEvent

import java.time.ZonedDateTime
import java.time.format.{DateTimeFormatter, DateTimeFormatterBuilder, TextStyle}
import java.util.Locale
import scala.util.{Failure, Success, Try}
import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._

object CiscoDateMapper {
    private val formatter: DateTimeFormatter = new DateTimeFormatterBuilder().parseCaseInsensitive().appendPattern("MMM dd yyyy HH:mm:ss z").toFormatter(Locale.ENGLISH)

    def apply(isoc: InternalSocEvent): Long = {
        val fallback = isoc.message.eventReceivedTime

        val (month, day, year, time, timeZone) = (
            isoc.event.getOrElse("month", fallback.getMonth.getDisplayName(TextStyle.SHORT, Locale.ENGLISH)),
            isoc.event.extractOpt("day").map(d => s"0$d".takeRight(2)).getOrElse(fallback.getDayOfMonth.toString),
            isoc.event.getOrElse("year", fallback.getYear.toString),
            isoc.event.extractOpt("time").map(_.take(8)).getOrElse(s"${fallback.getHour}:${fallback.getMinute}:${fallback.getSecond}"),
            isoc.event.extractOpt("timezone").filter(_.length == 3).getOrElse(fallback.getZone.getDisplayName(TextStyle.SHORT_STANDALONE, Locale.ENGLISH))
        )

        Try(ZonedDateTime.parse(s"$month $day $year $time $timeZone", formatter).toEpochSecond) match {
            case Success(value) =>
                value
            case Failure(_) =>
                fallback.toEpochSecond
        }
    }
}
