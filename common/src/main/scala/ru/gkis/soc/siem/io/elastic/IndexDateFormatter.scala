package ru.gkis.soc.siem.io.elastic

import org.elasticsearch.hadoop.serialization.field.IndexFormatter
import org.elasticsearch.hadoop.util.{Constants, StringUtils}

import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

/**
 * This class was added to fix index date formatting problem resided in
 * org.elasticsearch.hadoop.serialization.field.DateIndexFormatter. Basic class uses
 * java.util.Calendar to convert date which causes implicit UTC timestamp conversion to LocalTime
 */
class IndexDateFormatter extends IndexFormatter {

    /**
     * this should never happen!
     * we run this check just to avoid random formatting problems if it does
     * @see org.elasticsearch.hadoop.serialization.field.DateIndexFormatter#fixDateForJdk
     */
    if (!Constants.JRE_IS_MINIMUM_JAVA7) {
        throw new RuntimeException("This code is designed for JDK7+")
    }

    /**
     * Nulls OK here - this will be run from java code
     */
    private var dateFormat: DateTimeFormatter = null

    override def configure(format: String): Unit =
        this.dateFormat = DateTimeFormatter.ofPattern(format)

    override def format(value: String): String =
        if (StringUtils.hasText(value)) ZonedDateTime.parse(value).format(dateFormat)
        else null

}
