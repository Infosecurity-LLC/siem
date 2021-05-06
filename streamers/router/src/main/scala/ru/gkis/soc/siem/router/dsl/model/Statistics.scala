package ru.gkis.soc.siem.router.dsl.model

/**
 * @param total - Total message count
 * @param garbage - count messages without registered organization and/or topic
 * @param skipped - count messages that throw to /dev/null
 * @param sent - count sent messages by topic from configuration
 */
case class Statistics(total: Int, garbage: Int, skipped: Int, sent: Map[String, Int]) {
    def +(other: Statistics): Statistics = {
        Statistics(
            total = total + other.total,
            garbage = garbage + other.garbage,
            skipped = skipped + other.skipped,
            sent = (sent.toSeq ++ other.sent.toSeq).groupBy(_._1).mapValues(_.map(_._2).sum)
        )
    }
}
