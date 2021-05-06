package ru.gkis.soc.siem.cache

import java.time.{Instant, LocalDateTime, LocalTime, ZoneOffset}
import java.util.Date
import io.getquill.{PostgresJdbcContext, SnakeCase}
import ru.gkis.soc.siem.model.access._

class MetaCacheContext(conf: CacheConfig) {

    // create sql context
    val dsl: PostgresJdbcContext[SnakeCase] = new PostgresJdbcContext(SnakeCase, conf.metabaseConfig)
    import dsl._

    // reqister java LocalDateTime implicit mappings
    implicit val encodeDate: MappedEncoding[Date, LocalDateTime] = MappedEncoding[Date, LocalDateTime](d =>  LocalDateTime.ofInstant(Instant.ofEpochMilli(d.getTime), ZoneOffset.UTC) )
    implicit val decodeDate: MappedEncoding[LocalDateTime, Date] = MappedEncoding[LocalDateTime, Date](ldt => Date.from(ldt.toInstant(ZoneOffset.UTC)))

    ////https://jdbc.postgresql.org/documentation/head/8-date-time.html
    implicit val encodeLocalTime: Encoder[LocalTime] =
        encoder(
            java.sql.Types.OTHER,
            (index, value, row) => row.setObject(index, value)
        )

    implicit val decodeLocalTime: Decoder[LocalTime] =
        decoder(
            (index, row) => row.getObject(index, classOf[LocalTime])
        )

    implicit class ForLocalDateTime(ldt: LocalDateTime) {
        def > = quote((arg: LocalDateTime) => infix"$ldt > $arg".as[Boolean])
        def < = quote((arg: LocalDateTime) => infix"$ldt < $arg".as[Boolean])
    }

    val encodeNetworkArray: MappedEncoding[String, Array[String]] = MappedEncoding[String, Array[String]](value => value.split(";"))

    implicit val encodeRuleResult: MappedEncoding[Int, RuleResult] = MappedEncoding[Int, RuleResult]{
        case 0 => Allowed
        case 1 => Restricted
    }

    implicit val encodeRuleType: MappedEncoding[String, RuleType] = MappedEncoding[String, RuleType]{
        case "WindowsLogon" => WindowsLogon
        case "WindowsObject" => WindowsObject
        case "WindowsProcess" => WindowsProcess
        case "LinuxLogon" => LinuxLogon
        case "LinuxObject" => LinuxObject
        case "LinuxProcess" => LinuxProcess
        case "VpnLogon" => VpnLogon
        case "DatabaseLogon" => DatabaseLogon
        case "DatabaseObject" => DatabaseObject
        case "FirewallConnection" => FirewallConnection
    }
}
