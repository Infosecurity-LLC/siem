package ru.gkis.soc.siem.normalizer.validators

import ru.gkis.soc.siem.normalizer.ParsedEvent
import java.util.regex.Pattern

import com.google.common.net.InetAddresses

class FortigateValidator extends AbstractValidator[ParsedEvent] {

    import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._

    private val subTypeListForTraffic = Set("forward", "local")
    private val fieldsWithIpAddress = Set("srcip", "remip", "ip", "dstip", "locip", "tunnelip")
    private val eventIdsListForEventSystem = Set("0100032001", "0100032002", "0100032003", "0100032053", "0100032054")
    private val patternTimeLong =  Pattern.compile("""^\d{10}|\d{13}|\d{16}|\d{19}$""")

    "All fields containing IP address" should "match correct pattern" in {
       evt => evt.event.keys.foldLeft(true)((res, key) => if (fieldsWithIpAddress.contains(key)) evt.event.extractOpt(key).fold(res)( ip => InetAddresses.isInetAddress(ip) && res)  else res)
    }

    "Field eventtime" is "required" in {
        _.event.contains("eventtime")
    }

    "Type of eventtime field" is "Long" in {
        evt => evt.event.extractOpt("eventtime").map(patternTimeLong.matcher).fold(false)(_.matches)
    }

    "Field logid" is "required" in {
        _.event.contains("logid")
    }

    "Field type" is "required" in {
        _.event.contains("type")
    }

    "Field subtype" is "required" in {
        evt => evt.event.contains("subtype")
    }

    whether {
        evt => evt.event.contains("type") &&
               evt.event.contains("subtype") &&
               evt.event.extract("type") == "traffic" &&
               subTypeListForTraffic.contains(evt.event.extract("subtype"))
    } check {

        "Field service" is "required" in {
            evt => evt.event.contains("service")
        }

        "Field rcvdbyte" is "required" in {
            evt => evt.event.contains("rcvdbyte")
        }

        "Field sentbyte" is "required" in {
            evt => evt.event.contains("sentbyte")
        }

        "Field rcvdpkt" is "required" in {
            evt => evt.event.contains("rcvdpkt")
        }

        "Field sentpkt" is "required" in {
            evt => evt.event.contains("sentpkt")
        }

        "Field srcip" is "required" in {
            evt => evt.event.contains("srcip") || evt.event.contains("remip") || evt.event.contains("ip")
        }

        "Field srcport" is "required" in {
            evt => evt.event.contains("srcport")
        }

        "Field srccountry" is "required" in {
            evt => evt.event.contains("srccountry")
        }

        "Field dstip" is "required" in {
            _.event.contains("dstip")
        }

        "Field dstport" is "required" in {
            _.event.contains("dstport")
        }

        "Field dstcountry" is "required" in {
            evt => evt.event.contains("dstcountry")
        }

    }

    whether {
        evt => evt.event.contains("type") &&
               evt.event.contains("subtype") &&
               evt.event.extract("type") == "event" &&
               evt.event.extract("subtype") == "user"
    } check {

        "Field srcip" is "required" in {
            evt => evt.event.contains("srcip") || evt.event.contains("remip") || evt.event.contains("ip")
        }

        "Field user" is "required" in {
            _.event.contains("user")
        }
    }

    whether {
        evt => evt.event.contains("type") &&
               evt.event.contains("subtype") &&
               evt.event.extract("type") == "event" &&
               evt.event.extract("subtype") == "system" &&
               eventIdsListForEventSystem.contains(evt.event.extract("logid"))
    } check {

        "Field srcip" is "required" in {
            evt => evt.event.contains("srcip") || evt.event.contains("remip") || evt.event.contains("ip")
        }

        "Field dstip" is "required" in {
            evt => evt.event.contains("dstip") || evt.event.contains("locip") || evt.event.contains("tunnelip")
        }

        "Field user" is "required" in {
            _.event.contains("user")
        }

        "Field action" is "required" in {
            _.event.contains("action")
        }

        "Field status" is "required" in {
            _.event.contains("status")
        }

        "Field reason" is "required" in {
            _.event.contains("reason")
        }
    }

    whether {
        evt => evt.event.contains("type") &&
               evt.event.contains("subtype") &&
               evt.event.extract("type") == "event" &&
               evt.event.extract("subtype") == "vpn"
    } check {

        "Field remip" is "required" in {
            _.event.contains("remip")
        }

        "Field user" is "required" in {
            _.event.contains("user")
        }
    }
}

object FortigateValidator {
    val name: String = "fortigate"
    val version: Int = 1
}