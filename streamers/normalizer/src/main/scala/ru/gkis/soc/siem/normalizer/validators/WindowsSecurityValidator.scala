package ru.gkis.soc.siem.normalizer.validators

import com.google.common.net.InetAddresses
import ru.gkis.soc.siem.normalizer.ParsedEvent
import ru.gkis.soc.siem.normalizer.mappers.helpers.TypedExtractor._

import java.util.regex.Pattern

class WindowsSecurityValidator extends AbstractValidator[ParsedEvent] {

    private val allowedEventIds = Set(
        "4624", "4625", "5140", "5145", "4663", "4729", "4733", "4747", "4752", "4757", "4762",
        "4728", "4732", "4746", "4751", "4756", "4761", "4722", "4725", "4720", "4726",
        "4723", "4724", "4764", "4785", "4786", "4787", "4788", "4801",
        "4771", "4768",
        "4776", "4794", "4769", "4765", "4766","4738","4719"
    )

    private val hexPattern = Pattern.compile("^0[xX][0-9a-fA-F]+$")

    "Field EventID" is "required" in {
        isoc => isoc.event.contains("EventID")
    }

    "Field EventID" is s"should be one of ${allowedEventIds}" in {
        isoc => isoc.event.contains("EventID") && allowedEventIds.contains(isoc.event.extract("EventID"))
    }

    "Windows local machine authentications" should "be filtered out" in {
        isoc => !isoc
                    .event
                    .extractOpt(int"LogonType")
                    .map(_ == 3)   // check if logonType is set and is 3
                    .map(res =>    // check if targetUsername ends with $
                        isoc.event.extractOpt("TargetUserName").fold(false)(_.endsWith("$") & res)
                    )
                    .fold(false)(res => res)
    }

    "Field SourceAddress" should "be a valid ip address" in {
        evt => !evt.event.contains("SourceAddress") || InetAddresses.isInetAddress(evt.event("SourceAddress"))
    }

    "Field IpAddress" should "be a valid ip address" in {
        evt => !evt.event.contains("IpAddress") || InetAddresses.isInetAddress(evt.event("IpAddress"))
    }

    "Field ClientAddress" should "be a valid ip address" in {
        evt => !evt.event.contains("ClientAddress") || InetAddresses.isInetAddress(evt.event("ClientAddress"))
    }

    whether {
        _.event.contains("AccessMask")
    } check {
        "Field AccessMask" fits "0x00 hex number format if present" in {
            evt => hexPattern.matcher(evt.event("AccessMask")).matches
        }
    }

}

object WindowsSecurityValidator {
    val name: String = "windows_security"
    val version: Int = 2
}

