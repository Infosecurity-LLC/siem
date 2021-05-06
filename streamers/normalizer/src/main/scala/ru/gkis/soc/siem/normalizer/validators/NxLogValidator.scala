package ru.gkis.soc.siem.normalizer.validators

import com.google.common.net.{InetAddresses, InternetDomainName}
import ru.gkis.soc.siem.model.TransformationPreferences
import ru.gkis.soc.siem.normalizer.ParsedMessage

class NxLogValidator extends AbstractValidator[(ParsedMessage, TransformationPreferences)] {

    "Organization" is "inactive or does not have configured pipelines" in { case (msg, prefs) =>
        prefs.contains(msg.organization)
    }

    "DevType" is "not configured for organization" in { case (msg, prefs) =>
        prefs.contains(msg.organization) && prefs(msg.organization).contains(msg.eventDevType)
    }

    "collectorHostIP" is "correct IP address" in { case (msg, _) =>
        InetAddresses.isInetAddress(msg.collectorHostIP)
    }

    "eventHostIP" is "correct IP address" in { case (msg, _) =>
            InetAddresses.isInetAddress(msg.eventHostIP)
    }

    "collectorHostname" is "correct hostname" in { case (msg, _) =>
            InternetDomainName.isValid(msg.collectorHostname)
    }

    "eventHostname" is "correct if existst" in { case (msg, _) =>
        msg.eventHostname.isEmpty || InternetDomainName.isValid(msg.eventHostname.get)
    }
}

object NxLogValidator {
    val name: String = "org-devtype"
    val version: Int = 1
}