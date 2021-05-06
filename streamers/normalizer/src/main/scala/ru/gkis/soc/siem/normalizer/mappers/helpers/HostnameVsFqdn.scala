package ru.gkis.soc.siem.normalizer.mappers.helpers

object HostnameVsFqdn {

    private[this] def parseFqdn(str: String): (Option[String], Option[String]) = {
        val pos = str.indexOf('.')
        if (pos > 0) (Some(str), Some(str.substring(0, pos)))
        else (None, Some(str))
    }

    /**
     * Unties hostname and fqdn. This function is needed because lots of devices and even NXLog send fqdn in hostnames and
     * vice versa
     * @param fqdn
     * @param hostname
     * @return (fqdn, hostname)
     */
    def apply(maybeFqdn: Option[String], maybeHostname: Option[String]): (Option[String], Option[String]) = {
        (maybeFqdn, maybeHostname) match {
            case (Some(fullAddress), Some(address)) =>
                val fqdn = parseFqdn(fullAddress)
                val hostname = parseFqdn(address)
                (fqdn._1.orElse(hostname._1), fqdn._2.orElse(hostname._2))
            case (Some(fullAddress), None) =>
                parseFqdn(fullAddress)
            case (None, Some(address)) =>
                parseFqdn(address)
            case bothNone =>
                bothNone
        }
    }

}
