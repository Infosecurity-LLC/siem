package ru.gkis.soc.siem.enricher.cache

import java.time.{Instant, LocalDateTime, ZoneOffset}

import ru.gkis.soc.siem.model.DomainLogin
import ru.gkis.soc.siem.model.access.LoginWithOrg

object LoginsCache {

    def apply(items: List[LoginWithOrg]): LoginsCache = {
        val logins = items.map {
            case LoginWithOrg(login, orgShortName, userName, groupId, phone, email, monitored, userDomain, startWork) =>
                val key = makeKey(orgShortName.toLowerCase, userDomain.fold(any)(_.toLowerCase), login.fold(any)(_.toLowerCase))

                key -> DomainLogin(groupId, userName, phone, email, monitored, startWork)
        }.toMap

        new LoginsCache(logins)
    }

    private[enricher] def makeKey(org: String, domain: String, login: String): String = {
        s"${org}_${domain}_${login}"
    }
}


case class LoginsCache(logins: Map[String, DomainLogin],
                       lastUpdated: Long = Instant.now().getEpochSecond) extends CacheStatus {
    def find(org: String, domain: String, login: String): Option[DomainLogin] = {
        logins.get(LoginsCache.makeKey(org, domain, login))
    }

    override def size: Long = logins.size
}
