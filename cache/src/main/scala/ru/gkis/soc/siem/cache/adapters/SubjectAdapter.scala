package ru.gkis.soc.siem.cache.adapters

import ru.gkis.soc.siem.model.access.{Organization, Subject}

import java.time.LocalDateTime

private[cache] case class SubjectAdapter(id: Int,
                                         login: Option[String],
                                         orgId: Int,
                                         userName: Option[String],
                                         groupId: Int,
                                         phone: Option[String],
                                         email: Option[String],
                                         monitored: Boolean,
                                         userDomain: Option[String],
                                         startWork: LocalDateTime) {
    def subject(organization: Organization): Subject = {
        Subject(id = id,
            organization = organization,
            login = login,
            userName = userName,
            groupId = groupId,
            phone = phone,
            email = email,
            monitored = monitored,
            userDomain = userDomain,
            startWork = startWork)
    }
}