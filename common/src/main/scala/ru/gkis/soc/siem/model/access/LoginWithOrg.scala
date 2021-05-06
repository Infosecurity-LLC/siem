package ru.gkis.soc.siem.model.access

import java.time.LocalDateTime

case class LoginWithOrg(login: Option[String],
                        orgShortName: String,
                        userName: Option[String],
                        groupId: Int,
                        phone: Option[String],
                        email: Option[String],
                        monitored: Boolean,
                        userDomain: Option[String],
                        startWork: LocalDateTime)
