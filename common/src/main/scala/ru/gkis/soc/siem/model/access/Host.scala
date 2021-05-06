package ru.gkis.soc.siem.model.access

import java.time.LocalDateTime

case class Host(id: Int,
                hostName: Option[String],
                orgId: Int,
                userName: Option[String],
                hostIp: Option[String],
                added: LocalDateTime,
                description: Option[String])
