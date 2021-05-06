package ru.gkis.soc.siem.model.access

import java.time.LocalDateTime

case class Organization(id: Int, shortName: String, name: String, activeFrom: LocalDateTime, activeTo: Option[LocalDateTime])
